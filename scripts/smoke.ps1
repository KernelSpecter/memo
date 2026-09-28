<#
.SYNOPSIS
  Real-workload smoke test for memo.

.DESCRIPTION
  Each workload runs a real toolchain command through memo against a fixture
  project from scripts\fixtures. The fixture is copied to a fresh work dir
  under target\memo-smoke (not %TEMP%: memo ignores it) with its own MEMO_DIR.

    1. Three runs. Run 1 must be cached, and run 3 must be a replay. Tools that
       read their own previous outputs (.pyc, cargo fingerprints) need two real
       runs to converge. The replay's stdout, stderr and exit code must match
       the last real run, and the work tree must be byte-identical afterwards.
    2. Edit a source file's contents. The next run must not be a replay.
       (A bare touch is not enough: memo fingerprints read files by content.)

  A workload with Expect = 'network' instead must be refused as network
  access on every run: a stale replay there would hide a real server check.

  A workload whose toolchain is not installed is skipped with a message. The
  script never installs anything: network access during a traced run makes
  memo refuse to cache.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\smoke.ps1
  powershell -ExecutionPolicy Bypass -File scripts\smoke.ps1 -Only node-build,cargo-test
#>
param(
    # Use the existing target\release binaries instead of building them.
    [switch]$NoBuild,
    # Run only these workloads (by name).
    [string[]]$Only
)

$ErrorActionPreference = 'Stop'

$Repo = Split-Path -Parent $PSScriptRoot
$Fixtures = Join-Path $PSScriptRoot 'fixtures'
$SmokeRoot = Join-Path $Repo 'target\memo-smoke'
$MemoExe = Join-Path $Repo 'target\release\memo.exe'

# Artifacts left behind if someone ran a fixture in place; never copied.
$ArtifactNames = @('dist', 'target', 'Cargo.lock', '__pycache__', '.pytest_cache', 'node_modules')

function Test-Tool([string]$Name) {
    [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# True if `python -c "import pytest"` succeeds. Uses Process directly because
# PowerShell 5.1 turns redirected native stderr into terminating errors.
function Test-Pytest {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { return $false }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $py.Source
    $psi.Arguments = '-c "import pytest"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $null = $p.StandardOutput.ReadToEnd()
    $null = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    $p.ExitCode -eq 0
}

$Workloads = @(
    @{ Name = 'node-build';  Fixture = 'node'; Cmd = @('node', 'build.js')
       Edit = 'src\math.js'; Comment = '//'; Requires = { Test-Tool node }; Missing = 'node' }
    @{ Name = 'node-test';   Fixture = 'node'; Cmd = @('node', '--test')
       Edit = 'src\math.js'; Comment = '//'; Requires = { Test-Tool node }; Missing = 'node' }
    # Must NOT cache: a connect-only check that sends no data.
    @{ Name = 'node-net';    Fixture = 'node'; Cmd = @('node', 'net-check.js'); Expect = 'network'
       Requires = { Test-Tool node }; Missing = 'node' }
    @{ Name = 'py-unittest'; Fixture = 'py';   Cmd = @('python', '-m', 'unittest', 'discover', '-s', 'tests', '-t', '.')
       Edit = 'calc\ops.py'; Comment = '#';  Requires = { Test-Tool python }; Missing = 'python' }
    @{ Name = 'pytest';      Fixture = 'py';   Cmd = @('python', '-m', 'pytest', '-q')
       Edit = 'calc\ops.py'; Comment = '#';  Requires = { Test-Pytest }; Missing = 'pytest (python -m pip install pytest)' }
    @{ Name = 'cargo-test';  Fixture = 'rust'; Cmd = @('cargo', 'test', '--offline')
       Edit = 'src\lib.rs';  Comment = '//'; Requires = { Test-Tool cargo }; Missing = 'cargo' }
    @{ Name = 'tsc';         Fixture = 'ts';   Cmd = @('tsc', '-p', '.')
       Edit = 'src\index.ts'; Comment = '//'; Requires = { Test-Tool tsc }; Missing = 'tsc (npm install -g typescript)' }
)

function ConvertTo-ArgString([string]$Arg) {
    if ($Arg -match '[\s"]') { '"' + ($Arg -replace '"', '\"') + '"' } else { $Arg }
}

# memo's status line (forced on by MEMO_FORCE_STATUS since stderr is captured).
# Matched on words, not the glyph, so a console code page can't break it.
$StatusRe = '^memo \S (?<kind>replayed|not cached|cached)\b(?<rest>.*)$'

function Invoke-Memo([string]$WorkDir, [string]$CacheDir, [string[]]$CommandArgs) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $MemoExe
    $psi.Arguments = ($CommandArgs | ForEach-Object { ConvertTo-ArgString $_ }) -join ' '
    $psi.WorkingDirectory = $WorkDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $psi.EnvironmentVariables['MEMO_DIR'] = $CacheDir
    $psi.EnvironmentVariables['MEMO_FORCE_STATUS'] = '1'

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = [System.Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    $sw.Stop()

    $kind = 'none'
    $detail = ''
    $kept = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($errTask.Result -split "`r?`n")) {
        if ($line -match $StatusRe) {
            $kind = $Matches['kind']
            $detail = $Matches['rest'].Trim()
        } else {
            $kept.Add($line)
        }
    }
    [pscustomobject]@{
        Kind    = $kind
        Detail  = $detail
        Stdout  = $outTask.Result
        Stderr  = ($kept -join "`n")
        Exit    = $p.ExitCode
        Seconds = $sw.Elapsed.TotalSeconds
    }
}

# Content hash of every file under $Dir, keyed by relative path.
function Get-TreeHash([string]$Dir) {
    $root = (Resolve-Path $Dir).Path.TrimEnd('\') + '\'
    $lines = Get-ChildItem -LiteralPath $Dir -Recurse -File -Force |
        ForEach-Object { $_.FullName.Substring($root.Length).ToLowerInvariant() + ' ' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } |
        Sort-Object
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    [System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', ''
}

function Copy-Fixture([string]$From, [string]$To) {
    New-Item -ItemType Directory -Force -Path $To | Out-Null
    Get-ChildItem -LiteralPath $From -Force | Where-Object { $ArtifactNames -notcontains $_.Name } |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $To -Recurse -Force }
}

function Show-Run([int]$N, $R) {
    $line = '  run {0}: {1,-10} exit {2}  {3,7:N2}s' -f $N, $R.Kind, $R.Exit, $R.Seconds
    if ($R.Detail) { $line += "  $($R.Detail)" }
    Write-Host $line
}

# Both runs must be refused as network access, never cached or replayed.
function Invoke-NetworkWorkload($W, [string]$Work, [string]$Cache, $Fail) {
    $runs = @()
    for ($i = 1; $i -le 2; $i++) {
        $r = Invoke-Memo $Work $Cache $W.Cmd
        $runs += $r
        Show-Run $i $r
        if ($r.Exit -ne 0) { $Fail.Add("run $i exited $($r.Exit)") }
        if ($r.Kind -ne 'not cached' -or $r.Detail -notmatch 'network') {
            $Fail.Add("run $i was '$($r.Kind)' $($r.Detail), expected not cached: network access")
        }
    }
    foreach ($f in $Fail) { Write-Host "  FAIL: $f" -ForegroundColor Red }
    [pscustomobject]@{
        Name   = $W.Name
        Result = if ($Fail.Count -eq 0) { 'PASS' } else { 'FAIL' }
        Real   = $runs[0].Seconds
        Run2   = $runs[1].Kind
        Replay = $null
    }
}

function Invoke-Workload($W) {
    $base = Join-Path $SmokeRoot $W.Name
    if (Test-Path $base) { Remove-Item -LiteralPath $base -Recurse -Force }
    $work = Join-Path $base 'work'
    $cache = Join-Path $base 'cache'
    Copy-Fixture (Join-Path $Fixtures $W.Fixture) $work
    New-Item -ItemType Directory -Force -Path $cache | Out-Null

    $fail = New-Object System.Collections.Generic.List[string]
    if ($W.Expect -eq 'network') { return Invoke-NetworkWorkload $W $work $cache $fail }
    $runs = @()
    $recorded = $null   # the last real run that memo cached

    for ($i = 1; $i -le 3; $i++) {
        if ($i -eq 3) { $treeBefore = Get-TreeHash $work }
        $r = Invoke-Memo $work $cache $W.Cmd
        $runs += $r
        Show-Run $i $r
        if ($r.Kind -eq 'cached') { $recorded = $r }
    }
    $r1 = $runs[0]; $r3 = $runs[2]

    if ($r1.Exit -ne 0) { $fail.Add("run 1 exited $($r1.Exit)") }
    if ($r1.Kind -ne 'cached') { $fail.Add("run 1 was '$($r1.Kind)', expected cached $($r1.Detail)") }
    if ($r3.Kind -ne 'replayed') {
        $fail.Add("run 3 was '$($r3.Kind)', expected replayed $($r3.Detail)")
    } elseif ($recorded) {
        if ($r3.Stdout -cne $recorded.Stdout) { $fail.Add('replayed stdout differs from the recorded run') }
        if ($r3.Stderr -cne $recorded.Stderr) { $fail.Add('replayed stderr differs from the recorded run') }
        if ($r3.Exit -ne $recorded.Exit) { $fail.Add("replayed exit $($r3.Exit) != recorded $($recorded.Exit)") }
        if ((Get-TreeHash $work) -ne $treeBefore) { $fail.Add('replay changed the work tree') }
    }

    # Change a source file's contents; the next run must really execute.
    $editPath = Join-Path $work $W.Edit
    Add-Content -LiteralPath $editPath -Value "$($W.Comment) smoke edit"
    $r4 = Invoke-Memo $work $cache $W.Cmd
    Show-Run 4 $r4
    if ($r4.Kind -eq 'replayed') { $fail.Add("run 4 replayed after editing $($W.Edit)") }
    if ($r4.Exit -ne 0) { $fail.Add("run 4 exited $($r4.Exit)") }

    foreach ($f in $fail) { Write-Host "  FAIL: $f" -ForegroundColor Red }
    if ($fail.Count -gt 0 -and $recorded -eq $null -and $r1.Stderr) {
        Write-Host '  run 1 stderr:' -ForegroundColor DarkGray
        Write-Host ($r1.Stderr.TrimEnd()) -ForegroundColor DarkGray
    }
    [pscustomobject]@{
        Name   = $W.Name
        Result = if ($fail.Count -eq 0) { 'PASS' } else { 'FAIL' }
        Real   = $r1.Seconds
        Run2   = $runs[1].Kind
        Replay = if ($r3.Kind -eq 'replayed') { $r3.Seconds } else { $null }
    }
}

# --- main ---

if (-not $NoBuild) {
    Write-Host 'Building memo (release)...'
    Push-Location $Repo
    try {
        & cargo build --release -p memo -p memo-hook
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
    } finally { Pop-Location }
}
foreach ($bin in @($MemoExe, (Join-Path $Repo 'target\release\memo_hook.dll'))) {
    if (-not (Test-Path $bin)) { throw "missing $bin (build with: cargo build --release -p memo -p memo-hook)" }
}

$results = @()
foreach ($w in $Workloads) {
    if ($Only -and ($Only -notcontains $w.Name)) { continue }
    Write-Host ''
    Write-Host "== $($w.Name): memo $($w.Cmd -join ' ')"
    if (-not (& $w.Requires)) {
        Write-Host "  SKIP: $($w.Missing) not installed" -ForegroundColor Yellow
        $results += [pscustomobject]@{ Name = $w.Name; Result = 'SKIP'; Real = $null; Run2 = ''; Replay = $null }
        continue
    }
    $results += Invoke-Workload $w
}

Write-Host ''
$results | Format-Table -AutoSize Name, Result,
    @{ n = 'real run (s)'; e = { if ($_.Real -ne $null) { '{0:N2}' -f $_.Real } } },
    @{ n = 'run 2'; e = { $_.Run2 } },
    @{ n = 'replay (s)'; e = { if ($_.Replay -ne $null) { '{0:N2}' -f $_.Replay } } } | Out-Host

$failed = @($results | Where-Object { $_.Result -eq 'FAIL' })
if ($failed.Count -gt 0) {
    Write-Host "$($failed.Count) workload(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host 'All workloads passed.' -ForegroundColor Green
