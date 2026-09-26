# memo — design spec

Date: 2026-09-26
Status: approved to build (owner said "build the entire thing as you see fit")

## 1. What memo is

`memo` is a Windows command-line tool that caches the result of **any** command with
zero configuration:

```
> memo npx vitest run      # real run: 41.2s
> memo npx vitest run      # nothing relevant changed: replayed in ~50ms
```

It works by injecting a hook DLL into every process the command spawns, observing
every file the process tree reads, probes, lists, and writes, and fingerprinting
those inputs. On the next invocation, if every recorded input still matches, memo
replays the recorded console output, restores the files the command produced, and
exits with the recorded exit code — without running the command.

Think "Bazel-grade action caching without BUILD files".

### Goals

- Zero config: `memo <any command>` just works.
- **Never replay a stale result.** A false miss (re-running when a replay would have
  been fine) costs seconds. A false hit (replaying when a real run would differ)
  destroys trust. Every design decision below favors misses over wrong hits.
- Never break the user's command. If memo cannot trace, it runs the command
  normally and says why it did not cache.
- Make misses explainable: `memo explain <command>` says exactly which input
  changed.

### Non-goals (v1)

- Remote/shared cache, CI integration.
- 32-bit (WOW64) child processes — detected, run untraced, not cached.
- ARM64 Windows.
- Pseudo-console (ConPTY) capture — v1 uses pipes (see §7.4).
- Linux/macOS.

## 2. Environment and constraints

- Windows 10 1809+ / Windows 11, x86-64 only.
- Rust (stable, MSVC target), static CRT (`+crt-static`) so the hook DLL has no
  runtime dependency on `vcruntime140.dll`.
- Microsoft Detours (MIT), vendored at `vendor/detours`, compiled with the `cc` crate.
- No admin rights required.

## 3. Architecture

Cargo workspace:

| Crate | Kind | Responsibility |
|---|---|---|
| `memo-detours` | lib (sys) | Compiles vendored Detours, exposes the handful of Detours functions memo needs |
| `memo-proto` | lib | Wire format between hook DLL and memo: message types, framing, payload struct |
| `memo-hook` | cdylib → `memo_hook.dll` | Runs inside every traced process; hooks ntdll/kernelbase; reports events |
| `memo-core` | lib | Paths, fingerprints, directory listings, stat cache, content-addressed store, cache entries, matching |
| `memo` | bin → `memo.exe` | CLI, command resolution, cache lookup, traced launch, event server, finalize/store, replay, explain/stats/gc |
| `memo-probe` | bin (test fixture) | Tiny program that performs scripted file/process/network operations for integration tests |

`memo.exe` and `memo_hook.dll` ship side by side; memo finds the DLL next to its
own executable.

### 3.1 Data flow

1. **Resolve** the command (PATH + PATHEXT; `.cmd`/`.bat` go through `cmd.exe /d /s /c`).
2. **Key**: `key = BLAKE3(format_version, normalized cwd, argv, filtered env)`.
3. **Lookup**: load entries stored under `key`, newest first. For each, verify all
   recorded input fingerprints against the filesystem (§6). First full match → **hit**.
4. **Hit**: restore outputs (§7.2), replay console output, exit with recorded code.
5. **Miss**: create a pipe server, create a job object, spawn the root process
   suspended, inject `memo_hook.dll` with `DetourUpdateProcessWithDll`, copy the
   run payload (pipe name, run id) with `DetourCopyPayloadToProcess`, assign to the
   job, resume.
6. Every process in the tree (the hook re-injects into children) streams events to
   memo. Mutations are synchronous (§5.3).
7. When the root exits and the job drains, memo **finalizes**: decides cacheability,
   computes input fingerprints and output states, stores blobs and the entry.

## 4. The hook DLL (`memo_hook.dll`)

### 4.1 Loading

- Injected by Detours' import-table rewrite, so it loads before any of the target's
  own code runs.
- `DllMain(PROCESS_ATTACH)`: if `DetourIsHelperProcess()` return; call
  `DetourRestoreAfterWith()`; read payload via `DetourFindPayloadEx(MEMO_GUID)`; if
  no payload → do nothing (DLL loaded outside memo). Install hooks in one Detours
  transaction. Connect to memo's pipe and send `Hello`.
- Exports ordinal 1 (`DetourFinishHelperProcess`) as Detours requires (via a `.def`
  file).
- Enumerates modules already loaded (the loader mapped them before our hooks were
  live) and reports them in `Hello` as read inputs.

### 4.2 Hooked functions

| Function | Why |
|---|---|
| `NtCreateFile`, `NtOpenFile` | All file/dir opens: reads, probes, creates, writes, delete-on-close, negative lookups. Also detects opening by file ID (taint) |
| `NtQueryAttributesFile`, `NtQueryFullAttributesFile` | Path-based stat without opening |
| `NtQueryInformationByName` (if present) | Newer path-based stat (used by Rust std, Python 3.12+) |
| `NtQueryDirectoryFile`, `NtQueryDirectoryFileEx` | Directory enumeration |
| `NtSetInformationFile` | Rename, hard link, delete disposition, basic info (timestamps/attributes), EOF/allocation |
| `NtDeleteFile` | Delete by name |
| `NtFsControlFile` | `FSCTL_SET_REPARSE_POINT`/`DELETE` → taint (symlink/junction creation not replayable in v1) |
| `NtDeviceIoControlFile` | AFD connect / super-connect / send-datagram → taint `network` |
| `CreateProcessW`, `CreateProcessA`, `CreateProcessAsUserW` (kernelbase) | Propagate injection to children |

Every hook: a thread-local reentrancy guard; hook logic runs inside
`catch_unwind`; on any internal failure the hook reports a `Taint` (if it can) and
always calls the original function with the original arguments. Hooks never change
the result of the underlying call.

### 4.3 Child processes

The `CreateProcess*` hooks call the real function with `CREATE_SUSPENDED` added,
then:
- if the child is WOW64 → send `Taint(Wow64Child)`, resume without injection;
- else `DetourUpdateProcessWithDll` + `DetourCopyPayloadToProcess`; on failure send
  `Taint(InjectFailed)`;
- resume unless the caller asked for `CREATE_SUSPENDED`.

Independently, memo receives `JOB_OBJECT_MSG_NEW_PROCESS` for every process in the
job. Any job process that never sends `Hello` → not cacheable. This catches
processes created by paths the hooks do not cover (e.g. direct
`NtCreateUserProcess`).

### 4.4 Path normalization (in the hook)

The hook reports **Win32-style absolute paths**:
- `\??\C:\x` → `C:\x`; `\??\UNC\s\sh\x` → `\\s\sh\x`.
- `RootDirectory`-relative names are resolved with `NtQueryObject(ObjectNameInformation)`
  on the root handle.
- `\Device\HarddiskVolumeN\x` → drive letter via a volume map built at hook init
  (`QueryDosDeviceW` over A–Z).
- Pipes (`\Device\NamedPipe`, `\??\pipe\`), console (`\Device\ConDrv`, `CON`,
  `CONIN$`, `CONOUT$`), `NUL`, `\Device\Afd`, `\Device\KsecDD`, `\Device\CNG` and other
  non-filesystem devices are not reported as files.

memo further normalizes: strips trailing separators, collapses `.`/`..`, and uses a
case-folded form as the identity key while keeping the original spelling for I/O.

### 4.5 Event dedupe

Each process keeps a set of `(kind, case-folded path)` already reported; only the
first occurrence is sent. Mutations are deduped per process after the first
synchronous `PreMutate` for that path.

## 5. Tracing semantics

### 5.1 Observations (potential inputs)

| Event | Trigger |
|---|---|
| `Read(path)` | Open succeeded with `FILE_READ_DATA`/`FILE_EXECUTE`/`GENERIC_READ`/`GENERIC_ALL` (note `FILE_LIST_DIRECTORY` == `FILE_READ_DATA`: on a directory this is just a probe) |
| `Probe(path)` | Open succeeded with metadata-only access; any path-based stat call that succeeded; opens that failed with a non-"not found" error |
| `ProbeAbsent(path)` | Open or stat failed with `STATUS_OBJECT_NAME_NOT_FOUND` / `STATUS_OBJECT_PATH_NOT_FOUND` |
| `List(dir)` | `NtQueryDirectoryFile(Ex)` on a directory handle |

### 5.2 Mutations (potential outputs)

A mutation is any operation that can change a path's existence, content, or
metadata: open with write/append/write-attributes/delete access or with
`SUPERSEDE`/`CREATE`/`OVERWRITE`/`OVERWRITE_IF`/`OPEN_IF` dispositions,
`FILE_DELETE_ON_CLOSE`, rename (both source and target), hard link target, delete
disposition, `NtDeleteFile`, set-basic-info, set-EOF/allocation.

### 5.3 Synchronous pre-mutation snapshots

Before the real mutating call runs, the hook sends `PreMutate(path)` and **blocks
until memo acknowledges**. On the first `PreMutate` for a path in a run, memo
snapshots:
- the path's **pre-run state**: `Absent`, `Dir`, or `File{size, mtime, hash}`;
- the parent directory's **pre-run listing**, if not already snapshotted.

Because every tree mutation waits for this snapshot, memo always knows what a path
and its directory looked like *before the command touched them* — which is what
the command actually observed on earlier reads. This is what makes read-then-write
patterns (incremental compilers, test caches, `.pyc` files) correct.

### 5.4 Taints (make the run uncacheable)

- `Network` — any AFD connect/super-connect/datagram send (socket creation alone is
  fine: libuv creates dummy sockets at startup).
- `ReparsePoint` — creating or deleting a symlink/junction.
- `OpenById` — open by file ID (path unknown).
- `Wow64Child`, `InjectFailed`, `HookInstallFailed`, `NoHello` (job process never checked in).
- `ExternalModification` — an input's ChangeTime is later than the run start and
  the tree did not mutate it (someone else changed it mid-run).
- `Outlived` — a tree process was still alive 2s after the root exited (daemon).
- `Interrupted` — Ctrl+C / root terminated abnormally.
- `NonZeroExit` — unless `--cache-failures`.
- `InternalError` — anything unexpected in memo or the hook.

A tainted run's output is shown to the user normally; memo prints one line saying
why it was not cached.

### 5.5 Ignored paths

Neither inputs nor outputs:
- `%TEMP%`/`%TMP%` (and their long-path forms);
- `%SystemRoot%` (reads; OS updates are out of scope — writes there taint);
- memo's own cache directory;
- `%LOCALAPPDATA%\npm-cache\_logs` (npm writes a timestamped log every run and lists the directory);
- user additions via `MEMO_IGNORE` (`;`-separated path prefixes).

## 6. Fingerprints and matching

### 6.1 Input set

Every observed path (not ignored) is an input. Its fingerprint is its **pre-run
state**: the `PreMutate` snapshot if the tree mutated it, otherwise its state at
the end of the run (checked for external modification).

Per path, flags accumulate across all processes: `read`, `meta`, `listed`.

| Pre-run state | Fingerprint |
|---|---|
| absent | `Absent` |
| directory | `Dir`, plus `Listing` if `listed` |
| file | `File{ size, mtime?, hash? }` — `hash` iff `read`; `size`+`mtime` iff `meta` |

**Metadata downgrade rule:** if the tree later mutated a path, its `mtime` is
dropped from the fingerprint (existence, type, size, and content-if-read remain).
Rationale: tools stat their own outputs before deleting/overwriting them (clean
steps, `rm -rf dist`). Without this rule, every real run rewrites outputs with new
mtimes and the command never reaches a steady state. The rule is safe because a
mutated path's new content is produced by this command, not consumed from outside.

### 6.2 Listings

A listing fingerprint is BLAKE3 over the sorted entries of the directory:
`(case-folded name, is_dir, size, mtime)` for each entry, except entries the tree
mutated, which contribute only `(name, is_dir)`. The entry stores the set of
stripped names so verification can recompute the same hash.

### 6.3 Verification (lookup)

- `Absent` → path must not exist. `Dir` → must be a directory.
- `File` → must be a file; `size` (and `mtime` if recorded) must match; if `hash`
  is recorded, look up the **stat cache** (`path → (size, mtime, ChangeTime,
  file_id) → hash`) and re-hash only if the stat signature changed.
- `Listing` → re-enumerate and recompute.
- Inputs are verified in parallel (rayon); first mismatch aborts that entry.

### 6.4 Guarantee (what "never stale" means precisely)

memo replays only if every file the command read has byte-identical content,
every path it probed has the same existence/type/size (and mtime, unless it was
the command's own output), and every directory it listed has the same entries.
Known blind spots, documented in the README: wall-clock time and randomness,
registry reads, metadata read through an already-open handle, files under ignored
paths, 8.3 short-name aliasing, and IPC with processes outside the tree other than
over the network.

## 7. Outputs and replay

### 7.1 Output set

Every mutated path whose final state differs from its pre-run state. Final state is
`Absent`, `Dir`, or `File{content blob, mtime, readonly}`. File contents go to the
content-addressed store.

### 7.2 Restore order

1. Deletions, deepest path first (files, then directories).
2. Directory creations, shallowest first.
3. Files: write to a temp name in the destination directory, set mtime/attributes,
   `MoveFileExW(REPLACE_EXISTING)`.

Outputs are restored with their **recorded** mtimes so downstream memoized commands
that probe them keep hitting.

### 7.3 Console output

stdout and stderr are captured through pipes as a sequence of
`(stream, bytes)` chunks in arrival order, stored as one blob, and replayed in the
same order to memo's own stdout/stderr.

### 7.4 Colors

With pipes, programs see a non-TTY. When memo's own stdout is a console, memo sets
`FORCE_COLOR=1`, `CLICOLOR_FORCE=1`, `CARGO_TERM_COLOR=always`, `PY_COLORS=1` in the
child environment (unless already set, or `--no-color-env`). This is part of the
key, so terminal and redirected runs are cached separately. ConPTY capture is future
work.

### 7.5 stdin

The child gets `NUL` as stdin in v1.

## 8. Cache store

Location: `%LOCALAPPDATA%\memo` (override `MEMO_DIR`).

```
memo/
  cas/ab/abcdef…            content blobs (BLAKE3), raw
  entries/<key>/<id>.entry  postcard-encoded Entry
  runs/<argv-cwd-hash>.last last env + key for `explain` env diffs
  statcache.bin             path → stat signature → hash
```

An `Entry` holds: format version, argv, cwd, created time, duration, exit code,
inputs (path + fingerprint), outputs (path + final state), console blob hash.

Writes are atomic (temp file + rename). Concurrent memo processes are safe: blobs
are content-addressed; entries have unique ids.

`memo gc [--max-size 5G]` evicts least-recently-hit entries, then unreferenced
blobs.

## 9. CLI

```
memo [flags] <command> [args...]
memo -- <command named like a subcommand> ...
memo explain <command> [args...]   why the last run missed / would miss
memo stats                          cache size, entries, hits, time saved
memo gc [--max-size SIZE]
memo clear
```

Flags: `--cache-failures`, `--allow-network`, `--no-color-env`, `--no-read`
(always run, still store), `-q/--quiet`, `-v/--verbose` (print taint details and
counts).

Status line on stderr (only when stderr is a console, suppressed by `-q`):
- `memo ⚡ replayed (saved 41.2s)`
- `memo ● cached (41.2s · 1,204 inputs · 38 outputs)`
- `memo ○ not cached: network access by node.exe (pid 1234)`

Exit code: the command's (real or replayed); memo's own failures exit 125 only if
the command could not be started at all.

## 10. Error handling

- memo cannot create pipe/job/inject root → run command untraced, warn, don't cache.
- Hook cannot reach memo (pipe gone) → silently stop reporting; memo detects
  missing `Hello`/events via job accounting and taints.
- Corrupt entry or blob (hash mismatch, decode failure) → treat as miss, delete it.
- Restore failure mid-replay (e.g. file locked) → report error, fall back to running
  the command for real.
- Ctrl+C: memo ignores it while the child runs (child shares the console and gets
  it directly); the run is marked `Interrupted`.

## 11. Testing

- **Unit** (`memo-core`, `memo-proto`): path normalization, fingerprint merge rules,
  listing hashing with stripped entries, entry encode/decode, matching, stat cache,
  CAS.
- **Integration** (`memo/tests`, driven by `memo-probe`): each syscall class —
  read, probe, negative probe, list, write, rename, delete, mkdir/rmdir, child and
  grandchild processes, network connect, junction creation. For each: first run
  stores, second run hits and replays identical stdout/exit code/outputs; mutating
  each kind of input (content, new file in listed dir, creating a previously-absent
  probed path, env var) causes a miss; taints are reported. Tests run in sandboxes
  under `target/memo-it/` (not `%TEMP%`, which memo ignores) with an isolated
  `MEMO_DIR`.
- **Staleness fuzz** (`memo/tests/fuzz_stale.rs`): random mutation sequences on a
  fixture tree with a deterministic probe script; after every step, compare memo's
  output against a real run. Any divergence is a bug.
- **Real workloads** (`scripts/smoke.ps1`): `tsc`, `vitest run`, `pytest`,
  `cargo test` on fixture projects; assert run → run → hit convergence and identical
  outputs.

## 12. Known behaviors worth documenting

- Commands that read their own previous outputs (pytest cache, `.pyc`, cargo
  fingerprints, tools that clean `dist/`) need **two** real runs before replays
  start: the second run sees the first run's outputs as inputs. After that they
  replay steadily.
- Anything touching the network is not cached unless `--allow-network`.
