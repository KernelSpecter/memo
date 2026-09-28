# memo

Zero-config command result caching for Windows.

```
> memo cargo test
   ...
memo ● cached (41.2s · 1204 inputs · 38 outputs)

> memo cargo test
   ...
memo ⚡ replayed (saved 41.2s)
```

`memo <any command>` runs the command while tracing the file I/O of its whole
process tree. When you run the same command again and nothing it depended on
has changed, memo replays the recorded console output, restores the files the
command produced and exits with the recorded exit code, all without running it.
Think Bazel-grade action caching without BUILD files.

memo's one rule: **never replay a stale result.** A false miss (re-running when a
replay would have been fine) costs you seconds. A false hit (replaying when a
real run would differ) would destroy trust, so whenever memo can't fully observe
a run, it runs the command normally and doesn't cache it, and it tells you why.

## How it works

memo starts the command suspended and injects `memo_hook.dll` using
[Microsoft Detours](https://github.com/microsoft/Detours). The DLL propagates to
every child process and reports each file the tree **reads**, **probes** (checks
for existence or metadata, including paths that turn out not to exist), **lists**
and **writes**. After the run memo fingerprints every input (content hash for
files that were read, metadata for files that were only probed, entry list for
directories that were listed) and stores the outputs in a content-addressed
cache.

On the next run of the same command line, in the same directory and with the
same environment, memo checks the recorded inputs against the current state. If
every one still matches, the run is replayed.

## Requirements

- Windows 10 1809+ or Windows 11, x86-64. No admin rights needed.
- To build: Rust stable with the MSVC toolchain (pinned in `rust-toolchain.toml`).

## Install

```
cargo build --release -p memo -p memo-hook
```

Copy `target\release\memo.exe` **and** `target\release\memo_hook.dll` into the
same directory on your `PATH`. memo looks for the DLL next to its own exe. Both
are built with a static CRT, so they have no runtime dependencies.

## Usage

```
memo [flags] <command> [args...]    run through the cache
memo -- <command> [args...]         for a command named like a subcommand
memo explain <command> [args...]    why the last run missed / would miss
memo stats                          cache size, entries, hits, time saved
memo gc [--max-size SIZE]           evict least-recently-used entries (e.g. 2G, 500M)
memo clear                          delete the whole cache
```

| Flag | Effect |
| --- | --- |
| `--cache-failures` | also cache runs that exit non-zero |
| `--allow-network` | cache even if the command used the network |
| `--no-color-env` | don't force color env vars (see below) |
| `--no-read` | always run for real, but still record a fresh entry |
| `-q`, `--quiet` | no status line |
| `-v`, `--verbose` | print every reason a run was not cached |

The status line goes to stderr, and only when stderr is a console:

- `memo ⚡ replayed (saved 41.2s)`: nothing relevant changed.
- `memo ● cached (41.2s · 1204 inputs · 38 outputs)`: ran for real and stored.
- `memo ○ not cached: network access (AFD connect/send)`: ran for real, not
  stored, with the reason.

memo exits with the command's exit code, real or replayed. It exits 125 only if
the command couldn't be started at all.

### Environment variables

| Variable | Effect |
| --- | --- |
| `MEMO_DIR` | cache location (default `%LOCALAPPDATA%\memo`) |
| `MEMO_IGNORE` | `;`-separated path prefixes that are neither inputs nor outputs |
| `MEMO_FORCE_STATUS` | print the status line even when stderr is redirected |

### Colors

memo captures output through pipes, so the command sees a non-terminal and many
tools turn colors off. When memo's own stdout is a console, it sets
`FORCE_COLOR=1`, `CLICOLOR_FORCE=1`, `CARGO_TERM_COLOR=always` and `PY_COLORS=1`
for the command, unless they're already set or you pass `--no-color-env`. The
environment is part of the cache key, so runs in a terminal and redirected runs
are cached separately.

## Good to know

**Some commands need two real runs before they replay.** Tools that read their own
previous outputs, such as Python's `.pyc` files, cargo's fingerprints, pytest's
cache and tools that clean `dist/`, see different inputs on the second run than
on the first: run 1's outputs are now there. After the second run they replay
steadily.

```
memo python -m unittest    ● cached      (writes __pycache__)
memo python -m unittest    ● cached      (now reads __pycache__)
memo python -m unittest    ⚡ replayed
```

**Editing a file the command read forces a re-run; touching it doesn't.** Files
that were read are fingerprinted by content, so a new timestamp alone still
replays. Files that were only probed are fingerprinted by size and mtime, so
touching one of those does force a re-run.

**memo won't cache a run when it can't vouch for it.** These runs execute
normally but aren't stored (`-v` shows why):

- network access: a connect or a send (`--allow-network` overrides this);
- a non-zero exit code (`--cache-failures` overrides this);
- a 32-bit (WOW64) child process, or any child the hook couldn't be injected into;
- creating a junction or other reparse point, or opening a file by its ID;
- a file the command read being modified by something else during the run;
- a process outliving the command by more than 2 s (the tree is then killed).

Ctrl+C stops memo along with the command, and an interrupted run is never cached.

### Blind spots

memo replays only if every file the command read has byte-identical content,
every path it probed has the same existence, type and size (and mtime, unless the
command itself wrote it), and every directory it listed has the same entries.
Things it **can't** see:

- wall-clock time and randomness;
- registry reads;
- metadata read through a handle that was already open;
- anything under an ignored path: `%TEMP%`/`%TMP%`, `%SystemRoot%`, memo's own
  cache, `%LOCALAPPDATA%\npm-cache\_logs` and `MEMO_IGNORE`;
- 8.3 short-name aliases of a path;
- communication with processes outside the tree, other than over the network.

If a command's result depends on one of these, don't run it through memo, or add
whatever it depends on to its command line or environment so it becomes part of
the key.

### Limitations

- x86-64 only; no ARM64. 32-bit child processes are detected and run untraced.
- No pseudo-console capture yet: the command's stdout and stderr are pipes, and
  its stdin is `NUL`, so interactive commands won't work under memo.
- The cache is local; there's no remote or shared cache.

## Measured

From `scripts\smoke.ps1` on the fixture projects in `scripts\fixtures`. These
fixtures are deliberately tiny, so what matters is the replay time, not the
absolute savings.

| Workload | First real run | Replay | Real runs before first replay |
| --- | --- | --- | --- |
| `node build.js` | 1.69 s | 0.02 s | 1 |
| `node --test` | 0.27 s | 0.02 s | 1 |
| `python -m unittest` | 0.31 s | 0.03 s | 2 (`.pyc`) |
| `cargo test --offline` | 1.03 s | 0.07 s | 2 (fingerprints) |

## Development

```
cargo test --workspace                                         # unit + integration tests
powershell -ExecutionPolicy Bypass -File scripts\smoke.ps1     # real toolchains
```

The integration tests (`crates/memo/tests`) run the real `memo.exe` and hook
against `memo-probe`, a scripted fixture that performs file, process and socket
operations on request. `fuzz_stale` applies random mutation sequences and checks
every result against a real run; set `MEMO_FUZZ_SEED` to explore other sequences.

`smoke.ps1` runs `node`, `node --test`, `python -m unittest`, `pytest`,
`cargo test` and `tsc` through memo. It checks that each command converges to a
replay with identical output and that editing a source file forces a real run.
It also checks that a Node connect-only check is never cached. It skips
toolchains that aren't installed and never installs anything itself.

| Crate | Role |
| --- | --- |
| `memo` | the CLI: launch, pipe server, run finalization, replay |
| `memo-hook` | the injected DLL: file, process and socket hooks |
| `memo-core` | paths, fingerprints, verification, content-addressed store |
| `memo-proto` | hook ↔ memo wire protocol |
| `memo-detours` | builds the vendored Detours and exposes its FFI |
| `memo-probe` | test fixture |

Design: `docs/superpowers/specs/2026-09-26-memo-design.md`.

## License

MIT. Microsoft Detours is vendored under `vendor/detours` under its MIT license.
