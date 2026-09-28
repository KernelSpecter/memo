# memo

memo caches the result of any Windows command and replays it when nothing the
command depended on has changed. There is nothing to configure. You put `memo`
in front of a command and run it as usual.

```
> memo cargo test
   ... runs for real, 41.2s ...
memo cached (41.2s, 1204 inputs, 38 outputs)

> memo cargo test
memo replayed (saved 41.2s)
```

The second run did not run `cargo test`. memo replayed the recorded output,
restored the files the command wrote, and exited with the same code.

## What it does

When you run `memo <command>`, memo runs the command once and watches every file
the whole process tree reads, checks for, lists, and writes. It records those
files as the inputs and outputs of that run.

The next time you run the same command in the same directory with the same
environment, memo checks the recorded inputs against the files on disk. If they
all still match, it replays the recorded result instead of running the command.

The one rule memo never breaks: it will not replay a stale result. If it cannot
fully observe what a run did, it runs the command normally and does not cache it.
A needless re-run costs you a few seconds. A wrong replay would cost you trust,
so memo always errs toward running again.

## Requirements

- Windows 10 (version 1809 or newer) or Windows 11, 64-bit.
- No administrator rights.
- To build it: Rust (stable) with the MSVC toolchain. The exact toolchain is
  pinned in `rust-toolchain.toml`, so `rustup` picks it up automatically.

## Install

Build the release binaries:

```
cargo build --release -p memo -p memo-hook
```

This produces two files in `target\release`:

- `memo.exe`
- `memo_hook.dll`

Copy both of them into the same folder, and put that folder on your `PATH`.
memo.exe looks for memo_hook.dll next to itself, so the two must stay together.
Both are built with the static C runtime, so there is nothing else to install.

## Use it

```
memo <command> [args...]        run through the cache
memo -- <command> [args...]     use this if the command name looks like a memo subcommand
memo explain <command> ...      say why the last run did or did not replay
memo stats                      show cache size, entry count, hits, and time saved
memo gc --max-size 2G           delete least-recently-used entries down to a size limit
memo clear                      delete the whole cache
```

Flags:

| Flag | What it does |
| --- | --- |
| `--cache-failures` | also cache runs that exit with a non-zero code |
| `--allow-network` | cache even if the command used the network |
| `--no-color-env` | do not set the color environment variables described below |
| `--no-read` | always run the command, but still record a fresh entry |
| `-q`, `--quiet` | no status line |
| `-v`, `--verbose` | print every reason a run was not cached |

memo prints one status line to standard error, but only when standard error is a
console:

- `memo replayed (saved 41.2s)` means nothing relevant changed.
- `memo cached (41.2s, 1204 inputs, 38 outputs)` means it ran for real and stored the result.
- `memo not cached: network access (AFD connect/send)` means it ran for real and did not store it, with the reason.

memo exits with the command's own exit code, whether the command ran or was
replayed. It exits 125 only when it could not start the command at all.

### Environment variables

| Variable | What it does |
| --- | --- |
| `MEMO_DIR` | where the cache lives (default: `%LOCALAPPDATA%\memo`) |
| `MEMO_IGNORE` | extra path prefixes to ignore, separated by `;` |
| `MEMO_HOOK_DLL` | a custom path to memo_hook.dll (mostly for testing) |

### Colors

memo captures a command's output through pipes, so the command sees something
that is not a real terminal, and many tools turn colors off. When memo's own
output is going to a real console, memo turns colors back on for the command by
setting `FORCE_COLOR=1`, `CLICOLOR_FORCE=1`, `CARGO_TERM_COLOR=always`, and
`PY_COLORS=1`, unless you already set them or pass `--no-color-env`. These
variables are part of the cache key, so a run in a terminal and the same run with
output redirected to a file are cached separately.

## Things worth knowing

**Some commands need two real runs before they replay.** Tools that read their
own previous output, like Python's `.pyc` files, cargo's fingerprints, and
anything that writes into a folder it also lists, see different inputs the second
time (the first run's output is now there). After the second run they replay
steadily.

**Editing a file the command read forces a re-run. Touching it does not.** Files
that were read are compared by content, so changing only a timestamp still
replays. Files that were only checked for existence or size are compared by that,
so changing one of those does force a re-run.

**memo does not cache a run when it cannot vouch for it.** These runs still
execute normally, they just are not stored. Run with `-v` to see the reason:

- the command used the network (a connect or a send). Use `--allow-network` to cache anyway.
- the command exited with a non-zero code. Use `--cache-failures` to cache anyway.
- a 32-bit child process ran, or a child that memo could not trace.
- the command created a junction or other reparse point, or opened a file by its ID.
- a file the command read was changed by something else while the command ran.
- a process outlived the command by more than 2 seconds. It keeps running; the run just is not cached. memo never kills your background processes.
- the command wrote under `%SystemRoot%`.

Pressing Ctrl+C (or Ctrl+Break) stops the command the usual way. memo stays up,
passes the command's output and exit code through, and does not cache an
interrupted run.

### What memo cannot see

memo replays only when every file the command read has the same content, every
path it checked has the same existence, type, and size, and every folder it
listed has the same entries. It cannot see these things, so do not run a command
through memo if its result depends on one of them:

- the current time or random numbers
- registry reads
- file metadata read through a handle that was already open
- anything under an ignored path: `%TEMP%`, `%TMP%`, `%SystemRoot%`, memo's own cache, `%LOCALAPPDATA%\npm-cache\_logs`, and anything in `MEMO_IGNORE`
- 8.3 short-name aliases of a path
- talking to another process that is not part of the command's own process tree, except over the network

### Limits

- 64-bit only. A 32-bit child process is detected and run without tracing.
- No pseudo-console support yet. The command's input and output go through pipes,
  and its standard input is empty, so fully interactive commands do not work
  under memo.
- The cache is on your machine only. There is no shared or remote cache.
- For a `.cmd` or `.bat` command, memo quotes each argument so cmd special
  characters (`& | < > ( ) ^`) are passed through as text, but an argument that
  contains `%VAR%` is still expanded by cmd. That is a limit of the Windows
  command line, not of memo.

## How it works, briefly

memo starts the command in a suspended state and injects `memo_hook.dll` into it
using [Microsoft Detours](https://github.com/microsoft/Detours). The DLL follows
the command into every child process and reports each file operation back to
memo.exe over a private pipe. memo fingerprints the inputs, stores the outputs in
a content-addressed folder, and records the console output and exit code. On a
later run it checks the fingerprints and, if they match, restores everything
without starting the command.

## Development

```
cargo test --workspace
powershell -ExecutionPolicy Bypass -File scripts\smoke.ps1
```

The integration tests run the real `memo.exe` and hook against `memo-probe`, a
small test program that performs file, process, and socket operations on request.
`scripts\smoke.ps1` runs real toolchains (node, node --test, python, cargo)
through memo and checks that each one converges to a replay with identical output,
and that editing a source file forces a real run. It skips a toolchain that is
not installed and never installs anything.

| Crate | What it is |
| --- | --- |
| `memo` | the command-line tool: launch, pipe server, finalize, replay |
| `memo-hook` | the injected DLL: file, process, and socket hooks |
| `memo-core` | paths, fingerprints, verification, the content-addressed store |
| `memo-proto` | the messages the hook and memo send each other |
| `memo-detours` | builds the vendored Detours library and exposes it to Rust |
| `memo-probe` | the test fixture |

The design notes are in `docs/superpowers/specs/2026-09-26-memo-design.md`.

## License

MIT. Microsoft Detours is included under `vendor/detours` under its own MIT
license.
