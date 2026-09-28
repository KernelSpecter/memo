# memo Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every stale-replay path, the data-loss bug, and the exit-hang that the Task 18 whole-branch review found, so memo upholds its core guarantee: never replay a stale result.

**Architecture:** memo is a Cargo workspace. `memo.exe` launches a command suspended, injects `memo_hook.dll` (vendored Detours), and collects file-I/O events over a per-run named pipe; it fingerprints inputs and outputs and replays on a later matching run. This plan fixes bugs in the existing crates; it does not change that architecture. The review (in the session that produced this plan) is the source of truth for the defects; this plan turns each into a TDD task. Where the plan-of-record (`2026-09-26-memo.md`) and the spec disagree, **the spec wins** (user decision 2026-09-28): specifically its listing semantics (§6.2) and its "taint, don't kill" rule for outliving processes (§5.4).

**Tech Stack:** Rust (stable, MSVC, `+crt-static`), Microsoft Detours (vendored), windows-sys 0.59, BLAKE3, postcard+serde, rayon, named pipes, job objects.

**Spec:** `docs/superpowers/specs/2026-09-26-memo-design.md`

## Global Constraints

- Windows x86-64 only; no admin; Windows 10 1809+.
- Hook DLL + deps build with `-C target-feature=+crt-static`.
- Never alter the return value/args of any hooked call; every hook body wrapped in `catch_unwind` + thread-local reentrancy guard.
- **Never replay stale:** any un-observable condition makes the run uncacheable. A false miss (re-running) is acceptable; a false hit (stale replay) is a critical bug.
- Paths compared case-insensitively (case-folded key), stored with original spelling.
- BLAKE3 for content and keys. **This plan bumps `FORMAT_VERSION`** (Task 15) because it changes listing and input-pinning semantics; entries written under the old rules must not be read back.
- Attribution on commits: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Author/committer: `KernelSpecter <KernelSpecter@users.noreply.github.com>`. Do not push to GitHub.
- Tooling gate after every task: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check` all clean before commit.
- **Windows char/string escaping trap (learned this session):** in a Rust source line, the char literal for a backslash is `'\\'` and a UTF-16 encode of `"\\"` is two backslashes. Editing these through a shell here-doc or Python string doubles or halves them. Use the Edit tool with exact literal matching for any line containing backslashes; never round-trip them through `sed`/Python string escaping.

## Review Focus

These are the input classes most likely to bite a user that this plan must keep pinned. Each has its test in the task that owns the code.

- **Directory enumeration by tools that call `NtQueryDirectoryFile` (non-Ex) or `NtQueryInformationByName`** — Node/libuv, .NET, Python 3.12+/3.14. Uninstalled hooks made their reads invisible → stale replay. (Tasks 2, 6)
- **A file the command appends to, or opens read-write through one handle** — its output depends on pre-run content that was never pinned; a replay overwrote a user's edit. (Tasks 4, 5)
- **A directory the command lists and also writes into** — the listing the command saw must be pinned so the next run re-runs until steady, never replaying a listing that excludes an entry now present. (Task 6)
- **A file or directory changed by someone else mid-run, or a read file deleted mid-run** — must taint, not record a state the command didn't observe. (Task 7)
- **A child process's own executable being replaced between runs** — the child image (and statically loaded DLLs) must be inputs. (Task 8)

---

## Task 1: C5 — never block in `DllMain(DETACH)`; bound the wait

**Root cause:** `memo-hook/src/lib.rs:58-63` calls `client::bye(true)` on `DLL_PROCESS_DETACH`. `bye`→`pid`→`send` all lock the `CLIENT` mutex (`client.rs:90-95,127-139`). On process termination the loader lock is held and every other thread is already gone; if one held `CLIENT`, this deadlocks. memo then waits on the root with `INFINITE` (`launch.rs:207`), so the user's command never returns. memo ignores `Bye` anyway (`server.rs`).

**Files:**
- Modify: `crates/memo-hook/src/lib.rs`, `crates/memo-hook/src/client.rs`
- Modify: `crates/memo-hook/src/hooks.rs` (no functional change; only if a helper moves)
- Test: `crates/memo-probe/src/main.rs` (new `threads=` op), `crates/memo/tests/exit_hang.rs`

**Interfaces — Produces:** unchanged public API. `client::send`/`client::pid`/`client::bye` become non-blocking (never wait on a held lock).

- [ ] **Step 1: probe op.** In `memo-probe/src/main.rs` add a `threads=<n>` op: spawn `<n>` threads, each looping ~200× opening and reading `Cargo.toml`-sized data from a temp file, then the main thread calls `std::process::exit(0)` while they run (abrupt exit with live threads). Print `THREADS <n>` before spawning.

- [ ] **Step 2: failing test.** `crates/memo/tests/exit_hang.rs`: run memo on the probe with `threads=8` and a small file, 25 times, each `child.wait_timeout`-style bounded to 15s (spawn memo, poll `try_wait` in a loop with an overall deadline; fail if any run exceeds the deadline). Assert all 25 complete and exit 0.

- [ ] **Step 3: run → observe hangs** (pre-fix, some runs time out). Expected: FAIL.

- [ ] **Step 4: fix.** In `lib.rs` `DllMain`, on `DLL_PROCESS_DETACH` do nothing when `_reserved` is non-null (process is terminating — the only case memo sees). Keep the `catch_unwind` for the FreeLibrary case but call `bye` only when `!_reserved.is_null()` is false, i.e.:
```rust
DLL_PROCESS_DETACH => {
    // _reserved != null => process termination: other threads are gone and
    // the loader lock is held; touching any lock can deadlock. Do nothing.
    if _reserved.is_null() {
        let _ = std::panic::catch_unwind(|| {
            if client::is_active() {
                client::bye(true);
            }
        });
    }
}
```
  Change the `DllMain` signature to name the parameter `reserved` (drop the leading underscore where used). In `client.rs`, change `send` and `pid` to use `try_lock` and fall back (send: drop the message; pid: `GetCurrentProcessId`) so no hook path can ever block on a poisoned/held lock.

- [ ] **Step 5: defense in depth.** In `launch.rs`, replace the root `WaitForSingleObject(pi.hProcess, INFINITE)` with a bounded wait loop (e.g. 1s slices) that also drains the completion port, so a future hook bug can't hang memo forever; if the root itself never exits within a large cap (e.g. 1 hour) treat as `outlived`. Keep behavior identical for normal exits.

- [ ] **Step 6: run → PASS.** Then full tooling gate.

- [ ] **Step 7: Commit.** `Fix C5: never block in DllMain detach; bound the root wait`

## Task 2: C1 — install the three uninstalled hooks

**Root cause:** `hooks.rs` installs only `NtQueryDirectoryFileEx`. The spec §4.2 also requires `NtQueryDirectoryFile` (non-Ex), `NtQueryInformationByName` (Rust std / Python 3.12+ / Win11 `GetFileInformationByName`), and `NtDeleteFile`. Node/libuv `readdirSync` calls the non-Ex form; Python `os.stat`/`os.path.exists` on this build calls `NtQueryInformationByName`. Their reads/probes are invisible → stale replay (VERIFIED: node --test replays "pass" after a failing test file is added; Python replays stale `exists`/`size`).

**Files:**
- Modify: `crates/memo-hook/src/ntdef.rs` (signatures), `crates/memo-hook/src/hooks.rs` (detours + install)
- Test: covered end-to-end in Task 15's integration tests (`node --test` add-file, Python stat); add a direct probe test here.

**Interfaces — Produces:** three new installed detours. `NtQueryInformationByName` reports Probe/ProbeAbsent for the named path (like `query_attrs_common`). `NtDeleteFile` reports PreMutate + Delete. `NtQueryDirectoryFile` behaves exactly like the Ex hook (List/Probe per Task 3).

- [ ] **Step 1: signatures in `ntdef.rs`:**
```rust
pub type NtDeleteFileFn =
    unsafe extern "system" fn(ObjectAttributes: *mut OBJECT_ATTRIBUTES) -> NTSTATUS;

pub type NtQueryInformationByNameFn = unsafe extern "system" fn(
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    FileInformation: *mut c_void,
    Length: u32,
    FileInformationClass: i32,
) -> NTSTATUS;
```
  `NtQueryDirectoryFile` reuses the 11-arg shape (Event, Apc, ApcCtx, Iosb, FileInformation, Length, class, ReturnSingleEntry: BOOLEAN as u8, FileName: *mut UNICODE_STRING, RestartScan: u8). Declare `NtQueryDirectoryFileFn` next to the Ex type in `hooks.rs`.

- [ ] **Step 2: failing test.** Add `crates/memo/tests/missing_hooks.rs` using `memo-probe`: (a) a probe that stats a path via a helper that forces `NtQueryInformationByName` — since std `Path::exists` may route there, use `probe=` and assert that creating a previously-absent probed path causes a miss even for a Python-style stat; (b) a `delete=` of an existing file must record it as an output/mutation such that deleting the file externally between runs and re-running restores nothing stale. Since the probe already exercises these through std, this test mainly guards non-Ex directory listing: add a probe op `listnonex=<dir>` that calls `FindFirstFileEx`/the non-Ex path (a bare `std::fs::read_dir` on this toolchain uses the Ex form, so call `NtQueryDirectoryFile` via a small FFI in the probe). Assert list churn is detected. Expected: FAIL for the non-Ex path pre-fix.

- [ ] **Step 3: implement** the three detour fns and add them to `install_inner`'s attach block and `proc_addr` lookups. `h_ntdeletefile`: classify the OA; if a File path, `premutate_wait` then, on success (`status >= 0`), `mutate(Delete, path, None)`. `h_ntqueryinformationbyname`: classify OA, call real, then Probe/ProbeAbsent by status (reuse `query_attrs_common`). `h_ntquerydirectoryfile`: identical body to `h_ntquerydirectoryfileex`, forwarding its args, and using the Task 3 classification.

- [ ] **Step 4: run → PASS.** Tooling gate.

- [ ] **Step 5: Commit.** `Fix C1: install NtQueryDirectoryFile, NtQueryInformationByName, NtDeleteFile hooks`

## Task 3: I7 — a single-name directory query is a Probe, not a full listing

**Root cause:** the directory-query hooks ignore the `FileName` filter and always emit `List` on the directory handle (`hooks.rs:471-475`). `FindFirstFile("dir\\exact")`, `GetLongPathName`, and stat-by-enumeration therefore fingerprint an entire directory (`C:\`, `C:\Users`, the repo, `target\…`) as a listing → huge, flaky false misses, and listings that wrongly include ignored entries.

**Files:**
- Modify: `crates/memo-hook/src/hooks.rs`
- Test: `crates/memo/tests/list.rs` (extend)

**Interfaces — Produces:** a directory query with a non-wildcard `FileName` reports `Probe`/`ProbeAbsent` of `dir\name`; a query with no name or a wildcard (`*`/`?`) reports `List` of the directory.

- [ ] **Step 1: failing test.** In `list.rs`, add a test: a probe that stats one exact child name in a large-ish dir must NOT cause a miss when an unrelated sibling changes. (Probe op `probe=<dir>\<name>` already routes through a single-name query on some toolchains; if not, add `findfirst=<dir>\<name>` to memo-probe using `FindFirstFileW`.) Assert: create sibling `other.txt` after caching → still replays (the single-name lookup didn't fingerprint the whole dir). Expected: FAIL pre-fix (whole-dir listing makes it miss).

- [ ] **Step 2: implement.** Factor the directory-query bodies into one helper `fn on_dir_query(file_handle, file_name: *mut UNICODE_STRING, status)`. If `file_name` is non-null with a name containing no `*`/`?`, resolve `handle_to_win32(file_handle)` + `\` + name and emit `Probe` (or `ProbeAbsent` if `status` is not-found), deduped. Otherwise emit `List` of the directory. Call it from both `h_ntquerydirectoryfile` and `...ex`.

- [ ] **Step 3: run → PASS.** Tooling gate.

- [ ] **Step 4: Commit.** `Fix I7: single-name directory query is a probe, not a listing`

## Task 4: C2a — mark a path mutated only on success; pin content for append / read-write

**Root cause:** (1) `collect.rs on_premutate` inserts into `self.mutated` before the real call, so an open that then FAILS (e.g. `CreateDirectory` on an existing dir, a denied write) is still treated as a mutation. (2) `hooks.rs post_open` returns early for a mutating open without ever reporting `Read`, so a read-write handle (`r+`) and an append never pin pre-run content, though their output depends on it.

**Files:**
- Modify: `crates/memo-hook/src/hooks.rs`, `crates/memo/src/collect.rs`
- Test: `crates/memo/tests/write_then_read.rs` (extend), `crates/memo/tests/mutate_fail.rs` (new)

**Interfaces — Consumes:** `pre_open` returns `(Option<String>, is_mut, by_id, wants_content)` where `wants_content` = the open has `READ_ACCESS_MASK` or `FILE_APPEND_DATA`. **Produces:** `on_premutate` snapshots but does NOT mark mutated; `on_mutate` (sent only on success) marks mutated. `post_open` reports `Read` for a successful mutating open that `wants_content`.

- [ ] **Step 1: failing tests.**
  - `mutate_fail.rs`: probe `mkdirp=<d>` twice (create_dir_all on an existing dir issues a create that fails with "already exists"); a run whose only "mutation" is that failed create must be cacheable and, with the dir unchanged, replay. Pre-fix it is treated as a mutation and (with Task 5) would over-pin; assert it replays. Also: a denied write (write to a path under a read-only parent) must not appear as an output.
  - `write_then_read.rs`: extend `append_then_read_...` to assert the append alone (no explicit read op) pins pre-content: append to `log.txt`, cache; change `log.txt` to same length/different bytes; re-run must NOT replay (output depends on pre-content). Expected: FAIL pre-fix (append doesn't pin content).

- [ ] **Step 2: implement hook side.** In `pre_open`, compute `wants_content = desired & (READ_ACCESS_MASK | FILE_APPEND_DATA) != 0` and thread it through. In `post_open`, for `is_mut && status >= 0`: send `mutate(kind,…)` as now, AND if `wants_content` also `client::access(Read, path)`. Keep `premutate_wait` in `pre_open` (snapshot must precede the real call).

- [ ] **Step 3: implement collect side.** In `on_premutate`, remove `self.mutated.insert(id.clone())` — keep only the snapshot into `premutated`. (`on_mutate`, sent post-success, is what marks `mutated`.) Verify `set_info_pre` mutations still send a post-success `mutate` (they do, `hooks.rs:317-321`).

- [ ] **Step 4: run → PASS.** Tooling gate.

- [ ] **Step 5: Commit.** `Fix C2a: mark mutated only on success; pin content for append/read-write`

## Task 5: C2b — every mutated path becomes an input pinning its pre-run state

**Root cause:** `collect.rs finalize` builds inputs only from `obs` (`:240`). A path that was mutated but never read/probed/listed (a pure append with content now pinned via Task 4 is in obs; but a pure `create`, a `rename` source, a `delete`) has no input pinning its pre-run existence → the next run replays regardless of whether that path now exists (VERIFIED: rename with a missing source replays and re-creates the destination from cache).

**Files:**
- Modify: `crates/memo/src/collect.rs`
- Test: `crates/memo/tests/write.rs`, `crates/memo/tests/rename.rs`, `crates/memo/tests/delete.rs` (extend each)

**Interfaces — Produces:** `finalize` iterates the union of `obs` keys and `mutated` keys. For a mutated path not in `obs`, it emits an input pinning pre-run existence/type: `Absent`→`InputFp::Absent`; `Dir`→`InputFp::Dir { listing: None }`; `File`→`InputFp::File { size, mtime: None, hash: <pinned iff content matters> }`.

- [ ] **Step 1: failing tests.**
  - `rename.rs`: cache `rename src→dst`; delete both; re-run must NOT replay (a real run renames nothing). Assert `!replayed`.
  - `delete.rs`: cache `delete=f` (f existed); re-create `f` externally with different content is irrelevant; delete `f` externally (so it's absent) then re-run — must re-run, not replay a delete of an already-absent file into recreating stale state. Assert convergence and no stale dst.
  - `write.rs`: `create=new.txt` (was absent); leave new.txt in place; re-run must NOT replay (pre-state Absent no longer holds) — it re-runs, then converges. Assert run2 executes.
  Expected: FAIL pre-fix (these replay).

- [ ] **Step 2: implement.** Replace the `for (id, o) in &self.obs` loop with a loop over `let ids: BTreeSet<&PathId> = self.obs.keys().chain(self.mutated.iter()).collect();`. For each id, fetch `o = self.obs.get(id)` (may be `None`) and `mutated = self.mutated.contains(id)`. Reuse the existing mutated/non-mutated fingerprint logic, but drive "was it read / meta / listed" off `o.map(|x| x.read).unwrap_or(false)` etc. For a mutated path with no `obs`, that yields hash only when Task 4 marked it read (append/read-write); otherwise existence+type only. Keep the existing "could not hash pre-run content" taint. Ensure a mutated path whose snapshot is missing (`None`) still pins `Absent` (it does today via `Some(PreSnap::Absent) | None => PreState::Absent`), which is correct for create.

- [ ] **Step 3: run → PASS.** Then run `fuzz_stale` with several `MEMO_FUZZ_SEED`s (1, 42, 1234567). Expected: PASS.

- [ ] **Step 4: Commit.** `Fix C2b: pin pre-run state of every mutated path as an input`

## Task 6: C2c — listing semantics per spec §6.2 (synchronous pre-List snapshot; no stripping)

**Root cause:** the listing fingerprint is computed at finalize from the POST-run directory with the tree's own outputs stripped (`collect.rs:284-296`, `fingerprint.rs:116-136`). But the command's own output persists to the next run, so on the next run the command (if run) would see it. Excluding it makes the recorded listing match a directory that now really contains the output → the recorded stdout (from when the output was absent) replays stale (VERIFIED: `LIST d` replays `a.txt` while a real run prints `a.txt,out.txt`). The spec (§5.3, §6.2, §12) instead snapshots the listing the command actually saw and converges in two real runs.

**Design:** make `List` synchronous like `PreMutate`. On the first `List` of a directory in a process, the hook sends a message that blocks for an ack; memo enumerates the directory THEN (capturing exactly what the command is about to see) and stores it as the listing fingerprint — the full set of entries, nothing stripped. Verification recomputes the full current listing and compares. A tool that lists then writes into the dir therefore misses on the next run (the dir now contains the new entry), re-runs, and on the third run the dir is steady and it replays. Never stale.

**Files:**
- Modify: `crates/memo-proto/src/lib.rs` (a `PreList`/ack, or reuse `PreMutate` with a kind), `crates/memo-hook/src/client.rs`, `crates/memo-hook/src/hooks.rs`, `crates/memo/src/server.rs`, `crates/memo/src/collect.rs`, `crates/memo-core/src/fingerprint.rs`, `crates/memo-core/src/verify.rs`
- Test: `crates/memo-core/src/fingerprint.rs` (inline), `crates/memo/tests/list.rs`

**Interfaces — Produces:**
- `memo-proto`: `Msg::PreList { pid, seq, path }` acked with one byte (mirror `PreMutate`).
- `client::prelist_wait(path)` — like `premutate_wait`.
- `RunState::on_prelist(&mut self, path)` — enumerate the dir now, store `ListingFp` (full, no exclusions) keyed by `PathId`; ack after.
- `ListingFp { hash, entries_count }` — drop `stripped`. `compute_listing_fp(entries)` and `recompute_listing_hash(entries)` both hash ALL entries (name, is_dir, size, mtime). Remove the `mutated_names`/`stripped` parameters and `mutated_names_in`.
- `finalize` uses the stored pre-List snapshot for a listed directory instead of re-enumerating at finalize.

- [ ] **Step 1: failing tests.**
  - `fingerprint.rs`: replace `listing_excludes_mutated_entries` (which encodes the wrong behavior) with `listing_hash_covers_all_entries`: adding any entry (whether or not the tree wrote it) changes the hash.
  - `list.rs`: rewrite `listed_dir_churn_from_own_output_still_hits` into `listed_dir_write_converges_then_replays`: run1 lists `d` and writes `d/out.txt`; run2 must RE-RUN (dir now has out.txt); run3 must REPLAY; and compare run3's stdout to a fresh real run's stdout in a clean copy (assert equal). Add `list_reflects_external_file`: after caching, an externally added file makes it miss.
  Expected: FAIL pre-fix.

- [ ] **Step 2: proto + client.** Add `Msg::PreList`; round-trip test in `memo-proto`. Add `client::prelist_wait`. In `hooks.rs on_dir_query`, on the FIRST `List` decision for a `(pid, dir)` (dedupe per process), call `prelist_wait(dir)` instead of `access(List, dir)`; still emit nothing else. (Probes from Task 3 stay async `access(Probe,…)`.)

- [ ] **Step 3: server + collect.** Handle `PreList` in `server.rs` like `PreMutate`: call `state.on_prelist(&path)` then write the ack byte. `on_prelist`: if not ignored and not already snapshotted, `read_dir_entries(path)`; store `Some(ListingFp)` in a new `listings: HashMap<PathId, ListingFp>` and mark the path listed. In `finalize`, for a non-mutated directory that was listed, use `self.listings.get(id)` rather than re-reading at finalize; for a directory with no snapshot (enumeration failed), taint `InternalError`.

- [ ] **Step 4: fingerprint + verify.** Drop `stripped` from `ListingFp` and the exclusion logic; `hash_entries` hashes all entries. Update `verify_input` for `InputFp::Dir { listing: Some(lfp) }` to `recompute_listing_hash(&entries) == lfp.hash`. Update all call sites.

- [ ] **Step 5: run → PASS**, including the real-run comparison. Tooling gate. Note: this changes convergence for list-then-write from 1 run to 2 — update Task 15's smoke expectations accordingly.

- [ ] **Step 6: Commit.** `Fix C2c: snapshot the listing the command saw; drop output-stripping (spec 6.2)`

## Task 7: C3 — external mid-run changes to directories and deletions taint

**Root cause:** the external-modification check (`collect.rs:300-305`) only covers non-mutated FILES via ChangeTime. A directory whose contents changed mid-run, and a path observed present that is ABSENT at finalize (a read file deleted mid-run), are not caught → memo records a state the command didn't observe (VERIFIED: a file created in a listed dir 1s into a 2.5s run is recorded into the listing; a read file deleted mid-run is recorded Absent and replays "READ 0").

**Files:**
- Modify: `crates/memo/src/collect.rs`
- Test: `crates/memo/tests/external.rs` (new)

**Interfaces — Produces:** `RunState` records, per observed path, whether it was seen present (any Read/Probe success or List) or absent (ProbeAbsent). `finalize` taints `ExternalModification` when: a non-mutated observed-present path is absent at finalize; a non-mutated observed-absent path is present at finalize; or a listed directory's finalize-time ChangeTime is after `run_start` (its entries changed after the snapshot). Keep the existing file ChangeTime check.

- [ ] **Step 1: failing tests.** `external.rs`, using the probe's `sleep=`/`ready=` ops and a helper thread in the test that mutates the sandbox mid-run:
  - Read a file, sleep; the test deletes it mid-run → run must taint (not cached).
  - List a dir, sleep; the test adds a file mid-run → run must taint.
  - Probe an absent path, sleep; the test creates it mid-run → run must taint.
  Expected: FAIL pre-fix (cached).

- [ ] **Step 2: implement.** Add presence tracking to `Obs` (`seen_present: bool`, `seen_absent: bool`) set in `on_access`. In `finalize`, for each non-mutated observed path, compare recorded presence to current `file_signature`; on mismatch push `ExternalModification`. For listed dirs, compare the snapshot's directory ChangeTime (capture it in `on_prelist`) against a fresh stat at finalize; if changed, taint. (This is belt-and-suspenders with the listing hash, but catches entry-content changes the hash of names+size+mtime might miss.)

- [ ] **Step 3: run → PASS.** Tooling gate.

- [ ] **Step 4: Commit.** `Fix C3: taint external mid-run changes to dirs, deletions, and appearances`

## Task 8: C4 — a child's executable and each process's loaded modules are inputs

**Root cause:** (1) `childhook.rs h_createprocessw` holds the reentrancy guard across the real `CreateProcessW` (`:130-145`), so the PATH-search opens the loader does are suppressed and the child's image is never recorded (VERIFIED: replacing `bin\tool.exe` between runs replays the old output). (2) `client::init` sends `loaded_modules: Vec::new()` though spec §4.1 requires enumerating them as read inputs.

**Files:**
- Modify: `crates/memo-hook/src/childhook.rs`, `crates/memo-hook/src/client.rs`, `crates/memo-hook/src/lib.rs`, `crates/memo/src/collect.rs`, `crates/memo/src/server.rs` (Hello handling)
- Test: `crates/memo/tests/child_image.rs` (new)

**Interfaces — Produces:** after a successful child create, the hook reports the child's resolved image path as a `Read`. `Hello.loaded_modules` is populated (via `CreateToolhelp32Snapshot`/module walk) and memo records each as a `Read` input, subject to the `%SystemRoot%`/ignored-path rules.

- [ ] **Step 1: failing test.** `child_image.rs`: a probe `spawnpath=<exe> <args>` that resolves an exe on a sandbox `PATH` and runs it. Cache; replace the exe with a different one (different output); re-run must NOT replay. Expected: FAIL pre-fix.

- [ ] **Step 2: child image.** In `handle_child` (runs after the real create, inside its own `catch_unwind` — the guard is already dropped there? verify: the guard is held for the whole `h_createprocessw`; `handle_child` runs while held). Report the image: resolve the child's full image path via `QueryFullProcessImageNameW(h_process)` and send `access(Read, image)` — but `client::access` early-returns if the reentrancy guard is set. So report it via a guard-independent send, or release/re-acquire: simplest is to compute the path and call a new `client::access_raw` that sends without the guard check (the guard only gates hook bodies, not our own explicit report). Add `access_raw`.

- [ ] **Step 3: loaded modules.** In `lib.rs on_attach`, before/after `client::init`, enumerate loaded modules (`CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`), collect full paths, and pass them to `init`, which puts them in `Hello.loaded_modules`. In `server.rs`, on `Hello`, for each module path call `state.on_access(Read, path)` (ignored-path rule applies, so `%SystemRoot%` DLLs drop out).

- [ ] **Step 4: run → PASS.** Confirm smoke still caches (system DLLs under `%SystemRoot%` are ignored, so this shouldn't explode the input set for node/python/cargo). Tooling gate.

- [ ] **Step 5: Commit.** `Fix C4: record child image path and loaded modules as inputs`

## Task 9: I1 — do not kill processes that outlive the command (spec §5.4)

**Root cause:** `launch.rs:242-247` calls `TerminateJobObject` when the tree doesn't drain in 2s. The spec (§5.4) and plan-of-record only say to TAINT (`Outlived`). Killing breaks build daemons (Gradle, MSBuild node reuse, VBCSCompiler, sccache) and `start /b`. User decision 2026-09-28: don't kill.

**Files:**
- Modify: `crates/memo/src/launch.rs`, `crates/memo/src/run.rs` (already taints Outlived), `README.md`
- Test: `crates/memo/tests/outlived.rs` (new)

**Interfaces — Produces:** `LaunchResult.outlived` is still set, but the job is NOT terminated; background processes keep running. The run is tainted `Outlived` (already wired in `run.rs:186-191`).

- [ ] **Step 1: failing test.** `outlived.rs`: a probe `detach=<marker>` that spawns a child which sleeps ~5s and writes `<marker>` when done (marker under `%TEMP%`), then the probe exits 0 immediately. Run under memo: assert the run is `not cached` (`Outlived`) AND, after ~6s, the marker appears (the child was NOT killed). Expected: FAIL pre-fix (marker never appears — child killed). Do NOT use `start`/ShellExecute; spawn via the probe's own `CreateProcess`.

- [ ] **Step 2: implement.** Remove the `TerminateJobObject` call; keep `outlived = !zero`. Ensure reader threads and handle cleanup don't block on the still-running child: the child inherited the stdout/stderr write ends, so the reader threads won't see EOF until it exits. Detach the readers (don't `join` when `outlived`; drop the read handles) so memo returns promptly while the child runs on. Close the job handle WITHOUT kill-on-close (the job has no `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, confirmed — none is set).

- [ ] **Step 3: update README** limitations: outliving processes keep running and the run isn't cached (remove the "memo kills the tree" note).

- [ ] **Step 4: run → PASS.** Tooling gate.

- [ ] **Step 5: Commit.** `Fix I1: taint outliving processes instead of killing them (spec 5.4)`

## Task 10: I2 — escape arguments passed to `.cmd`/`.bat` shims

**Root cause:** `resolve.rs` wraps `.cmd`/`.bat` via `cmd /d /s /c` and quotes arguments with `arg_quote` designed for CreateProcess, not for cmd.exe. `cmd` metacharacters (`&`, `|`, `^`, `<`, `>`, `(`, `)`, `%`, `"`) in an argument are interpreted (VERIFIED: `memo echoarg.cmd "a&whoami"` runs `whoami`). npm/npx/tsc are `.cmd` shims, so this is a real injection.

**Files:**
- Modify: `crates/memo/src/resolve.rs`
- Test: `crates/memo/src/resolve.rs` (inline)

**Interfaces — Produces:** `resolve` escapes each argument for cmd.exe when `via_cmd` is true, matching how Rust std's `Command` escapes batch-file arguments since 1.77 (percent signs cannot be fully escaped — caret-escape the metacharacters and wrap in quotes; document the `%VAR%` caveat).

- [ ] **Step 1: failing test.** Inline in `resolve.rs`: resolving a `.cmd` with an argument `a&b` produces a cmdline where `&` is caret-escaped inside quotes so cmd passes `a&b` literally; assert the argument substring is `"a^&b"` (or the exact std form) and that `whoami`/`&` is not left unescaped. Expected: FAIL pre-fix.

- [ ] **Step 2: implement.** Add `fn cmd_escape(arg: &str) -> String` that quotes the argument and caret-escapes `()%!^"<>&|` per the batch rules (mirror `std::sys::args::windows` batch escaping). Use it in the `.cmd`/`.bat` branch instead of `arg_quote`. Keep `arg_quote` for the normal exe branch.

- [ ] **Step 3: run → PASS.** Tooling gate.

- [ ] **Step 4: Commit.** `Fix I2: escape arguments to .cmd/.bat shims against command injection`

## Task 11: I3 — replay failures fall back to a real run; verify blob hashes

**Root cause:** `run.rs restore_outputs` swallows a failed rename (`:296-299`), so a locked output leaves stale content while replay reports success; other restore errors and a missing blob bubble up as exit 125 without running the command; blob content is never verified against its hash on read (spec §10).

**Files:**
- Modify: `crates/memo/src/run.rs`, `crates/memo-core/src/cas.rs` (verify-on-read helper)
- Test: `crates/memo/tests/replay_fallback.rs` (new)

**Interfaces — Produces:** `replay` returns a `Result` that, on any restore error, is turned by `execute` into a real (traced) run of the command instead of an error exit. `cas::read_verified(hash)` re-hashes and errors on mismatch; a corrupt/missing blob is treated as a miss (the entry is skipped/removed) rather than a fatal error.

- [ ] **Step 1: failing tests.** `replay_fallback.rs`: (a) cache a run that writes `out.txt`; hold `out.txt` open for writing in the test (deny rename), trigger replay → assert memo runs the command for real (marker grows) and `out.txt` ends correct, no `*.memo-tmp-*` left behind. (b) Corrupt the entry's console blob in the CAS; re-run → assert it re-runs rather than exiting 125. Expected: FAIL pre-fix.

- [ ] **Step 2: implement.** Make `restore_outputs` return an error on the first unrecoverable failure and clean up temp files; in `execute`, when `verify_entry` passed but `replay` errored, fall through to `launch_and_store` (log a `-v` note). Verify output blob hashes on read via `read_verified`; a mismatch/missing blob makes that entry a miss (skip it, continue to the next entry or to a real run) and removes the corrupt entry.

- [ ] **Step 3: run → PASS.** Tooling gate.

- [ ] **Step 4: Commit.** `Fix I3: fall back to a real run on replay/restore failure; verify blobs`

## Task 12: I4 — run untraced when tracing can't be set up (spec §10)

**Root cause:** `run.rs` treats `dll_path()?`, `PipeServer::start(...)?`, and `launch(...)?` failures, and an ignored `AssignProcessToJobObject` return, as fatal (exit 125). Spec §10: if memo can't create the pipe/job/inject, run the command untraced, warn, and don't cache.

**Files:**
- Modify: `crates/memo/src/run.rs`, `crates/memo/src/launch.rs`
- Test: `crates/memo/tests/untraced_fallback.rs` (new)

**Interfaces — Produces:** `fn run_untraced(resolved, env, cwd) -> Result<ExitCode>` that spawns the command with normal inherited stdio and no injection, warns `not cached: <reason>`, and returns its exit code. `launch_and_store` calls it on any setup failure. `AssignProcessToJobObject`'s failure downgrades to untraced (can't account for children).

- [ ] **Step 1: failing test.** `untraced_fallback.rs`: point memo at a hook DLL path that doesn't exist (env override or a temp copy of memo.exe with no DLL beside it) and run a command that writes a file; assert exit code is the command's, the file is written, and stderr says `not cached`. Expected: FAIL pre-fix (exit 125, command not run).

- [ ] **Step 2: implement.** Add `run_untraced`; wrap the setup in `launch_and_store` so any `Err` (or a false `AssignProcessToJobObject`) warns and calls `run_untraced`. Distinguish a 32-bit ROOT (Detours reports this) with a clear `not cached: 32-bit process` message rather than the misleading `NoHello`.

- [ ] **Step 3: run → PASS.** Tooling gate.

- [ ] **Step 4: Commit.** `Fix I4: run the command untraced when tracing can't be set up (spec 10)`

## Task 13: I6 — paths memo can't map taint instead of being dropped or mis-resolved

**Root cause:** `paths.rs from_nt` classifies unknown `\Device\HarddiskVolumeN`, `\Device\Mup`, and any other `\Device\*` as devices (silently ignored), and turns `\??\Volume{GUID}\…` / `\??\MountPointManager` into RELATIVE paths resolved against memo's cwd (VERIFIED: `MountPointManager` appeared as an input). An input on the wrong volume, or a real file silently dropped, can cause a stale hit.

**Files:**
- Modify: `crates/memo-core/src/paths.rs`, `crates/memo-hook/src/hooks.rs`/`pathres.rs` (surface an Unknown taint)
- Test: `crates/memo-core/src/paths.rs` (inline)

**Interfaces — Produces:** `Classified` gains an `Unknown(String)` variant for a path that is neither a mappable file nor a known non-filesystem device. The hooks taint `InternalError` ("unmappable path <p>") when they see `Unknown`, so the run is not cached rather than silently trusting an unmapped path.

- [ ] **Step 1: failing tests.** Inline in `paths.rs`: `\Device\HarddiskVolume99\x` with a VolumeMap that lacks 99 → `Unknown`, not `Device` and not a drive-letter guess. `\??\Volume{...}\x` → `Unknown`, not a relative file. `\??\MountPointManager` → `Device` (it is a control device) or `Unknown`, never a relative file. Expected: FAIL pre-fix.

- [ ] **Step 2: implement.** Add `Classified::Unknown(String)`. In `from_nt`: an unmatched `\Device\HarddiskVolumeN` (N not in the map) → `Unknown`. A `\??\Volume{GUID}` path → try to resolve via the volume map; if not resolvable → `Unknown`. Keep known control devices (`MountPointManager`, `KsecDD`, `CNG`, `Afd`, pipes, console, `NUL`) → `Device`. In the hooks, map `Unknown` to a taint. Update `classify_object`/`classify_target` and all `match Classified` arms (they currently have two arms; add the third).

- [ ] **Step 3: run → PASS.** Tooling gate. Manually confirm a normal run still caches (no spurious `Unknown`).

- [ ] **Step 4: Commit.** `Fix I6: unmappable NT paths taint instead of being dropped or mis-resolved`

## Task 14: I8/I9 + Minor cluster (perf and small correctness)

**Files:**
- Modify: `crates/memo-hook/src/hooks.rs` (I8, dedupe §4.5), `crates/memo-core/src/stat.rs` (I9), `crates/memo/src/run.rs` (exit code), `crates/memo-hook/src/childhook.rs` (Minor: taint A/AsUserW failures; ResumeThread outside catch_unwind path)
- Test: inline where possible; `crates/memo/tests/exit_code.rs` (new)

**Interfaces — Produces:** no public API change beyond `stat::file_signature` semantics (errors other than not-found no longer map to `None`).

- [ ] **Step 1: I8 (seek perf).** In `h_ntsetinformationfile`, switch on `class` FIRST and only call `handle_to_win32`/`set_info_pre` for the classes that mutate (rename/link/disposition/basic/EOF). For `FilePositionInformation` (class 14) and pipe classes, return immediately after the real call. Add a micro-benchmark note; no unit test required, but add a `#[test]` that a `FilePositionInformation` set is classified as no-op (a probe `seekloop=<f> <n>` + assert the run still caches and is fast is a smoke concern, keep it light).

- [ ] **Step 2: I9 (stat readability).** In `stat.rs file_signature`, open with `FILE_READ_ATTRIBUTES` (not `GENERIC_READ`) and `FILE_FLAG_BACKUP_SEMANTICS`; map not-found to `None` but any OTHER error (locked, denied) to a distinct `Err`, and have callers treat that as a verification failure/taint rather than "absent". Inline test: a file opened exclusively still stats as present (size may be unknown → verification fails safe), not as absent.

- [ ] **Step 3: exit code.** In `run.rs`, stop clamping to 8 bits; use `std::process::exit(code)` from `main` for the real/replayed command code so `exit 1000` is preserved. `exit_code.rs`: `memo <probe> exit=7` → memo exits 7; a probe `exit=256` → memo exits 256 (via `process::exit`). Keep `ExitCode` only for memo's own 125.

- [ ] **Step 4: dedupe (§4.5).** Add a per-process `HashSet<(u8, String)>` of already-sent `(kind, case-folded path)` in `client.rs`; skip duplicates for `Access`. This cuts the repeated `List`/`Probe` volume. Keep `PreMutate`/`PreList` deduped after first. Guard with the client mutex already held.

- [ ] **Step 5: childhook Minors.** Taint on `CreateProcessA`/`AsUserW` failure too (not just W). Move `ResumeThread` so a panic in `handle_child` can't leave a child suspended (resume in a `finally`-style guard even if reporting panicked).

- [ ] **Step 6: run each → PASS.** Tooling gate.

- [ ] **Step 7: Commit.** `Fix I8/I9 and minors: seek perf, stat readability, exit codes, event dedupe`

## Task 15: FORMAT_VERSION bump + test-suite and smoke overhaul + README

**Root cause of the escape:** the tests didn't compare against a fresh REAL run, and `smoke.ps1` compared the replay to the recorded run and never added a file (I10). One list test encoded the stale behavior; `write.rs::rename_output_restored` accepted `replayed() || cached()`.

**Files:**
- Modify: `crates/memo-core/src/lib.rs` (or wherever `FORMAT_VERSION` lives), `crates/memo/tests/*` (audit), `scripts/smoke.ps1`, `README.md`
- Create: `crates/memo/tests/ground_truth.rs` (helper comparing memo vs a clean real run)

**Interfaces — Produces:** `FORMAT_VERSION` incremented by 1 (entries from old rules are ignored, not misread). A shared test helper `run_vs_real(sandbox, ops)` that runs the command under memo and, separately, in a pristine copy of the sandbox without memo, and asserts stdout+exit+resulting-tree-hash equal on a replay.

- [ ] **Step 1: bump `FORMAT_VERSION`.** Confirm `Store::load_entries` skips entries whose `format` != current (add the check if missing) so a stale-rules entry is never replayed. Test: an entry with the old version is ignored.

- [ ] **Step 2: audit existing tests.** Fix `write.rs::rename_output_restored` to assert the CORRECT outcome (converges then replays with identical bytes), not `replayed() || cached()`. Remove/replace any test that encodes stale behavior (the old `list.rs` churn test, replaced in Task 6). Ensure `fuzz_stale` also exercises append and directory listing, not just concat of two files.

- [ ] **Step 3: ground-truth helper + tests.** `ground_truth.rs`: for a scenario, keep two sandboxes; run memo in one across N runs, run the command for real in a fresh copy of the other at the same logical state, assert equality. Add NoHello and junction integration tests (Task 14 of the original plan required them and they're absent): a probe that spawns via an uninjectable path → `not cached (NoHello)`; a junction create → `not cached (ReparsePoint)`.

- [ ] **Step 4: smoke.ps1.** Add an "edit then compare against a fresh real run" step to every workload (not just compare replay to the recording): after convergence, add a NEW file / test and assert memo's next run matches a real run's stdout+exit. Update the convergence-count column (list-then-write and truncating writes now take one extra real run after Task 5/6). Keep the network and skip-if-absent behavior.

- [ ] **Step 5: README.** Update the "two real runs to converge" note (some cases now three), the removed process-kill note (Task 9), the exit-code note (Task 14), and the blind-spots list.

- [ ] **Step 6: run everything.** `cargo test --workspace`; `scripts/smoke.ps1`. Expected: PASS. Tooling gate.

- [ ] **Step 7: Commit.** `Bump FORMAT_VERSION; overhaul tests and smoke to compare against real runs`

## Task 16: final verification pass

- [ ] **Step 1:** `cargo build --release --workspace`; `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`.
- [ ] **Step 2:** Run `scripts/smoke.ps1` and each stale-scenario integration test; re-run `fuzz_stale` with 6+ seeds.
- [ ] **Step 3:** Request a fresh whole-branch code review (superpowers:requesting-code-review) over the remediation range; fix findings.
- [ ] **Step 4:** Final commit; leave a summary for morning review.

## Self-review notes

- **Spec coverage:** C1 restores the spec §4.2 hook table (Task 2). C2/C3 restore §5.3 (synchronous pre-observation snapshots), §6.2 (listing semantics), §6.4 (the guarantee), §12 (two-run convergence) (Tasks 4–7). C4 restores §4.1 module enumeration and child-image inputs (Task 8). §5.4 outlived = taint (Task 9). §10 error handling = untraced fallback + replay fallback (Tasks 11–12). §4.5 dedupe (Task 14).
- **Plan-vs-spec conflict resolved:** the original plan's Review Focus #3 ("exclude the tree's own writes from the listing so it hits") is the direct cause of C2c and is DISCARDED in favor of spec §6.2 + §12 (Task 6), per user decision.
- **Ordering:** C5 first (a hang blocks all other testing), then the missing hooks (C1) since later fingerprint work depends on those events existing, then the pinning/listing redesign (C2), external checks (C3), child inputs (C4), then the I-series, then the FORMAT_VERSION bump and test overhaul last so all new semantics are in before entries change shape.
- **Migration:** FORMAT_VERSION bump (Task 15) invalidates old entries; there is no on-disk migration (cache is disposable). `Store::load_entries` must skip mismatched versions so no pre-fix entry is ever replayed under new verification.
- **Review Focus tests:** directory-enumeration (Tasks 2, 6 tests), append/read-write (Tasks 4, 5 tests), list-then-write convergence vs real run (Task 6 test), external mid-run change (Task 7 tests), child image replacement (Task 8 test). All five are pinned.
- **Escaping trap:** every task that edits backslash-bearing source lines must use exact-match Edit, not shell/Python string round-trips (see Global Constraints).
