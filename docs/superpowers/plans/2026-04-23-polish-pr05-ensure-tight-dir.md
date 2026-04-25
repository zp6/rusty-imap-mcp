# Polish PR 5 — Shared `ensure_tight_dir` helper (#147)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the TOCTOU-safe directory-tightening primitive from `rimap-server::daemon::socket_setup::prepare_socket_dir` into a shared `rimap_core::fs::ensure_tight_dir`. `prepare_socket_dir` delegates to it. `rimap-audit::writer::AuditWriter::open` switches from the best-effort `set_parent_mode_0700(..)` chmod to the strict `ensure_tight_dir` check, picking up symlink-refusal + uid-check for free on the audit parent directory.

**Architecture:** One private function moves up from `rimap-server` into `rimap-core::fs` (a new module). `socket_setup` becomes a thin wrapper so existing callers / tests keep their imports. The audit writer gains a stricter parent-dir contract — the diff is small but behaviourally significant: a symlinked or wrong-owned audit parent now fails `AuditWriter::open` instead of silently chmodding the symlink's target.

**Tech Stack:** Rust, `rustix 1.1` (fs + process features, Unix-only), `std::os::fd::OwnedFd`.

---

## Context the engineer must read first

Lesson 1 of `RESUME.md`: verify API assumptions before writing code.

- `crates/rimap-server/src/daemon/socket_setup.rs` — full file (267 lines). The function you are extracting is `prepare_socket_dir` (line 42) plus its private helpers: `leaf_is_symlink` (line 83), `split_parent_and_name` (line 93), `open_parent` (line 126), `path_is_symlink` (line 149), `verify_dir` (line 157), `uid_to_u32` (line 191), and the `DIR_OFLAGS` constant (line 17). All move together.
- `crates/rimap-audit/src/writer/mod.rs:105-125` — `AuditWriter::open` calls `std::fs::create_dir_all(parent)` and then `set_parent_mode_0700(parent)`. The `set_parent_mode_0700` function is declared at line 260; it FOLLOWS symlinks via `std::fs::set_permissions` and only emits a `tracing::warn!` on failure (no error propagation).
- `crates/rimap-server/src/main.rs:157-166` — the only `prepare_socket_dir` production caller. `our_uid` is computed by `rustix::process::geteuid().as_raw()` and the returned `OwnedFd` is held in `_parent_fd` as defense-in-depth across the `UnixListener::bind` call. The plan must preserve that fd-holding property (see "Signature divergence" below).
- `crates/rimap-audit/Cargo.toml` — no `rustix` today. The plan adds it as a Unix-only dep (audit writer needs `geteuid()` to pass `our_uid` to the shared helper).
- `crates/rimap-core/Cargo.toml` — no `rustix` today. The plan adds it as a Unix-only dep (the helper lives here).
- `crates/rimap-core/src/lib.rs` — no `fs` module today. The plan creates `pub mod fs;`.

## Signature divergence from the issue

Issue #147 proposes `fn ensure_tight_dir(path: &Path, our_uid: u32) -> io::Result<()>`. This plan keeps the parameter list (`&Path, u32`) but returns `io::Result<OwnedFd>`, NOT `io::Result<()>`. Reason: `main.rs:165` relies on the returned fd as ancestor-symlink-swap defense-in-depth across the subsequent `UnixListener::bind`. Throwing it away would regress a security property that `prepare_socket_dir` carefully established. Audit-writer callers ignore the fd (drop immediately).

---

## Files

- Modify: `Cargo.toml` — add `rustix` to `[workspace.dependencies]`.
- Modify: `crates/rimap-core/Cargo.toml` — add `rustix` under `[target.'cfg(unix)'.dependencies]`.
- Modify: `crates/rimap-audit/Cargo.toml` — add `rustix` under `[target.'cfg(unix)'.dependencies]`.
- Modify: `crates/rimap-core/src/lib.rs` — add `pub mod fs;`.
- Create: `crates/rimap-core/src/fs.rs` — host the shared `ensure_tight_dir` + its private helpers + unit tests.
- Modify: `crates/rimap-server/src/daemon/socket_setup.rs` — strip the implementation down to a 1-line delegation to `rimap_core::fs::ensure_tight_dir`; keep the integration tests in place (they still exercise the full path).
- Modify: `crates/rimap-audit/src/writer/mod.rs` — replace `create_dir_all + set_parent_mode_0700` with a call to `ensure_tight_dir`; delete both `set_parent_mode_0700` stubs (Unix + non-Unix).

## Task 1: Add `rustix` to the workspace, `rimap-core`, and `rimap-audit`

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/rimap-core/Cargo.toml`
- Modify: `crates/rimap-audit/Cargo.toml`

- [ ] **Step 1: Add `rustix` to `[workspace.dependencies]`**

In `Cargo.toml`, add this line inside the existing `[workspace.dependencies]` table (grouped with the OS-syscall crates — `libc` is at line 68, put `rustix` adjacent):

```toml
rustix = { version = "1.1", default-features = false, features = ["process", "fs"] }
```

Leave the existing direct-version `rustix` line in `crates/rimap-server/Cargo.toml:57` untouched for now; Task 1 step 4 will migrate it to workspace inheritance.

- [ ] **Step 2: Add `rustix` under `[target.'cfg(unix)'.dependencies]` in `rimap-core`**

In `crates/rimap-core/Cargo.toml`, add a new target-scoped block at the end of the file (if the file has no `[target.*]` section yet):

```toml
[target.'cfg(unix)'.dependencies]
rustix = { workspace = true }
```

- [ ] **Step 3: Add `rustix` under `[target.'cfg(unix)'.dependencies]` in `rimap-audit`**

In `crates/rimap-audit/Cargo.toml`, locate the existing `[target.'cfg(unix)'.dependencies]` block (currently contains `libc`) and add:

```toml
rustix = { workspace = true }
```

- [ ] **Step 4: Migrate `rimap-server`'s `rustix` dep to workspace inheritance**

In `crates/rimap-server/Cargo.toml`, replace line 57:

```toml
rustix = { version = "1.1", default-features = false, features = ["process", "fs"] }
```

with:

```toml
rustix = { workspace = true }
```

Now every crate that uses `rustix` picks up the single workspace-level version.

- [ ] **Step 5: Verify workspace resolution**

Run: `cargo tree -p rimap-core -i rustix && cargo tree -p rimap-audit -i rustix && cargo tree -p rimap-server -i rustix`
Expected: each call resolves to the same `rustix` version under the corresponding crate.

- [ ] **Step 6: `cargo deny check`**

Run: `cargo deny check advisories bans licenses`
Expected: clean. Rustix is already in the graph via `rimap-server`; this PR merely adds two more dependent edges.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock \
        crates/rimap-core/Cargo.toml \
        crates/rimap-audit/Cargo.toml \
        crates/rimap-server/Cargo.toml
git commit -m "$(cat <<'EOF'
chore(deps): hoist rustix to workspace and add to rimap-core, rimap-audit (#147)

rimap-core gets rustix so the upcoming rimap_core::fs::ensure_tight_dir
helper can perform the openat/fstat/mkdirat TOCTOU-safe dance.
rimap-audit gets rustix so AuditWriter::open can call geteuid() before
delegating to the helper. rimap-server was pinning rustix directly;
move it to workspace inheritance so the version is declared once.

Refs #147.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 2: Create `rimap_core::fs::ensure_tight_dir` and its tests

**Files:**
- Create: `crates/rimap-core/src/fs.rs`
- Modify: `crates/rimap-core/src/lib.rs`

- [ ] **Step 1: Scaffold the module and write ONE failing test first**

Create `crates/rimap-core/src/fs.rs` with the following content — the function signature is defined but the body is `unimplemented!()` so tests fail immediately:

```rust
//! Filesystem primitives shared across `rimap-*` crates.
//!
//! Currently hosts [`ensure_tight_dir`], the TOCTOU-safe "create or verify
//! that this directory is mode 0700 and owned by us, refusing symlinks" op
//! used by the daemon socket-directory bootstrap and the audit writer's
//! parent-directory tightening.

#![cfg(unix)]

use std::ffi::OsStr;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, mkdirat, open, openat, statat};
use rustix::io::Errno;

/// Flags used for every directory handle this module holds.
///
/// `O_NOFOLLOW` refuses a symlinked leaf, `O_DIRECTORY` refuses a non-directory,
/// `O_CLOEXEC` stops the fd leaking across `exec`, `O_PATH` means we only need
/// the fd as an anchor for subsequent `*at` syscalls — we never read or write
/// it directly.
const DIR_OFLAGS: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Ensure `dir` exists, is owned by `our_uid`, is mode 0700, and is not a
/// symlink. Creates the directory (mode 0700) if missing.
///
/// The leaf is opened with `openat(parent_fd, name, O_NOFOLLOW | O_DIRECTORY
/// | O_CLOEXEC | O_PATH)` so that a hostile swap of an ancestor between
/// syscalls cannot smuggle the caller onto a different directory. The returned
/// [`OwnedFd`] pins the verified directory — callers that perform follow-up
/// syscalls inside `dir` should keep the fd alive and use `*at` syscalls
/// against it rather than re-walking the path. Callers that need only the
/// invariant can drop the fd immediately.
///
/// Refuses to operate on a symlinked directory, a wrong-owner directory, or a
/// too-permissive directory — these signal a hostile or compromised filesystem
/// state and should fail loudly rather than be "fixed" silently.
///
/// # Errors
/// Returns `PermissionDenied` if the directory (or its leaf component) is a
/// symlink, is owned by a different UID, or has mode other than 0700. A
/// directory with any of setuid, setgid, or sticky bits set is rejected for
/// the same reason — remove those bits (e.g. `chmod 0700`) to proceed.
/// Returns `NotADirectory` if the path exists but is not a directory. Returns
/// the underlying I/O error from `create_dir_all` / `mkdirat` on bootstrap.
pub fn ensure_tight_dir(dir: &Path, our_uid: u32) -> io::Result<OwnedFd> {
    unimplemented!("ensure_tight_dir body lands in step 3")
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::ensure_tight_dir;
    use std::io;
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::TempDir;

    fn our_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[test]
    fn creates_dir_when_absent() {
        let base = TempDir::new().unwrap();
        let target = base.path().join("r/sock-dir");
        ensure_tight_dir(&target, our_uid()).unwrap();
        assert!(target.is_dir());
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn accepts_existing_dir_that_is_already_0700_and_ours() {
        let base = TempDir::new().unwrap();
        let target = base.path().join("ok");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        ensure_tight_dir(&target, our_uid()).unwrap();
    }

    #[test]
    fn rejects_too_permissive_dir() {
        let base = TempDir::new().unwrap();
        let target = base.path().join("slack");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = ensure_tight_dir(&target, our_uid()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("0700"));
    }

    #[test]
    fn rejects_symlinked_dir() {
        let base = TempDir::new().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = ensure_tight_dir(&link, our_uid()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn rejects_symlinked_ancestor() {
        let base = TempDir::new().unwrap();
        let real_parent = base.path().join("real");
        std::fs::create_dir_all(real_parent.join("ok")).unwrap();
        std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            real_parent.join("ok"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real_parent, &link).unwrap();
        let err = ensure_tight_dir(&link.join("ok"), our_uid()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_wrong_owner_reports_uid_in_message() {
        // Cannot actually chown to a different UID without root, so we
        // assert the rejection message contains the uid we asked for by
        // passing our_uid + 1 (the dir is ours). This forces the wrong-uid
        // branch deterministically.
        let base = TempDir::new().unwrap();
        let target = base.path().join("mine");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bogus_uid = our_uid().wrapping_add(1);
        let err = ensure_tight_dir(&target, bogus_uid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains(&bogus_uid.to_string()),
            "expected uid {bogus_uid} in error message: {err}",
        );
    }
}
```

Also add `tempfile` as a dev-dep on `rimap-core` if it is not already there:

Run: `rg -n '^tempfile' crates/rimap-core/Cargo.toml`
- If the line is under `[dev-dependencies]`, you are done.
- If no hit, add under `[dev-dependencies]`:
  ```toml
  tempfile = { workspace = true }
  ```

Also add `rustix` to `[target.'cfg(unix)'.dev-dependencies]` on `rimap-core` so the `our_uid()` test helper compiles (the production dep is `cfg(unix)` only; tests have `cfg_attr` implicit visibility but need an explicit dev-dep block to pick up features that dev-deps unify). Actually: because the module itself is `#![cfg(unix)]`, the `rustix` crate is pulled in by the production dep for this module; tests inherit. **Skip this step** — the production dep is enough. If the test module fails to build, THEN add `rustix` to dev-deps.

- [ ] **Step 2: Declare the module in `lib.rs`**

In `crates/rimap-core/src/lib.rs`, add this line in the `pub mod` block (keep alphabetical ordering — after `pub mod error;`):

```rust
#[cfg(unix)]
pub mod fs;
```

- [ ] **Step 3: Run the tests to confirm they fail loudly**

Run: `cargo test -p rimap-core --lib fs::tests`
Expected: every test panics with `unimplemented!()`.

- [ ] **Step 4: Fill in the implementation**

Replace the `unimplemented!()` body of `ensure_tight_dir` with the production implementation. The code is a straight copy-paste from the existing `prepare_socket_dir` (`crates/rimap-server/src/daemon/socket_setup.rs:42-78`) and its private helpers, with minor renames. Append the helpers inside `crates/rimap-core/src/fs.rs` (after the `ensure_tight_dir` function, before the `#[cfg(test)]` block):

```rust
pub fn ensure_tight_dir(dir: &Path, our_uid: u32) -> io::Result<OwnedFd> {
    let (parent, name) = split_parent_and_name(dir)?;

    let parent_fd = open_parent(parent)?;

    match openat(&parent_fd, name, DIR_OFLAGS, Mode::empty()) {
        Ok(fd) => verify_dir(&fd, dir, our_uid).map(|()| fd),
        // `O_NOFOLLOW | O_DIRECTORY` on a symlink-to-directory returns either
        // `ELOOP` or `ENOTDIR` depending on kernel path-walk order; treat both
        // as "leaf is a symlink" and refuse.
        Err(Errno::LOOP | Errno::NOTDIR) if leaf_is_symlink(&parent_fd, name) => {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("directory {} is a symlink", dir.display()),
            ))
        }
        Err(Errno::NOTDIR) => Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("parent of {} is not a directory", dir.display()),
        )),
        Err(Errno::NOENT) => {
            if let Err(e) = mkdirat(&parent_fd, name, Mode::from_raw_mode(0o700))
                && e != Errno::EXIST
            {
                return Err(io::Error::from_raw_os_error(e.raw_os_error()));
            }
            let fd = openat(&parent_fd, name, DIR_OFLAGS, Mode::empty())
                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
            verify_dir(&fd, dir, our_uid).map(|()| fd)
        }
        Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
    }
}

fn leaf_is_symlink(parent_fd: &OwnedFd, name: &OsStr) -> bool {
    statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW)
        .map(|s| FileType::from_raw_mode(s.st_mode) == FileType::Symlink)
        .unwrap_or(false)
}

fn split_parent_and_name(dir: &Path) -> io::Result<(&Path, &OsStr)> {
    let parent = dir.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("directory {} has no parent", dir.display()),
        )
    })?;
    let name = dir.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("directory {} has no file name", dir.display()),
        )
    })?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    Ok((parent, name))
}

fn open_parent(parent: &Path) -> io::Result<OwnedFd> {
    match open(parent, DIR_OFLAGS, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(Errno::LOOP | Errno::NOTDIR) if path_is_symlink(parent) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("parent {} is a symlink", parent.display()),
        )),
        Err(Errno::NOTDIR) => Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("parent {} is not a directory", parent.display()),
        )),
        Err(Errno::NOENT) => {
            std::fs::create_dir_all(parent)?;
            open(parent, DIR_OFLAGS, Mode::empty())
                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
        }
        Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
    }
}

fn path_is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn verify_dir(fd: &OwnedFd, dir: &Path, our_uid: u32) -> io::Result<()> {
    let stat = fstat(fd).map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
    let stat_uid = uid_to_u32(stat.st_uid);
    if stat_uid != our_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "directory {} is owned by uid {}, not {}",
                dir.display(),
                stat_uid,
                our_uid
            ),
        ));
    }
    let perm_bits = Mode::from_raw_mode(stat.st_mode)
        & (Mode::RWXU | Mode::RWXG | Mode::RWXO | Mode::SUID | Mode::SGID | Mode::SVTX);
    if perm_bits != Mode::RWXU {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "directory {} has mode {:o}, require 0700",
                dir.display(),
                perm_bits.as_raw_mode()
            ),
        ));
    }
    Ok(())
}

fn uid_to_u32<T: TryInto<u32>>(uid: T) -> u32 {
    uid.try_into().unwrap_or(u32::MAX)
}
```

Note the error-message wording differences from the socket_setup version: `socket directory {} is a symlink` becomes `directory {} is a symlink`, dropping the socket-specific noun. Callers with their own context (e.g. audit writer wrapping into `AuditError::ParentDir`) still get a usable message; socket-setup callers still see the same operational meaning without the redundant "socket" prefix.

- [ ] **Step 5: Run the tests to confirm they pass**

Run: `cargo test -p rimap-core --lib fs::tests`
Expected: all six tests pass.

- [ ] **Step 6: Run clippy on `rimap-core`**

Run: `cargo clippy -p rimap-core --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-core/Cargo.toml \
        crates/rimap-core/src/lib.rs \
        crates/rimap-core/src/fs.rs
git commit -m "$(cat <<'EOF'
feat(rimap-core): add fs::ensure_tight_dir TOCTOU-safe dir primitive (#147)

Moves the openat/fstat/mkdirat dance from rimap-server::daemon::socket_setup
into rimap-core::fs so rimap-audit can call it too. The returned OwnedFd is
still the defense-in-depth anchor for callers that pin a verified directory
across follow-up syscalls (dropped by callers that only need the invariant).

Refs #147.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 3: Shrink `prepare_socket_dir` to a delegator

**Files:**
- Modify: `crates/rimap-server/src/daemon/socket_setup.rs`

- [ ] **Step 1: Replace the file with a thin wrapper**

Rewrite `crates/rimap-server/src/daemon/socket_setup.rs` in its entirety:

```rust
//! Daemon socket-directory preparation — thin wrapper over
//! [`rimap_core::fs::ensure_tight_dir`].
//!
//! The production primitive lives in `rimap-core::fs` so the audit writer
//! can share it. This module retains its crate-local name for the one
//! daemon caller (`main.rs`) and continues to host the socket-flavoured
//! integration tests that exercise the full code path through rustix.

#![cfg(unix)]

use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

/// Ensure the daemon socket's parent directory exists, is owned by the
/// running user, and is mode 0700 — delegating to the shared helper.
///
/// # Errors
/// Propagates every error from [`rimap_core::fs::ensure_tight_dir`].
pub fn prepare_socket_dir(dir: &Path, our_uid: u32) -> io::Result<OwnedFd> {
    rimap_core::fs::ensure_tight_dir(dir, our_uid)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    //! The integration tests here exercise the same code paths as the
    //! `rimap_core::fs::tests` unit tests; both are kept because the
    //! socket-setup caller is a security-sensitive code path and bisecting
    //! a future regression is easier when both test suites are green.

    use super::prepare_socket_dir;
    use std::io;
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::TempDir;

    fn our_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[test]
    fn creates_dir_when_absent() {
        let base = TempDir::new().unwrap();
        let target = base.path().join("r/sock-dir");
        prepare_socket_dir(&target, our_uid()).unwrap();
        assert!(target.is_dir());
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn rejects_symlinked_dir() {
        let base = TempDir::new().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = prepare_socket_dir(&link, our_uid()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn rejects_too_permissive_dir() {
        let base = TempDir::new().unwrap();
        let target = base.path().join("slack");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = prepare_socket_dir(&target, our_uid()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("0700"));
    }
}
```

The dropped tests (`accepts_existing_dir_that_is_already_0700_and_ours`, `rejects_symlinked_ancestor`) are already covered in `rimap-core::fs::tests`. Keeping three socket-flavoured tests keeps the integration-layer signal without duplicating every case.

- [ ] **Step 2: Verify `main.rs` still compiles (signatures unchanged)**

Run: `cargo check -p rimap-server --all-targets`
Expected: clean. `prepare_socket_dir`'s signature is unchanged, so `main.rs:165` continues to build without edits.

- [ ] **Step 3: Run the socket-setup tests**

Run: `cargo test -p rimap-server --lib daemon::socket_setup`
Expected: three tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/daemon/socket_setup.rs
git commit -m "$(cat <<'EOF'
refactor(rimap-server): delegate prepare_socket_dir to rimap_core::fs (#147)

prepare_socket_dir is now a one-liner over rimap_core::fs::ensure_tight_dir.
Kept as a named wrapper so main.rs reads naturally ("prepare the socket
directory"); the shared primitive is now reusable by rimap-audit.

Three integration-flavoured tests remain in place; the detailed unit
coverage moved to rimap-core's test module.

Refs #147.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 4: Switch `AuditWriter::open` to `ensure_tight_dir`

**Files:**
- Modify: `crates/rimap-audit/src/writer/mod.rs`

- [ ] **Step 1: Write the failing behavioural test**

Append this test to the existing `#[cfg(test)] mod tests` block in `crates/rimap-audit/src/writer/mod.rs` (the module starts at line 274):

```rust
    #[cfg(unix)]
    #[test]
    fn open_rejects_audit_parent_that_is_a_symlink() {
        // Security invariant from #147: AuditWriter::open must refuse a
        // symlinked parent directory. Before #147, set_parent_mode_0700
        // silently chmodded through the symlink; after #147 we fail loud.
        use crate::record::ids::Seq;
        use std::os::unix::fs::PermissionsExt as _;
        use tempfile::TempDir;

        let base = TempDir::new().unwrap();
        let real_parent = base.path().join("real");
        std::fs::create_dir_all(&real_parent).unwrap();
        std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link_parent = base.path().join("link");
        std::os::unix::fs::symlink(&real_parent, &link_parent).unwrap();

        let audit_path = link_parent.join("audit.jsonl");
        let err = AuditWriter::open(&AuditOptions {
            path: audit_path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .unwrap_err();

        match err {
            AuditError::ParentDir { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
                assert!(
                    source.to_string().contains("symlink"),
                    "expected symlink-specific error, got: {source}",
                );
            }
            other => panic!("expected ParentDir, got {other:?}"),
        }
    }
```

Run the test to confirm it fails (`AuditWriter::open` currently does NOT reject a symlinked parent — it would proceed and create the audit file inside the symlinked target):

Run: `cargo test -p rimap-audit --lib writer::tests::open_rejects_audit_parent_that_is_a_symlink`
Expected: test FAILS — the writer opens successfully because `set_parent_mode_0700` follows the symlink and merely chmods the real target.

- [ ] **Step 2: Rewrite the parent-dir block in `AuditWriter::open`**

In `crates/rimap-audit/src/writer/mod.rs`, replace lines 106–115:

```rust
        if let Some(parent) = opts.path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|source| AuditError::ParentDir {
                path: opts.path.clone(),
                source,
            })?;
            set_parent_mode_0700(parent);
        }
```

with:

```rust
        if let Some(parent) = opts.path.parent()
            && !parent.as_os_str().is_empty()
        {
            #[cfg(unix)]
            {
                let our_uid = rustix::process::geteuid().as_raw();
                // Drop the OwnedFd immediately — the subsequent
                // writer_open_options().open(&opts.path) re-walks the path,
                // so holding the fd would be only a momentary defense. The
                // verified-state-at-this-instant is the security property we
                // want; a concurrent attacker with write access to the
                // parent directory would already have bigger problems.
                let _verified_parent =
                    rimap_core::fs::ensure_tight_dir(parent, our_uid).map_err(|source| {
                        AuditError::ParentDir {
                            path: opts.path.clone(),
                            source,
                        }
                    })?;
            }
            #[cfg(not(unix))]
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|source| AuditError::ParentDir {
                    path: opts.path.clone(),
                    source,
                })?;
            }
        }
```

- [ ] **Step 3: Delete both `set_parent_mode_0700` function definitions**

Delete lines 259–272 (the `#[cfg(unix)]` and `#[cfg(not(unix))]` stubs of `set_parent_mode_0700`). Both are now dead:

```rust
#[cfg(unix)]
fn set_parent_mode_0700(parent: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(parent) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        if let Err(err) = std::fs::set_permissions(parent, perms) {
            tracing::warn!(error = %err, "failed to set audit parent dir mode 0700");
        }
    }
}

#[cfg(not(unix))]
fn set_parent_mode_0700(_parent: &Path) {}
```

- [ ] **Step 4: Run the previously-failing test to confirm it now passes**

Run: `cargo test -p rimap-audit --lib writer::tests::open_rejects_audit_parent_that_is_a_symlink`
Expected: pass.

- [ ] **Step 5: Run the full writer test module**

Run: `cargo test -p rimap-audit --lib writer`
Expected: every pre-existing test passes (`open_creates_file_and_acquires_lock`, `second_open_against_same_path_fails_with_locked`, `drop_releases_the_lock`, `log_process_start_populates_chain_of_history_fields`, etc.).

If any test fails because the tempdir hierarchy has a symlinked ancestor under the test user's `/tmp` (some CI providers do this), capture the failure and switch the test to `tempfile::Builder::new().prefix("rimap-audit-").tempdir_in(...)` with an explicit canonical base. This is defensive scaffolding; on every CI we target today, `tempfile::TempDir::new()` lands under a non-symlinked path.

- [ ] **Step 6: Run clippy + fmt**

Run: `cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean. If clippy flags "unused import" for `Path` in `writer/mod.rs`, the import was only used by the deleted `set_parent_mode_0700`; prune it.

Run: `cargo fmt -p rimap-audit`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-audit/src/writer/mod.rs
git commit -m "$(cat <<'EOF'
refactor(rimap-audit): use rimap_core::fs::ensure_tight_dir for audit parent (#147)

Replaces the best-effort set_parent_mode_0700 chmod with the strict
TOCTOU-safe ensure_tight_dir check shared with daemon socket setup.
This is a security tightening: a symlinked or wrong-owned audit parent
now fails AuditWriter::open loudly (AuditError::ParentDir) instead of
silently chmodding the symlink's target and proceeding.

Operators who symlinked their audit directory (a dubious setup) will
see the new error; the fix is to make the audit parent a real 0700
directory owned by the running user. Documented in CHANGELOG for this
release.

Closes #147.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 5: Full-workspace verification + CHANGELOG note

**Files:**
- Modify (optional): `CHANGELOG.md` — flag the tightened audit-parent contract.

- [ ] **Step 1: Decide whether to add a CHANGELOG entry**

Run: `ls CHANGELOG.md 2>/dev/null && echo "exists" || echo "missing"`

- If `exists`, add the following line under the top-most unreleased / polish-release section:
  ```
  - **audit (security, minor-breaking):** `AuditWriter::open` now rejects a symlinked or wrong-owned audit parent directory. Any operator setup that symlinked the audit dir must be migrated to a real 0700 directory before upgrade. (#147)
  ```
- If `missing`, skip — the PR description carries the same note.

- [ ] **Step 2: `cargo fmt --check`**

Run: `cargo fmt --check`
Expected: clean.

- [ ] **Step 3: Full clippy with `-D warnings`**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 4: Full workspace test suite**

Run: `cargo test --workspace`
Expected: every test passes. Note two classes of green:

- `rimap-core::fs::tests` — six new tests for the shared helper.
- `rimap-server::daemon::socket_setup::tests` — three retained socket-flavoured tests.
- `rimap-audit::writer::tests` — every pre-existing writer test PLUS the new symlink-rejection test.

- [ ] **Step 5: `cargo deny check`**

Run: `cargo deny check advisories bans licenses`
Expected: clean. `rustix` is already in the graph; the new edges add no new crate.

- [ ] **Step 6: typos**

Run: `typos`
Expected: clean.

## Self-review checklist

- Shared helper lives in the lowest crate that both callers can reach (`rimap-core`) — no circular-dep risk.
- Helper signature matches issue body (`&Path, u32`) except return type intentionally preserves `OwnedFd` for defense-in-depth (divergence documented above).
- `prepare_socket_dir` is a 1-line delegator; the duplication is gone.
- Audit writer test proves the behavioural tightening (symlinked parent → failure) and runs in the regular `cargo test` path, no feature flag.
- Four commits land in order: deps → helper + tests → socket_setup delegator → audit writer rewire + CHANGELOG. Each is independently buildable and clippy-clean.
- Dev-deps sanity: `tempfile` already workspace-level; no new dev-dep additions.

## Out of scope

- **Making `ensure_tight_dir` discover `our_uid` internally** — deferred. Keeping the `u32` parameter keeps the helper pure-functional and testable with arbitrary uids. The convenience `geteuid()` call is at the two call sites (`main.rs` and `AuditWriter::open`).
- **Applying the same tightening to `resolve_download_dir_multi` in `main.rs`** — not in #147's scope. That function uses `std::fs::create_dir_all + set_permissions` today; a future PR can cut it over to `ensure_tight_dir` once the semantics are proven.
- **Windows equivalent** — both call sites are `#[cfg(unix)]`; Windows has its own DACL-based tightening (#133) which is a separate scope.

If you find yourself editing anything outside the Files list, stop and re-read the spec.
