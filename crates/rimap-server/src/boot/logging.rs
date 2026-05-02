//! Tracing subscriber initialization.
//!
//! Writes to stderr via the `fmt` layer's `with_writer(std::io::stderr)`.
//! The clippy `print_stderr` lint targets the `eprintln!` / `eprint!` macros,
//! not direct `Write` calls through the `tracing-subscriber` machinery, so
//! this initialization is compatible with the workspace lint set.
//!
//! The filter defaults to `info` but can be overridden by
//! `RUST_LOG` / `RIMAP_LOG` environment variables via the standard
//! `EnvFilter::try_from_default_env` chain.

use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::{EnvFilter, fmt};

/// Initialize the global default subscriber. Safe to call exactly once per
/// process; subsequent calls are no-ops.
pub fn init() {
    let filter = EnvFilter::try_from_env("RIMAP_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // `with_writer(std::io::stderr)` is an `fn() -> Stderr`, which satisfies
    // the `MakeWriter` trait; `.with_max_level(...)` is provided by the
    // `MakeWriterExt` trait.
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr.with_max_level(tracing::Level::TRACE))
        .with_target(true)
        .try_init();
}

/// Initialize the global default subscriber with a caller-supplied writer
/// instead of stderr. Used by the Windows SCM service path to redirect
/// `tracing` events to a log file. Safe to call exactly once per process;
/// subsequent calls (and a subsequent `init()`) are no-ops.
pub fn init_to_writer<W>(make_writer: W)
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = EnvFilter::try_from_env("RIMAP_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(make_writer)
        .with_target(true)
        .try_init();
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::io::Write as _;
    use std::sync::Mutex;

    /// `init_to_writer` accepts any `MakeWriter` implementation. A
    /// `Mutex<Vec<u8>>` is sufficient — `tracing-subscriber` has a
    /// `MakeWriter` impl for `Mutex<W> where W: Write`.
    ///
    /// Note: the `Arc<W>` blanket impl in `tracing-subscriber` requires
    /// `&W: Write`, which `Mutex` does *not* satisfy, so wrapping in `Arc`
    /// would not type-check. Use `Mutex<File>` (or a custom `MakeWriter`
    /// newtype) when sharing is needed.
    #[test]
    fn init_to_writer_accepts_mutex_vec_u8() {
        let buf: Mutex<Vec<u8>> = Mutex::new(Vec::new());
        // Compile-time check only: this test passes by virtue of compiling.
        // Runtime behavior is hard to test because the global subscriber
        // is set at most once per process, and other tests in the binary
        // may have already initialized it. The presence of this signature
        // proves the public API accepts our intended writer shape.
        let _: fn(Mutex<Vec<u8>>) = super::init_to_writer::<Mutex<Vec<u8>>>;
        // Sanity poke at the writer type — confirms `Vec<u8>` is `Write`.
        let mut guard = buf.lock().expect("lock");
        let _ = guard.write_all(b"sanity");
    }
}
