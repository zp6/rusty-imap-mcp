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
