//! Observability bootstrap: a JSON `tracing-subscriber` with an env filter.
//!
//! [`init`] installs the process-wide subscriber once at startup; tests build
//! an equivalent subscriber against an in-memory writer via
//! [`with_filter`]/[`subscriber`]. Every event is emitted as one JSON object so
//! a log pipeline can index structured fields (including the request id span
//! field set by [`super::request_id`]) without parsing free text.

use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};

/// Filter used when `RUST_LOG` is unset or invalid.
pub const DEFAULT_FILTER: &str = "info";

/// Build a JSON subscriber whose filter comes from `RUST_LOG`.
pub fn subscriber<W>(writer: W) -> impl tracing::Subscriber + Send + Sync + 'static
where
  W: for<'w> fmt::MakeWriter<'w> + Send + Sync + 'static,
{
  with_filter(environment_filter(), writer)
}

/// Build a JSON subscriber with an explicit filter and writer.
pub fn with_filter<W>(
  filter: EnvFilter,
  writer: W,
) -> impl tracing::Subscriber + Send + Sync + 'static
where
  W: for<'w> fmt::MakeWriter<'w> + Send + Sync + 'static,
{
  Registry::default()
    .with(filter)
    .with(fmt::layer().json().with_writer(writer))
}

/// Install the global JSON subscriber, writing to stdout.
///
/// # Errors
///
/// Returns an error if a global subscriber is already installed.
pub fn init() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
  tracing::subscriber::set_global_default(subscriber(std::io::stdout))?;
  Ok(())
}

/// `RUST_LOG` if present and valid, otherwise [`DEFAULT_FILTER`].
fn environment_filter() -> EnvFilter {
  EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER))
}
