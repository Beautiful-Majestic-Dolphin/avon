use avon_config::{LogFormat, ObservabilityArgs};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::ObservabilityError;

/// Install the global tracing subscriber. JSON output by default; text for
/// local development. Safe to call once per process.
pub fn init_tracing(args: &ObservabilityArgs) -> Result<(), ObservabilityError> {
    let filter = EnvFilter::try_new(&args.log_level)
        .map_err(|e| ObservabilityError::Tracing(e.to_string()))?;
    let registry = tracing_subscriber::registry().with(filter);
    let result = match args.log_format {
        LogFormat::Json => registry
            .with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true),
            )
            .try_init(),
        LogFormat::Text => registry.with(fmt::layer().compact()).try_init(),
    };
    result.map_err(|e| ObservabilityError::Tracing(e.to_string()))
}
