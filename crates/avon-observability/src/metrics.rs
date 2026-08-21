use std::net::SocketAddr;

use metrics_exporter_prometheus::PrometheusBuilder;

use crate::ObservabilityError;

/// Install the global Prometheus recorder and start its HTTP listener.
/// Services call this exactly once; metrics macros are no-ops before it runs.
pub fn install_metrics(addr: SocketAddr) -> Result<(), ObservabilityError> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| ObservabilityError::Metrics(e.to_string()))
}
