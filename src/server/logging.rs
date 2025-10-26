use std::time::Instant;

use axum::{extract::Request, middleware::Next, response::Response};

const LOG_TARGET: &str = "server::http";

/// Middleware that logs incoming HTTP requests and their responses
pub async fn log_requests(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path();
    let query = uri.query().unwrap_or("");

    // Log incoming request
    if query.is_empty() {
        tracing::info!(
            target = LOG_TARGET,
            %method,
            %path,
            "incoming request"
        );
    } else {
        tracing::info!(
            target = LOG_TARGET,
            %method,
            %path,
            %query,
            "incoming request"
        );
    }

    let start = Instant::now();

    // Execute the request
    let response = next.run(request).await;

    // Calculate duration
    let duration = start.elapsed();
    let status = response.status();

    // Log response
    tracing::info!(
        target = LOG_TARGET,
        %method,
        %path,
        status = %status.as_u16(),
        duration_ms = %duration.as_millis(),
        "request completed"
    );

    response
}
