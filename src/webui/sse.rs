//! Server-Sent Events (SSE) handler for real-time authorization event streaming.
//!
//! Provides a live feed of ALLOW/DENY decisions to the Web UI.

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use serde::Serialize;
use std::{convert::Infallible, time::Duration};

use crate::http::AppState;

/// Simplified authorization event for Web UI display.
/// Contains only the fields needed for the live feed.
#[derive(Debug, Clone, Serialize)]
pub struct WebUiAuthEvent {
    /// Principal/agent ID (e.g., "agent:web-browser")
    pub principal_id: String,
    /// Action attempted (e.g., "browser.navigate")
    pub action: String,
    /// Resource accessed (e.g., "https://example.com")
    pub resource: String,
    /// Authorization result: "ALLOW" or "DENY"
    pub result: String,
    /// Processing latency in microseconds
    pub latency_us: u64,
    /// Unix timestamp (seconds)
    pub timestamp: i64,
}

/// SSE handler for real-time authorization events.
///
/// Streams authorization decisions as they happen.
/// Uses polling of the proof ledger (option B from the design doc).
/// Respects shutdown signal for graceful termination.
pub async fn events_handler(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut shutdown_rx = state.shutdown_rx.clone();

    let stream = async_stream::stream! {
        let mut last_seen_count = 0usize;
        let poll_interval = Duration::from_millis(100);

        loop {
            // Check for shutdown signal
            if let Some(ref mut rx) = shutdown_rx {
                if *rx.borrow() {
                    tracing::debug!("SSE stream received shutdown signal");
                    break;
                }
            }

            // Get recent events from the ledger
            let events = state.proof_ledger.recent_events(100);
            let current_count = state.proof_ledger.event_count();

            // If we have new events, emit them
            if current_count > last_seen_count {
                // Calculate how many new events we have
                let new_count = current_count.saturating_sub(last_seen_count);

                // Get the new events (they're in reverse order, so take from the front)
                for event in events.iter().take(new_count).rev() {
                    let web_event = WebUiAuthEvent {
                        principal_id: event.principal_id.clone(),
                        action: event.action.clone(),
                        resource: event.resource.clone(),
                        result: if event.allowed { "ALLOW".to_string() } else { "DENY".to_string() },
                        latency_us: event.latency_us.unwrap_or(0),
                        timestamp: event.emitted_at_epoch_s,
                    };

                    if let Ok(json) = serde_json::to_string(&web_event) {
                        yield Ok(Event::default().data(json));
                    }
                }

                last_seen_count = current_count;
            }

            // Use tokio::select to handle both sleep and shutdown
            if let Some(ref mut rx) = shutdown_rx {
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = rx.changed() => {
                        if *rx.borrow() {
                            tracing::debug!("SSE stream received shutdown during sleep");
                            break;
                        }
                    }
                }
            } else {
                tokio::time::sleep(poll_interval).await;
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_web_ui_auth_event_serialization() {
        let event = WebUiAuthEvent {
            principal_id: "agent:test".to_string(),
            action: "browser.navigate".to_string(),
            resource: "https://example.com".to_string(),
            result: "ALLOW".to_string(),
            latency_us: 1234,
            timestamp: 1699999999,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"principal_id\":\"agent:test\""));
        assert!(json.contains("\"result\":\"ALLOW\""));
        assert!(json.contains("\"latency_us\":1234"));
    }

    #[test]
    fn test_web_ui_auth_event_deny() {
        let event = WebUiAuthEvent {
            principal_id: "agent:malicious".to_string(),
            action: "file.delete".to_string(),
            resource: "/etc/passwd".to_string(),
            result: "DENY".to_string(),
            latency_us: 567,
            timestamp: 1699999999,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"result\":\"DENY\""));
    }
}
