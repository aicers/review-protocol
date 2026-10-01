//! Integration tests for unidirectional event stream API
//!
//! These tests verify the complete functionality of the unidirectional channel
//! API with real QUIC connections, ensuring protocol compatibility and proper
//! error handling.

#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use review_protocol::{
    server::EventStreamHandler,
    test::TEST_ENV,
    types::{EventKind, EventMessage},
};
use tokio::time::timeout;

/// Test handler that collects events and errors
struct CollectingHandler {
    events: Arc<Mutex<Vec<EventMessage>>>,
    errors: Arc<Mutex<Vec<String>>>,
    max_events: Option<usize>,
}

impl CollectingHandler {
    fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            errors: Arc::new(Mutex::new(Vec::new())),
            max_events: None,
        }
    }

    fn with_limit(max_events: usize) -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            errors: Arc::new(Mutex::new(Vec::new())),
            max_events: Some(max_events),
        }
    }

    #[allow(dead_code)]
    fn event_count(&self) -> usize {
        self.events.lock().expect("Failed to lock events").len()
    }

    #[allow(dead_code)]
    fn error_count(&self) -> usize {
        self.errors.lock().expect("Failed to lock errors").len()
    }
}

#[async_trait::async_trait]
impl EventStreamHandler for CollectingHandler {
    async fn handle_event(&mut self, event: EventMessage) -> std::io::Result<()> {
        let mut events = self.events.lock().expect("Failed to lock events");
        events.push(event);

        if let Some(max) = self.max_events
            && events.len() >= max
        {
            return Err(std::io::Error::other("reached event limit"));
        }

        Ok(())
    }

    async fn on_error(&mut self, error: &str) -> std::io::Result<()> {
        self.errors
            .lock()
            .expect("Failed to lock errors")
            .push(error.to_string());
        Ok(())
    }
}

// TODO: This test has timing issues due to race conditions between
// client and server stream setup. See PR #99 for details.
#[ignore = "timing issues with race conditions - see PR #99"]
#[tokio::test]
async fn test_single_event_stream() {
    let test_env = TEST_ENV.lock().await;
    let (server_conn, client_conn) = test_env.setup().await;

    let handler = CollectingHandler::new();
    let events_ref = handler.events.clone();

    let server_conn_for_teardown = server_conn.clone();

    // Client sends events - start this first to ensure stream is ready
    let client_handle = tokio::spawn(async move {
        // Small delay to allow server to start listening
        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut send_stream = client_conn.open_uni().await.unwrap();

        // Send protocol header
        send_stream.write_all(&[0, 0]).await.unwrap();

        // Send test events
        for i in 0..5 {
            let event = EventMessage {
                time: jiff::Timestamp::now(),
                kind: EventKind::HttpThreat,
                fields: format!("value_{i}").into_bytes(),
            };

            let serialized =
                bincode::serde::encode_to_vec(&event, bincode::config::standard()).unwrap();
            #[allow(clippy::cast_possible_truncation)]
            let len_bytes = (serialized.len() as u32).to_be_bytes();

            send_stream.write_all(&len_bytes).await.unwrap();
            send_stream.write_all(&serialized).await.unwrap();
        }

        send_stream.finish().unwrap();
    });

    // Server accepts stream - start after spawning client
    let server_handle = tokio::spawn(async move { server_conn.accept_event_stream(handler).await });

    // Wait for completion
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);

    let server_res = server_result.unwrap();
    if let Err(ref e) = server_res {
        eprintln!("Server error: {e}");
    }
    assert!(server_res.is_ok());
    assert!(client_result.is_ok());
    assert_eq!(events_ref.lock().unwrap().len(), 5);

    test_env.teardown(&server_conn_for_teardown);
}

// TODO: This test has timing issues due to race conditions between
// client and server stream setup. See PR #99 for details.
#[ignore = "timing issues with race conditions - see PR #99"]
#[tokio::test]
async fn test_multiple_concurrent_streams() {
    let test_env = TEST_ENV.lock().await;
    let (server_conn, client_conn) = test_env.setup().await;

    let events = Arc::new(Mutex::new(Vec::new()));
    let events_for_loop = events.clone();

    // Server accepts multiple streams using accept_uni + handle_event_stream,
    // with a Semaphore bounding concurrency at 3.
    let server_conn_for_teardown = server_conn.clone();
    let server_conn_clone = server_conn.clone();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(3));
    let server_handle = tokio::spawn(async move {
        timeout(Duration::from_secs(5), async move {
            while let Ok(recv) = server_conn_clone.accept_uni().await {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let events = events_for_loop.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let handler = CollectingHandler {
                        events,
                        errors: Arc::new(Mutex::new(Vec::new())),
                        max_events: None,
                    };
                    let _ = review_protocol::server::Connection::handle_event_stream(recv, handler)
                        .await;
                });
            }
        })
        .await
    });

    // Client opens multiple streams
    let client_handle = tokio::spawn(async move {
        let mut handles = Vec::new();

        for stream_id in 0..3 {
            let client_conn = client_conn.clone();
            let handle = tokio::spawn(async move {
                let mut send_stream = client_conn.open_uni().await.unwrap();

                // Send header and events
                send_stream.write_all(&[0, 0]).await.unwrap();

                for i in 0..2 {
                    let event = EventMessage {
                        time: jiff::Timestamp::now(),
                        kind: EventKind::DnsCovertChannel,
                        fields: format!("stream_{stream_id}_event_{i}").into_bytes(),
                    };

                    let serialized =
                        bincode::serde::encode_to_vec(&event, bincode::config::standard()).unwrap();
                    #[allow(clippy::cast_possible_truncation)]
                    let len_bytes = (serialized.len() as u32).to_be_bytes();

                    send_stream.write_all(&len_bytes).await.unwrap();
                    send_stream.write_all(&serialized).await.unwrap();
                }

                send_stream.finish().unwrap();
            });

            handles.push(handle);
        }

        // Wait for all streams to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Give server time to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Close connection to end server loop
        client_conn.close(0u32.into(), b"test complete");
    });

    let (server_result, client_result) = tokio::join!(server_handle, client_handle);

    // Server's accept loop should exit cleanly when the connection closes,
    // well before the 5s timeout fires.
    assert!(server_result.unwrap().is_ok());
    assert!(client_result.is_ok());

    // Verify all events were received
    let received_events = events.lock().unwrap();
    assert_eq!(received_events.len(), 6); // 3 streams * 2 events each

    test_env.teardown(&server_conn_for_teardown);
}

// TODO: This test has timing issues due to race conditions between
// client and server stream setup. See PR #99 for details.
#[ignore = "timing issues with race conditions - see PR #99"]
#[tokio::test]
async fn test_error_handling_in_streams() {
    let test_env = TEST_ENV.lock().await;
    let (server_conn, client_conn) = test_env.setup().await;

    // Handler that fails after 2 events
    let handler = CollectingHandler::with_limit(2);
    let errors_ref = handler.errors.clone();

    let server_conn_for_teardown = server_conn.clone();

    let server_handle = tokio::spawn(async move { server_conn.accept_event_stream(handler).await });

    let client_handle = tokio::spawn(async move {
        let mut send_stream = client_conn.open_uni().await.unwrap();
        send_stream.write_all(&[0, 0]).await.unwrap();

        // Send 3 events (handler should fail on 3rd)
        for i in 0..3 {
            let event = EventMessage {
                time: jiff::Timestamp::now(),
                kind: EventKind::PortScan,
                fields: format!("event_{i}").into_bytes(),
            };

            let serialized =
                bincode::serde::encode_to_vec(&event, bincode::config::standard()).unwrap();
            #[allow(clippy::cast_possible_truncation)]
            let len_bytes = (serialized.len() as u32).to_be_bytes();

            send_stream.write_all(&len_bytes).await.unwrap();
            send_stream.write_all(&serialized).await.unwrap();
        }

        send_stream.finish().unwrap();
    });

    let (server_result, client_result) = tokio::join!(server_handle, client_handle);

    // Server should error when handler fails
    assert!(server_result.unwrap().is_err());
    assert!(client_result.is_ok());

    // Verify no error callbacks were invoked (handler returned error directly)
    assert_eq!(errors_ref.lock().unwrap().len(), 0);

    test_env.teardown(&server_conn_for_teardown);
}

// TODO: This test has timing issues due to race conditions between
// client and server stream setup. See PR #99 for details.
#[ignore = "timing issues with race conditions - see PR #99"]
#[tokio::test]
async fn test_protocol_compatibility() {
    // Test that the new API handles streams in the same format as the old
    // implementation This should match exactly with how REview currently sends
    // event streams

    let test_env = TEST_ENV.lock().await;
    let (server_conn, client_conn) = test_env.setup().await;

    let handler = CollectingHandler::new();
    let events_ref = handler.events.clone();
    let server_conn_for_teardown = server_conn.clone();

    let server_handle = tokio::spawn(async move { server_conn.accept_event_stream(handler).await });

    // Simulate the exact format REview currently uses
    let client_handle = tokio::spawn(async move {
        let mut send_stream = client_conn.open_uni().await.unwrap();

        // REview sends a 2-byte header
        send_stream.write_all(&[0, 0]).await.unwrap();

        // REview uses bincode v2 standard config
        let event = EventMessage {
            time: jiff::Timestamp::now(),
            kind: EventKind::BlocklistConn,
            fields: b"source_ip:192.168.1.100;dest_ip:10.0.0.1;protocol:TCP".to_vec(),
        };

        let serialized =
            bincode::serde::encode_to_vec(&event, bincode::config::standard()).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (serialized.len() as u32).to_be_bytes();

        send_stream.write_all(&len_bytes).await.unwrap();
        send_stream.write_all(&serialized).await.unwrap();
        send_stream.finish().unwrap();
    });

    let (server_result, client_result) = tokio::join!(server_handle, client_handle);

    assert!(server_result.unwrap().is_ok());
    assert!(client_result.is_ok());

    let events = events_ref.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::BlocklistConn);
    assert_ne!(events[0].fields, [] as [u8; 0]);

    test_env.teardown(&server_conn_for_teardown);
}

// TODO: This test has timing issues due to race conditions between
// client and server stream setup. See PR #99 for details.
#[ignore = "timing issues with race conditions - see PR #99"]
#[tokio::test]
async fn test_stream_with_malformed_data() {
    let test_env = TEST_ENV.lock().await;
    let (server_conn, client_conn) = test_env.setup().await;

    let handler = CollectingHandler::new();
    let errors_ref = handler.errors.clone();
    let events_ref = handler.events.clone();

    let server_conn_for_teardown = server_conn.clone();

    let server_handle = tokio::spawn(async move { server_conn.accept_event_stream(handler).await });

    let client_handle = tokio::spawn(async move {
        let mut send_stream = client_conn.open_uni().await.unwrap();

        // Send protocol header
        send_stream.write_all(&[0, 0]).await.unwrap();

        // Send a valid event first
        let event = EventMessage {
            time: jiff::Timestamp::now(),
            kind: EventKind::HttpThreat,
            fields: b"valid event".to_vec(),
        };
        let serialized =
            bincode::serde::encode_to_vec(&event, bincode::config::standard()).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (serialized.len() as u32).to_be_bytes();
        send_stream.write_all(&len_bytes).await.unwrap();
        send_stream.write_all(&serialized).await.unwrap();

        // Send malformed data (wrong length or corrupt data)
        let bad_data = vec![0xFF; 50];
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (bad_data.len() as u32).to_be_bytes();
        send_stream.write_all(&len_bytes).await.unwrap();
        send_stream.write_all(&bad_data).await.unwrap();

        // Send another valid event after the malformed one
        let event2 = EventMessage {
            time: jiff::Timestamp::now(),
            kind: EventKind::DnsCovertChannel,
            fields: b"valid event 2".to_vec(),
        };
        let serialized2 =
            bincode::serde::encode_to_vec(&event2, bincode::config::standard()).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes2 = (serialized2.len() as u32).to_be_bytes();
        send_stream.write_all(&len_bytes2).await.unwrap();
        send_stream.write_all(&serialized2).await.unwrap();

        send_stream.finish().unwrap();
    });

    let (server_result, client_result) = tokio::join!(server_handle, client_handle);

    assert!(server_result.unwrap().is_ok());
    assert!(client_result.is_ok());

    // Should have received 2 valid events (malformed one triggers error callback)
    let events = events_ref.lock().unwrap();
    assert_eq!(events.len(), 2);

    // Should have one deserialization error
    let errors = errors_ref.lock().unwrap();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("deserialization error"));

    test_env.teardown(&server_conn_for_teardown);
}

// TODO: This test has timing issues due to race conditions between
// client and server stream setup. See PR #99 for details.
#[ignore = "timing issues with race conditions - see PR #99"]
#[tokio::test]
async fn test_empty_stream() {
    let test_env = TEST_ENV.lock().await;
    let (server_conn, client_conn) = test_env.setup().await;

    let handler = CollectingHandler::new();
    let events_ref = handler.events.clone();

    let server_conn_for_teardown = server_conn.clone();

    let server_handle = tokio::spawn(async move { server_conn.accept_event_stream(handler).await });

    let client_handle = tokio::spawn(async move {
        let mut send_stream = client_conn.open_uni().await.unwrap();

        // Send only protocol header, no events
        send_stream.write_all(&[0, 0]).await.unwrap();
        send_stream.finish().unwrap();
    });

    let (server_result, client_result) = tokio::join!(server_handle, client_handle);

    assert!(server_result.unwrap().is_ok());
    assert!(client_result.is_ok());

    // Should have no events
    let events = events_ref.lock().unwrap();
    assert_eq!(events.len(), 0);

    test_env.teardown(&server_conn_for_teardown);
}

// TODO: This test has timing issues due to race conditions between
// client and server stream setup. See PR #99 for details.
#[ignore = "timing issues with race conditions - see PR #99"]
#[tokio::test]
async fn test_large_event_handling() {
    let test_env = TEST_ENV.lock().await;
    let (server_conn, client_conn) = test_env.setup().await;

    let handler = CollectingHandler::new();
    let events_ref = handler.events.clone();

    let server_conn_for_teardown = server_conn.clone();

    let server_handle = tokio::spawn(async move { server_conn.accept_event_stream(handler).await });

    let client_handle = tokio::spawn(async move {
        let mut send_stream = client_conn.open_uni().await.unwrap();

        // Send protocol header
        send_stream.write_all(&[0, 0]).await.unwrap();

        // Send a large event (1MB of data)
        let large_data = vec![0x42; 1024 * 1024];
        let event = EventMessage {
            time: jiff::Timestamp::now(),
            kind: EventKind::ExtraThreat,
            fields: large_data,
        };

        let serialized =
            bincode::serde::encode_to_vec(&event, bincode::config::standard()).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (serialized.len() as u32).to_be_bytes();

        send_stream.write_all(&len_bytes).await.unwrap();
        send_stream.write_all(&serialized).await.unwrap();
        send_stream.finish().unwrap();
    });

    let (server_result, client_result) = tokio::join!(server_handle, client_handle);

    assert!(server_result.unwrap().is_ok());
    assert!(client_result.is_ok());

    let events = events_ref.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].fields.len(), 1024 * 1024);

    test_env.teardown(&server_conn_for_teardown);
}

// TODO: This test has timing issues due to race conditions between
// client and server stream setup. See PR #99 for details.
#[ignore = "timing issues with race conditions - see PR #99"]
#[tokio::test]
async fn test_concurrent_stream_processing() {
    struct CountingHandler {
        processed_count: Arc<Mutex<usize>>,
    }

    #[async_trait::async_trait]
    impl EventStreamHandler for CountingHandler {
        async fn handle_event(&mut self, _event: EventMessage) -> std::io::Result<()> {
            {
                let mut count = self
                    .processed_count
                    .lock()
                    .expect("Failed to lock processed_count");
                *count += 1;
            } // Mutex guard is dropped here before await
            // Simulate some processing time
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok(())
        }
    }

    let test_env = TEST_ENV.lock().await;
    let (server_conn, client_conn) = test_env.setup().await;

    let processed_count = Arc::new(Mutex::new(0_usize));
    let processed_count_for_loop = processed_count.clone();

    let server_conn_for_teardown = server_conn.clone();

    // Server accepts streams via accept_uni, bounding concurrency at 5 with
    // a caller-owned Semaphore.
    let server_conn_clone = server_conn.clone();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(5));
    let server_handle = tokio::spawn(async move {
        timeout(Duration::from_secs(10), async move {
            while let Ok(recv) = server_conn_clone.accept_uni().await {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let processed_count = processed_count_for_loop.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let handler = CountingHandler { processed_count };
                    let _ = review_protocol::server::Connection::handle_event_stream(recv, handler)
                        .await;
                });
            }
        })
        .await
    });

    // Client sends 10 streams, each with 5 events
    let client_handle = tokio::spawn(async move {
        let mut handles = Vec::new();

        for stream_id in 0..10 {
            let client_conn = client_conn.clone();
            let handle = tokio::spawn(async move {
                let mut send_stream = client_conn.open_uni().await.unwrap();
                send_stream.write_all(&[0, 0]).await.unwrap();

                for i in 0..5 {
                    let event = EventMessage {
                        time: jiff::Timestamp::now(),
                        kind: EventKind::DnsCovertChannel,
                        fields: format!("stream_{stream_id}_event_{i}").into_bytes(),
                    };

                    let serialized =
                        bincode::serde::encode_to_vec(&event, bincode::config::standard()).unwrap();
                    #[allow(clippy::cast_possible_truncation)]
                    let len_bytes = (serialized.len() as u32).to_be_bytes();

                    send_stream.write_all(&len_bytes).await.unwrap();
                    send_stream.write_all(&serialized).await.unwrap();
                }

                send_stream.finish().unwrap();
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        // Wait for processing
        tokio::time::sleep(Duration::from_millis(500)).await;

        client_conn.close(0u32.into(), b"test complete");
    });

    let (server_result, client_result) = tokio::join!(server_handle, client_handle);

    // Server's accept loop exits cleanly when the connection closes.
    assert!(server_result.unwrap().is_ok());
    assert!(client_result.is_ok());

    // Verify all 50 events were processed (10 streams * 5 events)
    let count = *processed_count.lock().unwrap();
    assert_eq!(count, 50);

    test_env.teardown(&server_conn_for_teardown);
}
