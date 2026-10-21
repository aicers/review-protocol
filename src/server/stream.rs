//! Low-level event stream processing implementation.

use std::io;

use quinn::RecvStream;

use self::super::EventStreamHandler;
use crate::legacy_transport as oinq;

/// Processes a unidirectional event stream with the given handler
///
/// Reads `EventMessage` objects from the stream and calls handler methods
/// appropriately. Handles protocol framing, deserialization, and errors.
///
/// # Protocol Format
/// - 2-byte header (version/reserved)
/// - Sequence of length-prefixed messages:
///   - 4-byte big-endian length
///   - Message payload (bincode-serialized `EventMessage`)
///
/// # Arguments
/// * `recv` - The unidirectional receive stream
/// * `handler` - Handler implementing `EventStreamHandler` trait
///
/// # Returns
/// * `Ok(())` - Stream processed successfully until EOF
/// * `Err(e)` - Network error, protocol error, or handler error
///
/// # Errors
///
/// This function will return an error if:
/// * Failed to read the protocol header (network or stream error)
/// * A handler error occurs during event processing
/// * A handler error occurs during error handling
/// * A handler error occurs during stream end handling
/// * A network error occurs while reading messages
pub async fn process_event_stream<H>(mut recv: RecvStream, mut handler: H) -> io::Result<()>
where
    H: EventStreamHandler + Send,
{
    // Read 2-byte protocol header
    let mut header_buf = vec![0_u8; 2];
    recv.read_exact(&mut header_buf)
        .await
        .map_err(from_read_exact_error_to_io_error)?;

    // Setup for message processing
    let codec = bincode::config::standard();
    let mut message_buf = Vec::new();

    // Process messages until stream ends
    loop {
        // Read next message
        if let Err(e) = oinq::frame::recv_raw(&mut recv, &mut message_buf).await {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                // Stream ended
                handler.on_stream_end().await?;
                break;
            }
            return Err(e);
        }

        // Deserialize and handle message
        match bincode::serde::borrow_decode_from_slice(&message_buf, codec) {
            Ok((msg, _len)) => {
                handler.handle_event(msg).await?;
            }
            Err(e) => {
                let error_msg = format!("decoding error: {e}");
                handler.on_error(&error_msg).await?;
                // Continue processing other messages
            }
        }
    }

    Ok(())
}

fn from_read_exact_error_to_io_error(e: quinn::ReadExactError) -> io::Error {
    match e {
        quinn::ReadExactError::FinishedEarly(_) => io::Error::from(io::ErrorKind::UnexpectedEof),
        quinn::ReadExactError::ReadError(e) => e.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::types::EventMessage;

    // Mock handler for testing
    struct TestHandler {
        events: Arc<Mutex<Vec<EventMessage>>>,
        errors: Arc<Mutex<Vec<String>>>,
        should_fail_on_event: bool,
        stream_ended: Arc<Mutex<bool>>,
    }

    impl TestHandler {
        #[allow(dead_code)]
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                errors: Arc::new(Mutex::new(Vec::new())),
                should_fail_on_event: false,
                stream_ended: Arc::new(Mutex::new(false)),
            }
        }

        #[allow(dead_code)]
        fn with_failure() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                errors: Arc::new(Mutex::new(Vec::new())),
                should_fail_on_event: true,
                stream_ended: Arc::new(Mutex::new(false)),
            }
        }
    }

    #[async_trait::async_trait]
    impl EventStreamHandler for TestHandler {
        async fn handle_event(&mut self, event: EventMessage) -> io::Result<()> {
            if self.should_fail_on_event {
                return Err(io::Error::other("test failure"));
            }
            self.events.lock().unwrap().push(event);
            Ok(())
        }

        async fn on_error(&mut self, error: &str) -> io::Result<()> {
            self.errors.lock().unwrap().push(error.to_string());
            Ok(())
        }

        async fn on_stream_end(&mut self) -> io::Result<()> {
            *self.stream_ended.lock().unwrap() = true;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_recv_event_message_validates_length() {
        // TODO: Will be implemented in issue #93
        // Test that oversized messages are rejected
        // This would need mock stream implementation
        // The actual test implementation would require creating a mock RecvStream
        // with specific data to test the validation logic
    }

    #[tokio::test]
    async fn test_process_event_stream_handles_eof() {
        // TODO: Will be implemented in issue #93
        // Test normal stream termination
        // This would need mock stream implementation
        // The actual test implementation would require creating a mock RecvStream
        // that simulates EOF conditions
    }

    #[tokio::test]
    async fn test_process_event_stream_handles_handler_errors() {
        // TODO: Will be implemented in issue #93
        // Test that handler errors are properly propagated
        // This would need mock stream implementation
        // The actual test implementation would require creating a mock RecvStream
        // and a handler that returns errors
    }
}
