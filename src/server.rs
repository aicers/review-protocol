//! Server-specific protocol implementation.
//!
//! # Unidirectional Event Stream Handling
//!
//! The `review-protocol` crate provides high-level APIs for handling
//! unidirectional event streams from agents. This encapsulates all
//! protocol-level details and provides a clean interface for applications.
//!
//! ## Basic Usage
//!
//! Implement the `EventStreamHandler` trait to define how events should be
//! processed:
//!
//! ```rust,ignore
//! use review_protocol::{server::EventStreamHandler, types::EventMessage};
//!
//! struct MyEventHandler {
//!     event_count: usize,
//! }
//!
//! #[async_trait::async_trait]
//! impl EventStreamHandler for MyEventHandler {
//!     async fn handle_event(&mut self, event: EventMessage) -> std::io::Result<()> {
//!         self.event_count += 1;
//!         println!("Received event #{}: {:?}", self.event_count, event.kind);
//!         Ok(())
//!     }
//! }
//! ```
//!
//! Then use the handler to process incoming event streams:
//!
//! ```rust,ignore
//! # use review_protocol::{server::{Connection, EventStreamHandler}, types::EventMessage};
//! # struct MyEventHandler { event_count: usize }
//! # #[async_trait::async_trait]
//! # impl EventStreamHandler for MyEventHandler {
//! #     async fn handle_event(&mut self, event: EventMessage) -> std::io::Result<()> { Ok(()) }
//! # }
//! # async fn example(connection: Connection) -> anyhow::Result<()> {
//! let handler = MyEventHandler { event_count: 0 };
//! connection.accept_event_stream(handler).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Multiple Concurrent Streams
//!
//! Drive `accept_uni` directly and dispatch each stream to
//! [`Connection::handle_event_stream`]. The caller owns the spawn
//! lifetime, concurrency policy, and error handling:
//!
//! ```rust,ignore
//! # use std::sync::Arc;
//! # use review_protocol::{server::{Connection, EventStreamHandler}, types::EventMessage};
//! # struct MyEventHandler;
//! # #[async_trait::async_trait]
//! # impl EventStreamHandler for MyEventHandler {
//! #     async fn handle_event(&mut self, event: EventMessage) -> std::io::Result<()> { Ok(()) }
//! # }
//! # impl MyEventHandler { fn new() -> Self { MyEventHandler } }
//! # async fn example(connection: Connection) -> anyhow::Result<()> {
//! let semaphore = Arc::new(tokio::sync::Semaphore::new(5));
//! while let Ok(recv) = connection.accept_uni().await {
//!     let permit = semaphore.clone().acquire_owned().await?;
//!     let handler = MyEventHandler::new();
//!     tokio::spawn(async move {
//!         let _permit = permit;
//!         if let Err(e) = Connection::handle_event_stream(recv, handler).await {
//!             tracing::warn!(error = %e, "event stream ended with error");
//!         }
//!     });
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Integration with Connection Loop
//!
//! Combine bidirectional and unidirectional stream handling:
//!
//! ```rust,ignore
//! # use review_protocol::{server::{Connection, EventStreamHandler}, types::EventMessage};
//! # struct MyEventHandler;
//! # #[async_trait::async_trait]
//! # impl EventStreamHandler for MyEventHandler {
//! #     async fn handle_event(&mut self, event: EventMessage) -> std::io::Result<()> { Ok(()) }
//! # }
//! # impl MyEventHandler {
//! #     fn new() -> Self { MyEventHandler }
//! # }
//! # async fn example(connection: Connection) -> anyhow::Result<()> {
//! loop {
//!     tokio::select! {
//!         // Handle bidirectional requests
//!         res = connection.open_bi() => {
//!             // Handle request/response
//!         }
//!
//!         // Handle unidirectional event streams
//!         res = connection.accept_event_stream(MyEventHandler::new()) => {
//!             if let Err(e) = res {
//!                 tracing::warn!(error = %e, "event stream ended with error");
//!             }
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Error Handling
//!
//! The `EventStreamHandler` trait provides hooks for custom error handling:
//!
//! ```rust,ignore
//! use review_protocol::{server::EventStreamHandler, types::EventMessage};
//!
//! struct ResilientHandler {
//!     max_errors: usize,
//!     error_count: usize,
//! }
//!
//! #[async_trait::async_trait]
//! impl EventStreamHandler for ResilientHandler {
//!     async fn handle_event(&mut self, event: EventMessage) -> std::io::Result<()> {
//!         // Process event
//!         Ok(())
//!     }
//!
//!     async fn on_error(&mut self, error: &str) -> std::io::Result<()> {
//!         self.error_count += 1;
//!         tracing::warn!(error, count = self.error_count, "stream error");
//!
//!         if self.error_count >= self.max_errors {
//!             Err(std::io::Error::other(format!("Too many errors: {}", self.error_count)))
//!         } else {
//!             Ok(())  // Continue processing
//!         }
//!     }
//!
//!     async fn on_stream_end(&mut self) -> std::io::Result<()> {
//!         println!("Stream ended after {} errors", self.error_count);
//!         Ok(())
//!     }
//! }
//! ```

#[cfg(feature = "server")]
mod api;
#[cfg(feature = "server")]
mod handler;
#[cfg(feature = "server")]
pub mod node;
#[cfg(feature = "server")]
pub mod stream;

#[cfg(feature = "server")]
use std::io;
#[cfg(feature = "server")]
use std::net::SocketAddr;

#[cfg(any(feature = "client", feature = "server"))]
use num_enum::{FromPrimitive, IntoPrimitive};
#[cfg(feature = "server")]
use oinq::{
    frame,
    message::{send_err, send_ok},
};
#[cfg(feature = "server")]
use semver::{Version, VersionReq};

#[cfg(feature = "server")]
pub use self::handler::{Handler, handle, handle_authorized, handle_authorized_with_context};
#[cfg(feature = "server")]
pub use self::stream::process_event_stream;
#[cfg(feature = "server")]
use crate::types::EventMessage;
#[cfg(feature = "server")]
use crate::{
    AgentInfo, HandshakeError, client, decode_agent_info, handle_handshake_recv_io_error,
    handle_handshake_send_io_error, types::LabelDb,
};

/// Trait for handling incoming event messages from unidirectional streams
///
/// This trait provides a standardized interface for processing event messages
/// received from unidirectional streams, abstracting away protocol-level details.
#[cfg(feature = "server")]
#[async_trait::async_trait]
pub trait EventStreamHandler {
    /// Handles a single event message
    ///
    /// Called for each successfully deserialized `EventMessage` received
    /// from the unidirectional stream.
    ///
    /// # Arguments
    /// * `event` - The deserialized `EventMessage`
    ///
    /// # Returns
    /// * `Ok(())` - Continue processing messages
    /// * `Err(msg)` - Stop processing and return error
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The event processing logic fails
    /// * The handler determines the event is invalid or cannot be processed
    /// * Any downstream processing of the event fails
    async fn handle_event(&mut self, event: EventMessage) -> io::Result<()>;

    /// Called when the stream ends normally
    ///
    /// This is called when the peer closes the stream gracefully
    /// (EOF received). Default implementation does nothing.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * Cleanup operations fail
    /// * Final processing steps cannot be completed
    async fn on_stream_end(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Called when an error occurs during stream processing
    ///
    /// This includes deserialization errors, network errors, etc.
    /// The handler can decide whether to treat the error as fatal:
    /// return `Ok(())` to continue processing subsequent messages, or
    /// `Err(_)` to stop the stream and propagate the error to the
    /// caller of [`Connection::handle_event_stream`].
    ///
    /// The default implementation is a no-op; the library does not
    /// log on the application's behalf. Override this method to wire
    /// stream-level errors into your own logging or metrics.
    ///
    /// # Arguments
    /// * `error` - Description of the error that occurred
    async fn on_error(&mut self, _error: &str) -> io::Result<()> {
        Ok(())
    }
}

/// Numeric representation of the message types that a server should handle.
#[cfg(any(feature = "client", feature = "server"))]
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u32)]
pub(crate) enum RequestCode {
    GetDataSource = 0,
    GetIndicator = 1,
    GetMaxEventIdNum = 2,
    GetModel = 3,
    GetModelNames = 4,
    InsertColumnStatistics = 5,
    InsertModel = 6,
    InsertTimeSeries = 7,
    RemoveModel = 8,
    RemoveOutliers = 9,
    UpdateClusters = 10,
    UpdateModel = 11,
    UpdateOutliers = 12,
    InsertEventLabels = 13,
    GetDataSourceList = 14,
    GetLabelDbPatterns = 15,
    InsertDataSource = 20,
    RenewCertificate = 23,
    GetTrustedDomainList = 24,
    GetOutliers = 25,
    GetTorExitNodeList = 26,
    GetInternalNetworkList = 31,
    GetAllowlist = 32,
    GetBlocklist = 33,
    GetPretrainedModel = 34,
    GetTrustedUserAgentList = 35,
    GetConfig = 36,
    UpdateHostOpenedPorts = 37,
    UpdateHostOsAgents = 38,
    GetSamplingPolicyList = 39,
    ReportCustomerDataDeletion = 40,

    /// Unknown request
    #[num_enum(default)]
    Unknown = u32::MAX,
}

#[cfg(all(test, any(feature = "client", feature = "server")))]
mod request_code_tests {
    use num_enum::FromPrimitive;

    use super::RequestCode;

    #[test]
    fn customer_data_deletion_report_uses_code_40() {
        assert_eq!(u32::from(RequestCode::ReportCustomerDataDeletion), 40);
        assert_eq!(
            RequestCode::from_primitive(40),
            RequestCode::ReportCustomerDataDeletion
        );
    }
}

#[cfg(feature = "server")]
/// A connection to a single agent (node).
///
/// Each `Connection` wraps an underlying QUIC connection and
/// provides methods for sending requests to the agent on the other
/// end.  Because a `Connection` is bound to exactly one agent,
/// there is no additional node-selection parameter — calling any
/// method on this type sends the request to that agent.
///
/// The API is organized in three layers:
///
/// - **[`node()`](Self::node) handle** — the recommended entry
///   point for new code.  Returns a [`node::Node`] handle that
///   groups all node-family methods under a single namespace
///   (e.g. `conn.node().power(req)`).
/// - **`node_*` methods** — typed, per-feature-family methods that
///   accept a `Node*Request` enum and return a `Node*Response`.
///   Each request variant carries a
///   [`ServiceId`](crate::service_id::ServiceId) suitable for
///   fine-grained authorization.  These remain available as
///   compatibility wrappers.
/// - **Legacy flat methods** — simpler, backward-compatible
///   wrappers.  They do not expose `ServiceId` and cannot
///   participate in [`Authorizer`](crate::auth::Authorizer)-based
///   access control.
///
/// See the [`impl` block documentation](Self#node-api-vs-legacy-flat-api)
/// for migration guidance and the [`server::node`](node) module
/// for the service-family entry point.
#[derive(Clone, Debug)]
pub struct Connection {
    conn: quinn::Connection,
}

#[cfg(feature = "server")]
impl Connection {
    /// Creates a new connection from a QUIC connection from the `quinn` crate.
    #[must_use]
    pub fn from_quinn(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    /// Returns a [`Node`](node::Node) handle for issuing
    /// node-family requests over this connection.
    ///
    /// The returned handle borrows this connection and exposes
    /// the node API family through a service-family-oriented
    /// interface.  **Prefer this for new code** over calling
    /// the `node_*` methods on `Connection` directly.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use review_protocol::server::Connection;
    /// # async fn example(conn: Connection) -> anyhow::Result<()> {
    /// use review_protocol::types::node::NodePowerRequest;
    ///
    /// let node = conn.node();
    /// let resp = node.power(NodePowerRequest::GracefulReboot).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn node(&self) -> node::Node<'_> {
        node::Node::new(self)
    }

    /// Returns the QUIC connection compatible with the `quinn` crate.
    ///
    /// This is for backward compatibility only and will be removed in a future
    /// release.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    #[doc(hidden)]
    pub fn as_quinn(&self) -> &quinn::Connection {
        &self.conn
    }

    /// Returns the cryptographic identity of the peer.
    ///
    /// This directly corresponds to the `peer_identity` method of the underlying
    /// `quinn::Connection`. In the future, this method may be removed in favor
    /// of this crate's own implementation to provide additional features.
    #[must_use]
    pub fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        self.conn.peer_identity()
    }

    /// Initiates an outgoing bidirectional stream.
    ///
    /// This directly corresponds to the `open_bi` method of the underlying
    /// `quinn::Connection`. In the future, this method may be removed in favor
    /// of this crate's own implementation to provide additional features.
    #[must_use]
    pub fn open_bi(&self) -> quinn::OpenBi<'_> {
        self.conn.open_bi()
    }

    /// Accepts the next incoming unidirectional stream.
    ///
    /// This directly corresponds to the `accept_uni` method of the underlying
    /// `quinn::Connection`. Pair it with [`Connection::handle_event_stream`]
    /// to dispatch each stream with caller-controlled concurrency and error
    /// handling.
    #[must_use]
    pub fn accept_uni(&self) -> quinn::AcceptUni<'_> {
        self.conn.accept_uni()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn close(&self) {
        self.conn.close(0u32.into(), b"");
    }

    /// Accepts and handles the next unidirectional event stream
    ///
    /// This method waits for the next unidirectional stream from the agent
    /// and processes it using the provided event handler. The method returns
    /// when the stream ends or an error occurs.
    ///
    /// # Arguments
    /// * `handler` - Implementation of `EventStreamHandler` trait
    ///
    /// # Returns
    /// * `Ok(())` - Stream processed successfully
    /// * `Err(e)` - Connection error, protocol error, or handler error
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * Failed to accept unidirectional stream (connection error)
    /// * Stream processing failed (protocol error or handler error)
    ///
    /// # Example
    /// ```rust,ignore
    /// # use review_protocol::server::{Connection, EventStreamHandler};
    /// # use review_protocol::types::EventMessage;
    /// # struct MyEventHandler;
    /// # #[async_trait::async_trait]
    /// # impl EventStreamHandler for MyEventHandler {
    /// #     async fn handle_event(&mut self, event: EventMessage) -> std::io::Result<()> {
    /// #         Ok(())
    /// #     }
    /// # }
    /// # async fn example(connection: Connection) -> std::io::Result<()> {
    /// let handler = MyEventHandler;
    /// connection.accept_event_stream(handler).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn accept_event_stream<H>(&self, handler: H) -> io::Result<()>
    where
        H: EventStreamHandler + Send + 'static,
    {
        let recv_stream = self.conn.accept_uni().await?;

        self::stream::process_event_stream(recv_stream, handler).await
    }

    /// Handles a specific unidirectional stream with the given handler
    ///
    /// This is a lower-level method that processes a specific `RecvStream`.
    /// Useful for testing or when you already have a stream to process.
    ///
    /// # Arguments
    /// * `recv_stream` - The unidirectional receive stream
    /// * `handler` - Implementation of `EventStreamHandler` trait
    ///
    /// # Returns
    /// * `Ok(())` - Stream processed successfully
    /// * `Err(e)` - Protocol error or handler error
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * Stream processing failed (protocol error or handler error)
    ///
    /// # Example
    /// ```rust,ignore
    /// # use review_protocol::server::{Connection, EventStreamHandler};
    /// # use review_protocol::types::EventMessage;
    /// # struct MyEventHandler;
    /// # #[async_trait::async_trait]
    /// # impl EventStreamHandler for MyEventHandler {
    /// #     async fn handle_event(&mut self, event: EventMessage) -> std::io::Result<()> {
    /// #         Ok(())
    /// #     }
    /// # }
    /// # async fn example(recv_stream: quinn::RecvStream) -> anyhow::Result<()> {
    /// let handler = MyEventHandler;
    /// Connection::handle_event_stream(recv_stream, handler).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn handle_event_stream<H>(
        recv_stream: quinn::RecvStream,
        handler: H,
    ) -> io::Result<()>
    where
        H: EventStreamHandler + Send + 'static,
    {
        self::stream::process_event_stream(recv_stream, handler).await
    }
}

#[cfg(feature = "server")]
/// Processes a handshake message and sends a response.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
///
/// # Panics
///
/// * panic if it failed to parse version requirement string.
pub async fn handshake(
    conn: &quinn::Connection,
    addr: SocketAddr,
    version_req: &str,
    highest_protocol_version: &str,
) -> Result<AgentInfo, HandshakeError> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(HandshakeError::ConnectionLost)?;
    let mut buf = Vec::new();
    // The frame is read raw because `AgentInfo` carries a conditional tail: the
    // base struct is followed by however many tail fields the peer sent, and
    // decoding those needs the leftover bytes rather than a decoded value. A
    // tail that is present but does not decode is rejected here rather than
    // read as an absent tail.
    frame::recv_raw(&mut recv, &mut buf)
        .await
        .map_err(handle_handshake_recv_io_error)?;
    let mut agent_info = decode_agent_info(&buf).map_err(|_| HandshakeError::InvalidMessage)?;
    agent_info.addr = addr;
    let version_req = VersionReq::parse(version_req).expect("valid version requirement");
    let protocol_version = Version::parse(&agent_info.protocol_version).map_err(|_| {
        HandshakeError::IncompatibleProtocol(
            agent_info.protocol_version.clone(),
            version_req.to_string(),
        )
    })?;
    if version_req.matches(&protocol_version) {
        let highest_protocol_version =
            Version::parse(highest_protocol_version).expect("valid semver");
        if protocol_version <= highest_protocol_version {
            send_ok(&mut send, &mut buf, highest_protocol_version.to_string())
                .await
                .map_err(handle_handshake_send_io_error)?;
            Ok(agent_info)
        } else {
            send_err(&mut send, &mut buf, &highest_protocol_version)
                .await
                .map_err(handle_handshake_send_io_error)?;
            send.finish().ok();
            Err(HandshakeError::IncompatibleProtocol(
                protocol_version.to_string(),
                version_req.to_string(),
            ))
        }
    } else {
        send_err(&mut send, &mut buf, version_req.to_string())
            .await
            .map_err(handle_handshake_send_io_error)?;
        send.finish().ok();
        Err(HandshakeError::IncompatibleProtocol(
            protocol_version.to_string(),
            version_req.to_string(),
        ))
    }
}

#[cfg(feature = "server")]
/// Sends patterns from a label database.
///
/// # Errors
///
/// Returns an error if serialization failed or communication with the client failed.
#[deprecated(since = "0.8.1", note = "`handle` sends the response")]
pub async fn respond_with_labeldb_patterns(
    send: &mut quinn::SendStream,
    patterns: &[(String, Option<LabelDb>)],
) -> anyhow::Result<()> {
    use anyhow::Context;

    let mut buf = Vec::new();
    oinq::frame::send(send, &mut buf, Ok(patterns) as Result<_, &str>)
        .await
        .context("failed to send response")
}

#[cfg(feature = "server")]
/// Sends a list of trusted domains to the client.
///
/// # Errors
///
/// Returns an error if serialization failed or communication with the client failed.
#[deprecated(
    since = "0.8.1",
    note = "Use Connection::send_trusted_domain_list directly"
)]
pub async fn send_trusted_domain_list(
    conn: &quinn::Connection,
    list: &[String],
) -> anyhow::Result<()> {
    Connection::from_quinn(conn.clone())
        .send_trusted_domain_list(list)
        .await
}

#[cfg(feature = "server")]
/// Notifies the client that it should update its configuration.
///
/// # Errors
///
/// Returns an error if serialization failed or communication with the client failed.
pub async fn notify_config_update(conn: &quinn::Connection) -> anyhow::Result<()> {
    use anyhow::anyhow;

    let code: u32 = client::RequestCode::UpdateConfig.into();
    let Ok(msg) =
        bincode::serde::encode_to_vec(code, bincode::config::standard().with_fixed_int_encoding())
    else {
        unreachable!("serialization of u32 into memory buffer should not fail")
    };

    let (mut send, mut recv) = conn.open_bi().await?;
    frame::send_raw(&mut send, &msg).await?;

    let mut response = vec![];
    frame::recv::<Result<(), String>>(&mut recv, &mut response)
        .await?
        .map_err(|e| anyhow!(e))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "server")]
    use std::io;

    #[cfg(feature = "server")]
    use crate::EventStreamHandler;
    #[cfg(feature = "server")]
    use crate::types::EventMessage;

    #[cfg(feature = "server")]
    struct TestEventHandler {
        events: Vec<EventMessage>,
        errors: Vec<String>,
        stream_ended: bool,
    }

    #[cfg(feature = "server")]
    impl TestEventHandler {
        fn new() -> Self {
            Self {
                events: Vec::new(),
                errors: Vec::new(),
                stream_ended: false,
            }
        }
    }

    #[cfg(feature = "server")]
    #[async_trait::async_trait]
    impl EventStreamHandler for TestEventHandler {
        async fn handle_event(&mut self, event: EventMessage) -> io::Result<()> {
            self.events.push(event);
            Ok(())
        }

        async fn on_error(&mut self, error: &str) -> io::Result<()> {
            self.errors.push(error.to_string());
            Ok(())
        }

        async fn on_stream_end(&mut self) -> io::Result<()> {
            self.stream_ended = true;
            Ok(())
        }
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn test_event_stream_handler_interface() {
        use crate::types::EventKind;

        let mut handler = TestEventHandler::new();

        let event = EventMessage {
            time: jiff::Timestamp::now(),
            kind: EventKind::DnsCovertChannel,
            fields: vec![1, 2, 3, 4],
        };

        assert!(handler.handle_event(event.clone()).await.is_ok());
        assert_eq!(handler.events.len(), 1);
        assert_eq!(handler.events[0].kind, EventKind::DnsCovertChannel);
        assert_eq!(handler.events[0].fields, vec![1, 2, 3, 4]);

        assert!(handler.on_error("test error").await.is_ok());
        assert_eq!(handler.errors.len(), 1);
        assert_eq!(handler.errors[0], "test error");

        assert!(handler.on_stream_end().await.is_ok());
        assert!(handler.stream_ended);
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn test_event_handler_error_handling() {
        use crate::types::EventKind;

        struct FailingHandler;

        #[async_trait::async_trait]
        impl EventStreamHandler for FailingHandler {
            async fn handle_event(&mut self, _event: EventMessage) -> io::Result<()> {
                Err(io::Error::other("processing failed"))
            }

            async fn on_error(&mut self, _error: &str) -> io::Result<()> {
                Err(io::Error::other("error handling failed"))
            }

            async fn on_stream_end(&mut self) -> io::Result<()> {
                Err(io::Error::other("stream end failed"))
            }
        }

        let mut handler = FailingHandler;
        let event = EventMessage {
            time: jiff::Timestamp::now(),
            kind: EventKind::HttpThreat,
            fields: vec![],
        };

        assert!(handler.handle_event(event).await.is_err());
        assert!(handler.on_error("test").await.is_err());
        assert!(handler.on_stream_end().await.is_err());
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn test_default_implementations() {
        struct MinimalHandler;

        #[async_trait::async_trait]
        impl EventStreamHandler for MinimalHandler {
            async fn handle_event(&mut self, _event: EventMessage) -> io::Result<()> {
                Ok(())
            }
        }

        let mut handler = MinimalHandler;

        assert!(handler.on_stream_end().await.is_ok());
        assert!(handler.on_error("test error").await.is_ok());
    }

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn trusted_domain_list() {
        use crate::test::TEST_ENV;

        struct Handler {}

        #[async_trait::async_trait]
        impl crate::request::Handler for Handler {
            async fn trusted_domain_list(&mut self, domains: &[&str]) -> Result<(), String> {
                if domains == TRUSTED_DOMAIN_LIST {
                    Ok(())
                } else {
                    Err("unexpected domain list".to_string())
                }
            }
        }

        const TRUSTED_DOMAIN_LIST: &[&str] = &["example.com", "example.org"];

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        // Test `server::send_trusted_domain_list`
        let domains_to_send = TRUSTED_DOMAIN_LIST
            .iter()
            .map(|&domain| domain.to_string())
            .collect::<Vec<_>>();

        let mut handler = Handler {};
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_trusted_domain_list(&domains_to_send).await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn notify_config_update() {
        use crate::test::TEST_ENV;

        struct Handler {}

        #[async_trait::async_trait]
        impl crate::request::Handler for Handler {
            async fn update_config(&mut self) -> Result<(), String> {
                Ok(())
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = Handler {};
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = crate::server::notify_config_update(server_conn.as_quinn()).await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn test_accept_event_stream() {
        use std::sync::{Arc, Mutex};

        struct TestHandler {
            events: Arc<Mutex<Vec<EventMessage>>>,
        }

        #[async_trait::async_trait]
        impl EventStreamHandler for TestHandler {
            async fn handle_event(&mut self, event: EventMessage) -> io::Result<()> {
                self.events.lock().unwrap().push(event);
                Ok(())
            }
        }

        let test_env = crate::test::TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let handler = TestHandler {
            events: events_clone,
        };

        // Clone server connection for teardown
        let server_conn_for_teardown = server_conn.clone();

        // Client opens unidirectional stream and sends events
        let client_handle = tokio::spawn(async move {
            let mut send = client_conn.open_uni().await.unwrap();

            // Write protocol header
            send.write_all(&[0, 0]).await.unwrap();

            // Send test event
            let event = EventMessage {
                time: jiff::Timestamp::now(),
                kind: crate::types::EventKind::DnsCovertChannel,
                fields: vec![1, 2, 3, 4],
            };

            let codec = bincode::config::standard();
            let serialized = bincode::serde::encode_to_vec(&event, codec).unwrap();
            #[allow(clippy::cast_possible_truncation)]
            let len = serialized.len() as u32;

            send.write_all(&len.to_be_bytes()).await.unwrap();
            send.write_all(&serialized).await.unwrap();

            // Close stream properly to signal EOF
            send.finish().unwrap();

            // Give server time to accept the stream
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        // Wait for client to send data
        client_handle.await.unwrap();

        // Now accept and process the stream
        let server_res = server_conn.accept_event_stream(handler).await;

        assert!(server_res.is_ok());

        let received_events = events.lock().unwrap();
        assert_eq!(received_events.len(), 1);
        assert_eq!(
            received_events[0].kind,
            crate::types::EventKind::DnsCovertChannel
        );
        assert_eq!(received_events[0].fields, vec![1, 2, 3, 4]);

        test_env.teardown(&server_conn_for_teardown);
    }

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn test_handle_event_stream() {
        use std::sync::{Arc, Mutex};

        struct TestHandler {
            events: Arc<Mutex<Vec<EventMessage>>>,
        }

        #[async_trait::async_trait]
        impl EventStreamHandler for TestHandler {
            async fn handle_event(&mut self, event: EventMessage) -> io::Result<()> {
                self.events.lock().unwrap().push(event);
                Ok(())
            }
        }

        let test_env = crate::test::TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let handler = TestHandler {
            events: events_clone,
        };

        // Client opens unidirectional stream and sends events
        let client_handle = tokio::spawn(async move {
            let mut send = client_conn.open_uni().await.unwrap();

            // Write protocol header
            send.write_all(&[0, 0]).await.unwrap();

            // Send test event
            let event = EventMessage {
                time: jiff::Timestamp::now(),
                kind: crate::types::EventKind::HttpThreat,
                fields: vec![5, 6, 7],
            };

            let codec = bincode::config::standard();
            let serialized = bincode::serde::encode_to_vec(&event, codec).unwrap();
            #[allow(clippy::cast_possible_truncation)]
            let len = serialized.len() as u32;

            send.write_all(&len.to_be_bytes()).await.unwrap();
            send.write_all(&serialized).await.unwrap();

            // Close stream properly to signal EOF
            send.finish().unwrap();

            // Give server time to accept the stream
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        // Wait for client to send data
        client_handle.await.unwrap();

        // Now accept uni stream and handle it
        let server_conn_clone = server_conn.clone();
        let recv_stream = server_conn_clone.conn.accept_uni().await.unwrap();
        let server_res = crate::server::Connection::handle_event_stream(recv_stream, handler).await;

        assert!(server_res.is_ok());

        let received_events = events.lock().unwrap();
        assert_eq!(received_events.len(), 1);
        assert_eq!(received_events[0].kind, crate::types::EventKind::HttpThreat);
        assert_eq!(received_events[0].fields, vec![5, 6, 7]);

        test_env.teardown(&server_conn);
    }

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn test_accept_multiple_streams() {
        use std::sync::{Arc, Mutex};

        struct TestHandler {
            events: Arc<Mutex<Vec<EventMessage>>>,
        }

        #[async_trait::async_trait]
        impl EventStreamHandler for TestHandler {
            async fn handle_event(&mut self, event: EventMessage) -> io::Result<()> {
                self.events.lock().unwrap().push(event);
                Ok(())
            }
        }

        let test_env = crate::test::TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let events = Arc::new(Mutex::new(Vec::new()));
        let events_for_loop = events.clone();

        // Spawn the recommended accept loop: accept_uni + handle_event_stream
        // in a per-stream tokio::spawn, with the caller owning lifetime and
        // error handling.
        let server_conn_clone = server_conn.clone();
        let server_handle = tokio::spawn(async move {
            while let Ok(recv) = server_conn_clone.accept_uni().await {
                let handler = TestHandler {
                    events: events_for_loop.clone(),
                };
                tokio::spawn(async move {
                    let _ = crate::server::Connection::handle_event_stream(recv, handler).await;
                });
            }
        });

        // Client opens multiple unidirectional streams
        let client_handle = tokio::spawn(async move {
            for i in 0..3 {
                let mut send = client_conn.open_uni().await.unwrap();

                // Write protocol header
                send.write_all(&[0, 0]).await.unwrap();

                // Send test event
                let event = EventMessage {
                    time: jiff::Timestamp::now(),
                    kind: crate::types::EventKind::DnsCovertChannel,
                    fields: vec![u8::try_from(i).unwrap()],
                };

                let codec = bincode::config::standard();
                let serialized = bincode::serde::encode_to_vec(&event, codec).unwrap();
                #[allow(clippy::cast_possible_truncation)]
                let len = serialized.len() as u32;

                send.write_all(&len.to_be_bytes()).await.unwrap();
                send.write_all(&serialized).await.unwrap();

                // Close stream
                send.finish().ok();

                // Small delay to ensure streams are processed
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }

            // Wait a bit for processing
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        // Wait for client to finish sending
        client_handle.await.unwrap();

        // Give server time to process all streams
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Cancel the server task (it's in an infinite loop)
        server_handle.abort();

        let received_events = events.lock().unwrap();
        assert_eq!(received_events.len(), 3);

        test_env.teardown(&server_conn);
    }

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn test_concurrency_limiting() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        use tokio::sync::{Mutex, Semaphore};

        struct SlowHandler {
            concurrent_count: Arc<AtomicUsize>,
            max_concurrent: Arc<Mutex<usize>>,
        }

        #[async_trait::async_trait]
        impl EventStreamHandler for SlowHandler {
            async fn handle_event(&mut self, _event: EventMessage) -> io::Result<()> {
                let current = self.concurrent_count.fetch_add(1, Ordering::SeqCst) + 1;

                // Update max concurrent count
                let mut max = self.max_concurrent.lock().await;
                if current > *max {
                    *max = current;
                }
                drop(max); // Explicitly drop before await

                // Simulate slow processing
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                self.concurrent_count.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let test_env = crate::test::TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let concurrent_count = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(Mutex::new(0));

        let concurrent_count_for_loop = concurrent_count.clone();
        let max_concurrent_for_loop = max_concurrent.clone();

        // Limit to 2 concurrent streams via a caller-owned Semaphore.
        let max_limit = 2;
        let semaphore = Arc::new(Semaphore::new(max_limit));

        let server_conn_clone = server_conn.clone();
        let server_handle = tokio::spawn(async move {
            while let Ok(recv) = server_conn_clone.accept_uni().await {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let handler = SlowHandler {
                    concurrent_count: concurrent_count_for_loop.clone(),
                    max_concurrent: max_concurrent_for_loop.clone(),
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = crate::server::Connection::handle_event_stream(recv, handler).await;
                });
            }
        });

        // Client opens multiple unidirectional streams rapidly
        let client_handle = tokio::spawn(async move {
            for i in 0..5 {
                let mut send = client_conn.open_uni().await.unwrap();

                // Write protocol header
                send.write_all(&[0, 0]).await.unwrap();

                // Send test event
                let event = EventMessage {
                    time: jiff::Timestamp::now(),
                    kind: crate::types::EventKind::DnsCovertChannel,
                    fields: vec![u8::try_from(i).unwrap()],
                };

                let codec = bincode::config::standard();
                let serialized = bincode::serde::encode_to_vec(&event, codec).unwrap();
                #[allow(clippy::cast_possible_truncation)]
                let len = serialized.len() as u32;

                send.write_all(&len.to_be_bytes()).await.unwrap();
                send.write_all(&serialized).await.unwrap();

                // Close stream
                send.finish().ok();
            }

            // Wait for processing to complete
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        });

        // Wait for client to finish
        client_handle.await.unwrap();

        // Give server time to finish processing
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Cancel the server task
        server_handle.abort();

        // Verify concurrency was limited
        let max = *max_concurrent.lock().await;
        assert!(
            max <= max_limit,
            "Expected max concurrent <= {max_limit}, got {max}"
        );

        test_env.teardown(&server_conn);
    }
}
