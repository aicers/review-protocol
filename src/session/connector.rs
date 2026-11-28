use std::{
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use oinq::{Endpoint, TransportOptions};

use super::{
    AgentHandle, AgentIncoming, CloseReason, OutcomeCertainty, SessionError, SessionLifecycle,
    SessionOptions,
};

const MAX_RECEIVE_WINDOW: u64 = (1 << 62) - 1;

macro_rules! agent_transport_options {
    ($($(#[$doc:meta])* $field:ident: $ty:ty),+ $(,)?) => {
        /// QUIC configuration passed through to the session transport.
        ///
        /// Defaults match the legacy agent: 5-second keepalive and maximum
        /// connection receive credit. Other defaults follow the transport.
        /// Timeout milliseconds and receive windows must fit 62 bits.
        /// Incoming stream counts can be at
        /// most 2^60. A keepalive must be positive and shorter than the enabled
        /// idle timeout.
        #[derive(Clone, Copy, Debug)]
        pub struct AgentTransportOptions {
            $($(#[$doc])* pub $field: $ty),+
        }

        impl Default for AgentTransportOptions {
            fn default() -> Self {
                let defaults = TransportOptions {
                    keep_alive_interval: Some(Duration::from_secs(5)),
                    receive_window: MAX_RECEIVE_WINDOW,
                    ..TransportOptions::default()
                };
                Self { $($field: defaults.$field),+ }
            }
        }

        impl AgentTransportOptions {
            pub(super) fn to_transport(self) -> TransportOptions {
                TransportOptions { $($field: self.$field),+ }
            }
        }
    };
}

agent_transport_options! {
    /// Periodic traffic to avoid idle expiry. Defaults to 5 seconds.
    keep_alive_interval: Option<Duration>,
    /// Maximum idle time. `None` or a sub-millisecond duration disables the local limit.
    idle_timeout: Option<Duration>,
    /// Maximum concurrent incoming bidirectional streams.
    max_concurrent_bidi_streams: u64,
    /// Maximum concurrent incoming unidirectional streams.
    max_concurrent_uni_streams: u64,
    /// Receive credit for each stream, in bytes.
    stream_receive_window: u64,
    /// Receive credit for the connection, in bytes. Defaults to 2^62 - 1.
    receive_window: u64,
    /// Maximum buffered unacknowledged outgoing bytes.
    send_window: u64,
}

/// A cloneable agent-side connection control without a dispatch surface.
///
/// It shares drain state with the agent handle, the incoming owner, accepted
/// request streams, event owners, and outgoing exchanges of the same
/// connection. Applications own task cancellation and the deadline at which
/// they abort leftover tasks.
#[derive(Clone, Debug)]
pub struct AgentSessionControl {
    connection: oinq::Connection,
    lifecycle: SessionLifecycle,
}

impl AgentSessionControl {
    pub(super) fn new(connection: oinq::Connection, lifecycle: SessionLifecycle) -> Self {
        Self {
            connection,
            lifecycle,
        }
    }

    /// Returns the cloneable drain state shared by every connection owner.
    #[must_use]
    pub fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle.clone()
    }

    /// Stops incoming acceptance and refuses new outgoing exchanges.
    ///
    /// Already admitted work may complete. Repeated calls are idempotent.
    pub fn drain(&self) {
        self.lifecycle.drain();
    }

    /// Waits until every admitted exchange of this connection completes.
    ///
    /// Drain first and apply the application's own deadline outside this future.
    pub async fn wait_idle(&self) {
        self.lifecycle.wait_idle().await;
    }

    /// Waits for closure. Cancelling the wait leaves the session open.
    pub async fn closed(&self) -> CloseReason {
        CloseReason::from_wire(self.connection.closed().await)
    }

    /// Immediately closes the connection with application code zero.
    ///
    /// This drains first and marks the lifecycle closed, refusing later
    /// admissions. Reason bytes are subject to QUIC packet capacity.
    pub fn close(&self, reason: &[u8]) {
        self.lifecycle.mark_closed();
        self.connection.close(close_code(0), reason);
    }

    /// Immediately aborts the connection with application code one.
    pub fn abort(&self, reason: &[u8]) {
        self.lifecycle.mark_closed();
        self.connection.close(close_code(1), reason);
    }
}

impl AgentHandle {
    /// Returns a cloneable control for draining, closing, or waiting for idleness.
    #[must_use]
    pub fn control(&self) -> AgentSessionControl {
        AgentSessionControl::new(self.0.connection.clone(), self.0.lifecycle.clone())
    }
}

/// An agent endpoint for establishing protocol sessions.
///
/// Established sessions retain endpoint resources after this owner is dropped.
/// TLS policy can be supplied directly or built with [`super::client_config_from_pem`].
pub struct AgentConnector {
    endpoint: Endpoint,
    session: SessionOptions,
}

impl AgentConnector {
    /// Binds an agent endpoint with the supplied TLS and transport policy.
    ///
    /// # Errors
    /// Returns a classified socket, TLS or transport configuration error.
    pub fn bind(
        address: SocketAddr,
        tls: Arc<rustls::ClientConfig>,
        transport: AgentTransportOptions,
        session: SessionOptions,
    ) -> Result<Self, SessionError> {
        let endpoint = Endpoint::client(tls, address, transport.to_transport()).map_err(unsent)?;
        Ok(Self { endpoint, session })
    }

    /// Adopts a prebound UDP socket.
    ///
    /// # Errors
    /// Returns a classified socket, TLS or transport configuration error.
    pub fn from_socket(
        socket: UdpSocket,
        tls: Arc<rustls::ClientConfig>,
        transport: AgentTransportOptions,
        session: SessionOptions,
    ) -> Result<Self, SessionError> {
        let endpoint =
            Endpoint::client_with_socket(tls, socket, transport.to_transport()).map_err(unsent)?;
        Ok(Self { endpoint, session })
    }

    /// Establishes TLS and performs the protocol handshake once.
    ///
    /// The name is passed to TLS for server-name verification. Reconnect and retry
    /// policy belongs to the application.
    ///
    /// # Errors
    /// Returns a classified connection, protocol handshake, or deadline error.
    pub async fn connect(
        &self,
        remote: SocketAddr,
        server_name: &str,
        agent: &crate::AgentInfo,
    ) -> Result<(AgentHandle, AgentIncoming), SessionError> {
        let timeout = self.session.operation_timeout;
        let mut certainty = OutcomeCertainty::NotSent;
        let operation = async {
            let connection = self
                .endpoint
                .connect(remote, server_name)
                .await
                .map_err(|error| SessionError::transport(error, certainty))?;
            AgentHandle::from_transport(connection, self.session.clone(), agent, &mut certainty)
                .await
        };
        if let Some(timeout) = timeout {
            tokio::time::timeout(timeout, operation)
                .await
                .map_err(|source| SessionError::Deadline {
                    certainty,
                    source: Some(source),
                })?
        } else {
            operation.await
        }
    }

    /// Returns the bound socket address.
    ///
    /// # Errors
    /// Returns a classified socket inspection error.
    pub fn local_addr(&self) -> Result<SocketAddr, SessionError> {
        self.endpoint.local_addr().map_err(unsent)
    }

    /// Closes all connections on this endpoint.
    pub fn close(&self, reason: &[u8]) {
        self.endpoint.close(close_code(0), reason);
    }

    /// Aborts all connections on this endpoint.
    pub fn abort(&self, reason: &[u8]) {
        self.endpoint.close(close_code(1), reason);
    }

    /// Waits until transport shutdown has completed for all connections.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }
}

fn unsent(error: impl std::error::Error + Send + Sync + 'static) -> SessionError {
    SessionError::transport(error, OutcomeCertainty::NotSent)
}

fn close_code(code: u64) -> oinq::ApplicationCode {
    oinq::ApplicationCode::new(code).expect("only zero or one is passed as an application code")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_agent_defaults() {
        let options = AgentTransportOptions::default();
        assert_eq!(options.keep_alive_interval, Some(Duration::from_secs(5)));
        assert_eq!(options.idle_timeout, Some(Duration::from_secs(30)));
        assert_eq!(options.max_concurrent_bidi_streams, 100);
        assert_eq!(options.max_concurrent_uni_streams, 100);
        assert_eq!(options.stream_receive_window, 1_250_000);
        assert_eq!(options.receive_window, (1 << 62) - 1);
        assert_eq!(options.send_window, 10_000_000);
    }
}
