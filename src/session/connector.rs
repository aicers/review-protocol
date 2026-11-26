use std::{
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use oinq::{Endpoint, TransportOptions};

use super::{AgentHandle, AgentIncoming, OutcomeCertainty, SessionError, SessionOptions};

macro_rules! agent_transport_options {
    ($($(#[$doc:meta])* $field:ident: $ty:ty),+ $(,)?) => {
        /// QUIC configuration passed through to the session transport.
        ///
        /// Defaults are inherited from the transport. Timeout milliseconds and
        /// receive windows must fit 62 bits. Incoming stream counts can be at
        /// most 2^60. A keepalive must be positive and shorter than the enabled
        /// idle timeout.
        #[derive(Clone, Copy, Debug)]
        pub struct AgentTransportOptions {
            $($(#[$doc])* pub $field: $ty),+
        }

        impl Default for AgentTransportOptions {
            fn default() -> Self {
                let defaults = TransportOptions::default();
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
    /// Periodic traffic to avoid idle expiry. Disabled by default.
    keep_alive_interval: Option<Duration>,
    /// Maximum idle time. `None` or a sub-millisecond duration disables the local limit.
    idle_timeout: Option<Duration>,
    /// Maximum concurrent incoming bidirectional streams.
    max_concurrent_bidi_streams: u64,
    /// Maximum concurrent incoming unidirectional streams.
    max_concurrent_uni_streams: u64,
    /// Receive credit for each stream, in bytes.
    stream_receive_window: u64,
    /// Receive credit for the connection, in bytes.
    receive_window: u64,
    /// Maximum buffered unacknowledged outgoing bytes.
    send_window: u64,
}

/// An agent endpoint for establishing protocol sessions.
///
/// Established sessions retain endpoint resources after this owner is dropped.
/// TLS verification, provider and server-name policy remain caller supplied.
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
    /// Returns a classified connection or protocol handshake error.
    pub async fn connect(
        &self,
        remote: SocketAddr,
        server_name: &str,
        agent: &crate::AgentInfo,
    ) -> Result<(AgentHandle, AgentIncoming), SessionError> {
        let connection = self
            .endpoint
            .connect(remote, server_name)
            .await
            .map_err(unsent)?;
        AgentHandle::from_transport(connection, self.session.clone(), agent).await
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
