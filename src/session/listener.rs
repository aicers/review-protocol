use std::{
    net::{SocketAddr, UdpSocket},
    sync::{Arc, OnceLock},
    time::Duration,
};

use oinq::{ApplicationCode, CloseInfo, Connection, Endpoint, Incoming, TransportOptions};
use semver::{Version, VersionReq};
use tokio::{sync::watch, time::Instant};

use super::{
    HandshakeMetadata, OutcomeCertainty, PeerCertificates, ServerHandle, ServerIncoming,
    SessionError, SessionOptions, Shared, handshake::server_shared,
};
use crate::{
    AgentInfo,
    auth::{AuthorizationContext, AuthorizerV2},
};

/// The version advertised in a successful handshake and the accepted peer range.
///
/// A peer's version must satisfy the requirement and be at or below the
/// advertised version. The caller selects both values.
#[derive(Clone, Debug)]
pub struct ProtocolWindow {
    requirement: VersionReq,
    ceiling: Version,
    advertised: String,
}

impl ProtocolWindow {
    /// Validates the requirement and advertised version before accepting peers.
    ///
    /// For example, `ProtocolWindow::new(">=0.48.0", "0.49.0")` accepts agents
    /// that satisfy `>=0.48.0` and are at most `0.49.0`, and sends `0.49.0` in
    /// the handshake success reply.
    ///
    /// # Errors
    /// Returns [`SessionError::Malformed`] for invalid semver input.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "server")]
    /// # fn example() -> Result<(), review_protocol::session::SessionError> {
    /// use review_protocol::session::ProtocolWindow;
    ///
    /// let window = ProtocolWindow::new(">=0.48.0", "0.49.0")?;
    /// assert_eq!(window.advertised_version(), "0.49.0");
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(requirement: &str, advertised: &str) -> Result<Self, SessionError> {
        Ok(Self {
            requirement: VersionReq::parse(requirement).map_err(SessionError::malformed)?,
            ceiling: Version::parse(advertised).map_err(SessionError::malformed)?,
            advertised: advertised.to_owned(),
        })
    }

    /// The exact version string carried in the success reply.
    #[must_use]
    pub fn advertised_version(&self) -> &str {
        &self.advertised
    }

    /// The full version range carried in a rejection reply.
    #[must_use]
    pub fn accepted_range(&self) -> String {
        format!("{}, <={}", self.requirement, self.ceiling)
    }

    pub(super) fn accepts(&self, version: &str) -> bool {
        Version::parse(version).is_ok_and(|v| self.requirement.matches(&v) && v <= self.ceiling)
    }
}

macro_rules! server_transport_options {
    ($($(#[$doc:meta])* $field:ident: $ty:ty),+ $(,)?) => {
        /// QUIC configuration passed through to the session transport.
        ///
        /// Defaults are inherited from the transport. Timeout milliseconds and
        /// receive windows must fit 62 bits. Incoming stream counts can be at
        /// most 2^60. A keepalive must be positive and shorter than the enabled
        /// idle timeout.
        #[derive(Clone, Debug)]
        pub struct ServerTransportOptions {
            $($(#[$doc])* pub $field: $ty),+
        }

        impl Default for ServerTransportOptions {
            fn default() -> Self {
                let defaults = TransportOptions::default();
                Self { $($field: defaults.$field),+ }
            }
        }

        impl ServerTransportOptions {
            fn to_transport(&self) -> TransportOptions {
                TransportOptions { $($field: self.$field),+ }
            }
        }
    };
}

server_transport_options! {
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

/// Application-selected transport, frame budgets, and handshake policy.
#[derive(Clone, Debug)]
pub struct ServerListenerOptions {
    /// Transport options used by all connections accepted on this listener.
    pub transport: ServerTransportOptions,
    /// Frame budgets and the timeout for ordinary outbound operations.
    pub session: SessionOptions,
    /// Advertised protocol version and peer acceptance range.
    pub protocol: ProtocolWindow,
    /// Deadline spanning TLS and protocol handshaking, measured from listener acceptance.
    pub handshake_timeout: Duration,
}

/// A server listener that owns a UDP endpoint.
///
/// Run binding and socket adoption in a Tokio runtime with I/O and time
/// enabled. Applications acquire their own pending-work permits and supervise
/// each accepted handshake independently. The listener spawns no application
/// tasks. Accepted sessions retain the transport resources after listener drop.
///
/// # Examples
///
/// ```no_run
/// # #[cfg(feature = "server")]
/// # async fn example(
/// #     tls: std::sync::Arc<rustls::ServerConfig>,
/// #     context: review_protocol::auth::AuthorizationContext,
/// #     policy: std::sync::Arc<dyn review_protocol::auth::AuthorizerV2>,
/// # ) -> Result<(), review_protocol::session::SessionError> {
/// use std::{net::SocketAddr, sync::Arc, time::Duration};
///
/// use review_protocol::session::{
///     ProtocolWindow, ServerListener, ServerListenerOptions, ServerTransportOptions,
///     SessionOptions,
/// };
///
/// let options = ServerListenerOptions {
///     transport: ServerTransportOptions::default(),
///     session: SessionOptions::legacy_compatible(),
///     protocol: ProtocolWindow::new(">=0.48.0", "0.49.0")?,
///     handshake_timeout: Duration::from_secs(5),
/// };
/// let listener = ServerListener::bind("[::1]:0".parse::<SocketAddr>().unwrap(), tls, options)?;
/// let _addr = listener.local_addr()?;
///
/// // Acquire an application-owned permit before accept, then supervise each
/// // pending handshake independently.
/// if let Some(pending) = listener.accept().await? {
///     let unadmitted = pending.handshake().await?;
///     let (_handle, _incoming) = unadmitted.admit(context, policy);
/// }
///
/// listener.shutdown();
/// listener.wait_idle().await;
/// # Ok(())
/// # }
/// ```
pub struct ServerListener {
    endpoint: Endpoint,
    options: Arc<ServerListenerOptions>,
    stopped: watch::Sender<bool>,
    closed: ListenerClose,
}

/// The code and reason of the first listener-wide close, once one has run.
///
/// The endpoint delivers its close to each connection asynchronously, while a
/// connection's own close applies at once, and the first close to apply is the
/// one the peer observes. That includes the implicit close, with code zero and
/// no reason, that the transport applies when the last handle to a connection
/// drops. Owners of connections taken from this listener close with the
/// recorded code and reason instead of their own, and repeat it when they
/// drop, so neither a later owner close nor dropping the session or a stream
/// accepted on it can replace the listener's.
pub(super) type ListenerClose = Arc<OnceLock<(ApplicationCode, Box<[u8]>)>>;

/// Closes `connection` with the listener's close, if one has run.
pub(super) fn repeat_listener_close(connection: &Connection, listener: &ListenerClose) {
    if let Some((code, reason)) = listener.get() {
        connection.close(*code, reason);
    }
}

/// Closes `connection` with the listener's close if one has run, else with `code`.
fn close_connection(
    connection: &Connection,
    listener: Option<&ListenerClose>,
    code: ApplicationCode,
    reason: &[u8],
) {
    match listener.and_then(|closed| closed.get()) {
        Some((code, reason)) => connection.close(*code, reason),
        None => connection.close(code, reason),
    }
}

impl ServerListener {
    /// Binds the listener to the address, using the supplied TLS policy unchanged.
    ///
    /// # Errors
    /// Returns a typed error for socket, TLS, or transport configuration failures.
    pub fn bind(
        address: SocketAddr,
        tls: Arc<rustls::ServerConfig>,
        options: ServerListenerOptions,
    ) -> Result<Self, SessionError> {
        let endpoint =
            Endpoint::server(tls, address, options.transport.to_transport()).map_err(unsent)?;
        Ok(Self::new(endpoint, options))
    }

    /// Adopts an already-bound UDP socket and takes ownership of it.
    ///
    /// # Errors
    /// Returns a typed error for socket, TLS, or transport configuration failures.
    pub fn from_socket(
        socket: UdpSocket,
        tls: Arc<rustls::ServerConfig>,
        options: ServerListenerOptions,
    ) -> Result<Self, SessionError> {
        let endpoint = Endpoint::server_with_socket(tls, socket, options.transport.to_transport())
            .map_err(unsent)?;
        Ok(Self::new(endpoint, options))
    }

    fn new(endpoint: Endpoint, options: ServerListenerOptions) -> Self {
        Self {
            endpoint,
            options: Arc::new(options),
            stopped: watch::Sender::new(false),
            closed: ListenerClose::default(),
        }
    }

    /// Returns the actual address of the socket, including a dynamically bound port.
    ///
    /// # Errors
    /// Returns a typed transport error if the socket cannot be inspected.
    pub fn local_addr(&self) -> Result<SocketAddr, SessionError> {
        self.endpoint.local_addr().map_err(unsent)
    }

    /// Accepts an independently owned attempt before TLS or protocol handshaking.
    ///
    /// Cancellation consumes no attempt. Returns `None` once shut down.
    /// An accept that wins a race with shutdown can still return its attempt.
    /// TLS and protocol errors are reported by the pending owner.
    ///
    /// # Errors
    /// Returns a typed transport error if the endpoint stops unexpectedly.
    pub async fn accept(&self) -> Result<Option<PendingSession>, SessionError> {
        let mut stopped = self.stopped.subscribe();
        tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => Ok(None),
            incoming = self.endpoint.accept() => match incoming {
                Some(incoming) => Ok(Some(PendingSession {
                    incoming,
                    accepted: Instant::now(),
                    options: self.options.clone(),
                    listener: self.closed.clone(),
                })),
                None if *self.stopped.borrow() => Ok(None),
                None => Err(unsent(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "server endpoint stopped accepting connections",
                ))),
            },
        }
    }

    /// Replaces TLS configuration for future connections on the same socket.
    ///
    /// Pending attempts that have already started TLS and established sessions
    /// retain their configuration. Provider, verification and client-certificate
    /// policy come from the supplied config. Transport options are preserved.
    ///
    /// # Errors
    /// An invalid config returns a typed error and leaves the previous config installed.
    pub fn reload_tls(&self, tls: Arc<rustls::ServerConfig>) -> Result<(), SessionError> {
        self.endpoint.set_server_config(tls).map_err(unsent)
    }

    /// Stops acceptance and wakes pending accept calls. Accepted sessions can drain.
    ///
    /// The socket continues serving previously accepted sessions and no new
    /// handshakes are taken from the transport. Dropping the listener likewise
    /// ends acceptance while existing owners retain their connections.
    pub fn shutdown(&self) {
        self.stopped.send_replace(true);
    }

    /// Stops acceptance and immediately closes the endpoint and its connections
    /// with application code zero and the given reason.
    ///
    /// This is the listener-wide counterpart of [`ServerSessionControl::close`]:
    /// use it for normal shutdown when sessions need not drain first, and
    /// [`Self::abort`] (code one) for refusal. Established sessions, admitted or
    /// not, and pending sessions whose TLS has completed observe code zero and
    /// the reason; their pending `handshake` returns a transport error. An
    /// attempt still in TLS, or returned by [`Self::accept`] and not yet
    /// handshaken, cannot carry an application code, and its `handshake` fails
    /// no later than the handshake deadline. Nothing drains: accepted stream
    /// runners observe transport errors, and the application joins its own
    /// tasks. Each session's [`ServerSessionControl::closed`] reports
    /// [`ServerSessionClose::Local`], and [`Self::wait_idle`] returns once
    /// transport shutdown completes. Neither a later `close` or `abort`, nor
    /// closing a session through [`ServerSessionControl`] or dropping it or
    /// its accepted streams afterwards, changes the code and reason its peer
    /// observes;
    /// `ServerHandle::close`, which takes an explicit code, still applies its
    /// own.
    pub fn close(&self, reason: &[u8]) {
        self.close_endpoint(ApplicationCode::default(), reason);
    }

    /// Stops acceptance and immediately closes the endpoint and its connections
    /// with application code one and the given reason.
    ///
    /// Use it to refuse or abort; [`Self::close`] is the code-zero counterpart
    /// for normal shutdown, and the same delivery rules apply. Once either has
    /// run, a further `close` or `abort` only stops acceptance, so the code a
    /// peer observes stays the first one. The application still owns and joins
    /// or cancels its tasks.
    pub fn abort(&self, reason: &[u8]) {
        self.close_endpoint(abort_code(), reason);
    }

    /// Stops acceptance and closes the endpoint, unless a close already ran.
    fn close_endpoint(&self, code: ApplicationCode, reason: &[u8]) {
        self.shutdown();
        // Record the close before the endpoint delivers it, so an owner that
        // closes its connection afterwards repeats this code and reason.
        if self.closed.set((code, reason.into())).is_ok() {
            self.endpoint.close(code, reason);
        }
    }

    /// Waits for endpoint connections to finish transport shutdown.
    ///
    /// Stop acceptance and finish or close the sessions first. Cancelling this
    /// wait leaves connections and application tasks alone.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }
}

/// A transport attempt returned by the listener, ready for application supervision.
///
/// Dropping the attempt abandons establishment. No background task drives the
/// protocol handshake on the application's behalf.
#[must_use = "pending sessions must be handshaken to reach admission"]
pub struct PendingSession {
    incoming: Incoming,
    accepted: Instant,
    options: Arc<ServerListenerOptions>,
    listener: ListenerClose,
}

impl PendingSession {
    /// Returns the peer's transport address as observed when the attempt arrived.
    ///
    /// It is readable before [`Self::handshake`] consumes the owner, so a TLS
    /// or protocol-handshake failure can be logged with the peer's address.
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.incoming.remote_addr()
    }

    /// Awaits TLS and performs the bounded protocol handshake.
    ///
    /// The deadline includes time spent holding the pending owner and waiting
    /// for the peer's transport to acknowledge the reply or stop reading it.
    /// Cancelling the future abandons the attempt and closes any established
    /// connection.
    ///
    /// # Errors
    /// Returns typed TLS/transport, framing, limit, version or deadline errors.
    pub async fn handshake(self) -> Result<UnadmittedSession, SessionError> {
        let Some(remaining) = self
            .options
            .handshake_timeout
            .checked_sub(self.accepted.elapsed())
            .filter(|duration| !duration.is_zero())
        else {
            return Err(SessionError::Deadline {
                certainty: OutcomeCertainty::NotSent,
                source: None,
            });
        };

        tokio::time::timeout(remaining, async {
            let connection = self.incoming.await.map_err(unsent)?;
            let mut guard = AbortPending(Some(connection.clone()), self.listener.clone());
            let (claims, mut exchange) = ServerHandle::from_transport(
                &connection,
                &self.options.session,
                &self.options.protocol,
            )
            .await?;
            // A refusal can immediately close the connection. Let the reply
            // reach the peer's transport before exposing that control.
            exchange.finish_and_wait().await?;
            let control =
                ServerSessionControl::new(connection.clone()).with_listener(self.listener.clone());
            let shared = server_shared(
                connection,
                self.options.session.clone(),
                claims,
                Some(self.listener.clone()),
            );
            guard.0 = None;
            Ok(UnadmittedSession {
                shared,
                control,
                admitted: false,
            })
        })
        .await
        .map_err(|source| SessionError::Deadline {
            certainty: OutcomeCertainty::Unknown,
            source: Some(source),
        })?
    }
}

struct AbortPending(Option<Connection>, ListenerClose);

impl Drop for AbortPending {
    fn drop(&mut self) {
        if let Some(connection) = &self.0 {
            close_connection(
                connection,
                Some(&self.1),
                abort_code(),
                b"handshake did not complete",
            );
        }
    }
}

/// A successful protocol handshake awaiting the application's admission decision.
///
/// The protocol success reply has already been sent. Only admission yields the
/// owners for application requests, events, and outbound commands. Dropping
/// this owner closes the connection even if a control clone survives.
#[must_use = "dropping an unadmitted session closes its connection"]
pub struct UnadmittedSession {
    shared: Arc<Shared>,
    control: ServerSessionControl,
    admitted: bool,
}

impl UnadmittedSession {
    /// Returns the verified TLS peer chain, if the caller's TLS policy supplied one.
    ///
    /// The application interprets certificate identities, including SANs.
    #[must_use]
    pub fn peer_certificates(&self) -> Option<&PeerCertificates> {
        self.shared.certificates.as_ref()
    }

    /// Returns the agent's protocol handshake claims.
    ///
    /// The address is the observed transport peer address. The remaining
    /// values are self-reported and grant no permissions.
    #[must_use]
    pub fn agent_claims(&self) -> &AgentInfo {
        let HandshakeMetadata::Agent(claims) = &self.shared.metadata else {
            unreachable!("a server handshake always creates agent metadata");
        };
        claims
    }

    /// Returns a cloneable handle for monitoring, refusal, or shutdown.
    #[must_use]
    pub fn control(&self) -> ServerSessionControl {
        self.control.clone()
    }

    /// Admits the connection and binds the supplied policy to incoming requests.
    ///
    /// Admission is a local ownership transfer and sends no frame. A concurrent
    /// peer or control close can leave the returned handles already closed.
    #[must_use]
    pub fn admit(
        mut self,
        context: AuthorizationContext,
        policy: Arc<dyn AuthorizerV2>,
    ) -> (ServerHandle, ServerIncoming) {
        let incoming = ServerIncoming::with_control(self.shared.clone(), self.control.clone())
            .with_authorization(context, policy);
        self.admitted = true;
        (ServerHandle(self.shared.clone()), incoming)
    }
}

impl Drop for UnadmittedSession {
    fn drop(&mut self) {
        if !self.admitted {
            self.control.abort(b"session dropped before admission");
        }
    }
}

/// The result of waiting for a server session to close.
#[derive(Debug)]
pub enum ServerSessionClose {
    /// The local application closed the session or listener.
    Local,
    /// The peer closed the session with an application code and reason bytes.
    Peer {
        /// The peer's application close code.
        code: u64,
        /// The reason supplied by the peer.
        reason: Vec<u8>,
    },
    /// Transport-level closure, such as an idle timeout.
    Transport(SessionError),
}

/// A cloneable connection control handle without a dispatch or command surface.
///
/// All clones refer to the same connection and retain its transport resources.
/// Dropping a clone leaves other owners alone. Applications own their stream
/// runners and decide how long to allow them to finish after starting a drain.
#[derive(Clone, Debug)]
pub struct ServerSessionControl {
    connection: Connection,
    draining: watch::Sender<bool>,
    listener: Option<ListenerClose>,
}

impl ServerSessionControl {
    pub(super) fn new(connection: Connection) -> Self {
        Self {
            connection,
            draining: watch::Sender::new(false),
            listener: None,
        }
    }

    fn with_listener(mut self, listener: ListenerClose) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Waits for closure. Cancelling the wait leaves the session open.
    pub async fn closed(&self) -> ServerSessionClose {
        match self.connection.closed().await {
            CloseInfo::Local => ServerSessionClose::Local,
            CloseInfo::Application { code, reason } => ServerSessionClose::Peer {
                code: code.get(),
                reason,
            },
            CloseInfo::Transport(error) => {
                ServerSessionClose::Transport(unsent(error).on_connection(&self.connection))
            }
            other => ServerSessionClose::Transport(unsent(std::io::Error::other(format!(
                "connection closed: {other:?}"
            )))),
        }
    }

    /// Stops incoming stream acceptance and wakes a blocked accept.
    ///
    /// Accepted streams keep running, and outbound operations remain available.
    /// Draining an unadmitted session also stops acceptance if it is later admitted.
    /// After joining the supervised work, call [`Self::close`] to end the connection.
    pub fn drain(&self) {
        self.draining.send_replace(true);
    }

    /// Immediately closes the connection with application code zero and the given reason.
    ///
    /// Use after draining to signal orderly shutdown. Either close method can
    /// also refuse admission, with reason bytes subject to QUIC packet capacity.
    /// After [`ServerListener::close`] or [`ServerListener::abort`] has run on
    /// the listener that accepted this session, either method repeats the
    /// listener's code and reason instead, so the peer observes the listener's.
    pub fn close(&self, reason: &[u8]) {
        self.drain();
        close_connection(
            &self.connection,
            self.listener.as_ref(),
            ApplicationCode::default(),
            reason,
        );
    }

    /// Immediately refuses or aborts the connection with application code one.
    ///
    /// After a listener-wide close, it repeats the listener's code and reason,
    /// as [`Self::close`] does.
    pub fn abort(&self, reason: &[u8]) {
        self.drain();
        close_connection(
            &self.connection,
            self.listener.as_ref(),
            abort_code(),
            reason,
        );
    }

    pub(super) async fn drained(&self) {
        let _ = self
            .draining
            .subscribe()
            .wait_for(|draining| *draining)
            .await;
    }
}

impl Drop for ServerSessionControl {
    fn drop(&mut self) {
        if let Some(listener) = &self.listener {
            repeat_listener_close(&self.connection, listener);
        }
    }
}

pub(super) fn unsent(error: impl std::error::Error + Send + Sync + 'static) -> SessionError {
    SessionError::transport(error, OutcomeCertainty::NotSent)
}

fn abort_code() -> ApplicationCode {
    ApplicationCode::new(1).expect("the reserved abort code fits 62 bits")
}
