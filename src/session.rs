//! Additive transport-backed sessions with explicit frame budgets.
//!
//! The additive `session` module is enabled by `client` and/or `server`. Schema-only
//! builds do not enable oinq, Quinn, Tokio, bincode, or rustls. Existing builders,
//! connection wrappers, raw stream access, dispatch functions, typed operations,
//! error signatures, and public framing helpers remain supported. Their Quinn
//! compatibility framing is isolated in `legacy_transport`; it retains historical
//! wire behavior and allocation behavior. Bounded sessions are opt-in.
//!
//! ## Roles and ownership
//!
//! `ServerHandle` is the manager's cloneable handle for calling an agent. Its node
//! methods preserve typed responses, including immediate power `Sent` outcomes and
//! terminal package preflight outcomes. `AgentHandle` is the agent's cloneable handle
//! for calling the manager, including configuration and model transfers. Handles
//! expose domain operations, identity, handshake metadata, certificates, and closure.
//! They do not expose protocol streams.
//!
//! Construct an oinq `Endpoint` with the application's rustls configuration and
//! `TransportOptions`, establish a `Connection`, and pass it to the appropriate
//! `from_transport` constructor. The caller supplies the agent's complete
//! `AgentInfo`, or the manager's version requirement and ceiling. Constructors return
//! one handle and one non-cloneable incoming owner. Complete listener/connector
//! policy, acceptance loops, reconnects, and application draining are outside this
//! foundation's scope. Endpoint, owned awaitable `Incoming`, connection, options,
//! checked `ApplicationCode`, and structured transport errors are re-exported from
//! `session` for callers that do not otherwise depend on oinq.
//!
//! With `server`, `ServerIncoming::accept` returns a `ServerStream` containing
//! either a request stream or an event receiver. With `client`, `AgentIncoming::accept`
//! returns an agent command stream. Acceptance reads no frame or event header;
//! applications can supervise each stream independently, so one slow stream does
//! not block acceptance of another. The server waits for both stream directions in
//! one cancel-safe accept call.
//!
//! Request streams provide `next`, returning a typed invocation or `None` at clean
//! EOF. Each invocation borrows its stream through a single-use `Reply` or
//! `PackageReply`; respond before reading another request on that stream. A reply
//! does not close the stream. Match each domain request, apply authorization before
//! every handler invocation, and respond with `Ok(typed_value)` or `Err(remote_text)`.
//! For immediate reboot/shutdown, invoke the handler and call
//! `Reply::complete_without_response` because those operations expect no reply.
//!
//! Keep request stream owners alive until clean EOF, or call `finish` at a request
//! boundary when intentionally stopping dispatch. Dropping an owner resets/stops
//! its streams; dropping an unfinished response also aborts the borrowed stream.
//! On shutdown, stop acceptance, finish the active invocation, then call `finish`
//! before reading another request. Applications supervise, cancel, and join tasks;
//! these objects do not spawn background runners or provide application draining.
//! FIN and transport acknowledgment do not prove application processing.
//!
//! Package installs use `preflight`; terminal verdicts complete the invocation,
//! while `Proceed` returns the borrowed exchange for bounded chunk reads and a
//! terminal response. An incomplete install cannot send a terminal success. After
//! completion, the owner can read the next request with its unary frame budget
//! restored. Event senders and receivers own their streams privately; the existing
//! two-byte event header is preserved.
//!
//! ## Supervised server processing
//!
//! Use `ServerIncoming::with_authorization` to bind the application's authenticated
//! context and `AuthorizerV2` before accepting streams. An existing `Authorizer`
//! can be wrapped in `AuthorizerV2Adapter`. The request runner checks this policy
//! before every invocation, including subsequent requests on the same stream.
//! It passes the context's peer name to existing `server::Handler` methods that
//! take a peer argument. The event runner takes a `server::EventStreamHandler`
//! for a particular stream. Applications can supply peer-specific behavior in
//! that handler.
//!
//! ```no_run
//! # #[cfg(feature = "server")]
//! # async fn serve_one<H, E>(
//! #     incoming: review_protocol::session::ServerIncoming,
//! #     context: review_protocol::auth::AuthorizationContext,
//! #     policy: std::sync::Arc<dyn review_protocol::auth::AuthorizerV2>,
//! #     requests: std::sync::Arc<H>,
//! #     events: E,
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     H: review_protocol::server::Handler + Sync,
//! #     E: review_protocol::server::EventStreamHandler + Send,
//! # {
//! use review_protocol::session::{ServerRequestOutcome, ServerStream};
//!
//! let mut incoming = incoming.with_authorization(context, policy);
//! match incoming.accept().await? {
//!     ServerStream::Requests(stream) => {
//!         if let ServerRequestOutcome::Unhandled(request) = stream.run(requests).await? {
//!             // This application has no extension for the delegated code.
//!             request.into_stream().finish()?;
//!         }
//!     }
//!     ServerStream::Events(stream) => stream.run(events).await?,
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Each `run` future owns one stream. For concurrent service, accept another
//! stream while existing runners are supervised within the application's
//! concurrency limit. Retain and join any spawned tasks, including after
//! cancellation. Dropping an owned runner aborts the stream and cancels any
//! in-progress callback. A callback may already have performed application work.
//! To stop dispatch at a request boundary under application control, use
//! `ServerRequestStream::next` with per-invocation authorization and call
//! `finish` after the final reply. Borrowed framing reads can be suspended and
//! resumed while their owners are kept.
//!
//! Retain a handle while serving requests. Connection clones share a transport
//! connection and retain endpoint resources; streams retain connection resources.
//! Concurrent acceptors on clones of the underlying transport compete for streams;
//! they do not broadcast. Construct each session once per connection. The unique
//! incoming owner makes accidental competing session accept loops harder to create.
//! Dropping a handle does not explicitly close a connection retained elsewhere.
//! `close` closes the shared connection immediately, and `closed` supplies typed
//! `CloseReason` information with uninterpreted peer reason bytes.
//!
//! `SessionId` is a process-local correlation identifier shared by handle clones.
//! It is neither a credential nor a stable identity across reconnects.
//! `PeerCertificates::chain` exposes DER certificates in TLS order for application
//! identity resolution. The transport uses the caller's TLS configuration unchanged:
//! crypto provider, trust roots, certificate verification, server-name verification,
//! and client-certificate enforcement remain the caller's policy. Verification logic
//! continues to belong in the dedicated TLS modules. These sessions add no verifier.
//!
//! `HandshakeMetadata::Agent` contains peer claims. Capabilities, versions, trust
//! epochs, fingerprints, and audit metadata are not permissions. Applications derive
//! authorization context from verified certificate identity and corroborated policy
//! before dispatching privileged operations. This module never grants access from
//! an advertised capability.
//!
//! ## Explicit limits
//!
//! Every session constructor requires `SessionOptions`. There is no default profile.
//! `SessionOptions::legacy_compatible()` explicitly selects the existing `u32::MAX`
//! encoded payload bound for handshake, unary, event, and package-chunk frames, with
//! no deadline. It supports existing large transfers, but it is not a deployment
//! budget recommendation. Applications can replace each `FrameLimit` independently
//! or construct `SessionOptions` directly.
//!
//! ```rust
//! # #[cfg(any(feature = "client", feature = "server"))]
//! # fn example() -> Result<(), review_protocol::session::FrameError> {
//! use review_protocol::session::{FrameLimit, SessionOptions};
//!
//! let mut options = SessionOptions::legacy_compatible();
//! // Illustrative application-selected budget; measure actual payload requirements.
//! options.unary = FrameLimit::new(32 * 1024 * 1024)?;
//! # Ok(())
//! # }
//! ```
//!
//! Limits exclude the four-byte frame header; a unary request includes its four-byte
//! request code. Incoming declared lengths are checked before payload allocation.
//! Outgoing serialization is capped before any header is transmitted. Decoding
//! charges conservative in-memory collection element sizes and string/byte storage,
//! including nested collections, and hides untrusted collection allocation hints.
//! Handshake fields share a single allocation budget across base and conditional
//! tail. Encoded size alone is insufficient when selecting a budget for collections
//! of small values or strings. Custom serde deserializers remain responsible for
//! their own allocations. The internal guarded serde adapter follows oinq 0.14.0's
//! allocation guards and adds typed budget-exhaustion tracking and conditional-tail
//! support, without classifying errors by matching text.
//!
//! Frames transfer their buffers back through `Frame::into_bytes` and
//! `FramedReader::recycle`. Package chunk buffers are exchanged with the caller's
//! previous allocation rather than copied. Tests cover an 8 MiB model and 4 MiB
//! configuration under a configured 32 MiB unary budget, as well as nested allocation
//! claims and oversized declarations with no payload. Measure representative
//! collection-heavy workloads with the allocation guards enabled; these examples
//! do not prescribe consumer-specific operational limits.
//!
//! ## Errors, deadlines, and cancellation
//!
//! `SessionError` distinguishes transport failure, malformed data, incompatible
//! protocol, remote rejection, limit exhaustion, and deadline/cancellation. Original
//! sources are retained. Remote rejection text is preserved verbatim; its contents
//! are never used to infer structured wire errors. Typed domain failures, including
//! package and enrollment refusals, remain typed response values.
//!
//! `certainty()` supplies these outcomes where applicable:
//!
//! | Certainty | Meaning |
//! | --- | --- |
//! | `NotSent` | No request bytes were submitted to the transport. |
//! | `Rejected` | The receiving side explicitly rejected the operation. |
//! | `Unknown` | The operation may have taken effect; reconcile before retrying. |
//!
//! `Malformed` and `LimitExceeded` carry the certainty of the operation that
//! observed them: an oversized local request is `NotSent`, and a response that
//! is truncated, cannot be decoded, or exceeds its budget after the request was
//! sent is `Unknown`. They carry none when raised while reading a peer's request.
//!
//! A transport failure or deadline after submitting a mutation is `Unknown`, even
//! when no response was received. It is not a remote rejection. Certainty becomes
//! conservatively unknown when flushing starts; a partial frame cannot prove that
//! the peer did nothing. A successful write or transport acknowledgment does not
//! promise application processing. Immediate power `Sent` has the same limitation.
//!
//! `operation_timeout` optionally bounds a whole outbound domain operation, including
//! stream opening, preflight, package reads/writes, and its response. Constructors
//! also honor it for handshakes and event-stream opening. The lifetime of an opened
//! event sequence and its borrowed reads/flushes remains application-controlled.
//! An expired operation returns a `Deadline` error with
//! certainty and aborts its owned exchange. Dropping an operation future returns no
//! error at all; applications must track reconciliation needs if they cancel a
//! mutation this way.
//!
//! Abandoned or misaligned exchanges explicitly reset the send stream and stop the
//! receive stream with application code 1. Generic stream drop is not relied on as
//! a reset guarantee. Dropping an incoming request or package transfer also aborts
//! its exchange. Once an exchange has failed, further reads fail without consuming
//! new frames. An undecodable event is the exception described below: its frame
//! was read completely, so the event sequence stays aligned.
//!
//! Cancelling a *borrowed sub-operation* retains progress when its owner is kept:
//! `ServerIncoming::accept`, `AgentIncoming::accept`, request stream `next`,
//! `PackageReply::next_chunk`, `EventReceiver::next`, and
//! `EventSender::flush` can resume. Prepare each event once with `start`, then resume
//! `flush` after cancellation; do not replace a pending event. Dropping the entire
//! owner aborts its streams. Application callbacks and authorization run outside the
//! framing machinery and follow the application's cancellation and lifecycle policy.
//!
//! ## Runtime and transport policy
//!
//! Oinq 0.14.0 endpoints require an entered Tokio runtime with I/O and time enabled,
//! including socket-based constructors. Endpoint constructors take caller-supplied
//! rustls configurations; no configuration or selected transport option is replaced
//! by these session constructors.
//!
//! Oinq transport defaults are no keepalive, a 30-second idle timeout, 100 incoming
//! streams per direction, a 1,250,000-byte stream receive window, and 10,000,000-byte
//! connection receive and send windows. Idle timeouts are truncated to milliseconds;
//! `None` or less than one millisecond disables the local timeout. Keepalive must be
//! positive and shorter than an enabled truncated idle timeout. The peers negotiate
//! the effective idle timeout. These settings are independent of frame budgets and
//! operation deadlines. Pass the application's chosen `TransportOptions` directly
//! to `Endpoint`; sessions do not silently tune flow control or stream counts.
//!
//! Each `endpoint.accept().await` yields an independently owned `Incoming` attempt;
//! awaiting a failed attempt does not terminate endpoint acceptance.
//! `set_server_config` affects future connections. `close` is immediate, and
//! `wait_idle` waits for transport shutdown, not application draining. A stream's
//! `finish` queues FIN. `stopped` reports peer stop or data/FIN acknowledgment and
//! makes no application-processing guarantee. A rejected session handshake retains
//! its transport until the peer stops the stream or rejection bytes/FIN are
//! acknowledged (or its configured deadline expires), because the failed constructor
//! returns no session handle.
//!
//! ## Wire and rollout compatibility
//!
//! The wire remains four-byte big-endian payload lengths, four-byte little-endian
//! request codes, and bincode 2 standard serde bodies. Handshakes write the complete
//! tail, accept base-only peers and tails ending at field boundaries, and reject
//! malformed present fields. Prefix decoding preserves existing trailing-byte
//! compatibility. Request codes and representative responses have independently
//! captured release/current fixtures in `tests/fixtures`.
//!
//! Protocol `0.49.0` and the library's `>=0.49.0` suggested floor are unchanged.
//! Callers may still advertise `0.48.0` or select an explicit `>=0.48.0` through
//! `0.49.0` window. Protocol versions are independent of crate release versions.
//! No wire-version increment or synchronized deployment is required.
//!
//! Owned server runners preserve the legacy dispatcher's multi-request loop.
//! Handler results, including a default `not supported` or a service-specific
//! error, are sent as provided and dispatch continues. A policy denial or
//! unknown code ends dispatch with a typed error even if sending the legacy
//! rejection text fails. Codes 2, 9, and 14 are delegated to the application with
//! their raw arguments and the still-owned stream. Complete frames with invalid
//! arguments end dispatch without a response.
//!
//! Low-level request `next` retains the foundation's behavior of answering
//! unserved codes and continuing. It answers malformed arguments with a
//! rejection naming the code before ending the stream. An install answered
//! before its payload is complete drains the rest first.
//!
//! Event runners ignore both reserved header bytes, report a complete malformed
//! event to `on_error`, and continue if the callback succeeds. Budget failures
//! surface as typed errors. Only clean frame-boundary EOF calls `on_stream_end`.
//! The bounded server path reports a partial frame header, payload, or request
//! code as malformed data. Legacy framing could treat these inputs as EOF,
//! which concealed incomplete messages. A partial two-byte event stream header
//! still reports an unexpected EOF error.
//!
//! Existing applications can continue using the legacy API. A migration selects
//! limits based on real payload requirements and uses a released foundation.

mod events;

mod exchange;
#[cfg(feature = "server")]
pub use events::EventReceiver;
#[cfg(feature = "client")]
pub use events::EventSender;
mod decode;
mod handshake;
mod operations;

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

pub use oinq::frame::{FrameError, FrameLimit};
pub use oinq::{
    ApplicationCode, CloseInfo as CloseReason, Connection, Endpoint, Incoming, TransportError,
    TransportErrorKind, TransportOptions,
};
pub use operations::Reply;
#[cfg(feature = "client")]
pub use operations::{AgentIncoming, AgentRequest, AgentRequestStream, PackageReply};
#[cfg(feature = "server")]
pub use operations::{
    ServerIncoming, ServerRequest, ServerRequestOutcome, ServerRequestStream, ServerStream,
    UnhandledServerRequest,
};
use thiserror::Error;

/// The certainty of a failed operation's domain outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeCertainty {
    /// No request bytes were submitted to the transport.
    NotSent,
    /// The receiving side explicitly rejected the request.
    Rejected,
    /// The operation may have taken effect; reconcile before retrying mutations.
    Unknown,
}

/// A classified session failure retaining its diagnostic source.
#[derive(Debug, Error)]
pub enum SessionError {
    /// A connection or stream failure, including I/O during framing.
    #[error("transport failure ({certainty:?}): {source}")]
    Transport {
        certainty: OutcomeCertainty,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Invalid local or received protocol data.
    #[error("malformed protocol data: {source}")]
    Malformed {
        /// The outcome of the operation that observed the data, when it has one.
        ///
        /// A response that cannot be decoded after a request was sent is
        /// `Unknown`: the peer may already have applied the request.
        certainty: Option<OutcomeCertainty>,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A peer protocol version outside the caller-selected window.
    #[error("protocol {version} is incompatible with {required}")]
    IncompatibleProtocol { version: String, required: String },
    /// An uninterpreted peer rejection, never classified by matching its text.
    #[error("remote rejection: {0}")]
    RemoteRejection(String),
    /// A configured encoded-payload or allocation budget was exceeded.
    #[error("session limit exceeded: {source}")]
    LimitExceeded {
        /// The outcome of the operation that hit the limit, when it has one.
        ///
        /// An oversized local request is `NotSent`; an oversized response to a
        /// sent request is `Unknown`.
        certainty: Option<OutcomeCertainty>,
        #[source]
        source: FrameError,
    },
    /// An explicitly returned deadline/cancellation error.
    #[error("operation deadline or cancellation ({certainty:?})")]
    Deadline {
        /// Whether request submission had started.
        certainty: OutcomeCertainty,
        /// The original timeout error, when this failure comes from a deadline.
        #[source]
        source: Option<tokio::time::error::Elapsed>,
    },
}

/// A failure while running server request or event processing.
#[cfg(feature = "server")]
#[derive(Debug, Error)]
pub enum ServerRunError {
    /// A session framing or transport failure.
    #[error(transparent)]
    Session(#[from] SessionError),
    /// The application has not bound an authorization policy to this request stream.
    #[error("server request runner requires a bound authorization policy")]
    MissingAuthorization,
    /// The injected policy denied a request before dispatch.
    #[error("authorization denied for {service}: {source}")]
    AuthorizationDenied {
        /// The service requested by the peer.
        service: crate::service_id::ServiceId,
        #[source]
        source: crate::auth::AuthorizationError,
    },
    /// The server received a request code with no protocol assignment.
    #[error("unknown request code: {code}")]
    UnknownRequestCode {
        /// The unrecognized numeric code.
        code: u32,
    },
    /// An event callback returned an application error.
    #[error("event handler failed: {0}")]
    EventHandler(#[source] std::io::Error),
}

#[cfg(feature = "server")]
impl ServerRunError {
    /// Returns outcome certainty when the failure establishes one.
    #[must_use]
    pub fn certainty(&self) -> Option<OutcomeCertainty> {
        match self {
            Self::Session(error) => error.certainty(),
            Self::AuthorizationDenied { .. } | Self::UnknownRequestCode { .. } => {
                Some(OutcomeCertainty::Rejected)
            }
            Self::MissingAuthorization | Self::EventHandler(_) => None,
        }
    }
}

impl SessionError {
    /// Returns outcome certainty when the failure establishes one.
    #[must_use]
    pub fn certainty(&self) -> Option<OutcomeCertainty> {
        match self {
            Self::Transport { certainty, .. } | Self::Deadline { certainty, .. } => {
                Some(*certainty)
            }
            Self::Malformed { certainty, .. } | Self::LimitExceeded { certainty, .. } => *certainty,
            Self::RemoteRejection(_) | Self::IncompatibleProtocol { .. } => {
                Some(OutcomeCertainty::Rejected)
            }
        }
    }

    pub(crate) fn malformed(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Malformed {
            certainty: None,
            source: source.into(),
        }
    }

    pub(crate) fn limit(source: FrameError) -> Self {
        Self::LimitExceeded {
            certainty: None,
            source,
        }
    }

    /// Records the certainty of the enclosing operation on a data or limit
    /// error that was raised without one, such as a decoding failure.
    pub(crate) fn within(mut self, outcome: OutcomeCertainty) -> Self {
        if let Self::Malformed { certainty, .. } | Self::LimitExceeded { certainty, .. } = &mut self
        {
            certainty.get_or_insert(outcome);
        }
        self
    }

    pub(crate) fn transport(
        source: impl std::error::Error + Send + Sync + 'static,
        certainty: OutcomeCertainty,
    ) -> Self {
        Self::Transport {
            certainty,
            source: Box::new(source),
        }
    }

    pub(crate) fn frame(source: FrameError, certainty: OutcomeCertainty) -> Self {
        match source {
            FrameError::TooLarge { .. } | FrameError::InvalidLimit => Self::LimitExceeded {
                certainty: Some(certainty),
                source,
            },
            FrameError::Io(_) => Self::transport(source, certainty),
            _ => Self::Malformed {
                certainty: Some(certainty),
                source: Box::new(source),
            },
        }
    }
}

/// Required per-family payload and conservative allocation budgets.
///
/// No default profile is selected. Limits exclude the four-byte frame header.
/// Custom deserializers remain responsible for their own allocations.
#[derive(Clone, Debug)]
pub struct SessionOptions {
    /// Handshake frame budget.
    pub handshake: FrameLimit,
    /// Unary request and response budget (including the request code).
    pub unary: FrameLimit,
    /// Event frame budget.
    pub events: FrameLimit,
    /// Package chunk budget.
    pub package_chunks: FrameLimit,
    /// Optional deadline for a complete outbound operation, including stream opening.
    pub operation_timeout: Option<Duration>,
}

impl SessionOptions {
    /// Selects the legacy wire maximum for every family, without a deadline.
    ///
    /// # Panics
    /// Panics if the transport rejects the valid `u32` wire maximum.
    #[must_use]
    pub fn legacy_compatible() -> Self {
        let limit =
            FrameLimit::new(u32::MAX as usize).expect("the wire maximum is a valid frame limit");
        Self {
            handshake: limit,
            unary: limit,
            events: limit,
            package_chunks: limit,
            operation_timeout: None,
        }
    }
}

/// A process-local connection identity, shared by all clones of a handle.
///
/// This is a correlation identifier, not a secret or authorization credential.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(u64);

/// The peer certificate chain in TLS order, for application identity resolution.
#[derive(Clone, Debug)]
pub struct PeerCertificates(Arc<[Vec<u8>]>);

impl PeerCertificates {
    /// Returns the DER certificate chain without interpreting application identity.
    #[must_use]
    pub fn chain(&self) -> &[Vec<u8>] {
        &self.0
    }
}

/// Typed metadata returned by the application handshake.
#[derive(Clone, Debug)]
pub enum HandshakeMetadata {
    /// Agent-advertised claims, which do not grant permissions.
    Agent(crate::AgentInfo),
    /// The manager's selected protocol ceiling.
    Server { protocol_version: String },
}

#[derive(Debug)]
struct Shared {
    connection: Connection,
    options: SessionOptions,
    id: SessionId,
    metadata: HandshakeMetadata,
    certificates: Option<PeerCertificates>,
}

impl Shared {
    fn new(
        connection: Connection,
        options: SessionOptions,
        metadata: HandshakeMetadata,
    ) -> Arc<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let certificates = connection.peer_certificates().map(|chain| {
            PeerCertificates(chain.iter().map(|cert| cert.as_ref().to_vec()).collect())
        });
        Arc::new(Self {
            certificates,
            connection,
            options,
            id: SessionId(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            metadata,
        })
    }
}

/// A cloneable manager-side handle exposing domain calls to an agent.
#[cfg(feature = "server")]
#[derive(Clone, Debug)]
pub struct ServerHandle(Arc<Shared>);

/// A cloneable agent-side handle exposing domain calls to a manager.
#[cfg(feature = "client")]
#[derive(Clone, Debug)]
pub struct AgentHandle(Arc<Shared>);

macro_rules! handle_metadata {
    ($handle:ident) => {
        impl $handle {
            /// Returns the connection identity shared by clones.
            #[must_use]
            pub fn id(&self) -> SessionId {
                self.0.id
            }
            /// Returns typed handshake metadata; peer claims are not permissions.
            #[must_use]
            pub fn metadata(&self) -> &HandshakeMetadata {
                &self.0.metadata
            }
            /// Returns the verified TLS peer chain for application identity resolution.
            #[must_use]
            pub fn peer_certificates(&self) -> Option<PeerCertificates> {
                self.0.certificates.clone()
            }
            /// Returns the peer's current address.
            #[must_use]
            pub fn remote_addr(&self) -> std::net::SocketAddr {
                self.0.connection.remote_addr()
            }
            /// Waits for typed close information; cancelling this wait leaves the connection open.
            pub async fn closed(&self) -> CloseReason {
                self.0.connection.closed().await
            }
            /// Immediately closes the shared connection with a checked code and uninterpreted reason.
            pub fn close(&self, code: ApplicationCode, reason: &[u8]) {
                self.0.connection.close(code, reason);
            }
        }
    };
}
#[cfg(feature = "server")]
handle_metadata!(ServerHandle);
#[cfg(feature = "client")]
handle_metadata!(AgentHandle);
