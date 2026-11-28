//! Session-owned transport values and private transport adaptation.
use std::{
    error::Error,
    future::Future,
    task::{Context, Waker},
};

use oinq::Connection;
use thiserror::Error;

use super::{OutcomeCertainty, SessionError};

pub(super) type SessionConnection = oinq::Connection;

/// A checked application close code in the range zero through 2^62 - 1.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApplicationCode(u64);

/// An application close code outside the 62-bit range.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("application close code exceeds 2^62 - 1")]
pub struct InvalidApplicationCode;

impl ApplicationCode {
    /// The largest application close code.
    pub const MAX: u64 = (1 << 62) - 1;

    /// Checks the application close code range.
    ///
    /// # Errors
    /// Returns [`InvalidApplicationCode`] above [`Self::MAX`].
    pub fn new(value: u64) -> Result<Self, InvalidApplicationCode> {
        if value > Self::MAX {
            Err(InvalidApplicationCode)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the checked code.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(super) fn wire(self) -> oinq::ApplicationCode {
        oinq::ApplicationCode::new(self.0).expect("application code was checked at construction")
    }
}

/// An encoded payload and allocation budget, excluding the four-byte header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameLimit(oinq::frame::FrameLimit);

impl FrameLimit {
    /// Checks that a frame budget fits the wire's 32-bit length field.
    ///
    /// # Errors
    /// Returns [`FrameError::InvalidLimit`] above `u32::MAX`.
    pub fn new(bytes: usize) -> Result<Self, FrameError> {
        oinq::frame::FrameLimit::new(bytes)
            .map(Self)
            .map_err(|_| FrameError::InvalidLimit)
    }

    /// Returns the payload budget in bytes.
    #[must_use]
    pub fn get(self) -> usize {
        self.0.get()
    }

    pub(super) fn wire(self) -> oinq::frame::FrameLimit {
        self.0
    }
}

/// The part of a frame that ended prematurely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramePart {
    /// The four-byte payload length.
    Header,
    /// The declared payload bytes.
    Payload,
}

/// A framing, codec, or configured budget failure.
///
/// I/O failures are reported as [`SessionError::Transport`] instead.
#[derive(Debug, Error)]
pub enum FrameError {
    /// A budget cannot be represented by the wire length field.
    #[error("frame limit exceeds u32::MAX")]
    InvalidLimit,
    /// An encoded payload exceeds its budget.
    #[error("payload length {length} exceeds {limit:?}")]
    TooLarge { length: usize, limit: FrameLimit },
    /// A decoded allocation exceeds its budget.
    #[error("frame decoding: {0}")]
    Decode(#[source] bincode::error::DecodeError),
    /// EOF within a header or payload.
    #[error("truncated {part:?}: {received} of {expected} bytes")]
    Truncated {
        part: FramePart,
        received: usize,
        expected: usize,
    },
    /// Serialization failed before transmission.
    #[error("frame encoding: {0}")]
    Encode(#[source] bincode::error::EncodeError),
    /// Strict decoding left trailing bytes.
    #[error("decoded {consumed} of {length} bytes")]
    TrailingBytes { consumed: usize, length: usize },
    /// A pending frame cannot be replaced.
    #[error("a frame is already pending")]
    Pending,
    /// Earlier failure invalidated framing alignment.
    #[error("framing alignment was lost")]
    Poisoned,
}

/// The category of a transport-level connection close, without causal attribution.
///
/// This enum supports exhaustive matching. Unrecognized transport close kinds
/// map to [`Self::Other`]; adding a variant requires a breaking release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportCloseKind {
    /// A TLS failure, with its alert number when known.
    Crypto { alert: Option<u8> },
    /// No traffic arrived within the negotiated idle timeout.
    IdleTimeout,
    /// A connection reset without a close frame.
    Reset,
    /// No common QUIC version.
    VersionMismatch,
    /// Exhaustion of the endpoint's connection identifiers.
    ConnectionIdExhausted,
    /// Any other transport-level closure.
    Other,
}

/// The observed reason a session connection closed.
///
/// This enum supports exhaustive matching. Unrecognized transport close reasons
/// map to [`Self::Transport`] with [`TransportCloseKind::Other`]; adding a variant
/// requires a breaking release.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CloseReason {
    /// The peer's application close code and uninterpreted reason bytes.
    #[error("peer application close ({code:?}): {reason:?}")]
    Application {
        code: ApplicationCode,
        reason: Vec<u8>,
    },
    /// The application closed this connection locally.
    #[error("closed locally")]
    Local,
    /// A transport-level closure; the initiating side is unknown.
    #[error("transport close: {0:?}")]
    Transport(TransportCloseKind),
}

/// A transport failure classified without implementation-specific downcasts.
///
/// This enum supports exhaustive matching. Failures without a recognized close
/// state or a live connection map to [`Self::Other`]; adding a variant requires
/// a breaking release.
#[derive(Debug, Error)]
pub enum TransportFailure {
    /// The connection has closed; its close state takes precedence over stream errors.
    #[error("{reason}: {source}")]
    Closed {
        /// The observed connection close state.
        reason: CloseReason,
        /// The original error for diagnostics.
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
    /// A stream failed while its connection remained open.
    #[error("stream failed on an open connection: {0}")]
    StreamFailed(#[source] Box<dyn Error + Send + Sync>),
    /// Any other I/O or transport failure, such as socket inspection.
    #[error("transport operation failed: {0}")]
    Other(#[source] Box<dyn Error + Send + Sync>),
}

fn kind(error: &oinq::TransportError) -> TransportCloseKind {
    use oinq::TransportCloseKind as Kind;
    let Some(close) = error.transport_close() else {
        return TransportCloseKind::Other;
    };
    match close.kind() {
        Kind::Crypto => TransportCloseKind::Crypto {
            alert: close.tls_alert().map(u8::from),
        },
        Kind::TimedOut => TransportCloseKind::IdleTimeout,
        Kind::Reset => TransportCloseKind::Reset,
        Kind::VersionMismatch => TransportCloseKind::VersionMismatch,
        Kind::ConnectionIdExhausted => TransportCloseKind::ConnectionIdExhausted,
        _ => TransportCloseKind::Other,
    }
}

impl CloseReason {
    pub(super) fn from_wire(close: oinq::CloseInfo) -> Self {
        match close {
            oinq::CloseInfo::Application { code, reason } => Self::Application {
                code: ApplicationCode(code.get()),
                reason,
            },
            oinq::CloseInfo::Local => Self::Local,
            oinq::CloseInfo::Transport(error) => Self::Transport(kind(&error)),
            _ => Self::Transport(TransportCloseKind::Other),
        }
    }
}

pub(super) fn close_reason(connection: &Connection) -> Option<CloseReason> {
    let mut closed = std::pin::pin!(connection.closed());
    match closed
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        std::task::Poll::Ready(close) => Some(CloseReason::from_wire(close)),
        std::task::Poll::Pending => None,
    }
}

impl SessionError {
    pub(crate) fn transport(
        source: impl Error + Send + Sync + 'static,
        certainty: OutcomeCertainty,
    ) -> Self {
        // Connect failures have no Connection to inspect. Their structured close
        // details still identify TLS rejection and other connection-level failures.
        let error = &source as &(dyn Error + 'static);
        let reason = error
            .downcast_ref::<oinq::TransportError>()
            .filter(|error| error.transport_close().is_some())
            .map(|error| CloseReason::Transport(kind(error)));
        let source = Box::new(source);
        let source = match reason {
            Some(reason) => TransportFailure::Closed { reason, source },
            None => TransportFailure::Other(source),
        };
        Self::Transport { certainty, source }
    }

    pub(super) fn on_connection(self, connection: &Connection) -> Self {
        let Self::Transport { source, certainty } = self else {
            return self;
        };
        let source = match source {
            TransportFailure::Closed { source, .. }
            | TransportFailure::StreamFailed(source)
            | TransportFailure::Other(source) => source,
        };
        let source = match close_reason(connection) {
            Some(reason) => TransportFailure::Closed { reason, source },
            None => TransportFailure::StreamFailed(source),
        };
        Self::Transport { source, certainty }
    }

    pub(crate) fn frame(source: oinq::frame::FrameError, certainty: OutcomeCertainty) -> Self {
        use oinq::frame::FrameError as WireError;
        let source = match source {
            WireError::TooLarge { length, limit } => FrameError::TooLarge {
                length,
                limit: FrameLimit(limit),
            },
            WireError::InvalidLimit => FrameError::InvalidLimit,
            WireError::Io(error) => return Self::transport(error, certainty),
            WireError::Decode(error) => FrameError::Decode(error),
            WireError::Encode(error) => FrameError::Encode(error),
            WireError::Truncated {
                part,
                received,
                expected,
            } => FrameError::Truncated {
                part: match part {
                    oinq::frame::FramePart::Header => FramePart::Header,
                    oinq::frame::FramePart::Payload => FramePart::Payload,
                },
                received,
                expected,
            },
            WireError::TrailingBytes { consumed, length } => {
                FrameError::TrailingBytes { consumed, length }
            }
            WireError::Pending => FrameError::Pending,
            WireError::Poisoned => FrameError::Poisoned,
        };
        match source {
            FrameError::TooLarge { .. } | FrameError::InvalidLimit => Self::LimitExceeded {
                certainty: Some(certainty),
                source,
            },
            other => Self::Malformed {
                certainty: Some(certainty),
                source: Box::new(other),
            },
        }
    }
}
