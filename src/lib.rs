//! # review-protocol
//!
//! This crate defines the wire and API surface used to interact with
//! review nodes and services. It focuses on a small set of long-lived
//! abstractions that embedding applications should rely on when
//! integrating with the review protocol.
//!
//! ## Public modules
//!
//! - [`client`] – Client-side utilities and typed clients for calling
//!   review services.
//! - [`server`] – Server-side helpers, service wiring, and the
//!   `server::Connection` API used to issue requests to agents.
//!   The [`server::node`] module provides the recommended
//!   service-family entry point for node operations via
//!   [`Connection::node()`](server::Connection::node).
//! - [`types`] – Shared types used across the protocol surface.
//! - [`service_id`] – Definitions and helpers for [`ServiceId`], the
//!   key used to scope authorization and identify services.
//! - [`auth`] – Authorization-related types and helpers.
//! - [`protocol_error`] – Semantic error categories
//!   ([`ProtocolErrorKind`]) for internal classification.
//!
//! ## Node API family
//!
//! The preferred public terminology for the APIs that operate on an
//! agent/node is **node**. The node API family groups the endpoints and
//! types that model long-lived interactions with a managed node.
//! Embedding applications should treat the node APIs as the stable
//! surface for node-centric operations. Item-level docs on the
//! node-related modules provide concrete guidance and examples.
//!
//! ## Package install and node enrollment
//!
//! Two request families extend the node API family beyond the nine
//! configuration-oriented ones.
//!
//! **`node.package` (request code 109)** manages the components installed on
//! a node. `Remove`, `ListInstalled` and `Status` are unary. `Install` is
//! not: its payload does not travel in the request message but streams
//! afterwards. The manager sends the framed request, the agent answers with one
//! `InstallPreflight` verdict, and only on `Proceed` does the manager stream
//! the `.pkg` bytes as length-prefixed chunks over the request's own
//! bi-stream, followed by exactly one terminal response. A refusal is
//! terminal at the verdict, before a single byte of payload is sent. The
//! agent's handler receives the bytes through a `request::PackageReader`
//! bounded to the request's declared size, so it cannot over-read into the
//! next request frame.
//!
//! `Install` also carries the reserved `"trust"` target, which delivers a
//! release-signing trust-set generation rather than an installable component.
//! It travels the same streaming path and reports `TrustActive`,
//! `StaleTrustSet` or `UnsupportedManifestFormat`, each carrying the agent's
//! active trust epoch.
//!
//! **`node.enroll` (request code 110)** is unary, and is directed at the
//! agent that runs the registrar. `Register` returns the bootstrap material
//! for a service identity; `Deregister` returns `Done`. Registrar failures
//! are typed values on the response rather than strings, so a caller
//! classifies them by pattern-matching and reads `retry_after()` and
//! `leaves_teardown_owed()` off them.
//!
//! ## Capability routing is the manager's job
//!
//! Not every agent serves these families. An agent advertises what it carries
//! in [`AgentInfo::capabilities`], whose tags are named by
//! [`types::capability`] — `node.package` and `node.enroll` among them.
//!
//! **This crate transports that set and never inspects it.**
//! `server::handshake` hands the decoded [`AgentInfo`] back to its caller and
//! keeps no copy; the manager-side send paths take no capability set and
//! consult none. A manager that routes codes 109 and 110 therefore reads the
//! advertised set itself and decides for itself which agents to send them to.
//! Nothing here withholds a request code from an agent, and the tags are
//! advertised rather than authoritative — a manager corroborates a
//! security-sensitive claim elsewhere before granting anything.
//!
//! An agent that advertises nothing decodes to an empty set. It stays
//! connected and is simply not sent those codes by a manager that applies the
//! rule. If one is sent anyway, the agent still fails closed: a code it does
//! not know answers `"unknown request code"`, and a family it dispatches but
//! does not implement answers `"not supported"`.
//!
//! ## Protocol version and compatibility
//!
//! [`PROTOCOL_VERSION`] and [`MIN_PROTOCOL_VERSION_REQ`] are the wire
//! protocol version this crate's surface implements and the requirement a
//! manager that intends to route codes 109 and 110 enforces. They live in the
//! **protocol** namespace, which is not the crate version and is never
//! derived from it. They are values a caller may pass to
//! `client::ConnectionBuilder::new` and `server::handshake`; the crate
//! itself reads them at no decision point, and a consumer passing its own
//! strings is unaffected.
//!
//! The floor exists so that an agent too old to install anything is refused
//! **at handshake** rather than one request at a time. It is not a substitute
//! for capability routing, and capability routing is not a substitute for it:
//! the two do different jobs. The version window says whether the two peers
//! speak the same protocol at all; the capability set says which roles this
//! particular agent fills, which is version-independent and is the durable
//! half of the pair.
//!
//! Version skew does not break the handshake in either direction. The
//! capability tail decodes tolerantly: an agent predating the tail sends only
//! the base fields and is decoded with an empty capability set and unknown
//! readings for the rest, and an agent sending the full tail is read by an
//! older manager that ignores the trailing bytes. A manager that has not
//! raised its floor keeps talking to a new agent, and a new manager keeps
//! talking to an old agent it chooses not to gate.
//!
//! ## Compatibility with legacy flat APIs
//!
//! Historically some functionality was exposed through legacy, flatter
//! endpoints (for example: reboot or resource-usage endpoints). Those
//! legacy endpoints remain available for compatibility and may overlap
//! with the node API family. For new integrations prefer the node APIs,
//! but be aware the compatibility surface exists and may be relied upon
//! by existing consumers.
//!
//! ## Authorization model
//!
//! Authorization in this crate assumes certificate-backed peer identity
//! is available at request time. The embedding application provides
//! `PeerContext` at each authorization decision point—both when
//! handling incoming requests and when issuing authorized calls to
//! agents (e.g., the `node_*_authorized` methods on
//! `server::Connection`). The crate does not embed a policy engine:
//! authorization decisions are made by the embedding application using
//! the identity and the [`ServiceId`] to scope policies. In short:
//!
//! 1. Peer identity is certificate-backed and surfaced as
//!    `PeerContext`.
//! 2. Policy is supplied and enforced by the embedding application
//!    outside this crate.
//! 3. Authorization is keyed by [`ServiceId`] so policies can be
//!    targeted to individual services.
//!
//! ### Richer context with `AuthorizationContext`
//!
//! [`AuthorizationContext`] extends the authorization model with
//! optional authenticated metadata (agent kind, roles, protocol
//! version, and application-supplied attributes) without changing
//! the wire format or breaking existing code.
//! [`ServiceId`] remains **separate** from `AuthorizationContext`
//! so the operation being authorized is always explicit.
//!
//! Existing [`Authorizer`] implementations continue to work
//! unchanged.  To use them where an [`AuthorizerV2`] is required,
//! wrap with [`AuthorizerV2Adapter`].  New code that needs the
//! richer metadata can implement [`AuthorizerV2`] directly.
//! See [`auth::AuthorizationContext`] for construction examples
//! and migration guidance.
//!
//! **Compatibility:** policy engines remain outside
//! `review-protocol`.  This crate provides identity plumbing and
//! dispatch hooks; the actual allow/deny logic belongs to the
//! embedding application.  Existing `PeerContext` flows continue
//! to work unchanged — no migration is required until the
//! application opts in to the richer context.
//!
//! [`AuthorizationContext`]: auth::AuthorizationContext
//! [`Authorizer`]: auth::Authorizer
//! [`AuthorizerV2`]: auth::AuthorizerV2
//! [`AuthorizerV2Adapter`]: auth::AuthorizerV2Adapter
//!
//! ## Further reading
//!
//! Release-specific rollout choreography and sequencing are documented
//! in `CHANGELOG.md`. Item-level docs on each module contain
//! implementation detail.
//!
//! [`ServiceId`]: crate::service_id::ServiceId

#[cfg(any(feature = "client", feature = "server"))]
pub mod auth;
pub mod client;
#[cfg(feature = "client")]
pub mod frame;
pub mod protocol_error;
#[cfg(feature = "client")]
pub mod request;
pub mod server;
#[cfg(any(feature = "client", feature = "server"))]
pub mod service_id;
#[cfg(any(
    feature = "test-support",
    all(test, any(feature = "client", feature = "server"))
))]
#[doc(hidden)]
pub mod test;
pub mod types;

use std::{collections::BTreeSet, net::SocketAddr};

use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
pub use server::EventStreamHandler;
#[cfg(any(feature = "client", feature = "server"))]
use thiserror::Error;

pub use self::protocol_error::ProtocolErrorKind;
use crate::types::{AuditHealth, ManifestFormatRange, ProvisioningFingerprint, Status};

/// The wire protocol version this crate's surface implements.
///
/// This is the **protocol** version, and it is neither the crate version nor
/// derived from it. The two namespaces are unrelated in meaning and decades
/// apart in value, and deriving one from the other breaks a live deployment in
/// both directions: a requirement built from the crate version is weaker than
/// the one already in force and admits the agents it was meant to exclude,
/// while a ceiling built from it refuses every agent in the field.
///
/// An agent advertises this as its `protocol_version`; a manager passes it to
/// `server::handshake` as `highest_protocol_version`.
///
/// It is a `&str` rather than a `semver::Version` because that type is not
/// const-constructible and `semver` is an optional dependency. A caller parses
/// it, exactly as `server::handshake` parses the strings it is given.
///
/// The value is maintained by hand, and nothing in this crate can check it
/// against the deployed fleet.
pub const PROTOCOL_VERSION: &str = "0.49.0";

/// The protocol version requirement a manager that intends to route the
/// `node.package` (code 109) and `node.enroll` (code 110) request families
/// enforces.
///
/// This is a requirement in the **protocol** namespace, not the crate's. See
/// [`PROTOCOL_VERSION`] for why the two must not be conflated.
///
/// A manager passes it to `server::handshake` as `version_req`, which is what
/// refuses an agent too old to serve those families at the handshake rather
/// than one request at a time. The crate applies no such policy of its own:
/// this is a value a caller may pass, and a caller that passes its own
/// requirement is unaffected.
pub const MIN_PROTOCOL_VERSION_REQ: &str = ">=0.49.0";

/// The error type for a handshake failure.
#[cfg(any(feature = "client", feature = "server"))]
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("connection closed by peer")]
    ConnectionClosed,
    #[error("connection lost")]
    ConnectionLost(#[from] quinn::ConnectionError),
    #[error("cannot receive a message: {0}")]
    ReadError(std::io::Error),
    #[error("cannot send a message")]
    WriteError(std::io::Error),
    #[error("arguments are too long")]
    MessageTooLarge,
    #[error("invalid message")]
    InvalidMessage,
    #[error("protocol version {0} is not supported; version {1} is required")]
    IncompatibleProtocol(String, String),
}

#[cfg(feature = "server")]
fn handle_handshake_send_io_error(e: std::io::Error) -> HandshakeError {
    if e.kind() == std::io::ErrorKind::InvalidData {
        HandshakeError::MessageTooLarge
    } else {
        HandshakeError::WriteError(e)
    }
}

#[cfg(feature = "server")]
fn handle_handshake_recv_io_error(e: std::io::Error) -> HandshakeError {
    match e.kind() {
        std::io::ErrorKind::InvalidData => HandshakeError::InvalidMessage,
        std::io::ErrorKind::UnexpectedEof => HandshakeError::ConnectionClosed,
        _ => HandshakeError::ReadError(e),
    }
}

/// Properties of an agent.
///
/// # Wire compatibility
///
/// `AgentInfo` is exchanged as a single bincode-encoded frame, and bincode is
/// positional and not self-describing: a decoder that expects a field the
/// encoder did not write reads past the end of the buffer and fails. The five
/// fields up to and including `status` are therefore the **base**, always
/// present, and every field after them belongs to the **conditional tail**.
///
/// The tail is `capabilities`, `active_trust_epoch`, `manifest_formats`,
/// `provisioning_fingerprint`, `audit_health`, **in that order, which is
/// contractual**. A decoder reads the base first and then each tail field from
/// whatever bytes are left over, each field consuming exactly its own bytes, so
/// it may stop at any field boundary; a field the peer did not send reads as
/// unknown. Any future field follows the same discipline: append it at the tail,
/// extend the conditional decode, and let it consume exactly its own bytes.
/// Never insert a field in the middle, and never reorder.
///
/// The rule holds in both directions. An old peer sends only the base and the
/// new decoder fills the tail with unknown readings; a new peer sends the full
/// tail and an old decoder ignores the trailing bytes, because the frame is
/// length-delimited and `oinq::frame::recv` discards whatever follows the struct
/// it decoded.
///
/// A tail that is **present but does not decode** is an error, never an absent
/// tail: unknown readings apply only when there are no leftover bytes at all.
/// Silently treating a corrupt tail as absent would drop a security-relevant
/// claim — a peer that should advertise `registrar` or `colocated:*` would look
/// like one that simply claims nothing.
///
/// The derived `Serialize` writes the base followed by the tail in declaration
/// order, so sending an `AgentInfo` through `oinq::frame::send` produces exactly
/// the layout described here.
///
/// The derived `Deserialize`, by contrast, is **not** the conditional decode: it
/// is positional like any other bincode decode and so demands the full tail,
/// failing on the base-only frame an older agent sends. `server::handshake` is
/// what applies the rule above, and a manager reads `AgentInfo` off the wire
/// through it rather than through `oinq::frame::recv::<AgentInfo>`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentInfo {
    #[serde(rename = "agent_name", alias = "app_name")]
    pub agent_name: String,
    #[serde(rename = "agent_version", alias = "app_version", alias = "version")]
    pub agent_version: String,

    /// The wire protocol version the agent advertises.
    ///
    /// This is the **protocol** version, not the crate version. The value is
    /// supplied by the caller — an agent passes it to
    /// `client::ConnectionBuilder::new` — and this crate never fills it in.
    /// [`PROTOCOL_VERSION`] is the value this crate's surface corresponds to.
    ///
    /// `server::handshake` enforces a window on it from both sides: a floor,
    /// the caller's `version_req`, and a ceiling, the caller's
    /// `highest_protocol_version`. A version outside either end answers
    /// `HandshakeError::IncompatibleProtocol`. So a caller that passes a
    /// crate version into either argument breaks its own handshake — a floor
    /// in the crate's namespace is vacuous against a protocol version, and a
    /// ceiling in it refuses every agent.
    pub protocol_version: String,
    pub addr: SocketAddr,
    pub status: Status,

    // ── conditional tail ───────────────────────────────────────
    //
    // Append-only, decoded in declaration order. See the type-level
    // documentation before adding a field here.
    /// Namespaced capability tags the agent advertises.
    ///
    /// The set is **open**: [`types::capability`] lists the tags this crate
    /// knows about, but a consumer validates the ones it knows and preserves
    /// the rest untouched. A new capability is just another tag and needs no
    /// wire change, and one agent may hold several roles at once.
    ///
    /// Security-sensitive tags are **advertised, not authoritative**. This
    /// crate transports them; a manager corroborates them elsewhere before
    /// granting anything.
    ///
    /// This is unrelated to the crate's other `capabilities`, the
    /// `Vec<String>` on `auth::ProtocolMetadata`: a different field on a
    /// different type, attached to an `auth::AuthorizationContext` and never
    /// present on the handshake struct. The two are not merged, and whether
    /// they should ever converge is a question for elsewhere.
    ///
    /// An empty set means the agent advertised nothing — including the case of
    /// a peer too old to send the field at all.
    ///
    /// [`types::capability`]: crate::types::capability
    pub capabilities: BTreeSet<String>,

    /// The release-signing trust-set generation the agent reports itself
    /// active on, or `None` when the epoch is unknown.
    ///
    /// `None` means **unknown**, not epoch 0 and not confirmed.
    ///
    /// The value is agent-asserted, so it bounds the agent's status
    /// **downward only**: a consumer clamps it against its own active epoch,
    /// where a report at or below that epoch may mark the host caught up, and
    /// a report **above** it is treated as un-confirmed, never as confirmed.
    /// This crate does not implement the clamp; it transports the reading, and
    /// the consumer applies the rule.
    ///
    /// This is the **connect-time** reading only. It is exchanged once per
    /// connection and so cannot report an activation that happens later on a
    /// still-open connection; the per-apply trust acknowledgement carries that
    /// half of the picture.
    pub active_trust_epoch: Option<u64>,

    /// The range of package-manifest `format_version` values the agent can
    /// decode, or `None` when the agent did not report one.
    ///
    /// `None` means the agent's range is unknown, and the safe assumption is
    /// the launch format only.
    pub manifest_formats: Option<ManifestFormatRange>,

    /// Digests of the provisioning file as read by the enforcing daemon and
    /// relayed by the agent, or `None` when the agent did not report them.
    pub provisioning_fingerprint: Option<ProvisioningFingerprint>,

    /// The registrar's audit-store health, relayed from its local endpoint, or
    /// `None` when the agent did not report it.
    pub audit_health: Option<AuditHealth>,
}

/// The base fields of [`AgentInfo`], i.e. everything before the conditional
/// tail.
///
/// Decoding the tail requires knowing where the base ends, and bincode reports
/// that only as the number of bytes a decode consumed — so the base needs a type
/// of its own that stops at `status`. The fields must mirror the leading fields
/// of `AgentInfo` exactly. Two tests catch drift between them:
/// `agent_info_encodes_base_then_tail` fails if `AgentInfo` gains a field ahead
/// of the tail, and `base_only_decoder_ignores_the_tail` fails if this struct
/// stops consuming exactly the base.
#[cfg(feature = "server")]
#[derive(Deserialize)]
struct AgentInfoBase {
    #[serde(rename = "agent_name", alias = "app_name")]
    agent_name: String,
    #[serde(rename = "agent_version", alias = "app_version", alias = "version")]
    agent_version: String,
    protocol_version: String,
    addr: SocketAddr,
    status: Status,
}

/// The error type for a failed [`AgentInfo`] decode.
#[cfg(feature = "server")]
#[derive(Debug, Error)]
pub(crate) enum AgentInfoDecodeError {
    #[error("cannot decode the agent information: {0}")]
    Base(bincode::error::DecodeError),
    #[error("cannot decode `{field}` in the agent information tail: {source}")]
    Tail {
        field: &'static str,
        #[source]
        source: bincode::error::DecodeError,
    },
}

/// Decodes an [`AgentInfo`] frame, reading as much of the conditional tail as
/// the peer sent.
///
/// A tail field the peer omitted reads as unknown: an empty set for
/// `capabilities` and `None` for the rest. That applies only when the bytes run
/// out at a field boundary — a tail that is present but does not decode is an
/// error.
///
/// # Errors
///
/// Returns [`AgentInfoDecodeError::Base`] if the base struct does not decode,
/// and [`AgentInfoDecodeError::Tail`] if a tail field is present but does not
/// decode.
#[cfg(feature = "server")]
pub(crate) fn decode_agent_info(buf: &[u8]) -> Result<AgentInfo, AgentInfoDecodeError> {
    let config = bincode::config::standard();
    let (base, mut offset) =
        bincode::serde::borrow_decode_from_slice::<AgentInfoBase, _>(buf, config)
            .map_err(AgentInfoDecodeError::Base)?;

    let capabilities = decode_tail_field(buf, &mut offset, "capabilities")?.unwrap_or_default();
    let active_trust_epoch = decode_tail_field(buf, &mut offset, "active_trust_epoch")?.flatten();
    let manifest_formats = decode_tail_field(buf, &mut offset, "manifest_formats")?.flatten();
    let provisioning_fingerprint =
        decode_tail_field(buf, &mut offset, "provisioning_fingerprint")?.flatten();
    let audit_health = decode_tail_field(buf, &mut offset, "audit_health")?.flatten();

    Ok(AgentInfo {
        agent_name: base.agent_name,
        agent_version: base.agent_version,
        protocol_version: base.protocol_version,
        addr: base.addr,
        status: base.status,
        capabilities,
        active_trust_epoch,
        manifest_formats,
        provisioning_fingerprint,
        audit_health,
    })
}

/// Decodes one conditional-tail field from `buf` at `offset`, advancing
/// `offset` by exactly the number of bytes that field occupies.
///
/// Returns `Ok(None)` if the buffer ends at `offset`, meaning the peer stopped
/// before this field.
///
/// # Errors
///
/// Returns [`AgentInfoDecodeError::Tail`] if bytes remain but do not decode
/// into `T`.
#[cfg(feature = "server")]
fn decode_tail_field<'a, T>(
    buf: &'a [u8],
    offset: &mut usize,
    field: &'static str,
) -> Result<Option<T>, AgentInfoDecodeError>
where
    T: serde::Deserialize<'a>,
{
    let Some(rest) = buf.get(*offset..).filter(|rest| !rest.is_empty()) else {
        return Ok(None);
    };
    let (value, consumed) =
        bincode::serde::borrow_decode_from_slice::<T, _>(rest, bincode::config::standard())
            .map_err(|source| AgentInfoDecodeError::Tail { field, source })?;
    *offset += consumed;
    Ok(Some(value))
}

/// Sends a unary request and returns the response.
///
/// # Errors
///
/// Returns an error if there was a problem sending the request or receiving the
/// response.
#[cfg(any(feature = "client", all(test, feature = "server")))]
pub(crate) async fn unary_request<I, O>(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    code: u32,
    input: I,
) -> std::io::Result<O>
where
    I: serde::Serialize,
    O: serde::de::DeserializeOwned,
{
    let mut buf = vec![];
    oinq::message::send_request(send, &mut buf, code, input).await?;

    oinq::frame::recv(recv, &mut buf).await
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "client", feature = "server"))]
    use crate::test::{TOKEN, channel};

    /// The conditional-tail encode and decode of [`AgentInfo`](crate::AgentInfo).
    #[cfg(feature = "server")]
    mod agent_info_tail {
        use std::{
            collections::{BTreeMap, BTreeSet},
            net::{IpAddr, Ipv4Addr, SocketAddr},
        };

        use serde::Serialize;

        use crate::{
            AgentInfo, AgentInfoBase, AgentInfoDecodeError, decode_agent_info, decode_tail_field,
            types::{AuditHealth, ManifestFormatRange, ProvisioningFingerprint, Status},
        };

        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = "0.19.0";
        const TRUST_EPOCH: u64 = 42;

        fn config() -> bincode::config::Configuration {
            bincode::config::standard()
        }

        fn encode<T: Serialize>(value: T) -> Vec<u8> {
            bincode::serde::encode_to_vec(value, config()).unwrap()
        }

        fn addr() -> SocketAddr {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        }

        /// An `AgentInfo` advertising nothing, i.e. every tail field at its
        /// unknown reading.
        fn without_tail() -> AgentInfo {
            AgentInfo {
                agent_name: AGENT_NAME.to_string(),
                agent_version: AGENT_VERSION.to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                addr: addr(),
                status: Status::Ready,
                capabilities: BTreeSet::new(),
                active_trust_epoch: None,
                manifest_formats: None,
                provisioning_fingerprint: None,
                audit_health: None,
            }
        }

        fn capabilities() -> BTreeSet<String> {
            [
                crate::types::capability::REGISTRAR,
                crate::types::capability::NODE_PACKAGE,
            ]
            .into_iter()
            .map(ToString::to_string)
            .collect()
        }

        fn manifest_formats() -> ManifestFormatRange {
            ManifestFormatRange { min: 1, max: 2 }
        }

        fn provisioning_fingerprint() -> ProvisioningFingerprint {
            ProvisioningFingerprint {
                components: BTreeMap::from([("roxyd".to_string(), "sha256:abc".to_string())]),
                domain: "example.test".to_string(),
            }
        }

        fn audit_health() -> AuditHealth {
            AuditHealth {
                below_low_water: true,
                intent_without_outcome: 3,
            }
        }

        /// An `AgentInfo` advertising every tail field.
        fn with_full_tail() -> AgentInfo {
            AgentInfo {
                capabilities: capabilities(),
                active_trust_epoch: Some(TRUST_EPOCH),
                manifest_formats: Some(manifest_formats()),
                provisioning_fingerprint: Some(provisioning_fingerprint()),
                audit_health: Some(audit_health()),
                ..without_tail()
            }
        }

        /// The bytes an agent that knows only the base fields would send.
        fn base_bytes() -> Vec<u8> {
            let info = without_tail();
            encode((
                &info.agent_name,
                &info.agent_version,
                &info.protocol_version,
                info.addr,
                info.status,
            ))
        }

        /// The bytes of each tail field, in wire order.
        fn tail_bytes() -> [Vec<u8>; 5] {
            [
                encode(capabilities()),
                encode(Some(TRUST_EPOCH)),
                encode(Some(manifest_formats())),
                encode(Some(provisioning_fingerprint())),
                encode(Some(audit_health())),
            ]
        }

        /// A payload carrying the base fields and the first `fields` tail
        /// fields.
        fn payload_with_tail_prefix(fields: usize) -> Vec<u8> {
            let mut buf = base_bytes();
            for field in tail_bytes().iter().take(fields) {
                buf.extend_from_slice(field);
            }
            buf
        }

        /// The wire layout is the base struct followed by the tail fields in
        /// declaration order, which is what lets a decoder stop at any field
        /// boundary. This also pins `AgentInfoBase` to the leading fields of
        /// `AgentInfo`.
        #[test]
        fn agent_info_encodes_base_then_tail() {
            assert_eq!(encode(with_full_tail()), payload_with_tail_prefix(5));
        }

        /// Old peer to new decoder: a payload with no tail decodes, with every
        /// tail field at its unknown reading.
        #[test]
        fn decodes_payload_without_tail() {
            let agent_info = decode_agent_info(&base_bytes()).unwrap();

            assert_eq!(agent_info.agent_name, AGENT_NAME);
            assert_eq!(agent_info.agent_version, AGENT_VERSION);
            assert_eq!(agent_info.protocol_version, PROTOCOL_VERSION);
            assert_eq!(agent_info.addr, addr());
            assert!(agent_info.capabilities.is_empty());
            assert_eq!(agent_info.active_trust_epoch, None);
            assert_eq!(agent_info.manifest_formats, None);
            assert_eq!(agent_info.provisioning_fingerprint, None);
            assert_eq!(agent_info.audit_health, None);
        }

        #[test]
        fn decodes_payload_with_full_tail() {
            let agent_info = decode_agent_info(&encode(with_full_tail())).unwrap();

            assert_eq!(agent_info, with_full_tail());
        }

        /// New peer to old decoder: a decoder that knows only the base fields
        /// reads them and ignores the trailing bytes.
        #[test]
        fn base_only_decoder_ignores_the_tail() {
            let payload = encode(with_full_tail());

            let (base, consumed) =
                bincode::serde::borrow_decode_from_slice::<AgentInfoBase, _>(&payload, config())
                    .unwrap();

            assert_eq!(base.agent_name, AGENT_NAME);
            assert_eq!(base.agent_version, AGENT_VERSION);
            assert_eq!(base.protocol_version, PROTOCOL_VERSION);
            assert_eq!(base.addr, addr());
            assert_eq!(base.status, Status::Ready);
            assert_eq!(consumed, base_bytes().len());
            assert!(consumed < payload.len());
        }

        /// A decoder that knows only `capabilities` reads the correct set from
        /// a payload that also carries later fields, because each field
        /// consumes exactly its own bytes.
        #[test]
        fn capabilities_only_decoder_ignores_later_fields() {
            let payload = payload_with_tail_prefix(2);
            let mut offset = base_bytes().len();

            let decoded: Option<BTreeSet<String>> =
                decode_tail_field(&payload, &mut offset, "capabilities").unwrap();

            assert_eq!(decoded, Some(capabilities()));
            assert!(
                offset < payload.len(),
                "the later tail field must be left untouched"
            );
        }

        #[test]
        fn decodes_every_tail_prefix() {
            for fields in 0..=5 {
                let agent_info = decode_agent_info(&payload_with_tail_prefix(fields)).unwrap();

                assert_eq!(
                    agent_info.capabilities,
                    if fields >= 1 {
                        capabilities()
                    } else {
                        BTreeSet::new()
                    },
                    "tail prefix of {fields} field(s)"
                );
                assert_eq!(
                    agent_info.active_trust_epoch,
                    (fields >= 2).then_some(TRUST_EPOCH),
                    "tail prefix of {fields} field(s)"
                );
                assert_eq!(
                    agent_info.manifest_formats,
                    (fields >= 3).then(manifest_formats),
                    "tail prefix of {fields} field(s)"
                );
                assert_eq!(
                    agent_info.provisioning_fingerprint,
                    (fields >= 4).then(provisioning_fingerprint),
                    "tail prefix of {fields} field(s)"
                );
                assert_eq!(
                    agent_info.audit_health,
                    (fields >= 5).then(audit_health),
                    "tail prefix of {fields} field(s)"
                );
            }
        }

        /// A tail field the peer sent as absent is skipped, not read as the end
        /// of the tail: the fields after it still decode.
        ///
        /// Every other case pairs an absent field with absent successors, so a
        /// decoder that stopped at the first `None` would pass them all. This
        /// one interleaves the two readings and fails if the tail is ever
        /// terminated early rather than walked to the end.
        #[test]
        fn absent_tail_field_does_not_end_the_tail() {
            let agent_info = AgentInfo {
                capabilities: capabilities(),
                active_trust_epoch: None,
                manifest_formats: Some(manifest_formats()),
                provisioning_fingerprint: None,
                audit_health: Some(audit_health()),
                ..without_tail()
            };

            let mut payload = base_bytes();
            payload.extend_from_slice(&encode(&agent_info.capabilities));
            payload.extend_from_slice(&encode(Option::<u64>::None));
            payload.extend_from_slice(&encode(agent_info.manifest_formats));
            payload.extend_from_slice(&encode(Option::<ProvisioningFingerprint>::None));
            payload.extend_from_slice(&encode(agent_info.audit_health));

            assert_eq!(encode(&agent_info), payload);
            assert_eq!(decode_agent_info(&payload).unwrap(), agent_info);
        }

        /// The other half of the forward-compatibility story: a peer that
        /// appends a sixth field this decoder does not know about is decoded to
        /// the five it does, and the unknown bytes are left alone.
        #[test]
        fn ignores_a_future_tail_field() {
            let mut payload = payload_with_tail_prefix(5);
            payload.extend_from_slice(&encode(Some("a field from the future")));

            let agent_info = decode_agent_info(&payload).unwrap();

            assert_eq!(agent_info, with_full_tail());
        }

        /// A tail that is present but does not decode fails the decode; it is
        /// never read as an absent tail.
        #[test]
        fn truncated_tail_fails() {
            // A two-element set whose second element is missing.
            let mut payload = base_bytes();
            payload.extend_from_slice(&[0x02, 0x01, b'a']);

            let err = decode_agent_info(&payload).unwrap_err();
            assert!(
                matches!(err, AgentInfoDecodeError::Tail { field, .. } if field == "capabilities"),
                "unexpected error: {err}"
            );

            // A `Some(u64)` whose value is missing, after a complete
            // `capabilities` field.
            let mut payload = payload_with_tail_prefix(1);
            payload.push(0x01);

            let err = decode_agent_info(&payload).unwrap_err();
            assert!(
                matches!(
                    err,
                    AgentInfoDecodeError::Tail { field, .. } if field == "active_trust_epoch"
                ),
                "unexpected error: {err}"
            );

            // The same payloads without the corrupt bytes decode, so the
            // failure is the corruption and not the absence of a tail.
            assert!(decode_agent_info(&base_bytes()).is_ok());
            assert!(decode_agent_info(&payload_with_tail_prefix(1)).is_ok());
        }

        #[test]
        fn truncated_base_fails() {
            let payload = base_bytes();
            let err = decode_agent_info(&payload[..payload.len() - 1]).unwrap_err();

            assert!(
                matches!(err, AgentInfoDecodeError::Base(_)),
                "unexpected error: {err}"
            );
        }

        /// An unknown tag survives a round trip untouched, and the set's
        /// ordering is stable.
        #[test]
        fn preserves_unknown_capability_tags() {
            let tags = [
                "future:thing",
                crate::types::capability::ROLLBACK_SUPERVISOR,
                crate::types::capability::COLOCATED_REVIEW,
            ];
            let agent_info = AgentInfo {
                capabilities: tags.iter().map(ToString::to_string).collect(),
                ..without_tail()
            };

            let decoded = decode_agent_info(&encode(&agent_info)).unwrap();

            assert_eq!(decoded.capabilities, agent_info.capabilities);
            assert!(decoded.capabilities.contains("future:thing"));
            assert_eq!(
                decoded.capabilities.iter().collect::<Vec<_>>(),
                vec!["colocated:review", "future:thing", "rollback-supervisor"]
            );
        }
    }

    /// The reverse direction, over the wire: a receiver that knows only the
    /// base fields reads a full-tail frame through `oinq::frame::recv` without
    /// error and discards the trailing bytes.
    ///
    /// That tolerance is `oinq`'s, not this crate's — `recv` decodes into the
    /// struct and drops the byte count — so it is pinned here rather than
    /// assumed. An upgrade that started asserting full consumption would break
    /// every manager in the field that predates the tail, and this test is what
    /// catches it.
    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn base_only_receiver_ignores_the_tail_over_the_wire() {
        use std::{
            collections::BTreeSet,
            net::{IpAddr, Ipv4Addr, SocketAddr},
        };

        use crate::{
            AgentInfo, AgentInfoBase, Status,
            types::{AuditHealth, ManifestFormatRange, ProvisioningFingerprint, capability},
        };

        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let agent_info = AgentInfo {
            agent_name: AGENT_NAME.to_string(),
            agent_version: AGENT_VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            addr,
            status: Status::Ready,
            capabilities: BTreeSet::from([capability::REGISTRAR.to_string()]),
            active_trust_epoch: Some(7),
            manifest_formats: Some(ManifestFormatRange { min: 1, max: 2 }),
            provisioning_fingerprint: Some(ProvisioningFingerprint::default()),
            audit_health: Some(AuditHealth::default()),
        };

        let mut buf = Vec::new();
        oinq::frame::send(&mut channel.client.send, &mut buf, &agent_info)
            .await
            .unwrap();

        let base: AgentInfoBase = oinq::frame::recv(&mut channel.server.recv, &mut buf)
            .await
            .unwrap();

        assert_eq!(base.agent_name, AGENT_NAME);
        assert_eq!(base.agent_version, AGENT_VERSION);
        assert_eq!(base.protocol_version, PROTOCOL_VERSION);
        assert_eq!(base.addr, addr);
        assert_eq!(base.status, Status::Ready);
    }

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                AGENT_NAME,
                AGENT_VERSION,
                PROTOCOL_VERSION,
                Status::Ready,
            )
            .await
        });

        let agent_info = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            PROTOCOL_VERSION,
            PROTOCOL_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(agent_info.agent_name, AGENT_NAME);
        assert_eq!(agent_info.agent_version, AGENT_VERSION);
        assert_eq!(agent_info.protocol_version, PROTOCOL_VERSION);

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_ok());
    }

    /// An agent advertising the full conditional tail hands the manager
    /// exactly those values.
    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake_with_full_tail() {
        use std::{
            collections::{BTreeMap, BTreeSet},
            net::{IpAddr, Ipv4Addr, SocketAddr},
        };

        use crate::{
            AgentInfo, Status,
            types::{AuditHealth, ManifestFormatRange, ProvisioningFingerprint, capability},
        };

        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let capabilities: BTreeSet<String> = [capability::REGISTRAR, "future:thing"]
            .into_iter()
            .map(ToString::to_string)
            .collect();
        let fingerprint = ProvisioningFingerprint {
            components: BTreeMap::from([("roxyd".to_string(), "sha256:abc".to_string())]),
            domain: "example.test".to_string(),
        };
        let agent_info = AgentInfo {
            agent_name: AGENT_NAME.to_string(),
            agent_version: AGENT_VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            status: Status::Idle,
            capabilities: capabilities.clone(),
            active_trust_epoch: Some(7),
            manifest_formats: Some(ManifestFormatRange { min: 1, max: 2 }),
            provisioning_fingerprint: Some(fingerprint.clone()),
            audit_health: Some(AuditHealth {
                below_low_water: true,
                intent_without_outcome: 2,
            }),
        };

        let sent = agent_info.clone();
        let handle =
            tokio::spawn(async move { super::client::handshake_with(&client.conn, &sent).await });

        let received = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            PROTOCOL_VERSION,
            PROTOCOL_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(received.capabilities, capabilities);
        assert_eq!(received.active_trust_epoch, Some(7));
        assert_eq!(
            received.manifest_formats,
            Some(ManifestFormatRange { min: 1, max: 2 })
        );
        assert_eq!(received.provisioning_fingerprint, Some(fingerprint));
        assert_eq!(
            received.audit_health,
            Some(AuditHealth {
                below_low_water: true,
                intent_without_outcome: 2,
            })
        );
        assert_eq!(received.status, Status::Idle);

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_ok());
    }

    /// An agent that sends only the base fields, as one predating the tail
    /// would, stays connected and hands the manager the unknown readings.
    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake_without_tail() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            let (mut send, mut recv) = client.conn.open_bi().await.unwrap();
            let mut buf = Vec::new();
            // The base fields alone, which is byte-for-byte what an agent that
            // predates the conditional tail sends.
            let base = (
                AGENT_NAME,
                AGENT_VERSION,
                PROTOCOL_VERSION,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                Status::Ready,
            );
            oinq::frame::send(&mut send, &mut buf, base).await.unwrap();
            oinq::frame::recv::<Result<String, String>>(&mut recv, &mut buf)
                .await
                .unwrap()
        });

        let agent_info = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            PROTOCOL_VERSION,
            PROTOCOL_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(agent_info.agent_name, AGENT_NAME);
        assert!(agent_info.capabilities.is_empty());
        assert_eq!(agent_info.active_trust_epoch, None);
        assert_eq!(agent_info.manifest_formats, None);
        assert_eq!(agent_info.provisioning_fingerprint, None);
        assert_eq!(agent_info.audit_health, None);

        assert!(tokio::join!(handle).0.unwrap().is_ok());
    }

    /// A tail that is present but does not decode fails the handshake instead
    /// of being read as an absent tail.
    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake_corrupt_tail_err() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            let (mut send, _recv) = client.conn.open_bi().await.unwrap();
            let base = (
                AGENT_NAME,
                AGENT_VERSION,
                PROTOCOL_VERSION,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                Status::Ready,
            );
            let mut payload =
                bincode::serde::encode_to_vec(base, bincode::config::standard()).unwrap();
            // A capability set announcing two elements but carrying one.
            payload.extend_from_slice(&[0x02, 0x01, b'a']);
            oinq::frame::send_raw(&mut send, &payload).await.unwrap();
            send.finish().unwrap();
        });

        let res = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            PROTOCOL_VERSION,
            PROTOCOL_VERSION,
        )
        .await;

        assert!(matches!(res, Err(crate::HandshakeError::InvalidMessage)));

        tokio::join!(handle).0.unwrap();
    }

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake_version_incompatible_err() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                AGENT_NAME,
                AGENT_VERSION,
                PROTOCOL_VERSION,
                Status::Ready,
            )
            .await
        });

        let res = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            &format!("<{PROTOCOL_VERSION}"),
            PROTOCOL_VERSION,
        )
        .await;

        assert!(res.is_err());

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_err());
    }

    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake_incompatible_err() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let version_req = semver::VersionReq::parse(&format!(">={PROTOCOL_VERSION}")).unwrap();
        let mut highest_version = semver::Version::parse(PROTOCOL_VERSION).unwrap();
        highest_version.patch += 1;
        let mut protocol_version = highest_version.clone();
        protocol_version.minor += 1;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                AGENT_NAME,
                AGENT_VERSION,
                &protocol_version.to_string(),
                Status::Ready,
            )
            .await
        });

        let res = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            &version_req.to_string(),
            &highest_version.to_string(),
        )
        .await;

        assert!(res.is_err());

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_err());
    }

    /// The two constants sit in the protocol namespace, whose successor to the
    /// deployed `0.48.0` is `0.49.0`. Gated on the features that pull `semver`
    /// in.
    #[test]
    #[cfg(any(feature = "client", feature = "server"))]
    fn protocol_version_constants() {
        let version = semver::Version::parse(crate::PROTOCOL_VERSION).unwrap();
        assert_eq!(version, semver::Version::new(0, 49, 0));

        let req = semver::VersionReq::parse(crate::MIN_PROTOCOL_VERSION_REQ).unwrap();
        assert!(req.matches(&version));
        assert!(!req.matches(&semver::Version::parse("0.48.0").unwrap()));
    }

    /// An agent advertising [`crate::PROTOCOL_VERSION`] passes both halves of
    /// the window a manager applies with [`crate::MIN_PROTOCOL_VERSION_REQ`].
    ///
    /// The crate constants are used directly here, and no local
    /// `PROTOCOL_VERSION` shadows them: a local one would put the crate
    /// version back on the wire, which is the confusion these constants exist
    /// to end.
    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake_at_protocol_version_ok() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                AGENT_NAME,
                AGENT_VERSION,
                crate::PROTOCOL_VERSION,
                Status::Ready,
            )
            .await
        });

        let agent_info = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            crate::MIN_PROTOCOL_VERSION_REQ,
            crate::PROTOCOL_VERSION,
        )
        .await
        .unwrap();

        assert_eq!(agent_info.agent_name, AGENT_NAME);
        assert_eq!(agent_info.agent_version, AGENT_VERSION);
        assert_eq!(agent_info.protocol_version, crate::PROTOCOL_VERSION);

        assert!(tokio::join!(handle).0.unwrap().is_ok());
    }

    /// The floor is what this release exists for: an agent still advertising
    /// the predecessor protocol version, and so unable to serve request codes
    /// 109 and 110, is refused at the handshake rather than one request at a
    /// time.
    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake_below_min_protocol_version_err() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";
        /// The protocol version deployed before this release.
        const PREVIOUS_PROTOCOL_VERSION: &str = "0.48.0";

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                AGENT_NAME,
                AGENT_VERSION,
                PREVIOUS_PROTOCOL_VERSION,
                Status::Ready,
            )
            .await
        });

        let res = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            crate::MIN_PROTOCOL_VERSION_REQ,
            crate::PROTOCOL_VERSION,
        )
        .await;

        assert!(matches!(
            res,
            Err(crate::HandshakeError::IncompatibleProtocol(..))
        ));

        assert!(tokio::join!(handle).0.unwrap().is_err());
    }

    /// The ceiling half of the same window, pinned so that a consumer raising
    /// its floor without raising `highest_protocol_version` is caught here.
    #[tokio::test]
    #[cfg(all(feature = "client", feature = "server"))]
    async fn handshake_above_highest_protocol_version_err() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::Status;

        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";
        /// The protocol version deployed before this release.
        const PREVIOUS_PROTOCOL_VERSION: &str = "0.48.0";

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            super::client::handshake(
                &client.conn,
                AGENT_NAME,
                AGENT_VERSION,
                crate::PROTOCOL_VERSION,
                Status::Ready,
            )
            .await
        });

        let res = super::server::handshake(
            &server.conn,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            crate::MIN_PROTOCOL_VERSION_REQ,
            PREVIOUS_PROTOCOL_VERSION,
        )
        .await;

        assert!(matches!(
            res,
            Err(crate::HandshakeError::IncompatibleProtocol(..))
        ));

        assert!(tokio::join!(handle).0.unwrap().is_err());
    }
}
