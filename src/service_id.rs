//! Stable logical service identifiers independent of wire request
//! codes.
//!
//! This module defines a semantic naming layer for the protocol's
//! service families and methods.  Each [`ServiceId`] represents
//! either a logical API operation (e.g. `"node.power.reboot"`) or
//! a service family (e.g. `"node.power"`) that remains stable even
//! if the underlying wire `RequestCode` values are renumbered or
//! reorganized.
//!
//! `ServiceId` is the public, logical identifier for a service —
//! what the service *is* from the caller's viewpoint.  Callers use
//! it to make authorization decisions, select request handlers, and
//! produce meaningful log entries.  It deliberately abstracts away
//! transport-level details so that authorization rules and routing
//! logic remain valid across protocol revisions.
//!
//! # Stability
//!
//! `ServiceId` values are treated as public identifiers and callers
//! may rely on them for long-lived authorization rules and routing
//! tables.  If this policy changes it will be documented in a
//! compatibility notice in this crate's README or CHANGELOG.
//!
//! # Typical uses
//!
//! - **Authorization keying** – map a `ServiceId` to an ACL entry
//!   to decide whether a caller may invoke a particular service.
//! - **Routing decisions** – match on a `ServiceId` to choose
//!   which handler or endpoint processes the request.
//! - **Logging / tracing** – include the `ServiceId` in log lines
//!   so that operators can filter by logical service name.
//! - **Capability reporting** – use [`all()`] to enumerate every
//!   known service identifier for discovery or audit purposes.
//!
//! ```
//! use std::collections::HashMap;
//! use review_protocol::service_id::{self, ServiceId};
//!
//! // Build an authorization table keyed by ServiceId.
//! let mut acl: HashMap<ServiceId, bool> = HashMap::new();
//! acl.insert(service_id::NODE_POWER_REBOOT, true);
//! acl.insert(service_id::NODE_POWER_SHUTDOWN, false);
//!
//! // Check whether the caller is authorized.
//! let id = service_id::NODE_POWER_REBOOT;
//! let allowed = acl.get(&id).copied().unwrap_or(false);
//! assert!(allowed);
//! ```
//!
//! # Relationship to `RequestCode`
//!
//! Both `client::RequestCode` and `server::RequestCode` remain the
//! transport dispatch mechanisms.  The identifiers defined here are
//! **not** a replacement for request codes — they are a
//! higher-level abstraction suitable for:
//!
//! - authorization decisions
//! - capability reporting
//! - service-family organization
//! - public-facing API documentation
//!
//! Do **not** conflate `ServiceId` with internal `RequestCode`
//! values.  `RequestCode` is an internal numeric code used to
//! indicate message types within the transport layer; `ServiceId`
//! is the public logical identity.  Reasoning in terms of
//! `RequestCode` for authorization or public routing is
//! discouraged — always prefer `ServiceId`.
//!
//! Use `from_client_request_code` or `from_server_request_code`
//! (crate-internal) to map a wire request code to its logical
//! identifier.
//!
//! # Family-level vs method-level identifiers
//!
//! Some wire request codes identify only a service family (e.g.
//! `client::RequestCode::NodePower`); the specific method is
//! determined later by deserializing the request payload.  For
//! these, the mapping functions return a **family-level**
//! `ServiceId` whose `method` field is empty.  Family-level
//! identifiers display as `"{family}"` (e.g. `"node.power"`),
//! while method-level identifiers display as
//! `"{family}.{method}"` (e.g. `"node.power.reboot"`).
//!
//! # Naming conventions
//!
//! - **Family** components are separated by `.`
//!   (e.g. `"node.power"`, `"common"`, `"server.model"`).
//! - **Method** names use stable `lower_snake_case`
//!   (e.g. `"reboot"`, `"process_list"`).
//! - The canonical string form is `"{family}.{method}"` for
//!   method-level or `"{family}"` for family-level identifiers.

use std::fmt;

/// A logical service identifier.
///
/// `ServiceId` names a specific API operation or service family as a
/// `(family, method)` pair of static strings.  It is the public
/// identity used by callers to make authorization decisions, to
/// select request/interaction handlers, and to produce
/// human-meaningful log entries.
///
/// `ServiceId` is **not** a transport identifier.  Do not confuse it
/// with `RequestCode`, which is the internal numeric code carried on
/// the wire.  Authorization rules, routing tables, and capability
/// reports should always be expressed in terms of `ServiceId`.
///
/// The type is `Copy`, `Clone`, `Hash`, `Eq`, and `Send + Sync`, so
/// it can be used freely as a key in hash maps and sets, passed
/// across threads, and compared with `==`.
///
/// # Examples
///
/// Constructing a `ServiceId` and comparing it to a well-known
/// constant:
///
/// ```
/// use review_protocol::service_id::{self, ServiceId};
///
/// let id = ServiceId::new("node.power", "reboot");
/// assert_eq!(id, service_id::NODE_POWER_REBOOT);
/// assert_eq!(id.to_string(), "node.power.reboot");
/// ```
///
/// Using `ServiceId` in a routing match:
///
/// ```
/// use review_protocol::service_id::{self, ServiceId};
///
/// fn handle(id: ServiceId) -> &'static str {
///     match id {
///         service_id::NODE_POWER_REBOOT => "rebooting",
///         service_id::NODE_POWER_SHUTDOWN => "shutting down",
///         _ => "unknown",
///     }
/// }
///
/// assert_eq!(handle(service_id::NODE_POWER_REBOOT), "rebooting");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ServiceId {
    /// The service family (e.g. `"node.power"`, `"common"`).
    pub family: &'static str,
    /// The method within the family (e.g. `"reboot"`).
    ///
    /// An empty string indicates a family-level identifier; see
    /// [`is_family`](Self::is_family).
    pub method: &'static str,
}

impl ServiceId {
    /// Creates a new `ServiceId` from a family name and a method
    /// name.
    ///
    /// Pass an empty string for `method` to create a family-level
    /// identifier.
    ///
    /// ```
    /// use review_protocol::service_id::ServiceId;
    ///
    /// let method_level = ServiceId::new("node.power", "reboot");
    /// assert!(!method_level.is_family());
    ///
    /// let family_level = ServiceId::new("node.power", "");
    /// assert!(family_level.is_family());
    /// ```
    #[must_use]
    pub const fn new(family: &'static str, method: &'static str) -> Self {
        Self { family, method }
    }

    /// Returns `true` if this is a family-level identifier (no
    /// specific method).
    ///
    /// Family-level identifiers have an empty `method` field and
    /// display as just the family name (e.g. `"node.power"`).
    ///
    /// ```
    /// use review_protocol::service_id;
    ///
    /// assert!(service_id::NODE_POWER.is_family());
    /// assert!(!service_id::NODE_POWER_REBOOT.is_family());
    /// ```
    #[must_use]
    pub const fn is_family(&self) -> bool {
        self.method.is_empty()
    }
}

impl fmt::Display for ServiceId {
    /// Formats the identifier as `"{family}.{method}"` for
    /// method-level or `"{family}"` for family-level identifiers.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.method.is_empty() {
            write!(f, "{}", self.family)
        } else {
            write!(f, "{}.{}", self.family, self.method)
        }
    }
}

// ── Node family-level identifiers ─────────────────────────────
//
// Family-level constants represent a node service family without
// specifying a particular method.  Use the corresponding
// method-level constant (e.g. [`NODE_SERVICE_START`]) when the
// exact operation is known.

pub const NODE_SERVICE: ServiceId = ServiceId::new("node.service", "");
pub const NODE_NETWORK_INTERFACE: ServiceId = ServiceId::new("node.network_interface", "");
pub const NODE_HOSTNAME: ServiceId = ServiceId::new("node.hostname", "");
pub const NODE_TIME_SYNC: ServiceId = ServiceId::new("node.time_sync", "");
pub const NODE_LOGGING: ServiceId = ServiceId::new("node.logging", "");
pub const NODE_REMOTE_ACCESS: ServiceId = ServiceId::new("node.remote_access", "");
pub const NODE_POWER: ServiceId = ServiceId::new("node.power", "");
pub const NODE_OBSERVATION: ServiceId = ServiceId::new("node.observation", "");
pub const NODE_VERSION: ServiceId = ServiceId::new("node.version", "");
pub const NODE_PACKAGE: ServiceId = ServiceId::new("node.package", "");
pub const NODE_ENROLL: ServiceId = ServiceId::new("node.enroll", "");

// ── node.service (method-level) ───────────────────────────────

pub const NODE_SERVICE_START: ServiceId = ServiceId::new("node.service", "start");
pub const NODE_SERVICE_STOP: ServiceId = ServiceId::new("node.service", "stop");
pub const NODE_SERVICE_STATUS: ServiceId = ServiceId::new("node.service", "status");
pub const NODE_SERVICE_RESTART: ServiceId = ServiceId::new("node.service", "restart");

// ── node.network_interface ─────────────────────────────────────

pub const NODE_NETWORK_INTERFACE_LIST: ServiceId = ServiceId::new("node.network_interface", "list");
pub const NODE_NETWORK_INTERFACE_GET: ServiceId = ServiceId::new("node.network_interface", "get");
pub const NODE_NETWORK_INTERFACE_SET: ServiceId = ServiceId::new("node.network_interface", "set");
pub const NODE_NETWORK_INTERFACE_RESET_CONFIG: ServiceId =
    ServiceId::new("node.network_interface", "reset_config");
pub const NODE_NETWORK_INTERFACE_REMOVE: ServiceId =
    ServiceId::new("node.network_interface", "remove");

// ── node.hostname ──────────────────────────────────────────────

pub const NODE_HOSTNAME_GET: ServiceId = ServiceId::new("node.hostname", "get");
pub const NODE_HOSTNAME_SET: ServiceId = ServiceId::new("node.hostname", "set");

// ── node.time_sync ─────────────────────────────────────────────

pub const NODE_TIME_SYNC_GET: ServiceId = ServiceId::new("node.time_sync", "get");
pub const NODE_TIME_SYNC_SET: ServiceId = ServiceId::new("node.time_sync", "set");
pub const NODE_TIME_SYNC_ENABLE: ServiceId = ServiceId::new("node.time_sync", "enable");
pub const NODE_TIME_SYNC_DISABLE: ServiceId = ServiceId::new("node.time_sync", "disable");
pub const NODE_TIME_SYNC_STATUS: ServiceId = ServiceId::new("node.time_sync", "status");

// ── node.logging ───────────────────────────────────────────────

pub const NODE_LOGGING_GET: ServiceId = ServiceId::new("node.logging", "get");
pub const NODE_LOGGING_SET: ServiceId = ServiceId::new("node.logging", "set");
pub const NODE_LOGGING_CLEAR: ServiceId = ServiceId::new("node.logging", "clear");
pub const NODE_LOGGING_RESTART: ServiceId = ServiceId::new("node.logging", "restart");

// ── node.remote_access ─────────────────────────────────────────

pub const NODE_REMOTE_ACCESS_GET: ServiceId = ServiceId::new("node.remote_access", "get");
pub const NODE_REMOTE_ACCESS_SET: ServiceId = ServiceId::new("node.remote_access", "set");
pub const NODE_REMOTE_ACCESS_RESTART: ServiceId = ServiceId::new("node.remote_access", "restart");

// ── node.power ─────────────────────────────────────────────────

pub const NODE_POWER_REBOOT: ServiceId = ServiceId::new("node.power", "reboot");
pub const NODE_POWER_SHUTDOWN: ServiceId = ServiceId::new("node.power", "shutdown");
pub const NODE_POWER_GRACEFUL_REBOOT: ServiceId = ServiceId::new("node.power", "graceful_reboot");
pub const NODE_POWER_GRACEFUL_SHUTDOWN: ServiceId =
    ServiceId::new("node.power", "graceful_shutdown");

// ── node.observation ───────────────────────────────────────────

pub const NODE_OBSERVATION_PROCESS_LIST: ServiceId =
    ServiceId::new("node.observation", "process_list");
pub const NODE_OBSERVATION_RESOURCE_USAGE: ServiceId =
    ServiceId::new("node.observation", "resource_usage");
pub const NODE_OBSERVATION_UPTIME: ServiceId = ServiceId::new("node.observation", "uptime");

// ── node.version ───────────────────────────────────────────────

pub const NODE_VERSION_GET: ServiceId = ServiceId::new("node.version", "get");
pub const NODE_VERSION_SET_OS: ServiceId = ServiceId::new("node.version", "set_os_version");
pub const NODE_VERSION_SET_PRODUCT: ServiceId =
    ServiceId::new("node.version", "set_product_version");

// ── node.package ───────────────────────────────────────────────

pub const NODE_PACKAGE_INSTALL: ServiceId = ServiceId::new("node.package", "install");
pub const NODE_PACKAGE_REMOVE: ServiceId = ServiceId::new("node.package", "remove");
pub const NODE_PACKAGE_LIST: ServiceId = ServiceId::new("node.package", "list");
pub const NODE_PACKAGE_STATUS: ServiceId = ServiceId::new("node.package", "status");

// ── node.enroll ────────────────────────────────────────────────

pub const NODE_ENROLL_REGISTER: ServiceId = ServiceId::new("node.enroll", "register");
pub const NODE_ENROLL_DEREGISTER: ServiceId = ServiceId::new("node.enroll", "deregister");

// ── common ─────────────────────────────────────────────────────
//
// Legacy/common operations that are relevant for dispatch and
// compatibility during the transition to service families.

pub const COMMON_DNS_START: ServiceId = ServiceId::new("common", "dns_start");
pub const COMMON_DNS_STOP: ServiceId = ServiceId::new("common", "dns_stop");
pub const COMMON_RELOAD_CONFIG: ServiceId = ServiceId::new("common", "reload_config");
pub const COMMON_UPDATE_CONFIG: ServiceId = ServiceId::new("common", "update_config");
pub const COMMON_DELETE_CUSTOMER_DATA: ServiceId = ServiceId::new("common", "delete_customer_data");
pub const COMMON_RELOAD_TI: ServiceId = ServiceId::new("common", "reload_ti");
pub const COMMON_TOR_EXIT_NODE_LIST: ServiceId = ServiceId::new("common", "tor_exit_node_list");
pub const COMMON_TRUSTED_DOMAIN_LIST: ServiceId = ServiceId::new("common", "trusted_domain_list");
pub const COMMON_SAMPLING_POLICY_LIST: ServiceId = ServiceId::new("common", "sampling_policy_list");
pub const COMMON_DELETE_SAMPLING_POLICY: ServiceId =
    ServiceId::new("common", "delete_sampling_policy");
pub const COMMON_RELOAD_FILTER_RULE: ServiceId = ServiceId::new("common", "reload_filter_rule");
pub const COMMON_INTERNAL_NETWORK_LIST: ServiceId =
    ServiceId::new("common", "internal_network_list");
pub const COMMON_ALLOWLIST: ServiceId = ServiceId::new("common", "allowlist");
pub const COMMON_BLOCKLIST: ServiceId = ServiceId::new("common", "blocklist");
pub const COMMON_ECHO: ServiceId = ServiceId::new("common", "echo");
pub const COMMON_TRUSTED_USER_AGENT_LIST: ServiceId =
    ServiceId::new("common", "trusted_user_agent_list");
pub const COMMON_SEMI_SUPERVISED_MODELS: ServiceId =
    ServiceId::new("common", "semi_supervised_models");
pub const COMMON_RENEW_CERTIFICATE: ServiceId = ServiceId::new("common", "renew_certificate");

// ── server.data_source ────────────────────────────────────────

pub const SERVER_DATA_SOURCE_GET: ServiceId = ServiceId::new("server.data_source", "get");
pub const SERVER_DATA_SOURCE_LIST: ServiceId = ServiceId::new("server.data_source", "list");
pub const SERVER_DATA_SOURCE_INSERT: ServiceId = ServiceId::new("server.data_source", "insert");

// ── server.model ──────────────────────────────────────────────

pub const SERVER_MODEL_GET: ServiceId = ServiceId::new("server.model", "get");
pub const SERVER_MODEL_GET_NAMES: ServiceId = ServiceId::new("server.model", "get_names");
pub const SERVER_MODEL_INSERT: ServiceId = ServiceId::new("server.model", "insert");
pub const SERVER_MODEL_REMOVE: ServiceId = ServiceId::new("server.model", "remove");
pub const SERVER_MODEL_UPDATE: ServiceId = ServiceId::new("server.model", "update");
pub const SERVER_MODEL_GET_PRETRAINED: ServiceId = ServiceId::new("server.model", "get_pretrained");

// ── server.indicator ──────────────────────────────────────────

pub const SERVER_INDICATOR_GET: ServiceId = ServiceId::new("server.indicator", "get");

// ── server.event ──────────────────────────────────────────────

pub const SERVER_EVENT_GET_MAX_ID_NUM: ServiceId = ServiceId::new("server.event", "get_max_id_num");
pub const SERVER_EVENT_INSERT_LABELS: ServiceId = ServiceId::new("server.event", "insert_labels");

// ── server.statistics ─────────────────────────────────────────

pub const SERVER_STATISTICS_INSERT_COLUMN: ServiceId =
    ServiceId::new("server.statistics", "insert_column");
pub const SERVER_STATISTICS_INSERT_TIME_SERIES: ServiceId =
    ServiceId::new("server.statistics", "insert_time_series");

// ── server.outlier ────────────────────────────────────────────

pub const SERVER_OUTLIER_GET: ServiceId = ServiceId::new("server.outlier", "get");
pub const SERVER_OUTLIER_REMOVE: ServiceId = ServiceId::new("server.outlier", "remove");
pub const SERVER_OUTLIER_UPDATE: ServiceId = ServiceId::new("server.outlier", "update");

// ── server.cluster ────────────────────────────────────────────

pub const SERVER_CLUSTER_UPDATE: ServiceId = ServiceId::new("server.cluster", "update");

// ── server.label ──────────────────────────────────────────────

pub const SERVER_LABEL_GET_DB_PATTERNS: ServiceId =
    ServiceId::new("server.label", "get_db_patterns");

// ── server.certificate ────────────────────────────────────────

pub const SERVER_CERTIFICATE_RENEW: ServiceId = ServiceId::new("server.certificate", "renew");

// ── server.config ─────────────────────────────────────────────

pub const SERVER_CONFIG_GET: ServiceId = ServiceId::new("server.config", "get");

// ── server.host ───────────────────────────────────────────────

pub const SERVER_HOST_UPDATE_OPENED_PORTS: ServiceId =
    ServiceId::new("server.host", "update_opened_ports");
pub const SERVER_HOST_UPDATE_OS_AGENTS: ServiceId =
    ServiceId::new("server.host", "update_os_agents");

// ── server.list ───────────────────────────────────────────────
//
// Server-side query operations for lists that the client pushes.

pub const SERVER_LIST_TRUSTED_DOMAIN: ServiceId = ServiceId::new("server.list", "trusted_domain");
pub const SERVER_LIST_TOR_EXIT_NODE: ServiceId = ServiceId::new("server.list", "tor_exit_node");
pub const SERVER_LIST_INTERNAL_NETWORK: ServiceId =
    ServiceId::new("server.list", "internal_network");
pub const SERVER_LIST_ALLOWLIST: ServiceId = ServiceId::new("server.list", "allowlist");
pub const SERVER_LIST_BLOCKLIST: ServiceId = ServiceId::new("server.list", "blocklist");
pub const SERVER_LIST_TRUSTED_USER_AGENT: ServiceId =
    ServiceId::new("server.list", "trusted_user_agent");
pub const SERVER_LIST_SAMPLING_POLICY: ServiceId = ServiceId::new("server.list", "sampling_policy");

// ── server.customer_data_deletion ──────────────────────────────

pub const SERVER_CUSTOMER_DATA_DELETION_REPORT: ServiceId =
    ServiceId::new("server.customer_data_deletion", "report");

// ── Node request → method-level ServiceId ──────────────────────
//
// Each node request enum variant maps to the specific method-level
// `ServiceId`, enabling fine-grained authorization when the typed
// request is available (e.g. on the REview-to-agent path).

use crate::types::node::{
    NodeEnrollRequest, NodeHostnameRequest, NodeLoggingRequest, NodeNetworkInterfaceRequest,
    NodeObservationRequest, NodePackageRequest, NodePowerRequest, NodeRemoteAccessRequest,
    NodeServiceRequest, NodeTimeSyncRequest, NodeVersionRequest,
};

impl NodeServiceRequest {
    /// Returns the method-level [`ServiceId`] for this request.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        match self {
            Self::Start { .. } => NODE_SERVICE_START,
            Self::Stop { .. } => NODE_SERVICE_STOP,
            Self::Status { .. } => NODE_SERVICE_STATUS,
            Self::Restart { .. } => NODE_SERVICE_RESTART,
        }
    }
}

impl NodeNetworkInterfaceRequest {
    /// Returns the method-level [`ServiceId`] for this request.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        match self {
            Self::List { .. } => NODE_NETWORK_INTERFACE_LIST,
            Self::Get { .. } => NODE_NETWORK_INTERFACE_GET,
            Self::Set { .. } => NODE_NETWORK_INTERFACE_SET,
            Self::ResetConfig { .. } => NODE_NETWORK_INTERFACE_RESET_CONFIG,
            Self::Remove { .. } => NODE_NETWORK_INTERFACE_REMOVE,
        }
    }
}

impl NodeHostnameRequest {
    /// Returns the method-level [`ServiceId`] for this request.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        match self {
            Self::Get => NODE_HOSTNAME_GET,
            Self::Set { .. } => NODE_HOSTNAME_SET,
        }
    }
}

impl NodeTimeSyncRequest {
    /// Returns the method-level [`ServiceId`] for this request.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        match self {
            Self::Get => NODE_TIME_SYNC_GET,
            Self::Set { .. } => NODE_TIME_SYNC_SET,
            Self::Enable => NODE_TIME_SYNC_ENABLE,
            Self::Disable => NODE_TIME_SYNC_DISABLE,
            Self::Status => NODE_TIME_SYNC_STATUS,
        }
    }
}

impl NodeLoggingRequest {
    /// Returns the method-level [`ServiceId`] for this request.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        match self {
            Self::Get => NODE_LOGGING_GET,
            Self::Set { .. } => NODE_LOGGING_SET,
            Self::Clear => NODE_LOGGING_CLEAR,
            Self::Restart => NODE_LOGGING_RESTART,
        }
    }
}

impl NodeRemoteAccessRequest {
    /// Returns the method-level [`ServiceId`] for this request.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        match self {
            Self::Get => NODE_REMOTE_ACCESS_GET,
            Self::Set { .. } => NODE_REMOTE_ACCESS_SET,
            Self::Restart => NODE_REMOTE_ACCESS_RESTART,
        }
    }
}

impl NodePowerRequest {
    /// Returns the method-level [`ServiceId`] for this request.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        match self {
            Self::Reboot => NODE_POWER_REBOOT,
            Self::Shutdown => NODE_POWER_SHUTDOWN,
            Self::GracefulReboot => NODE_POWER_GRACEFUL_REBOOT,
            Self::GracefulShutdown => NODE_POWER_GRACEFUL_SHUTDOWN,
        }
    }
}

impl NodeObservationRequest {
    /// Returns the method-level [`ServiceId`] for this request.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        match self {
            Self::ProcessList => NODE_OBSERVATION_PROCESS_LIST,
            Self::ResourceUsage => NODE_OBSERVATION_RESOURCE_USAGE,
            Self::Uptime => NODE_OBSERVATION_UPTIME,
        }
    }
}

impl NodeVersionRequest {
    /// Returns the method-level [`ServiceId`] for this request.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        match self {
            Self::Get => NODE_VERSION_GET,
            Self::SetOsVersion { .. } => NODE_VERSION_SET_OS,
            Self::SetProductVersion { .. } => NODE_VERSION_SET_PRODUCT,
        }
    }
}

impl NodePackageRequest {
    /// Returns the method-level [`ServiceId`] for this request.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        match self {
            Self::Install { .. } => NODE_PACKAGE_INSTALL,
            Self::Remove { .. } => NODE_PACKAGE_REMOVE,
            Self::ListInstalled => NODE_PACKAGE_LIST,
            Self::Status { .. } => NODE_PACKAGE_STATUS,
        }
    }
}

impl NodeEnrollRequest {
    /// Returns the method-level [`ServiceId`] for this request.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        match self {
            Self::Register { .. } => NODE_ENROLL_REGISTER,
            Self::Deregister { .. } => NODE_ENROLL_DEREGISTER,
        }
    }
}

// ── RequestCode → ServiceId mapping ────────────────────────────
//
// Maps wire request codes to their logical service identifiers.
// This is an explicit match table so that the mapping does not
// depend on numeric request-code values.

#[cfg(any(feature = "client", feature = "server"))]
use crate::client::RequestCode as ClientRequestCode;
#[cfg(any(feature = "client", feature = "server"))]
use crate::server::RequestCode as ServerRequestCode;

/// Maps a client-side wire [`ClientRequestCode`](crate::client::RequestCode)
/// to its logical [`ServiceId`].
///
/// Returns `None` for `RequestCode::Unknown` or any code that does
/// not have a defined logical identifier.
///
/// Legacy flat codes that identify a specific operation map to a
/// **method-level** identifier.  Node family codes (e.g.
/// `NodePower`) map to a **family-level** identifier because the
/// specific method is only known after payload deserialization.
#[cfg(any(feature = "client", feature = "server"))]
#[must_use]
#[allow(dead_code)] // used by tests; retained for symmetry with from_server_request_code
pub(crate) fn from_client_request_code(code: ClientRequestCode) -> Option<ServiceId> {
    match code {
        // Legacy flat codes — these identify a specific operation.
        ClientRequestCode::DnsStart => Some(COMMON_DNS_START),
        ClientRequestCode::DnsStop => Some(COMMON_DNS_STOP),
        ClientRequestCode::Reboot => Some(NODE_POWER_REBOOT),
        ClientRequestCode::ReloadConfig => Some(COMMON_RELOAD_CONFIG),
        ClientRequestCode::ReloadTi => Some(COMMON_RELOAD_TI),
        ClientRequestCode::ResourceUsage => Some(NODE_OBSERVATION_RESOURCE_USAGE),
        ClientRequestCode::TorExitNodeList => Some(COMMON_TOR_EXIT_NODE_LIST),
        ClientRequestCode::SamplingPolicyList => Some(COMMON_SAMPLING_POLICY_LIST),
        ClientRequestCode::ReloadFilterRule => Some(COMMON_RELOAD_FILTER_RULE),
        ClientRequestCode::UpdateConfig => Some(COMMON_UPDATE_CONFIG),
        ClientRequestCode::DeleteCustomerData => Some(COMMON_DELETE_CUSTOMER_DATA),
        ClientRequestCode::DeleteSamplingPolicy => Some(COMMON_DELETE_SAMPLING_POLICY),
        ClientRequestCode::InternalNetworkList => Some(COMMON_INTERNAL_NETWORK_LIST),
        ClientRequestCode::Allowlist => Some(COMMON_ALLOWLIST),
        ClientRequestCode::Blocklist => Some(COMMON_BLOCKLIST),
        ClientRequestCode::EchoRequest => Some(COMMON_ECHO),
        ClientRequestCode::TrustedUserAgentList => Some(COMMON_TRUSTED_USER_AGENT_LIST),
        ClientRequestCode::TrustedDomainList => Some(COMMON_TRUSTED_DOMAIN_LIST),
        ClientRequestCode::ProcessList => Some(NODE_OBSERVATION_PROCESS_LIST),
        ClientRequestCode::SemiSupervisedModels => Some(COMMON_SEMI_SUPERVISED_MODELS),
        ClientRequestCode::Shutdown => Some(NODE_POWER_SHUTDOWN),

        // Node feature-family codes.  These map to the family
        // level; the specific method is determined by deserializing
        // the request payload, not by the wire code alone.
        ClientRequestCode::NodeService => Some(NODE_SERVICE),
        ClientRequestCode::NodeNetworkInterface => Some(NODE_NETWORK_INTERFACE),
        ClientRequestCode::NodeHostname => Some(NODE_HOSTNAME),
        ClientRequestCode::NodeTimeSync => Some(NODE_TIME_SYNC),
        ClientRequestCode::NodeLogging => Some(NODE_LOGGING),
        ClientRequestCode::NodeRemoteAccess => Some(NODE_REMOTE_ACCESS),
        ClientRequestCode::NodePower => Some(NODE_POWER),
        ClientRequestCode::NodeObservation => Some(NODE_OBSERVATION),
        ClientRequestCode::NodeVersion => Some(NODE_VERSION),
        ClientRequestCode::NodePackage => Some(NODE_PACKAGE),
        ClientRequestCode::NodeEnroll => Some(NODE_ENROLL),

        ClientRequestCode::Unknown => None,
    }
}

/// Maps a server-side wire [`ServerRequestCode`](crate::server::RequestCode)
/// to its logical [`ServiceId`].
///
/// Returns `None` for `RequestCode::Unknown` or any code that does
/// not have a defined logical identifier.  Each server request code
/// maps to a specific method-level identifier.
#[cfg(any(feature = "client", feature = "server"))]
#[must_use]
#[allow(dead_code)] // used by tests and by server::handler; unused under client-only builds
pub(crate) fn from_server_request_code(code: ServerRequestCode) -> Option<ServiceId> {
    match code {
        ServerRequestCode::GetDataSource => Some(SERVER_DATA_SOURCE_GET),
        ServerRequestCode::GetDataSourceList => Some(SERVER_DATA_SOURCE_LIST),
        ServerRequestCode::InsertDataSource => Some(SERVER_DATA_SOURCE_INSERT),
        ServerRequestCode::GetModel => Some(SERVER_MODEL_GET),
        ServerRequestCode::GetModelNames => Some(SERVER_MODEL_GET_NAMES),
        ServerRequestCode::InsertModel => Some(SERVER_MODEL_INSERT),
        ServerRequestCode::RemoveModel => Some(SERVER_MODEL_REMOVE),
        ServerRequestCode::UpdateModel => Some(SERVER_MODEL_UPDATE),
        ServerRequestCode::GetPretrainedModel => Some(SERVER_MODEL_GET_PRETRAINED),
        ServerRequestCode::GetIndicator => Some(SERVER_INDICATOR_GET),
        ServerRequestCode::GetMaxEventIdNum => Some(SERVER_EVENT_GET_MAX_ID_NUM),
        ServerRequestCode::InsertEventLabels => Some(SERVER_EVENT_INSERT_LABELS),
        ServerRequestCode::InsertColumnStatistics => Some(SERVER_STATISTICS_INSERT_COLUMN),
        ServerRequestCode::InsertTimeSeries => Some(SERVER_STATISTICS_INSERT_TIME_SERIES),
        ServerRequestCode::RemoveOutliers => Some(SERVER_OUTLIER_REMOVE),
        ServerRequestCode::UpdateOutliers => Some(SERVER_OUTLIER_UPDATE),
        ServerRequestCode::GetOutliers => Some(SERVER_OUTLIER_GET),
        ServerRequestCode::UpdateClusters => Some(SERVER_CLUSTER_UPDATE),
        ServerRequestCode::GetLabelDbPatterns => Some(SERVER_LABEL_GET_DB_PATTERNS),
        ServerRequestCode::RenewCertificate => Some(SERVER_CERTIFICATE_RENEW),
        ServerRequestCode::GetConfig => Some(SERVER_CONFIG_GET),
        ServerRequestCode::UpdateHostOpenedPorts => Some(SERVER_HOST_UPDATE_OPENED_PORTS),
        ServerRequestCode::UpdateHostOsAgents => Some(SERVER_HOST_UPDATE_OS_AGENTS),
        ServerRequestCode::GetTrustedDomainList => Some(SERVER_LIST_TRUSTED_DOMAIN),
        ServerRequestCode::GetTorExitNodeList => Some(SERVER_LIST_TOR_EXIT_NODE),
        ServerRequestCode::GetInternalNetworkList => Some(SERVER_LIST_INTERNAL_NETWORK),
        ServerRequestCode::GetAllowlist => Some(SERVER_LIST_ALLOWLIST),
        ServerRequestCode::GetBlocklist => Some(SERVER_LIST_BLOCKLIST),
        ServerRequestCode::GetTrustedUserAgentList => Some(SERVER_LIST_TRUSTED_USER_AGENT),
        ServerRequestCode::GetSamplingPolicyList => Some(SERVER_LIST_SAMPLING_POLICY),
        ServerRequestCode::ReportCustomerDataDeletion => Some(SERVER_CUSTOMER_DATA_DELETION_REPORT),
        ServerRequestCode::Unknown => None,
    }
}

/// Returns a slice of all known [`ServiceId`] constants.
///
/// Useful for capability reporting, audit, and testing coverage.
/// The slice includes both family-level and method-level
/// identifiers for all client (node/common) and server surfaces.
///
/// ```
/// use review_protocol::service_id;
///
/// let ids = service_id::all();
/// assert!(ids.contains(&service_id::NODE_POWER_REBOOT));
/// assert!(ids.contains(&service_id::NODE_POWER)); // family
/// ```
#[must_use]
// The body is one entry per identifier, so its length tracks the number of
// service identifiers rather than any branching to be broken up.
#[allow(clippy::too_many_lines)]
pub fn all() -> &'static [ServiceId] {
    &[
        // node family-level
        NODE_SERVICE,
        NODE_NETWORK_INTERFACE,
        NODE_HOSTNAME,
        NODE_TIME_SYNC,
        NODE_LOGGING,
        NODE_REMOTE_ACCESS,
        NODE_POWER,
        NODE_OBSERVATION,
        NODE_VERSION,
        NODE_PACKAGE,
        NODE_ENROLL,
        // node.service
        NODE_SERVICE_START,
        NODE_SERVICE_STOP,
        NODE_SERVICE_STATUS,
        NODE_SERVICE_RESTART,
        // node.network_interface
        NODE_NETWORK_INTERFACE_LIST,
        NODE_NETWORK_INTERFACE_GET,
        NODE_NETWORK_INTERFACE_SET,
        NODE_NETWORK_INTERFACE_RESET_CONFIG,
        NODE_NETWORK_INTERFACE_REMOVE,
        // node.hostname
        NODE_HOSTNAME_GET,
        NODE_HOSTNAME_SET,
        // node.time_sync
        NODE_TIME_SYNC_GET,
        NODE_TIME_SYNC_SET,
        NODE_TIME_SYNC_ENABLE,
        NODE_TIME_SYNC_DISABLE,
        NODE_TIME_SYNC_STATUS,
        // node.logging
        NODE_LOGGING_GET,
        NODE_LOGGING_SET,
        NODE_LOGGING_CLEAR,
        NODE_LOGGING_RESTART,
        // node.remote_access
        NODE_REMOTE_ACCESS_GET,
        NODE_REMOTE_ACCESS_SET,
        NODE_REMOTE_ACCESS_RESTART,
        // node.power
        NODE_POWER_REBOOT,
        NODE_POWER_SHUTDOWN,
        NODE_POWER_GRACEFUL_REBOOT,
        NODE_POWER_GRACEFUL_SHUTDOWN,
        // node.observation
        NODE_OBSERVATION_PROCESS_LIST,
        NODE_OBSERVATION_RESOURCE_USAGE,
        NODE_OBSERVATION_UPTIME,
        // node.version
        NODE_VERSION_GET,
        NODE_VERSION_SET_OS,
        NODE_VERSION_SET_PRODUCT,
        // node.package
        NODE_PACKAGE_INSTALL,
        NODE_PACKAGE_REMOVE,
        NODE_PACKAGE_LIST,
        NODE_PACKAGE_STATUS,
        // node.enroll
        NODE_ENROLL_REGISTER,
        NODE_ENROLL_DEREGISTER,
        // common
        COMMON_DNS_START,
        COMMON_DNS_STOP,
        COMMON_RELOAD_CONFIG,
        COMMON_UPDATE_CONFIG,
        COMMON_DELETE_CUSTOMER_DATA,
        COMMON_RELOAD_TI,
        COMMON_TOR_EXIT_NODE_LIST,
        COMMON_TRUSTED_DOMAIN_LIST,
        COMMON_SAMPLING_POLICY_LIST,
        COMMON_DELETE_SAMPLING_POLICY,
        COMMON_RELOAD_FILTER_RULE,
        COMMON_INTERNAL_NETWORK_LIST,
        COMMON_ALLOWLIST,
        COMMON_BLOCKLIST,
        COMMON_ECHO,
        COMMON_TRUSTED_USER_AGENT_LIST,
        COMMON_SEMI_SUPERVISED_MODELS,
        COMMON_RENEW_CERTIFICATE,
        // server.customer_data_deletion
        SERVER_CUSTOMER_DATA_DELETION_REPORT,
        // server.data_source
        SERVER_DATA_SOURCE_GET,
        SERVER_DATA_SOURCE_LIST,
        SERVER_DATA_SOURCE_INSERT,
        // server.model
        SERVER_MODEL_GET,
        SERVER_MODEL_GET_NAMES,
        SERVER_MODEL_INSERT,
        SERVER_MODEL_REMOVE,
        SERVER_MODEL_UPDATE,
        SERVER_MODEL_GET_PRETRAINED,
        // server.indicator
        SERVER_INDICATOR_GET,
        // server.event
        SERVER_EVENT_GET_MAX_ID_NUM,
        SERVER_EVENT_INSERT_LABELS,
        // server.statistics
        SERVER_STATISTICS_INSERT_COLUMN,
        SERVER_STATISTICS_INSERT_TIME_SERIES,
        // server.outlier
        SERVER_OUTLIER_GET,
        SERVER_OUTLIER_REMOVE,
        SERVER_OUTLIER_UPDATE,
        // server.cluster
        SERVER_CLUSTER_UPDATE,
        // server.label
        SERVER_LABEL_GET_DB_PATTERNS,
        // server.certificate
        SERVER_CERTIFICATE_RENEW,
        // server.config
        SERVER_CONFIG_GET,
        // server.host
        SERVER_HOST_UPDATE_OPENED_PORTS,
        SERVER_HOST_UPDATE_OS_AGENTS,
        // server.list
        SERVER_LIST_TRUSTED_DOMAIN,
        SERVER_LIST_TOR_EXIT_NODE,
        SERVER_LIST_INTERNAL_NETWORK,
        SERVER_LIST_ALLOWLIST,
        SERVER_LIST_BLOCKLIST,
        SERVER_LIST_TRUSTED_USER_AGENT,
        SERVER_LIST_SAMPLING_POLICY,
    ]
}

#[cfg(all(test, any(feature = "client", feature = "server")))]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn display_format() {
        assert_eq!(NODE_POWER_REBOOT.to_string(), "node.power.reboot");
        assert_eq!(
            NODE_OBSERVATION_PROCESS_LIST.to_string(),
            "node.observation.process_list"
        );
        assert_eq!(
            COMMON_RENEW_CERTIFICATE.to_string(),
            "common.renew_certificate"
        );
        assert_eq!(COMMON_ECHO.to_string(), "common.echo");
        assert_eq!(SERVER_MODEL_GET.to_string(), "server.model.get");
    }

    #[test]
    fn display_format_family_level() {
        assert_eq!(NODE_POWER.to_string(), "node.power");
        assert_eq!(NODE_SERVICE.to_string(), "node.service");
        assert_eq!(NODE_OBSERVATION.to_string(), "node.observation");
        assert_eq!(NODE_PACKAGE.to_string(), "node.package");
        assert_eq!(NODE_ENROLL.to_string(), "node.enroll");
    }

    #[test]
    fn node_package_display_format() {
        assert_eq!(NODE_PACKAGE_INSTALL.to_string(), "node.package.install");
        assert_eq!(NODE_PACKAGE_REMOVE.to_string(), "node.package.remove");
        assert_eq!(NODE_PACKAGE_LIST.to_string(), "node.package.list");
        assert_eq!(NODE_PACKAGE_STATUS.to_string(), "node.package.status");
    }

    #[test]
    fn node_enroll_display_format() {
        assert_eq!(NODE_ENROLL_REGISTER.to_string(), "node.enroll.register");
        assert_eq!(NODE_ENROLL_DEREGISTER.to_string(), "node.enroll.deregister");
    }

    #[test]
    fn is_family() {
        assert!(NODE_POWER.is_family());
        assert!(NODE_SERVICE.is_family());
        assert!(!NODE_POWER_REBOOT.is_family());
        assert!(!COMMON_ECHO.is_family());
        assert!(!SERVER_MODEL_GET.is_family());
    }

    #[test]
    fn equality_and_hash() {
        let a = ServiceId::new("node.power", "reboot");
        assert_eq!(a, NODE_POWER_REBOOT);

        let mut set = HashSet::new();
        set.insert(NODE_POWER_REBOOT);
        assert!(set.contains(&a));
    }

    #[test]
    fn client_from_request_code_legacy() {
        assert_eq!(
            from_client_request_code(ClientRequestCode::DnsStart),
            Some(COMMON_DNS_START)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::Reboot),
            Some(NODE_POWER_REBOOT)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::Shutdown),
            Some(NODE_POWER_SHUTDOWN)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::ResourceUsage),
            Some(NODE_OBSERVATION_RESOURCE_USAGE)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::ProcessList),
            Some(NODE_OBSERVATION_PROCESS_LIST)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::EchoRequest),
            Some(COMMON_ECHO)
        );
    }

    #[test]
    fn client_from_request_code_node_families() {
        // Node family codes should map to family-level identifiers.
        assert_eq!(
            from_client_request_code(ClientRequestCode::NodePower),
            Some(NODE_POWER)
        );
        assert!(
            from_client_request_code(ClientRequestCode::NodePower)
                .unwrap()
                .is_family()
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::NodeService),
            Some(NODE_SERVICE)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::NodeNetworkInterface),
            Some(NODE_NETWORK_INTERFACE)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::NodeHostname),
            Some(NODE_HOSTNAME)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::NodeTimeSync),
            Some(NODE_TIME_SYNC)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::NodeLogging),
            Some(NODE_LOGGING)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::NodeRemoteAccess),
            Some(NODE_REMOTE_ACCESS)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::NodeObservation),
            Some(NODE_OBSERVATION)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::NodeVersion),
            Some(NODE_VERSION)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::NodePackage),
            Some(NODE_PACKAGE)
        );
        assert_eq!(
            from_client_request_code(ClientRequestCode::NodeEnroll),
            Some(NODE_ENROLL)
        );
    }

    #[test]
    fn client_from_request_code_unknown() {
        assert_eq!(from_client_request_code(ClientRequestCode::Unknown), None);
    }

    /// Every non-`Unknown` client `RequestCode` variant should have
    /// a logical identifier mapping.
    #[test]
    fn all_known_client_request_codes_are_mapped() {
        let codes: &[ClientRequestCode] = &[
            ClientRequestCode::DnsStart,
            ClientRequestCode::DnsStop,
            ClientRequestCode::Reboot,
            ClientRequestCode::ReloadConfig,
            ClientRequestCode::ReloadTi,
            ClientRequestCode::ResourceUsage,
            ClientRequestCode::TorExitNodeList,
            ClientRequestCode::SamplingPolicyList,
            ClientRequestCode::ReloadFilterRule,
            ClientRequestCode::UpdateConfig,
            ClientRequestCode::DeleteCustomerData,
            ClientRequestCode::DeleteSamplingPolicy,
            ClientRequestCode::InternalNetworkList,
            ClientRequestCode::Allowlist,
            ClientRequestCode::Blocklist,
            ClientRequestCode::EchoRequest,
            ClientRequestCode::TrustedUserAgentList,
            ClientRequestCode::TrustedDomainList,
            ClientRequestCode::ProcessList,
            ClientRequestCode::SemiSupervisedModels,
            ClientRequestCode::Shutdown,
            ClientRequestCode::NodeService,
            ClientRequestCode::NodeNetworkInterface,
            ClientRequestCode::NodeHostname,
            ClientRequestCode::NodeTimeSync,
            ClientRequestCode::NodeLogging,
            ClientRequestCode::NodeRemoteAccess,
            ClientRequestCode::NodePower,
            ClientRequestCode::NodeObservation,
            ClientRequestCode::NodeVersion,
            ClientRequestCode::NodePackage,
            ClientRequestCode::NodeEnroll,
        ];
        for &code in codes {
            assert!(
                from_client_request_code(code).is_some(),
                "client::RequestCode::{code:?} should map to a ServiceId"
            );
        }
    }

    /// Every non-`Unknown` server `RequestCode` variant should have
    /// a logical identifier mapping.
    #[test]
    fn all_known_server_request_codes_are_mapped() {
        let codes: &[ServerRequestCode] = &[
            ServerRequestCode::GetDataSource,
            ServerRequestCode::GetIndicator,
            ServerRequestCode::GetMaxEventIdNum,
            ServerRequestCode::GetModel,
            ServerRequestCode::GetModelNames,
            ServerRequestCode::InsertColumnStatistics,
            ServerRequestCode::InsertModel,
            ServerRequestCode::InsertTimeSeries,
            ServerRequestCode::RemoveModel,
            ServerRequestCode::RemoveOutliers,
            ServerRequestCode::UpdateClusters,
            ServerRequestCode::UpdateModel,
            ServerRequestCode::UpdateOutliers,
            ServerRequestCode::InsertEventLabels,
            ServerRequestCode::GetDataSourceList,
            ServerRequestCode::GetLabelDbPatterns,
            ServerRequestCode::InsertDataSource,
            ServerRequestCode::RenewCertificate,
            ServerRequestCode::GetTrustedDomainList,
            ServerRequestCode::GetOutliers,
            ServerRequestCode::GetTorExitNodeList,
            ServerRequestCode::GetInternalNetworkList,
            ServerRequestCode::GetAllowlist,
            ServerRequestCode::GetBlocklist,
            ServerRequestCode::GetPretrainedModel,
            ServerRequestCode::GetTrustedUserAgentList,
            ServerRequestCode::GetConfig,
            ServerRequestCode::UpdateHostOpenedPorts,
            ServerRequestCode::UpdateHostOsAgents,
            ServerRequestCode::GetSamplingPolicyList,
            ServerRequestCode::ReportCustomerDataDeletion,
        ];
        for &code in codes {
            assert!(
                from_server_request_code(code).is_some(),
                "server::RequestCode::{code:?} should map to a ServiceId"
            );
        }
    }

    #[test]
    fn server_from_request_code_unknown() {
        assert_eq!(from_server_request_code(ServerRequestCode::Unknown), None);
    }

    #[test]
    fn server_from_request_code_samples() {
        assert_eq!(
            from_server_request_code(ServerRequestCode::GetDataSource),
            Some(SERVER_DATA_SOURCE_GET)
        );
        assert_eq!(
            from_server_request_code(ServerRequestCode::InsertModel),
            Some(SERVER_MODEL_INSERT)
        );
        assert_eq!(
            from_server_request_code(ServerRequestCode::GetConfig),
            Some(SERVER_CONFIG_GET)
        );
        assert_eq!(
            from_server_request_code(ServerRequestCode::RenewCertificate),
            Some(SERVER_CERTIFICATE_RENEW)
        );
        assert_eq!(
            from_server_request_code(ServerRequestCode::ReportCustomerDataDeletion),
            Some(SERVER_CUSTOMER_DATA_DELETION_REPORT)
        );
    }

    /// All service identifiers returned by [`all()`] should have
    /// unique string representations.
    #[test]
    fn all_ids_are_unique() {
        let ids = all();
        let strings: HashSet<String> = ids.iter().map(ToString::to_string).collect();
        assert_eq!(
            ids.len(),
            strings.len(),
            "duplicate ServiceId string representations found"
        );
    }

    /// The `all()` list should not be empty and should include
    /// identifiers from node families, common operations, and
    /// server operations.
    #[test]
    fn all_covers_families() {
        let ids = all();
        assert!(!ids.is_empty());
        // Family-level
        assert!(ids.contains(&NODE_POWER));
        // Node method-level
        assert!(ids.contains(&NODE_POWER_REBOOT));
        // Common
        assert!(ids.contains(&COMMON_RENEW_CERTIFICATE));
        assert!(ids.contains(&NODE_OBSERVATION_PROCESS_LIST));
        // Server
        assert!(ids.contains(&SERVER_MODEL_GET));
        assert!(ids.contains(&SERVER_DATA_SOURCE_LIST));
        assert!(ids.contains(&SERVER_CUSTOMER_DATA_DELETION_REPORT));
    }

    #[test]
    fn node_request_service_ids() {
        use crate::types::node::*;

        // node.power
        assert_eq!(NodePowerRequest::Reboot.service_id(), NODE_POWER_REBOOT);
        assert_eq!(NodePowerRequest::Shutdown.service_id(), NODE_POWER_SHUTDOWN);
        assert_eq!(
            NodePowerRequest::GracefulReboot.service_id(),
            NODE_POWER_GRACEFUL_REBOOT
        );
        assert_eq!(
            NodePowerRequest::GracefulShutdown.service_id(),
            NODE_POWER_GRACEFUL_SHUTDOWN
        );

        // node.observation
        assert_eq!(
            NodeObservationRequest::ProcessList.service_id(),
            NODE_OBSERVATION_PROCESS_LIST
        );
        assert_eq!(
            NodeObservationRequest::ResourceUsage.service_id(),
            NODE_OBSERVATION_RESOURCE_USAGE
        );
        assert_eq!(
            NodeObservationRequest::Uptime.service_id(),
            NODE_OBSERVATION_UPTIME
        );

        // node.service
        assert_eq!(
            NodeServiceRequest::Start {
                service: "x".into()
            }
            .service_id(),
            NODE_SERVICE_START
        );
        assert_eq!(
            NodeServiceRequest::Stop {
                service: "x".into()
            }
            .service_id(),
            NODE_SERVICE_STOP
        );

        // node.hostname
        assert_eq!(NodeHostnameRequest::Get.service_id(), NODE_HOSTNAME_GET);
        assert_eq!(
            NodeHostnameRequest::Set {
                hostname: "h".into()
            }
            .service_id(),
            NODE_HOSTNAME_SET
        );

        // node.version
        assert_eq!(NodeVersionRequest::Get.service_id(), NODE_VERSION_GET);
        assert_eq!(
            NodeVersionRequest::SetOsVersion {
                version: "v".into()
            }
            .service_id(),
            NODE_VERSION_SET_OS
        );
        assert_eq!(
            NodeVersionRequest::SetProductVersion {
                version: "v".into()
            }
            .service_id(),
            NODE_VERSION_SET_PRODUCT
        );
    }

    #[test]
    fn node_package_request_service_ids() {
        use crate::types::node::{FailurePolicy, NodePackageRequest};

        assert_eq!(
            NodePackageRequest::Install {
                target: "sensor".into(),
                instance: Some(1),
                version: "1.2.3".into(),
                commit: "0123456789abcdef".into(),
                size: 1024,
                idempotency_key: "k".into(),
                bootstrap_material: None,
                on_failure: FailurePolicy::Rollback,
            }
            .service_id(),
            NODE_PACKAGE_INSTALL
        );
        assert_eq!(
            NodePackageRequest::Remove {
                target: "sensor".into(),
                instance: None,
                idempotency_key: "k".into(),
            }
            .service_id(),
            NODE_PACKAGE_REMOVE
        );
        assert_eq!(
            NodePackageRequest::ListInstalled.service_id(),
            NODE_PACKAGE_LIST
        );
        assert_eq!(
            NodePackageRequest::Status {
                target: "sensor".into(),
                instance: Some(2),
            }
            .service_id(),
            NODE_PACKAGE_STATUS
        );

        for id in [
            NODE_PACKAGE_INSTALL,
            NODE_PACKAGE_REMOVE,
            NODE_PACKAGE_LIST,
            NODE_PACKAGE_STATUS,
        ] {
            assert!(!id.is_family());
            assert!(all().contains(&id));
        }
        assert!(NODE_PACKAGE.is_family());
        assert!(all().contains(&NODE_PACKAGE));
    }

    #[test]
    fn node_enroll_request_service_ids() {
        use std::time::Duration;

        use crate::types::node::{
            CertGroup, DeliveryMode, NodeEnrollRequest, ReloadHook, ServiceSpec,
        };

        assert_eq!(
            NodeEnrollRequest::Register {
                service_name: "sensor".into(),
                delivery_mode: DeliveryMode::RemoteBootstrap,
                host: "host01".into(),
                instance: Some(1),
                spec: ServiceSpec {
                    component: "sensor".into(),
                    service_name: "sensor".into(),
                    reload: ReloadHook("reload-sensor".into()),
                    cert_group: Some(CertGroup("internal".into())),
                },
                wrap_ttl: Duration::from_mins(10),
                idempotency_key: "k".into(),
            }
            .service_id(),
            NODE_ENROLL_REGISTER
        );
        assert_eq!(
            NodeEnrollRequest::Deregister {
                service_name: "sensor".into(),
                host: "host01".into(),
                instance: None,
                idempotency_key: "k".into(),
            }
            .service_id(),
            NODE_ENROLL_DEREGISTER
        );

        for id in [NODE_ENROLL_REGISTER, NODE_ENROLL_DEREGISTER] {
            assert!(!id.is_family());
            assert!(all().contains(&id));
        }
        assert!(NODE_ENROLL.is_family());
        assert!(all().contains(&NODE_ENROLL));
    }

    /// Every `service_id()` return value should be method-level
    /// (not family-level).
    #[test]
    fn node_request_service_ids_are_method_level() {
        use crate::types::node::*;

        assert!(!NodePowerRequest::Reboot.service_id().is_family());
        assert!(!NodeObservationRequest::ProcessList.service_id().is_family());
        assert!(
            !NodeServiceRequest::Start {
                service: "x".into()
            }
            .service_id()
            .is_family()
        );
        assert!(!NodeHostnameRequest::Get.service_id().is_family());
        assert!(!NodeTimeSyncRequest::Get.service_id().is_family());
        assert!(!NodeLoggingRequest::Get.service_id().is_family());
        assert!(!NodeRemoteAccessRequest::Get.service_id().is_family());
        assert!(!NodeVersionRequest::Get.service_id().is_family());
        assert!(!NodePackageRequest::ListInstalled.service_id().is_family());
    }
}
