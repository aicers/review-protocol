//! Data types used by the protocol.

use std::{
    net::{IpAddr, SocketAddr},
    ops::RangeInclusive,
    time::Duration,
};

use ipnet::IpNet;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
pub use structured::ColumnStatistics;

/// A request to delete data belonging to a customer from a service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerDataDeletionRequest {
    /// The customer whose data must be deleted.
    pub customer_id: u32,
    /// The FQDN of the service that must delete the customer data.
    pub host_fqdn: String,
    /// The deletion-request timestamp.
    pub requested_at: i64,
}

/// The final result of processing a customer-data deletion request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerDataDeletionReport {
    /// The customer ID copied from the original deletion request.
    pub customer_id: u32,
    /// The service FQDN copied from the original deletion request.
    pub host_fqdn: String,
    /// The original deletion-request timestamp.
    pub requested_at: i64,
    /// The completion or recorded failure timestamp, in the same unit as
    /// `requested_at`.
    pub completed_at: Option<i64>,
    /// The service that processed the deletion request.
    pub reporter: CustomerDataDeletionReporter,
    /// The final result of the deletion request.
    pub outcome: CustomerDataDeletionOutcome,
}

/// The service reporting a customer-data deletion result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustomerDataDeletionReporter {
    Sensor,
    SemiSupervised,
}

/// The outcome of a customer-data deletion request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustomerDataDeletionOutcome {
    Succeeded,
    Failed(String),
}

/// The data source key, either a numeric ID or a name.
#[derive(Debug, Deserialize, Serialize)]
pub enum DataSourceKey<'a> {
    Id(u32),
    Name(&'a str),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DataSource {
    pub id: u32,
    pub name: String,

    pub server_name: String,
    pub address: SocketAddr,

    pub data_type: DataType,
    pub source: String,
    pub kind: Option<String>,

    pub description: String,
}

/// The type of data that a data source provides.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, IntoPrimitive, TryFromPrimitive)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum DataType {
    /// comma-separated values
    Csv = 0,
    /// line-based text data
    Log = 1,
    /// time series data
    TimeSeries = 2,
}

/// CPU, memory, and disk usage.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResourceUsage {
    /// The average CPU usage in percent.
    pub cpu_usage: f32,

    /// The RAM size in bytes.
    pub total_memory: u64,

    /// The amount of used RAM in bytes.
    pub used_memory: u64,

    /// The disk space in bytes that is currently used.
    pub disk_used_bytes: u64,

    /// The disk space in bytes that is available to non-root users.
    pub disk_available_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Process {
    pub user: String,
    pub cpu_usage: f32,
    pub mem_usage: f64,
    pub start_time: i64,
    pub command: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostNetworkGroup {
    pub hosts: Vec<IpAddr>,
    pub networks: Vec<IpNet>,
    pub ip_ranges: Vec<RangeInclusive<IpAddr>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum SamplingKind {
    Conn = 0,
    Dns = 1,
    Http = 2,
    Rdp = 3,
}

// A policy for time series sampling.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SamplingPolicy {
    pub id: u32,
    pub kind: SamplingKind,
    pub interval: Duration,
    pub period: Duration,
    pub offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
}

// IP address, port numbers, and protocols.
pub type TrafficFilterRule = (IpNet, Option<Vec<u16>>, Option<Vec<u16>>);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u8)]
pub enum EventCategory {
    Reconnaissance = 1,
    InitialAccess = 2,
    Execution = 3,
    CredentialAccess = 4,
    Discovery = 5,
    LateralMovement = 6,
    CommandAndControl = 7,
    Exfiltration = 8,
    Impact = 9,
    Collection = 10,
    DefenseEvasion = 11,
    Persistence = 12,
    PrivilegeEscalation = 13,
    ResourceDevelopment = 14,
}

#[derive(Clone, Copy, Debug, Deserialize_repr, Eq, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum LabelDbKind {
    Ip = 0,
    Url = 1,
    Token = 2,
    Regex = 3,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum RuleKind {
    Os,
    AgentSoftware,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserAgent {
    pub name: String,
    pub header: String,
    pub kind: RuleKind,
    pub last_modification_time: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LabelDbRule {
    pub rule_id: u32,
    pub category: Option<EventCategory>,
    pub name: String,
    pub kind: Option<RuleKind>,
    pub description: Option<String>,
    pub references: Option<Vec<String>>,
    pub samples: Option<Vec<String>>,
    pub signatures: Option<Vec<String>>,
    pub confidence: Option<f32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LabelDb {
    pub id: u32,
    pub name: String,
    pub description: Option<String>,
    pub kind: LabelDbKind,
    pub category: Option<EventCategory>,
    pub version: String,
    pub patterns: Vec<LabelDbRule>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Status {
    Ready,
    Idle,
}

/// Threat level of a detection event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ThreatLevel {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ColumnStatisticsUpdate {
    pub cluster_id: u32,
    pub column_statistics: Vec<ColumnStatistics>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeCount {
    pub time: jiff::civil::DateTime,
    pub count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeSeries {
    pub count_index: Option<usize>,
    pub series: Vec<TimeCount>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeSeriesUpdate {
    pub cluster_id: u32,
    pub time_series: Vec<TimeSeries>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateClusterRequest {
    pub cluster_id: u32,
    pub detector_id: i32,
    pub signature: String,
    pub score: Option<f64>,
    pub size: i64,
    pub event_ids: Vec<(i64, String)>,
    pub status_id: i32,
    pub labels: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutlierInfo {
    pub id: i64,
    pub rank: i64,
    pub distance: f64,
    pub sensor: String,
}

#[derive(Serialize, Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[allow(clippy::module_name_repetitions)]
pub enum EventKind {
    DnsCovertChannel,
    HttpThreat,
    RdpBruteForce,
    RepeatedHttpSessions,
    ExtraThreat,
    TorConnection,
    DomainGenerationAlgorithm,
    FtpBruteForce,
    FtpPlainText,
    PortScan,
    MultiHostPortScan,
    NonBrowser,
    LdapBruteForce,
    LdapPlainText,
    ExternalDdos,
    CryptocurrencyMiningPool,
    BlocklistConn,
    BlocklistDns,
    BlocklistDceRpc,
    BlocklistFtp,
    BlocklistHttp,
    BlocklistKerberos,
    BlocklistLdap,
    BlocklistMqtt,
    BlocklistNfs,
    BlocklistNtlm,
    BlocklistRdp,
    BlocklistSmb,
    BlocklistSmtp,
    BlocklistSsh,
    BlocklistTls,
    WindowsThreat,
    NetworkThreat,
    LockyRansomware,
    SuspiciousTlsTraffic,
    BlocklistBootp,
    BlocklistDhcp,
    TorConnectionConn,
    BlocklistRadius,
    BlocklistMalformedDns,
    UnusualDestinationPattern,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventMessage {
    #[serde(with = "jiff::fmt::serde::timestamp::nanosecond::required")]
    pub time: jiff::Timestamp,
    pub kind: EventKind,
    #[serde(with = "serde_bytes")]
    pub fields: Vec<u8>,
}

/// Types for the `node` agent family, grouping host-control and
/// host-observation functionality under stable feature families.
///
/// Each feature family is represented by a request/response enum pair.
/// Callers construct a request variant, send it through the protocol
/// layer, and receive the corresponding response variant.
///
/// # Stability
///
/// Low-level wire-format details such as field layout, byte order, or
/// serialization encoding are **not** part of the public contract and
/// may change without notice.
pub mod node {
    use std::time::Duration;

    use serde::{Deserialize, Serialize};

    use super::{Process, ResourceUsage};

    // ── service control ─────────────────────────────────────────

    /// Request for managing system services on a node.
    ///
    /// Send one of the variants to start, stop, restart, or query the
    /// status of a named service on the target node.
    ///
    /// # Examples
    ///
    /// ```
    /// use review_protocol::types::node::NodeServiceRequest;
    ///
    /// let req = NodeServiceRequest::Start {
    ///     service: "nginx".into(),
    /// };
    /// assert_eq!(
    ///     format!("{req:?}"),
    ///     r#"Start { service: "nginx" }"#,
    /// );
    /// ```
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeServiceRequest {
        /// Start a service by name.
        Start { service: String },
        /// Stop a service by name.
        Stop { service: String },
        /// Query the status of a service by name.
        Status { service: String },
        /// Restart a service by name.
        Restart { service: String },
    }

    /// Response from a service-control operation.
    ///
    /// A [`Status`](Self::Status) variant is returned for
    /// [`NodeServiceRequest::Status`]; all other operations return
    /// [`Done`](Self::Done) on success.
    ///
    /// # Examples
    ///
    /// ```
    /// use review_protocol::types::node::NodeServiceResponse;
    ///
    /// let resp = NodeServiceResponse::Status { active: true };
    /// match resp {
    ///     NodeServiceResponse::Status { active } => {
    ///         assert!(active);
    ///     }
    ///     NodeServiceResponse::Done => {}
    /// }
    /// ```
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeServiceResponse {
        /// Status of the queried service.
        Status { active: bool },
        /// The operation completed successfully.
        Done,
    }

    // ── network interface management ────────────────────────────

    /// Request for managing network interfaces on a node.
    ///
    /// Use this type to list, inspect, configure, or reset network
    /// devices on the target node.  [`Set`](Self::Set) applies a
    /// partial configuration (only the fields present in
    /// [`NodeNetworkInterfaceConfig`] are changed), while
    /// [`Remove`](Self::Remove) removes the specified settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use review_protocol::types::node::{
    ///     NodeNetworkInterfaceConfig, NodeNetworkInterfaceRequest,
    /// };
    ///
    /// // Enable DHCP on eth0 without changing other settings.
    /// let req = NodeNetworkInterfaceRequest::Set {
    ///     device: "eth0".into(),
    ///     config: NodeNetworkInterfaceConfig {
    ///         addresses: None,
    ///         dhcp4: Some(true),
    ///         gateway4: None,
    ///         nameservers: None,
    ///     },
    /// };
    /// assert!(matches!(
    ///     req,
    ///     NodeNetworkInterfaceRequest::Set { .. },
    /// ));
    /// ```
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeNetworkInterfaceRequest {
        /// List network interface names, optionally filtered by a
        /// prefix.
        List { prefix: Option<String> },
        /// Get the full interface details for a device.
        Get { device: String },
        /// Reset the configuration of a device to defaults.
        ResetConfig { device: String },
        /// Apply configuration to a named device.
        Set {
            device: String,
            config: NodeNetworkInterfaceConfig,
        },
        /// Remove specific configuration from a named device.
        Remove {
            device: String,
            config: NodeNetworkInterfaceConfig,
        },
    }

    /// Response from a network-interface operation.
    ///
    /// [`List`](Self::List) is returned for
    /// [`NodeNetworkInterfaceRequest::List`], [`Get`](Self::Get) for
    /// [`NodeNetworkInterfaceRequest::Get`], and [`Done`](Self::Done)
    /// for mutating operations.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeNetworkInterfaceResponse {
        /// A list of device names.
        List { devices: Vec<String> },
        /// Full details for a single interface.
        Get {
            interface: Option<NodeNetworkInterface>,
        },
        /// The operation completed successfully.
        Done,
    }

    /// Configuration payload for a network interface.
    ///
    /// All fields are optional so that partial updates can be
    /// expressed (e.g. changing only `dhcp4` without touching
    /// `addresses`).  When used in a
    /// [`NodeNetworkInterfaceRequest::Set`], only the present fields
    /// are applied; `None` fields are left unchanged on the node.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub struct NodeNetworkInterfaceConfig {
        /// IP addresses to assign (as strings to support CIDR
        /// notation).
        pub addresses: Option<Vec<String>>,
        /// Whether DHCP for IPv4 should be enabled.
        pub dhcp4: Option<bool>,
        /// Default IPv4 gateway address.
        pub gateway4: Option<String>,
        /// DNS nameserver addresses.
        pub nameservers: Option<Vec<String>>,
    }

    /// A network interface together with its configuration.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub struct NodeNetworkInterface {
        /// The device name (e.g. `"eth0"`).
        pub device: String,
        /// The interface configuration.
        pub config: NodeNetworkInterfaceConfig,
    }

    // ── hostname management ─────────────────────────────────────

    /// Request for reading or setting the node hostname.
    ///
    /// # Examples
    ///
    /// ```
    /// use review_protocol::types::node::NodeHostnameRequest;
    ///
    /// let req = NodeHostnameRequest::Set {
    ///     hostname: "sensor-01".into(),
    /// };
    /// assert!(matches!(req, NodeHostnameRequest::Set { .. }));
    /// ```
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeHostnameRequest {
        /// Retrieve the current hostname.
        Get,
        /// Set the hostname to the given value.
        Set { hostname: String },
    }

    /// Response from a hostname operation.
    ///
    /// [`Get`](Self::Get) is returned for
    /// [`NodeHostnameRequest::Get`]; [`Done`](Self::Done) is returned
    /// after a successful [`NodeHostnameRequest::Set`].
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeHostnameResponse {
        /// The current hostname.
        Get { hostname: String },
        /// The operation completed successfully.
        Done,
    }

    // ── time synchronization management ─────────────────────────

    /// Request for managing NTP / time-synchronization settings.
    ///
    /// Use [`Get`](Self::Get) and [`Status`](Self::Status) for
    /// read-only queries.  [`Set`](Self::Set) replaces the entire NTP
    /// server list, while [`Enable`](Self::Enable) and
    /// [`Disable`](Self::Disable) control whether synchronization is
    /// active.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeTimeSyncRequest {
        /// Retrieve the current time-sync configuration.
        Get,
        /// Replace the list of NTP servers.
        Set { servers: Vec<String> },
        /// Enable time synchronization.
        Enable,
        /// Disable time synchronization.
        Disable,
        /// Query synchronization status.
        Status,
    }

    /// Response from a time-synchronization operation.
    ///
    /// [`Get`](Self::Get) returns the current NTP server list,
    /// [`Status`](Self::Status) indicates whether synchronization is
    /// enabled, and [`Done`](Self::Done) confirms a mutating
    /// operation succeeded.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeTimeSyncResponse {
        /// Current NTP server list, or `None` if not configured.
        Get { servers: Option<Vec<String>> },
        /// Current synchronization status.
        Status { enabled: bool },
        /// The operation completed successfully.
        Done,
    }

    // ── logging configuration ───────────────────────────────────

    /// Transport protocol for a logging endpoint.
    ///
    /// Used as part of [`NodeLoggingEndpoint`] to select the
    /// transport layer for forwarding log messages.
    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeLoggingProtocol {
        /// TCP transport.
        Tcp,
        /// UDP transport.
        Udp,
    }

    /// A remote logging endpoint.
    ///
    /// Describes a single destination to which the node forwards log
    /// messages.  Combine one or more endpoints in a
    /// [`NodeLoggingRequest::Set`] to configure forwarding.
    ///
    /// # Examples
    ///
    /// ```
    /// use review_protocol::types::node::{
    ///     NodeLoggingEndpoint, NodeLoggingProtocol,
    /// };
    ///
    /// let ep = NodeLoggingEndpoint {
    ///     protocol: NodeLoggingProtocol::Tcp,
    ///     address: "192.168.1.100".into(),
    ///     port: 514,
    /// };
    /// assert_eq!(ep.port, 514);
    /// ```
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct NodeLoggingEndpoint {
        /// Transport protocol to use.
        pub protocol: NodeLoggingProtocol,
        /// The destination address (hostname or IP).
        pub address: String,
        /// The destination port.
        pub port: u16,
    }

    /// Request for managing logging configuration on a node.
    ///
    /// [`Set`](Self::Set) replaces the entire endpoint list;
    /// [`Clear`](Self::Clear) removes all endpoints; and
    /// [`Restart`](Self::Restart) restarts the logging subsystem
    /// without changing its configuration.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeLoggingRequest {
        /// Retrieve the current logging endpoint configuration.
        Get,
        /// Replace the logging endpoint list.
        Set { endpoints: Vec<NodeLoggingEndpoint> },
        /// Remove all configured logging endpoints.
        Clear,
        /// Restart the logging subsystem.
        Restart,
    }

    /// Response from a logging-configuration operation.
    ///
    /// [`Get`](Self::Get) returns the current endpoint list (or
    /// `None` if no endpoints are configured); [`Done`](Self::Done)
    /// confirms a mutating operation succeeded.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeLoggingResponse {
        /// The current logging endpoint list, or `None` if not
        /// configured.
        Get {
            endpoints: Option<Vec<NodeLoggingEndpoint>>,
        },
        /// The operation completed successfully.
        Done,
    }

    // ── remote access configuration ─────────────────────────────

    /// Remote-access (SSH) configuration for a node.
    ///
    /// Currently exposes only the listen port.
    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct NodeRemoteAccessConfig {
        /// SSH listen port.
        pub port: u16,
    }

    /// Request for managing remote-access (e.g. SSH) settings.
    ///
    /// [`Get`](Self::Get) retrieves the current configuration,
    /// [`Set`](Self::Set) replaces it, and [`Restart`](Self::Restart)
    /// restarts the remote-access service with the current settings.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeRemoteAccessRequest {
        /// Retrieve the current remote-access configuration.
        Get,
        /// Replace the remote-access configuration.
        Set { config: NodeRemoteAccessConfig },
        /// Restart the remote-access service.
        Restart,
    }

    /// Response from a remote-access operation.
    ///
    /// [`Get`](Self::Get) is returned for
    /// [`NodeRemoteAccessRequest::Get`]; [`Done`](Self::Done)
    /// confirms a mutating operation succeeded.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeRemoteAccessResponse {
        /// The current remote-access configuration.
        Get { config: NodeRemoteAccessConfig },
        /// The operation completed successfully.
        Done,
    }

    // ── power control ───────────────────────────────────────────

    /// Request for node power-control operations.
    ///
    /// The immediate variants ([`Reboot`](Self::Reboot),
    /// [`Shutdown`](Self::Shutdown)) take effect right away, while
    /// the graceful variants allow running services to drain before
    /// the operation proceeds.
    ///
    /// # Examples
    ///
    /// ```
    /// use review_protocol::types::node::NodePowerRequest;
    ///
    /// let req = NodePowerRequest::GracefulReboot;
    /// assert!(matches!(req, NodePowerRequest::GracefulReboot));
    /// ```
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodePowerRequest {
        /// Reboot the node immediately.
        Reboot,
        /// Shut down the node immediately.
        Shutdown,
        /// Reboot the node gracefully.
        GracefulReboot,
        /// Shut down the node gracefully.
        GracefulShutdown,
    }

    /// Response from a power-control operation.
    ///
    /// [`Initiated`](Self::Initiated) confirms that the node has
    /// accepted the power command.  The node may become unreachable
    /// shortly after this response is received.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodePowerResponse {
        /// The power operation has been initiated.
        Initiated,
    }

    // ── host observation ────────────────────────────────────────

    /// Request for observing host state (read-only).
    ///
    /// All variants are side-effect-free queries that inspect the
    /// current state of the node without modifying it.
    ///
    /// # Examples
    ///
    /// ```
    /// use review_protocol::types::node::NodeObservationRequest;
    ///
    /// let req = NodeObservationRequest::ResourceUsage;
    /// assert!(matches!(
    ///     req,
    ///     NodeObservationRequest::ResourceUsage,
    /// ));
    /// ```
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeObservationRequest {
        /// List all running processes.
        ProcessList,
        /// Get aggregate resource usage (CPU, memory, disk).
        ResourceUsage,
        /// Get the node uptime.
        Uptime,
    }

    /// Response from a host-observation operation.
    ///
    /// Each variant corresponds to the identically named request
    /// variant.  The payload reuses the existing [`Process`] and
    /// [`ResourceUsage`] types defined in the parent module.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeObservationResponse {
        /// List of running processes.
        ProcessList { processes: Vec<Process> },
        /// Aggregate resource usage for a host.
        ResourceUsage {
            hostname: String,
            resource_usage: ResourceUsage,
        },
        /// The node uptime.
        Uptime { uptime: Duration },
    }

    // ── version management ──────────────────────────────────────

    /// Request for querying or updating the node version strings.
    ///
    /// [`Get`](Self::Get) retrieves both the OS and product version
    /// strings in a single call.  The two `Set*` variants update
    /// each string independently.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeVersionRequest {
        /// Get the current OS and product version strings.
        Get,
        /// Set the OS version string.
        SetOsVersion { version: String },
        /// Set the product version string.
        SetProductVersion { version: String },
    }

    /// Response from a version-management operation.
    ///
    /// [`Get`](Self::Get) returns both version strings;
    /// [`Done`](Self::Done) confirms a `Set*` operation succeeded.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeVersionResponse {
        /// The current version strings.
        Get {
            os_version: String,
            product_version: String,
        },
        /// The operation completed successfully.
        Done,
    }

    #[cfg(all(test, any(feature = "client", feature = "server")))]
    mod tests {
        use std::time::Duration;

        use super::super::ResourceUsage;
        use super::*;

        /// Helper: bincode round-trip for any `Serialize + Deserialize`
        /// type.
        fn roundtrip<T>(value: &T) -> T
        where
            T: Serialize + serde::de::DeserializeOwned + std::fmt::Debug,
        {
            let bytes = bincode::serde::encode_to_vec(
                value,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("serialization should succeed");
            let (decoded, _): (T, usize) = bincode::serde::decode_from_slice(
                &bytes,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("deserialization should succeed");
            decoded
        }

        #[test]
        fn serde_roundtrip_node_service() {
            let req = NodeServiceRequest::Start {
                service: "nginx".into(),
            };
            assert_eq!(req, roundtrip(&req));

            let req = NodeServiceRequest::Status {
                service: "nginx".into(),
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeServiceResponse::Status { active: true };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeServiceResponse::Done;
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_network_interface() {
            let req = NodeNetworkInterfaceRequest::List {
                prefix: Some("eth".into()),
            };
            assert_eq!(req, roundtrip(&req));

            let req = NodeNetworkInterfaceRequest::Set {
                device: "eth0".into(),
                config: NodeNetworkInterfaceConfig {
                    addresses: Some(vec!["192.168.1.10/24".into()]),
                    dhcp4: Some(false),
                    gateway4: Some("192.168.1.1".into()),
                    nameservers: Some(vec!["8.8.8.8".into()]),
                },
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeNetworkInterfaceResponse::Get {
                interface: Some(NodeNetworkInterface {
                    device: "eth0".into(),
                    config: NodeNetworkInterfaceConfig {
                        addresses: Some(vec!["192.168.1.10/24".into()]),
                        dhcp4: Some(false),
                        gateway4: Some("192.168.1.1".into()),
                        nameservers: Some(vec!["8.8.8.8".into()]),
                    },
                }),
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeNetworkInterfaceResponse::List {
                devices: vec!["eth0".into(), "eth1".into()],
            };
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_hostname() {
            let req = NodeHostnameRequest::Set {
                hostname: "node-1".into(),
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeHostnameResponse::Get {
                hostname: "node-1".into(),
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeHostnameResponse::Done;
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_time_sync() {
            let req = NodeTimeSyncRequest::Set {
                servers: vec!["0.pool.ntp.org".into(), "1.pool.ntp.org".into()],
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeTimeSyncResponse::Get {
                servers: Some(vec!["0.pool.ntp.org".into()]),
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeTimeSyncResponse::Status { enabled: true };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeTimeSyncResponse::Done;
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_logging() {
            let req = NodeLoggingRequest::Set {
                endpoints: vec![NodeLoggingEndpoint {
                    protocol: NodeLoggingProtocol::Tcp,
                    address: "192.168.1.100".into(),
                    port: 514,
                }],
            };
            assert_eq!(req, roundtrip(&req));

            let req = NodeLoggingRequest::Clear;
            assert_eq!(req, roundtrip(&req));

            let resp = NodeLoggingResponse::Get {
                endpoints: Some(vec![NodeLoggingEndpoint {
                    protocol: NodeLoggingProtocol::Udp,
                    address: "10.0.0.1".into(),
                    port: 514,
                }]),
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeLoggingResponse::Done;
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_remote_access() {
            let req = NodeRemoteAccessRequest::Set {
                config: NodeRemoteAccessConfig { port: 22 },
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeRemoteAccessResponse::Get {
                config: NodeRemoteAccessConfig { port: 2222 },
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeRemoteAccessResponse::Done;
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_power() {
            let req = NodePowerRequest::Reboot;
            assert_eq!(req, roundtrip(&req));

            let req = NodePowerRequest::GracefulShutdown;
            assert_eq!(req, roundtrip(&req));

            let resp = NodePowerResponse::Initiated;
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_observation() {
            let req = NodeObservationRequest::Uptime;
            assert_eq!(req, roundtrip(&req));

            let resp = NodeObservationResponse::ProcessList {
                processes: vec![Process {
                    user: "root".into(),
                    cpu_usage: 1.5,
                    mem_usage: 0.8,
                    start_time: 1_700_000_000,
                    command: "/usr/sbin/sshd".into(),
                }],
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeObservationResponse::ResourceUsage {
                hostname: "node-1".into(),
                resource_usage: ResourceUsage {
                    cpu_usage: 45.2,
                    total_memory: 16_000_000_000,
                    used_memory: 8_000_000_000,
                    disk_used_bytes: 100_000_000_000,
                    disk_available_bytes: 400_000_000_000,
                },
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeObservationResponse::Uptime {
                uptime: Duration::from_hours(24),
            };
            assert_eq!(resp, roundtrip(&resp));
        }

        #[test]
        fn serde_roundtrip_node_version() {
            let req = NodeVersionRequest::SetOsVersion {
                version: "22.04".into(),
            };
            assert_eq!(req, roundtrip(&req));

            let resp = NodeVersionResponse::Get {
                os_version: "22.04".into(),
                product_version: "2.0.0".into(),
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeVersionResponse::Done;
            assert_eq!(resp, roundtrip(&resp));
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "client", feature = "server"))]
    use super::*;

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn event_kind_serialization_round_trip() {
        // Test that all EventKind variants can be serialized and deserialized
        let test_cases = vec![
            EventKind::DnsCovertChannel,
            EventKind::HttpThreat,
            EventKind::RdpBruteForce,
            EventKind::RepeatedHttpSessions,
            EventKind::ExtraThreat,
            EventKind::TorConnection,
            EventKind::DomainGenerationAlgorithm,
            EventKind::FtpBruteForce,
            EventKind::FtpPlainText,
            EventKind::PortScan,
            EventKind::MultiHostPortScan,
            EventKind::NonBrowser,
            EventKind::LdapBruteForce,
            EventKind::LdapPlainText,
            EventKind::ExternalDdos,
            EventKind::CryptocurrencyMiningPool,
            EventKind::BlocklistConn,
            EventKind::BlocklistDns,
            EventKind::BlocklistDceRpc,
            EventKind::BlocklistFtp,
            EventKind::BlocklistHttp,
            EventKind::BlocklistKerberos,
            EventKind::BlocklistLdap,
            EventKind::BlocklistMqtt,
            EventKind::BlocklistNfs,
            EventKind::BlocklistNtlm,
            EventKind::BlocklistRdp,
            EventKind::BlocklistSmb,
            EventKind::BlocklistSmtp,
            EventKind::BlocklistSsh,
            EventKind::BlocklistTls,
            EventKind::WindowsThreat,
            EventKind::NetworkThreat,
            EventKind::LockyRansomware,
            EventKind::SuspiciousTlsTraffic,
            EventKind::BlocklistBootp,
            EventKind::BlocklistDhcp,
            EventKind::TorConnectionConn,
            EventKind::BlocklistRadius,
            EventKind::BlocklistMalformedDns,
            EventKind::UnusualDestinationPattern,
        ];

        for kind in test_cases {
            // Serialize with bincode (used in the protocol)
            let serialized = bincode::serde::encode_to_vec(
                kind,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("serialization should succeed");

            // Deserialize back
            let (deserialized, _len): (EventKind, usize) = bincode::serde::decode_from_slice(
                &serialized,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("deserialization should succeed");

            // Verify round-trip
            assert_eq!(kind, deserialized, "EventKind {kind:?} failed round-trip");
        }
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn event_message_with_blocklist_radius_serialization() {
        // Test EventMessage with BlocklistRadius variant
        let event = EventMessage {
            time: jiff::Timestamp::now(),
            kind: EventKind::BlocklistRadius,
            fields: vec![1, 2, 3, 4, 5],
        };

        // Serialize with bincode (used in the protocol)
        let serialized = bincode::serde::encode_to_vec(
            &event,
            bincode::config::standard().with_fixed_int_encoding(),
        )
        .expect("serialization should succeed");

        // Deserialize back
        let (deserialized, _len): (EventMessage, usize) = bincode::serde::decode_from_slice(
            &serialized,
            bincode::config::standard().with_fixed_int_encoding(),
        )
        .expect("deserialization should succeed");

        // Verify the kind matches
        assert_eq!(
            event.kind, deserialized.kind,
            "EventKind should match after round-trip"
        );
        assert_eq!(
            event.fields, deserialized.fields,
            "Fields should match after round-trip"
        );
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn threat_level_serialization_round_trip() {
        // Test that all ThreatLevel variants can be serialized and deserialized
        let test_cases = vec![
            ThreatLevel::VeryLow,
            ThreatLevel::Low,
            ThreatLevel::Medium,
            ThreatLevel::High,
            ThreatLevel::VeryHigh,
        ];

        for level in test_cases {
            // Serialize with bincode (used in the protocol)
            let serialized = bincode::serde::encode_to_vec(
                level,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("serialization should succeed");

            // Deserialize back
            let (deserialized, _len): (ThreatLevel, usize) = bincode::serde::decode_from_slice(
                &serialized,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("deserialization should succeed");

            // Verify round-trip
            assert_eq!(
                level, deserialized,
                "ThreatLevel {level:?} failed round-trip"
            );
        }
    }

    #[test]
    fn threat_level_as_hash_key() {
        use std::collections::HashMap;

        use super::ThreatLevel;

        let mut counts: HashMap<ThreatLevel, usize> = HashMap::new();
        let events = [
            ThreatLevel::Low,
            ThreatLevel::High,
            ThreatLevel::Low,
            ThreatLevel::Medium,
            ThreatLevel::High,
            ThreatLevel::High,
        ];
        for level in &events {
            *counts.entry(*level).or_insert(0) += 1;
        }
        assert_eq!(counts[&ThreatLevel::Low], 2);
        assert_eq!(counts[&ThreatLevel::High], 3);
        assert_eq!(counts[&ThreatLevel::Medium], 1);
        assert_eq!(counts.get(&ThreatLevel::VeryLow), None);
    }
}
