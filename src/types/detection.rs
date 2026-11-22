//! Detection events, the findings a detection engine sends to `REview`.

use std::{fmt, net::IpAddr};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use super::{EventCategory, RawEventBody, RawEventKind};

/// The maximum number of related IPs a [`Target::Subject`] carries.
///
/// A model that finds more drops the rest and counts them in its detail's
/// `truncated_related_ips`.
pub const MAX_RELATED_IPS: usize = 64;

/// What `Debug` prints in place of a captured credential.
const REDACTED: &str = "<redacted>";

/// The detection model that produced a [`DetectionEvent`].
///
/// A model is serialized as its number in every format, never as its name or
/// declaration index.
///
/// The numbers are permanent once released. A later model is appended at the
/// end with the next unused number, and a released number is never renumbered
/// or reused for another model, even after its model is removed.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize_repr,
    Eq,
    Hash,
    IntoPrimitive,
    PartialEq,
    Serialize_repr,
    TryFromPrimitive,
)]
#[repr(u32)]
pub enum DetectionModel {
    WatchlistMatch = 0,
    CryptocurrencyMiningPool = 1,
    LockyRansomware = 2,
    SuspiciousTlsTraffic = 3,
    PortScan = 4,
    MultiHostPortScan = 5,
    ExternalDdos = 6,
    RdpBruteForce = 7,
    FtpBruteForce = 8,
    LdapBruteForce = 9,
    RepeatedHttpSessions = 10,
    FtpPlainText = 11,
    LdapPlainText = 12,
    NonBrowser = 13,
    TorExitNode = 14,
    DomainGenerationAlgorithm = 15,
    DnsCovertChannel = 16,
    UnusualDestinationPattern = 17,
}

/// A detection: what a detection model found, about which target, and why.
///
/// Decoding never checks the rules [`validate`](Self::validate) states: every
/// decodable event is delivered as is. The endpoints call `validate`, the
/// engine before sending and `REview` after receiving, so that a receiver can
/// log and skip one bad event without failing the rest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// When the detection was made.
    #[serde(with = "jiff::fmt::serde::timestamp::nanosecond::required")]
    pub time: jiff::Timestamp,
    /// The sensor the detection's raw events came from, if one.
    pub sensor: Option<String>,
    /// The model that made the detection.
    pub detection_model: DetectionModel,
    /// The kind of the raw events the detection covers.
    pub raw_event_kind: RawEventKind,
    /// The MITRE tactic; `None` when the model has no assigned tactic.
    pub category: Option<EventCategory>,
    /// What the detection is about.
    pub target: Target,
    /// How suspicious the detection is; higher is more suspicious.
    pub score: f64,
    /// The model-specific detail.
    pub detail: Detail,
}

/// What a [`DetectionEvent`] is about.
// `RawEvent` carries a whole raw event body and is the larger variant by
// design; boxing it would change the public field type the schema fixes.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Target {
    /// A single raw event, identified by its time together with the event's
    /// `raw_event_kind` and `sensor`.
    RawEvent {
        /// The raw event's time, the Giganto key timestamp.
        #[serde(with = "jiff::fmt::serde::timestamp::nanosecond::required")]
        time: jiff::Timestamp,
        /// The raw event itself.
        body: RawEventBody,
    },
    /// A subject observed across raw events.
    Subject {
        /// The subject the detection is about.
        primary: PrimarySubject,
        /// Other IPs involved, at most [`MAX_RELATED_IPS`].
        related_ips: Vec<RelatedIp>,
        /// The times of the raw events the detection covers.
        window: TimeWindow,
    },
}

/// The subject a [`Target::Subject`] is about.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PrimarySubject {
    /// A host.
    Host {
        /// The host's address.
        ip: IpAddr,
        /// Whether the host causes or suffers the threat.
        role: ThreatRole,
    },
    /// A cluster of a clustering model.
    Cluster {
        /// The clustering model's id.
        clustering_model: u32,
        /// The cluster's id within that model.
        cluster_id: u32,
    },
    /// The sensor named by the event's `sensor`.
    Sensor,
    /// A customer network.
    Network {
        /// The customer's id.
        customer: u32,
        /// The network's name.
        name: String,
        /// Whether the network causes or suffers the threat.
        role: ThreatRole,
    },
}

/// An IP related to a detection, with the endpoint role it was observed in.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RelatedIp {
    /// The address.
    pub ip: IpAddr,
    /// Whether the address was the observed source or destination.
    pub role: EndpointRole,
}

/// A closed range of times, both ends included.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// The earliest time in the range.
    #[serde(with = "jiff::fmt::serde::timestamp::nanosecond::required")]
    pub start: jiff::Timestamp,
    /// The latest time in the range.
    #[serde(with = "jiff::fmt::serde::timestamp::nanosecond::required")]
    pub end: jiff::Timestamp,
}

/// The model's interpretation of a primary subject's part in a threat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatRole {
    /// The subject causes the threat.
    Actor,
    /// The subject suffers the threat.
    Target,
}

/// A fact read from a raw event: which endpoint of the connection an IP was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EndpointRole {
    /// The observed source of the connection.
    Source,
    /// The observed destination of the connection.
    Destination,
}

/// The model-specific detail of a [`DetectionEvent`], one variant per
/// [`DetectionModel`] with the same name.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Detail {
    WatchlistMatch(WatchlistMatchDetail),
    CryptocurrencyMiningPool(CryptocurrencyMiningPoolDetail),
    LockyRansomware,
    SuspiciousTlsTraffic,
    PortScan(PortScanDetail),
    MultiHostPortScan(MultiHostPortScanDetail),
    ExternalDdos(ExternalDdosDetail),
    RdpBruteForce(RdpBruteForceDetail),
    FtpBruteForce(FtpBruteForceDetail),
    LdapBruteForce(LdapBruteForceDetail),
    RepeatedHttpSessions(RepeatedHttpSessionsDetail),
    FtpPlainText,
    LdapPlainText,
    NonBrowser,
    TorExitNode,
    DomainGenerationAlgorithm,
    DnsCovertChannel,
    UnusualDestinationPattern(UnusualDestinationPatternDetail),
}

impl Detail {
    /// Returns the detection model this detail belongs to.
    #[must_use]
    pub fn detection_model(&self) -> DetectionModel {
        match self {
            Self::WatchlistMatch(_) => DetectionModel::WatchlistMatch,
            Self::CryptocurrencyMiningPool(_) => DetectionModel::CryptocurrencyMiningPool,
            Self::LockyRansomware => DetectionModel::LockyRansomware,
            Self::SuspiciousTlsTraffic => DetectionModel::SuspiciousTlsTraffic,
            Self::PortScan(_) => DetectionModel::PortScan,
            Self::MultiHostPortScan(_) => DetectionModel::MultiHostPortScan,
            Self::ExternalDdos(_) => DetectionModel::ExternalDdos,
            Self::RdpBruteForce(_) => DetectionModel::RdpBruteForce,
            Self::FtpBruteForce(_) => DetectionModel::FtpBruteForce,
            Self::LdapBruteForce(_) => DetectionModel::LdapBruteForce,
            Self::RepeatedHttpSessions(_) => DetectionModel::RepeatedHttpSessions,
            Self::FtpPlainText => DetectionModel::FtpPlainText,
            Self::LdapPlainText => DetectionModel::LdapPlainText,
            Self::NonBrowser => DetectionModel::NonBrowser,
            Self::TorExitNode => DetectionModel::TorExitNode,
            Self::DomainGenerationAlgorithm => DetectionModel::DomainGenerationAlgorithm,
            Self::DnsCovertChannel => DetectionModel::DnsCovertChannel,
            Self::UnusualDestinationPattern(_) => DetectionModel::UnusualDestinationPattern,
        }
    }
}

/// The detail of a [`DetectionModel::WatchlistMatch`] detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WatchlistMatchDetail {
    /// The id of the matched watchlist (blocklist) entry.
    pub entry_id: u64,
    /// Which endpoint of the raw events matched the entry.
    pub matched_side: EndpointRole,
    /// The number of raw events grouped into the detection.
    pub raw_event_count: u64,
    /// The number of related IPs dropped to stay within [`MAX_RELATED_IPS`].
    pub truncated_related_ips: u64,
    /// Whether the engine's open-group limit forced the group to close.
    pub closed_early: bool,
}

/// The detail of a [`DetectionModel::CryptocurrencyMiningPool`] detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CryptocurrencyMiningPoolDetail {
    /// The coins the pool mines.
    pub coins: Vec<String>,
}

/// The detail of a [`DetectionModel::PortScan`] detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortScanDetail {
    /// The scanned responder ports.
    pub resp_ports: Vec<u16>,
    /// The IP protocol number.
    pub proto: u8,
}

/// The detail of a [`DetectionModel::MultiHostPortScan`] detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MultiHostPortScanDetail {
    /// The scanned responder port.
    pub resp_port: u16,
    /// The IP protocol number.
    pub proto: u8,
    /// The number of related IPs dropped to stay within [`MAX_RELATED_IPS`].
    pub truncated_related_ips: u64,
}

/// The detail of a [`DetectionModel::ExternalDdos`] detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExternalDdosDetail {
    /// The IP protocol number.
    pub proto: u8,
    /// The number of related IPs dropped to stay within [`MAX_RELATED_IPS`].
    pub truncated_related_ips: u64,
}

/// The detail of a [`DetectionModel::RdpBruteForce`] detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RdpBruteForceDetail {
    /// The IP protocol number.
    pub proto: u8,
    /// The number of related IPs dropped to stay within [`MAX_RELATED_IPS`].
    pub truncated_related_ips: u64,
}

/// The detail of a [`DetectionModel::FtpBruteForce`] detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FtpBruteForceDetail {
    /// The responder port.
    pub resp_port: u16,
    /// The IP protocol number.
    pub proto: u8,
    /// The user names tried.
    pub user_list: Vec<String>,
    /// Whether the attempts came from an internal network.
    pub is_internal: bool,
}

/// The detail of a [`DetectionModel::LdapBruteForce`] detection.
///
/// `Debug` prints every password in `user_pw_list` as `<redacted>`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct LdapBruteForceDetail {
    /// The responder port.
    pub resp_port: u16,
    /// The IP protocol number.
    pub proto: u8,
    /// The user and password pairs tried.
    pub user_pw_list: Vec<(String, String)>,
}

/// The passwords in `user_pw_list` were captured from the session, so they
/// are redacted rather than derived; the user names and every other field
/// are printed as a derived `Debug` would print them.
impl fmt::Debug for LdapBruteForceDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// A `(user, password)` pair printed with its password redacted.
        struct RedactedPair<'a>(&'a str);

        impl fmt::Debug for RedactedPair<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple("")
                    .field(&self.0)
                    .field(&format_args!("{REDACTED}"))
                    .finish()
            }
        }

        /// `user_pw_list` printed with every password redacted.
        struct RedactedList<'a>(&'a [(String, String)]);

        impl fmt::Debug for RedactedList<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(self.0.iter().map(|(user, _)| RedactedPair(user)))
                    .finish()
            }
        }

        // Destructured so that a field added to the struct fails to compile
        // here until it is printed or redacted.
        let Self {
            resp_port,
            proto,
            user_pw_list,
        } = self;
        f.debug_struct("LdapBruteForceDetail")
            .field("resp_port", resp_port)
            .field("proto", proto)
            .field("user_pw_list", &RedactedList(user_pw_list))
            .finish()
    }
}

/// The detail of a [`DetectionModel::RepeatedHttpSessions`] detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RepeatedHttpSessionsDetail {
    /// The originator port.
    pub orig_port: u16,
    /// The responder port.
    pub resp_port: u16,
    /// The IP protocol number.
    pub proto: u8,
}

/// The detail of a [`DetectionModel::UnusualDestinationPattern`] detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnusualDestinationPatternDetail {
    /// The observed count.
    pub count: u64,
    /// The expected mean of the count.
    pub expected_mean: f64,
    /// The standard deviation of the count.
    pub std_deviation: f64,
    /// How many standard deviations the count lies from the mean.
    pub z_score: f64,
    /// The number of related IPs dropped to stay within [`MAX_RELATED_IPS`].
    pub truncated_related_ips: u64,
}

impl DetectionEvent {
    /// Checks the rules a well-formed detection event follows.
    ///
    /// The rules, numbered as [`DetectionEventError::rule`] reports them:
    ///
    /// 1. `detail`'s variant matches `detection_model`.
    /// 2. For [`Target::RawEvent`]: `sensor` is `Some`, and `body`'s variant
    ///    matches `raw_event_kind`.
    /// 3. For [`PrimarySubject::Sensor`]: `sensor` is `Some`.
    /// 4. For [`Target::Subject`]: `window.start <= window.end`.
    /// 5. For [`Target::Subject`]: at most [`MAX_RELATED_IPS`] related IPs.
    /// 6. `score` is finite.
    /// 7. For [`Target::RawEvent`]: `time` equals the raw event's time.
    ///
    /// It accepts [`PrimarySubject::Network`] and [`PrimarySubject::Cluster`]
    /// subjects: whether to take those depends on the connection and request,
    /// which the receiver checks.
    ///
    /// # Errors
    ///
    /// Returns the first rule, in the order above, that the event breaks.
    pub fn validate(&self) -> Result<(), DetectionEventError> {
        let detail = self.detail.detection_model();
        if detail != self.detection_model {
            return Err(DetectionEventError::DetailMismatch {
                detection_model: self.detection_model,
                detail,
            });
        }
        match &self.target {
            Target::RawEvent { body, .. } => {
                if self.sensor.is_none() {
                    return Err(DetectionEventError::RawEventWithoutSensor);
                }
                let body = raw_event_body_kind(body);
                if body != self.raw_event_kind {
                    return Err(DetectionEventError::RawEventBodyMismatch {
                        raw_event_kind: self.raw_event_kind,
                        body,
                    });
                }
            }
            Target::Subject {
                primary,
                related_ips,
                window,
            } => {
                if matches!(primary, PrimarySubject::Sensor) && self.sensor.is_none() {
                    return Err(DetectionEventError::SensorSubjectWithoutSensor);
                }
                if window.start > window.end {
                    return Err(DetectionEventError::InvertedWindow {
                        start: window.start,
                        end: window.end,
                    });
                }
                if related_ips.len() > MAX_RELATED_IPS {
                    return Err(DetectionEventError::TooManyRelatedIps {
                        count: related_ips.len(),
                    });
                }
            }
        }
        if !self.score.is_finite() {
            return Err(DetectionEventError::NonFiniteScore { score: self.score });
        }
        if let Target::RawEvent { time, .. } = &self.target
            && *time != self.time
        {
            return Err(DetectionEventError::RawEventTimeMismatch {
                time: self.time,
                raw_event_time: *time,
            });
        }
        Ok(())
    }
}

/// Returns the kind a raw event body belongs to. The match has no wildcard,
/// so a variant added to `RawEventBody` must be handled here.
fn raw_event_body_kind(body: &RawEventBody) -> RawEventKind {
    match body {
        RawEventBody::Conn(_) => RawEventKind::Conn,
        RawEventBody::Dns(_) => RawEventKind::Dns,
        RawEventBody::Http(_) => RawEventKind::Http,
        RawEventBody::Rdp(_) => RawEventKind::Rdp,
        RawEventBody::Smtp(_) => RawEventKind::Smtp,
        RawEventBody::Ntlm(_) => RawEventKind::Ntlm,
        RawEventBody::Kerberos(_) => RawEventKind::Kerberos,
        RawEventBody::Ssh(_) => RawEventKind::Ssh,
        RawEventBody::DceRpc(_) => RawEventKind::DceRpc,
        RawEventBody::Ftp(_) => RawEventKind::Ftp,
        RawEventBody::Mqtt(_) => RawEventKind::Mqtt,
        RawEventBody::Ldap(_) => RawEventKind::Ldap,
        RawEventBody::Tls(_) => RawEventKind::Tls,
        RawEventBody::Smb(_) => RawEventKind::Smb,
        RawEventBody::Nfs(_) => RawEventKind::Nfs,
        RawEventBody::Bootp(_) => RawEventKind::Bootp,
        RawEventBody::Dhcp(_) => RawEventKind::Dhcp,
        RawEventBody::Radius(_) => RawEventKind::Radius,
        RawEventBody::MalformedDns(_) => RawEventKind::MalformedDns,
        RawEventBody::Icmp(_) => RawEventKind::Icmp,
        RawEventBody::ProcessCreate(_) => RawEventKind::ProcessCreate,
        RawEventBody::FileCreateTime(_) => RawEventKind::FileCreateTime,
        RawEventBody::NetworkConnect(_) => RawEventKind::NetworkConnect,
        RawEventBody::ProcessTerminate(_) => RawEventKind::ProcessTerminate,
        RawEventBody::ImageLoad(_) => RawEventKind::ImageLoad,
        RawEventBody::FileCreate(_) => RawEventKind::FileCreate,
        RawEventBody::RegistryValueSet(_) => RawEventKind::RegistryValueSet,
        RawEventBody::RegistryKeyRename(_) => RawEventKind::RegistryKeyRename,
        RawEventBody::FileCreateStreamHash(_) => RawEventKind::FileCreateStreamHash,
        RawEventBody::PipeEvent(_) => RawEventKind::PipeEvent,
        RawEventBody::DnsQuery(_) => RawEventKind::DnsQuery,
        RawEventBody::FileDelete(_) => RawEventKind::FileDelete,
        RawEventBody::ProcessTamper(_) => RawEventKind::ProcessTamper,
        RawEventBody::FileDeleteDetected(_) => RawEventKind::FileDeleteDetected,
        RawEventBody::Netflow5(_) => RawEventKind::Netflow5,
        RawEventBody::Netflow9(_) => RawEventKind::Netflow9,
    }
}

/// The rule of [`DetectionEvent::validate`] an event breaks, and how.
// `Display` and `Error` are written by hand: this type builds with no optional
// feature, and `thiserror` is a dependency of the `client` and `server`
// features only.
#[derive(Clone, Debug, PartialEq)]
pub enum DetectionEventError {
    /// Rule 1: `detail` belongs to another model than `detection_model`.
    DetailMismatch {
        /// The event's `detection_model`.
        detection_model: DetectionModel,
        /// The model the event's `detail` belongs to.
        detail: DetectionModel,
    },
    /// Rule 2: a [`Target::RawEvent`] event has no `sensor`.
    RawEventWithoutSensor,
    /// Rule 2: a [`Target::RawEvent`] body is of another kind than
    /// `raw_event_kind`.
    RawEventBodyMismatch {
        /// The event's `raw_event_kind`.
        raw_event_kind: RawEventKind,
        /// The kind of the raw event's body.
        body: RawEventKind,
    },
    /// Rule 3: a [`PrimarySubject::Sensor`] event has no `sensor`.
    SensorSubjectWithoutSensor,
    /// Rule 4: a [`Target::Subject`] window starts after it ends.
    InvertedWindow {
        /// The window's start.
        start: jiff::Timestamp,
        /// The window's end.
        end: jiff::Timestamp,
    },
    /// Rule 5: a [`Target::Subject`] has more than [`MAX_RELATED_IPS`]
    /// related IPs.
    TooManyRelatedIps {
        /// The number of related IPs.
        count: usize,
    },
    /// Rule 6: `score` is NaN or infinite.
    NonFiniteScore {
        /// The event's `score`.
        score: f64,
    },
    /// Rule 7: a [`Target::RawEvent`] event's `time` differs from the raw
    /// event's time.
    RawEventTimeMismatch {
        /// The event's `time`.
        time: jiff::Timestamp,
        /// The raw event's time.
        raw_event_time: jiff::Timestamp,
    },
}

impl DetectionEventError {
    /// Returns the number, 1 to 7, of the rule of
    /// [`DetectionEvent::validate`] that failed.
    #[must_use]
    pub fn rule(&self) -> u8 {
        match self {
            Self::DetailMismatch { .. } => 1,
            Self::RawEventWithoutSensor | Self::RawEventBodyMismatch { .. } => 2,
            Self::SensorSubjectWithoutSensor => 3,
            Self::InvertedWindow { .. } => 4,
            Self::TooManyRelatedIps { .. } => 5,
            Self::NonFiniteScore { .. } => 6,
            Self::RawEventTimeMismatch { .. } => 7,
        }
    }
}

impl fmt::Display for DetectionEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "detection event rule {}: ", self.rule())?;
        match self {
            Self::DetailMismatch {
                detection_model,
                detail,
            } => write!(
                f,
                "detail is for {detail:?}, but detection_model is {detection_model:?}"
            ),
            Self::RawEventWithoutSensor => f.write_str("a raw event target requires a sensor"),
            Self::RawEventBodyMismatch {
                raw_event_kind,
                body,
            } => write!(
                f,
                "raw event body is {body:?}, but raw_event_kind is {raw_event_kind:?}"
            ),
            Self::SensorSubjectWithoutSensor => {
                f.write_str("a sensor primary subject requires a sensor")
            }
            Self::InvertedWindow { start, end } => {
                write!(f, "window starts at {start}, after its end at {end}")
            }
            Self::TooManyRelatedIps { count } => write!(
                f,
                "{count} related IPs exceed the maximum of {MAX_RELATED_IPS}"
            ),
            Self::NonFiniteScore { score } => write!(f, "score {score} is not finite"),
            Self::RawEventTimeMismatch {
                time,
                raw_event_time,
            } => write!(
                f,
                "time {time} differs from the raw event's time {raw_event_time}"
            ),
        }
    }
}

impl std::error::Error for DetectionEventError {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::types::raw_event;

    /// The models and numbers the schema commits to.
    pub(super) const TABLE: [(DetectionModel, u32); 18] = [
        (DetectionModel::WatchlistMatch, 0),
        (DetectionModel::CryptocurrencyMiningPool, 1),
        (DetectionModel::LockyRansomware, 2),
        (DetectionModel::SuspiciousTlsTraffic, 3),
        (DetectionModel::PortScan, 4),
        (DetectionModel::MultiHostPortScan, 5),
        (DetectionModel::ExternalDdos, 6),
        (DetectionModel::RdpBruteForce, 7),
        (DetectionModel::FtpBruteForce, 8),
        (DetectionModel::LdapBruteForce, 9),
        (DetectionModel::RepeatedHttpSessions, 10),
        (DetectionModel::FtpPlainText, 11),
        (DetectionModel::LdapPlainText, 12),
        (DetectionModel::NonBrowser, 13),
        (DetectionModel::TorExitNode, 14),
        (DetectionModel::DomainGenerationAlgorithm, 15),
        (DetectionModel::DnsCovertChannel, 16),
        (DetectionModel::UnusualDestinationPattern, 17),
    ];

    /// 2026-03-15T15:00:04.12Z.
    pub(super) const NANOS: i128 = 1_773_586_804_120_000_000;
    /// A valid timestamp's nanoseconds that do not fit in an `i64`, so that
    /// its encoding tells an `i128` field from an `i64` one.
    pub(super) const WIDE_NANOS: i128 = 200_000_000_000_000_000_000;

    pub(super) fn at(nanos: i128) -> jiff::Timestamp {
        jiff::Timestamp::from_nanosecond(nanos).expect("the test timestamp is in range")
    }

    pub(super) fn conn() -> RawEventBody {
        RawEventBody::Conn(raw_event::Conn {
            orig_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            orig_port: 46378,
            resp_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            resp_port: 80,
            proto: 6,
            conn_state: "SF".to_string(),
            start_time: 1_700_000_000_000_000_000,
            duration: 1_234_567,
            service: "http".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 3,
            resp_pkts: 4,
            orig_l2_bytes: 200,
            resp_l2_bytes: 400,
        })
    }

    /// Returns one detail per model, in [`TABLE`] order.
    pub(super) fn details() -> Vec<Detail> {
        vec![
            Detail::WatchlistMatch(WatchlistMatchDetail {
                entry_id: u64::MAX,
                matched_side: EndpointRole::Destination,
                raw_event_count: 12,
                truncated_related_ips: 3,
                closed_early: true,
            }),
            Detail::CryptocurrencyMiningPool(CryptocurrencyMiningPoolDetail {
                coins: vec!["xmr".to_string(), "btc".to_string()],
            }),
            Detail::LockyRansomware,
            Detail::SuspiciousTlsTraffic,
            Detail::PortScan(PortScanDetail {
                resp_ports: vec![22, 80, 443],
                proto: 6,
            }),
            Detail::MultiHostPortScan(MultiHostPortScanDetail {
                resp_port: 445,
                proto: 6,
                truncated_related_ips: 1,
            }),
            Detail::ExternalDdos(ExternalDdosDetail {
                proto: 17,
                truncated_related_ips: 9,
            }),
            Detail::RdpBruteForce(RdpBruteForceDetail {
                proto: 6,
                truncated_related_ips: 0,
            }),
            Detail::FtpBruteForce(FtpBruteForceDetail {
                resp_port: 21,
                proto: 6,
                user_list: vec!["user-a".to_string(), "user-b".to_string()],
                is_internal: false,
            }),
            Detail::LdapBruteForce(LdapBruteForceDetail {
                resp_port: 389,
                proto: 6,
                user_pw_list: vec![("user-a".to_string(), "synthetic".to_string())],
            }),
            Detail::RepeatedHttpSessions(RepeatedHttpSessionsDetail {
                orig_port: 50_000,
                resp_port: 8080,
                proto: 6,
            }),
            Detail::FtpPlainText,
            Detail::LdapPlainText,
            Detail::NonBrowser,
            Detail::TorExitNode,
            Detail::DomainGenerationAlgorithm,
            Detail::DnsCovertChannel,
            Detail::UnusualDestinationPattern(UnusualDestinationPatternDetail {
                count: 40,
                expected_mean: 2.5,
                std_deviation: 1.25,
                z_score: 30.0,
                truncated_related_ips: 2,
            }),
        ]
    }

    fn raw_event_target() -> DetectionEvent {
        DetectionEvent {
            time: at(NANOS),
            sensor: Some("sensor-1".to_string()),
            detection_model: DetectionModel::NonBrowser,
            raw_event_kind: RawEventKind::Conn,
            category: Some(EventCategory::CommandAndControl),
            target: Target::RawEvent {
                time: at(NANOS),
                body: conn(),
            },
            score: 0.75,
            detail: Detail::NonBrowser,
        }
    }

    fn subject(primary: PrimarySubject) -> DetectionEvent {
        DetectionEvent {
            time: at(NANOS),
            sensor: None,
            detection_model: DetectionModel::PortScan,
            raw_event_kind: RawEventKind::Conn,
            category: None,
            target: Target::Subject {
                primary,
                related_ips: vec![RelatedIp {
                    ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                    role: EndpointRole::Destination,
                }],
                window: TimeWindow {
                    start: at(NANOS - 1_000),
                    end: at(NANOS),
                },
            },
            score: 3.0,
            detail: Detail::PortScan(PortScanDetail {
                resp_ports: vec![22],
                proto: 6,
            }),
        }
    }

    fn host() -> PrimarySubject {
        PrimarySubject::Host {
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            role: ThreatRole::Actor,
        }
    }

    fn with_related_ips(count: usize) -> DetectionEvent {
        let mut event = subject(host());
        let Target::Subject { related_ips, .. } = &mut event.target else {
            unreachable!("subject() builds a subject target");
        };
        *related_ips = (0..count)
            .map(|i| RelatedIp {
                ip: IpAddr::V6(Ipv6Addr::new(
                    0x2001,
                    0xdb8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    u16::try_from(i).expect("the test counts fit u16"),
                )),
                role: EndpointRole::Source,
            })
            .collect();
        event
    }

    fn window_of(event: &mut DetectionEvent) -> &mut TimeWindow {
        match &mut event.target {
            Target::Subject { window, .. } => window,
            Target::RawEvent { .. } => unreachable!("the event has a subject target"),
        }
    }

    #[test]
    fn model_numbers_match_table_without_gap() {
        for (index, (model, number)) in TABLE.iter().enumerate() {
            assert_eq!(u32::from(*model), *number, "{model:?}");
            assert_eq!(
                usize::try_from(*number).expect("fits usize"),
                index,
                "numbers are 0-17 with no gap"
            );
            assert_eq!(DetectionModel::try_from(*number).ok(), Some(*model));
        }
        assert!(DetectionModel::try_from(18_u32).is_err());
        assert!(DetectionModel::try_from(u32::MAX).is_err());
    }

    #[test]
    fn model_serializes_as_number_in_json() {
        for (model, number) in TABLE {
            let json = serde_json::to_string(&model).expect("serializes");
            assert_eq!(json, number.to_string(), "{model:?}");
            let decoded: DetectionModel = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(decoded, model);
        }
        assert_eq!(
            serde_json::to_string(&DetectionModel::UnusualDestinationPattern).expect("serializes"),
            "17"
        );
        assert!(serde_json::from_str::<DetectionModel>("18").is_err());
        assert!(serde_json::from_str::<DetectionModel>("\"PortScan\"").is_err());
    }

    #[test]
    fn detail_names_its_model() {
        let details = details();
        assert_eq!(details.len(), TABLE.len());
        for (detail, (model, _)) in details.iter().zip(TABLE) {
            assert_eq!(detail.detection_model(), model);
        }
    }

    #[test]
    fn max_related_ips_is_64() {
        assert_eq!(MAX_RELATED_IPS, 64);
    }

    #[test]
    fn validate_accepts_every_target_and_subject_shape() {
        raw_event_target().validate().expect("raw event target");
        subject(host()).validate().expect("host subject");
        subject(PrimarySubject::Cluster {
            clustering_model: 4,
            cluster_id: 17,
        })
        .validate()
        .expect("cluster subject");
        let mut sensor = subject(PrimarySubject::Sensor);
        sensor.sensor = Some("sensor-1".to_string());
        sensor.validate().expect("sensor subject");
        subject(PrimarySubject::Network {
            customer: 2,
            name: "office".to_string(),
            role: ThreatRole::Target,
        })
        .validate()
        .expect("network subject");
    }

    #[test]
    fn validate_accepts_every_detail_with_its_model() {
        for (detail, (model, _)) in details().into_iter().zip(TABLE) {
            let mut event = subject(host());
            event.detection_model = model;
            event.detail = detail;
            event.validate().expect("matching detail");
        }
    }

    fn assert_rule(event: &DetectionEvent, rule: u8) -> DetectionEventError {
        let error = event.validate().expect_err("the event breaks a rule");
        assert_eq!(error.rule(), rule, "{error}");
        assert!(
            error
                .to_string()
                .starts_with(&format!("detection event rule {rule}: ")),
            "{error}"
        );
        error
    }

    #[test]
    fn validate_rejects_detail_of_another_model() {
        let mut event = subject(host());
        event.detail = Detail::LockyRansomware;
        let error = assert_rule(&event, 1);
        assert_eq!(
            error,
            DetectionEventError::DetailMismatch {
                detection_model: DetectionModel::PortScan,
                detail: DetectionModel::LockyRansomware,
            }
        );
        assert_eq!(
            error.to_string(),
            "detection event rule 1: detail is for LockyRansomware, but detection_model is \
             PortScan"
        );
    }

    #[test]
    fn validate_rejects_raw_event_without_sensor() {
        let mut event = raw_event_target();
        event.sensor = None;
        let error = assert_rule(&event, 2);
        assert_eq!(error, DetectionEventError::RawEventWithoutSensor);
        assert_eq!(
            error.to_string(),
            "detection event rule 2: a raw event target requires a sensor"
        );
    }

    #[test]
    fn validate_rejects_raw_event_body_of_another_kind() {
        let mut event = raw_event_target();
        event.raw_event_kind = RawEventKind::Http;
        let error = assert_rule(&event, 2);
        assert_eq!(
            error,
            DetectionEventError::RawEventBodyMismatch {
                raw_event_kind: RawEventKind::Http,
                body: RawEventKind::Conn,
            }
        );
        assert_eq!(
            error.to_string(),
            "detection event rule 2: raw event body is Conn, but raw_event_kind is Http"
        );
        assert_ne!(error, DetectionEventError::RawEventWithoutSensor);
    }

    #[test]
    fn validate_matches_every_raw_event_body_to_its_kind() {
        let mut covered = Vec::new();
        for body in raw_event::tests::bodies() {
            // The body's serde variant name is an oracle independent of
            // `raw_event_body_kind`: it must name the same kind.
            // Read from the text: some bodies hold integers that
            // `serde_json::Value` cannot represent.
            let json = serde_json::to_string(&body).expect("serializes");
            let name = json
                .strip_prefix("{\"")
                .and_then(|rest| rest.split_once("\":"))
                .map(|(name, _)| name.to_string())
                .expect("a body serializes as an externally tagged variant");
            let kind = raw_event_body_kind(&body);
            assert_eq!(format!("{kind:?}"), name);
            covered.push(u32::from(kind));

            let mut event = raw_event_target();
            event.raw_event_kind = kind;
            event.target = Target::RawEvent {
                time: event.time,
                body: body.clone(),
            };
            assert_eq!(event.validate(), Ok(()), "{name}");

            let other = if kind == RawEventKind::Conn {
                RawEventKind::Dns
            } else {
                RawEventKind::Conn
            };
            event.raw_event_kind = other;
            assert_eq!(
                event.validate(),
                Err(DetectionEventError::RawEventBodyMismatch {
                    raw_event_kind: other,
                    body: kind,
                }),
                "{name}"
            );
        }
        let total = covered.len();
        covered.sort_unstable();
        covered.dedup();
        assert_eq!(covered.len(), total, "one body per kind");
        assert_eq!(covered.len(), 36, "every raw event kind");
    }

    #[test]
    fn validate_rejects_sensor_subject_without_sensor() {
        let error = assert_rule(&subject(PrimarySubject::Sensor), 3);
        assert_eq!(error, DetectionEventError::SensorSubjectWithoutSensor);
    }

    #[test]
    fn validate_checks_window_order_inclusively() {
        let mut event = subject(host());
        let window = window_of(&mut event);
        window.start = at(NANOS);
        window.end = at(NANOS);
        event.validate().expect("start == end is a valid window");

        window_of(&mut event).start = at(NANOS + 1);
        let error = assert_rule(&event, 4);
        assert_eq!(
            error,
            DetectionEventError::InvertedWindow {
                start: at(NANOS + 1),
                end: at(NANOS),
            }
        );
        assert_eq!(
            error.to_string(),
            "detection event rule 4: window starts at 2026-03-15T15:00:04.120000001Z, after its \
             end at 2026-03-15T15:00:04.12Z"
        );
    }

    #[test]
    fn validate_bounds_related_ips_at_the_maximum() {
        with_related_ips(MAX_RELATED_IPS)
            .validate()
            .expect("64 related IPs");
        let error = assert_rule(&with_related_ips(MAX_RELATED_IPS + 1), 5);
        assert_eq!(error, DetectionEventError::TooManyRelatedIps { count: 65 });
        assert_eq!(
            error.to_string(),
            "detection event rule 5: 65 related IPs exceed the maximum of 64"
        );
    }

    #[test]
    fn validate_rejects_non_finite_score() {
        for score in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut event = raw_event_target();
            event.score = score;
            let error = assert_rule(&event, 6);
            assert!(matches!(
                error,
                DetectionEventError::NonFiniteScore { score: s } if s.to_bits() == score.to_bits()
            ));
        }
        let mut event = raw_event_target();
        event.score = -1.0e300;
        event.validate().expect("any finite score");
    }

    #[test]
    fn validate_rejects_raw_event_time_mismatch() {
        let mut event = raw_event_target();
        event.time = at(NANOS + 1);
        let error = assert_rule(&event, 7);
        assert_eq!(
            error,
            DetectionEventError::RawEventTimeMismatch {
                time: at(NANOS + 1),
                raw_event_time: at(NANOS),
            }
        );
    }

    #[test]
    fn time_fields_encode_as_nanosecond_number_in_json() {
        let expected = serde_json::Value::from(
            i64::try_from(NANOS).expect("the test timestamp fits i64 nanoseconds"),
        );
        let raw = serde_json::to_value(raw_event_target()).expect("serializes");
        assert_eq!(raw["time"], expected);
        assert_eq!(raw["target"]["RawEvent"]["time"], expected);

        let mut event = subject(host());
        *window_of(&mut event) = TimeWindow {
            start: at(NANOS),
            end: at(NANOS + 5),
        };
        let value = serde_json::to_value(&event).expect("serializes");
        let window = &value["target"]["Subject"]["window"];
        assert_eq!(window["start"], expected);
        assert_eq!(
            window["end"],
            serde_json::Value::from(i64::try_from(NANOS + 5).expect("fits i64"))
        );

        for event in [raw_event_target(), event] {
            let json = serde_json::to_string(&event).expect("serializes");
            let decoded: DetectionEvent = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(decoded, event);
        }
    }

    #[test]
    fn time_fields_encode_beyond_i64_as_exact_json_integer() {
        assert!(i64::try_from(WIDE_NANOS).is_err());
        assert!(i64::try_from(-WIDE_NANOS).is_err());

        let mut raw = raw_event_target();
        raw.time = at(WIDE_NANOS);
        raw.target = Target::RawEvent {
            time: at(-WIDE_NANOS),
            body: conn(),
        };
        let json = serde_json::to_string(&raw).expect("serializes");
        assert!(
            json.starts_with(r#"{"time":200000000000000000000,"#),
            "{json}"
        );
        assert!(
            json.contains(r#""RawEvent":{"time":-200000000000000000000,"body":"#),
            "{json}"
        );
        let decoded: DetectionEvent = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(decoded, raw);

        let mut subject = subject(host());
        *window_of(&mut subject) = TimeWindow {
            start: at(-WIDE_NANOS),
            end: at(WIDE_NANOS),
        };
        let json = serde_json::to_string(&subject).expect("serializes");
        assert!(
            json.contains(
                r#""window":{"start":-200000000000000000000,"end":200000000000000000000}"#
            ),
            "{json}"
        );
        let decoded: DetectionEvent = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(decoded, subject);
    }

    #[test]
    fn ldap_brute_force_debug_redacts_passwords() {
        const PASSWORD: &str = "synthetic-password";
        let detail = LdapBruteForceDetail {
            resp_port: 389,
            proto: 6,
            user_pw_list: vec![
                ("user-a".to_string(), PASSWORD.to_string()),
                ("user-b".to_string(), PASSWORD.to_string()),
            ],
        };
        let mut event = subject(host());
        event.detection_model = DetectionModel::LdapBruteForce;
        event.detail = Detail::LdapBruteForce(detail.clone());

        for rendered in [format!("{event:?}"), format!("{event:#?}")] {
            assert!(!rendered.contains(PASSWORD), "{rendered}");
        }
        assert_eq!(
            format!("{detail:?}"),
            r#"LdapBruteForceDetail { resp_port: 389, proto: 6, user_pw_list: [("user-a", <redacted>), ("user-b", <redacted>)] }"#
        );
        let rendered = format!("{event:?}");
        assert!(
            rendered.contains(r#"user_pw_list: [("user-a", <redacted>), ("user-b", <redacted>)]"#),
            "{rendered}"
        );

        // Redaction is `Debug` only: the password is still on the wire.
        let json = serde_json::to_string(&event).expect("serializes");
        assert!(json.contains(PASSWORD), "{json}");
        let decoded: DetectionEvent = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(decoded, event);
    }

    #[test]
    fn every_detail_round_trips_through_json() {
        for detail in details() {
            let json = serde_json::to_string(&detail).expect("serializes");
            let decoded: Detail = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(decoded, detail);
        }
    }

    #[test]
    fn error_is_a_std_error() {
        fn assert_error<E: std::error::Error + Send + Sync + 'static>() {}
        assert_error::<DetectionEventError>();
    }
}

#[cfg(all(test, any(feature = "client", feature = "server")))]
mod bincode_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use serde::{Serialize, de::DeserializeOwned};

    use super::tests::{NANOS, TABLE, WIDE_NANOS, at, conn, details};
    use super::*;

    /// The crate's bincode 2 encoding of [`NANOS`] as an `i128`: the
    /// zigzagged value in a `u64` varint.
    const NANOS_BYTES: [u8; 9] = [0xfd, 0x00, 0x2c, 0xc9, 0x5b, 0x9a, 0x17, 0x3a, 0x31];

    /// The crate's bincode 2 encoding of [`WIDE_NANOS`] as an `i128`: the
    /// zigzagged value in a `u128` varint, which no `i64` encodes to.
    const WIDE_NANOS_BYTES: [u8; 17] = [
        0xfe, 0x00, 0x00, 0x40, 0x8c, 0xb5, 0x78, 0x1d, 0xaf, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    fn encode<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
        bincode::serde::encode_to_vec(value, bincode::config::standard())
            .expect("serialization should succeed")
    }

    fn decode<T: DeserializeOwned>(bytes: &[u8]) -> T {
        let (value, len): (T, usize) =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard())
                .expect("deserialization should succeed");
        assert_eq!(len, bytes.len());
        value
    }

    #[test]
    fn model_serializes_as_number_in_bincode() {
        for (model, number) in TABLE {
            let bytes = encode(&model);
            assert_eq!(bytes, encode(&number), "{model:?}");
            assert_eq!(decode::<DetectionModel>(&bytes), model);
        }
        assert_eq!(encode(&DetectionModel::UnusualDestinationPattern), [17]);
        assert!(
            bincode::serde::decode_from_slice::<DetectionModel, _>(
                &encode(&18_u32),
                bincode::config::standard(),
            )
            .is_err()
        );
    }

    #[test]
    fn nanos_bytes_are_the_i128_encoding() {
        assert_eq!(encode(&NANOS), NANOS_BYTES);
        assert_eq!(encode(&WIDE_NANOS), WIDE_NANOS_BYTES);
    }

    fn header(event: &DetectionEvent) -> Vec<u8> {
        let mut bytes = encode(&event.sensor);
        bytes.extend(encode(&event.detection_model));
        bytes.extend(encode(&event.raw_event_kind));
        bytes.extend(encode(&event.category));
        bytes
    }

    #[test]
    fn raw_event_times_encode_as_nanosecond_i128() {
        // Each case pins the header time to its expected bytes; the
        // wide one needs an `i128` for both times.
        for (time, time_bytes, raw_time) in [
            (NANOS, NANOS_BYTES.as_slice(), NANOS - 7),
            (WIDE_NANOS, WIDE_NANOS_BYTES.as_slice(), -WIDE_NANOS),
        ] {
            let event = DetectionEvent {
                time: at(time),
                sensor: Some("sensor-1".to_string()),
                detection_model: DetectionModel::NonBrowser,
                raw_event_kind: RawEventKind::Conn,
                category: None,
                target: Target::RawEvent {
                    time: at(raw_time),
                    body: conn(),
                },
                score: 1.5,
                detail: Detail::NonBrowser,
            };

            let mut target = encode(&0_u32);
            target.extend(encode(&raw_time));
            target.extend(encode(&conn()));
            assert_eq!(encode(&event.target), target);

            let mut expected = time_bytes.to_vec();
            expected.extend(header(&event));
            expected.extend(target);
            expected.extend(encode(&1.5_f64));
            expected.extend(encode(&event.detail));
            assert_eq!(encode(&event), expected);
            assert_eq!(decode::<DetectionEvent>(&expected), event);
        }
    }

    #[test]
    fn subject_window_times_encode_as_nanosecond_i128() {
        // Each case pins the window start to its expected bytes; the wide
        // one needs an `i128` for every time.
        for (start, start_bytes, end, time) in [
            (NANOS, NANOS_BYTES.as_slice(), NANOS + 1, -NANOS),
            (
                WIDE_NANOS,
                WIDE_NANOS_BYTES.as_slice(),
                WIDE_NANOS + 1,
                -WIDE_NANOS,
            ),
        ] {
            let window = TimeWindow {
                start: at(start),
                end: at(end),
            };
            let mut expected_window = start_bytes.to_vec();
            expected_window.extend(encode(&end));
            assert_eq!(encode(&window), expected_window);
            assert_eq!(decode::<TimeWindow>(&expected_window), window);

            let primary = PrimarySubject::Sensor;
            let event = DetectionEvent {
                time: at(time),
                sensor: Some("sensor-1".to_string()),
                detection_model: DetectionModel::TorExitNode,
                raw_event_kind: RawEventKind::Tls,
                category: Some(EventCategory::CommandAndControl),
                target: Target::Subject {
                    primary: primary.clone(),
                    related_ips: vec![RelatedIp {
                        ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                        role: EndpointRole::Source,
                    }],
                    window: window.clone(),
                },
                score: 0.0,
                detail: Detail::TorExitNode,
            };
            let Target::Subject { related_ips, .. } = &event.target else {
                unreachable!("the event has a subject target");
            };

            let mut expected = encode(&time);
            expected.extend(header(&event));
            expected.extend(encode(&1_u32));
            expected.extend(encode(&primary));
            expected.extend(encode(related_ips));
            expected.extend(expected_window);
            expected.extend(encode(&0.0_f64));
            expected.extend(encode(&event.detail));
            assert_eq!(encode(&event), expected);
            assert_eq!(decode::<DetectionEvent>(&expected), event);
        }
    }

    #[test]
    fn every_detail_round_trips_through_bincode() {
        for detail in details() {
            assert_eq!(decode::<Detail>(&encode(&detail)), detail);
        }
    }

    #[test]
    fn decoding_does_not_validate() {
        let event = DetectionEvent {
            time: at(NANOS),
            sensor: None,
            detection_model: DetectionModel::PortScan,
            raw_event_kind: RawEventKind::Conn,
            category: None,
            target: Target::Subject {
                primary: PrimarySubject::Sensor,
                related_ips: Vec::new(),
                window: TimeWindow {
                    start: at(NANOS + 1),
                    end: at(NANOS),
                },
            },
            score: f64::INFINITY,
            detail: Detail::DnsCovertChannel,
        };
        assert!(event.validate().is_err());
        assert_eq!(decode::<DetectionEvent>(&encode(&event)), event);
    }
}
