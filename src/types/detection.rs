//! Detection events, the findings a detection engine sends to `REview`.

use std::{fmt, net::IpAddr};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use uuid::Uuid;

use super::raw_event::{EndpointHeader, NetStateSource};
use super::{EventCategory, RawEventBody, RawEventKind};

/// The maximum number of related IPs a [`Target::Subject`] carries.
///
/// A model that finds more drops the rest and counts them in its detail's
/// `truncated_related_ips`.
pub const MAX_RELATED_IPS: usize = 64;

/// The maximum number of slots in [`WindowOutlierDetail::top_slots`].
const MAX_TOP_SLOTS: usize = 3;

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
    /// Label DB rules matched against the raw events in the clusters of a
    /// clustering model's round.
    ///
    /// One detection event per matched raw event and rule, carrying a
    /// [`Detail::LabelDbMatch`]. `category` is the rule's category. `score`
    /// is the rule's confidence ([`LabelDbMatchDetail::rule_confidence`])
    /// when the rule has one, otherwise the match score
    /// ([`LabelDbMatchDetail::match_score`]).
    LabelDbMatch = 18,
    /// Raw events of a new outlier token pattern far from every known cluster
    /// prefix of a clustering model's round.
    ///
    /// Each raw event that is a new outlier of this round (not an outlier
    /// carried over from an earlier round), and whose token pattern is not
    /// the pattern of any carried-over outlier, is one candidate. A candidate
    /// becomes a detection event, carrying a [`Detail::FarOutlier`], unless
    /// the exclusion-list filter, the per-pattern cap or the per-round cap
    /// removes it. `category` is `None`.
    ///
    /// The **best prefix** is chosen among the prefixes of all clusters after
    /// the round's clustering, including clusters created in this round. It
    /// is the prefix with the highest share of its tokens matched by the
    /// outlier's pattern from the first token on. Ties go to more matched
    /// tokens, then the lower cluster id, then the earlier regex.
    ///
    /// `score` is 1 − (`matched_tokens` ÷ `prefix_len`) for the best prefix
    /// (see [`FarOutlierDetail::Prefix`]), and 1 when there is no cluster
    /// prefix or the pattern has no token.
    FarOutlier = 19,
    /// Windows of per-IP time series that fall in no cluster of a time-series
    /// clustering model's round.
    ///
    /// A time series is one internal IP's series of a time-series generation
    /// policy, identified as `<policy id>/<IP>`
    /// ([`WindowOutlierDetail::time_series_id`]). Every producer follows this
    /// contract:
    ///
    /// - One detection event per window of a time series that falls in no
    ///   cluster of the round, carrying a [`Detail::WindowOutlier`].
    /// - `time` is the window's start, `category` is `None`, and
    ///   `raw_event_kind` is the kind the time series counts, for example
    ///   [`RawEventKind::Tls`].
    /// - `sensor` is filled by `REview` on receipt from the series' policy:
    ///   its single sensor, otherwise `None`. Any value the engine sends is
    ///   overwritten.
    /// - The target is [`Target::Subject`] with `primary`
    ///   [`PrimarySubject::Host`] `{ ip, role }`, no `related_ips`, and a
    ///   `window`. `ip` is the IP part of `time_series_id`, and `role` is the
    ///   threat role of the series' time-series type.
    /// - `window` runs from the start of the earliest slot in
    ///   [`top_slots`](WindowOutlierDetail::top_slots) to the end of the
    ///   latest one, where a slot's end is its start + slot size − 1 ns. When
    ///   `top_slots` is empty, it is the whole window: from the window start
    ///   to the window start + window size − 1 ns.
    /// - `score` is [`distance`](WindowOutlierDetail::distance).
    WindowOutlier = 20,
    /// Emerging Threats Open rules ([`SignatureSource::EtOpen`]) matched
    /// against raw events, other than the policy rules
    /// [`EtPolicySignature`](Self::EtPolicySignature) reports.
    ///
    /// Every producer follows this contract:
    ///
    /// - One detection event per matched raw event and matched rule,
    ///   carrying a [`Detail::EtSignature`], with a [`Target::RawEvent`] target.
    /// - `category` is the [`EventCategory`] of the rule's first MITRE tactic
    ///   (see [`EventCategory::from_mitre_tactic_id`]), or `None` when the
    ///   rule has none.
    /// - `score` is the matched rule's severity on a 0 to 1 scale.
    EtSignature = 21,
    /// Emerging Threats Open policy rules ([`SignatureSource::EtOpen`])
    /// matched against raw events.
    ///
    /// Every producer follows this contract:
    ///
    /// - One detection event per matched raw event and matched rule,
    ///   carrying a [`Detail::EtPolicySignature`], with a [`Target::RawEvent`] target.
    /// - `category` is the [`EventCategory`] of the rule's first MITRE tactic
    ///   (see [`EventCategory::from_mitre_tactic_id`]), or `None` when the
    ///   rule has none.
    /// - `score` is the matched rule's severity on a 0 to 1 scale.
    EtPolicySignature = 22,
    /// `SigmaHQ` rules, from its releases ([`SignatureSource::SigmaHq`]) or
    /// its emerging threats rules ([`SignatureSource::SigmaHqEmerging`]),
    /// matched against raw events.
    ///
    /// Every producer follows this contract:
    ///
    /// - One detection event per matched raw event and matched rule,
    ///   carrying a [`Detail::SigmaSignature`], with a [`Target::RawEvent`] target.
    /// - `category` is the [`EventCategory`] of the rule's first MITRE tactic
    ///   (see [`EventCategory::from_mitre_tactic_id`]), or `None` when the
    ///   rule has none.
    /// - `score` is the matched rule's severity on a 0 to 1 scale.
    SigmaSignature = 23,
}

/// A detection: what a detection model found, about which target, and why.
///
/// Decoding never checks the rules [`validate`](Self::validate) states: every
/// decodable event is delivered as is. The endpoints call `validate`, the
/// engine before sending and `REview` after receiving, so that a receiver can
/// log and skip one bad event without failing the rest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// The detection's time.
    ///
    /// For a [`Target::RawEvent`] this must be the raw event's time, the
    /// Giganto key timestamp, the same value as that target's `time`, even
    /// when the detection is made later or from historical data;
    /// [`validate`](Self::validate) rejects any other value (rule 7), and a
    /// receiver skips the event.
    #[serde(with = "jiff::fmt::serde::timestamp::nanosecond::required")]
    pub time: jiff::Timestamp,
    /// The sensor the detection's raw events came from, if one.
    ///
    /// For a [`PrimarySubject::Endpoint`] subject, or a [`Target::RawEvent`]
    /// whose body has a host header, it is the endpoint id as a lowercase
    /// hyphenated UUID string, whichever sensor the underlying raw events
    /// were read from ([`validate`](Self::validate) rules 11 and 12).
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
        /// The raw event's time, the Giganto key timestamp. The header's
        /// [`DetectionEvent::time`] must carry the same value.
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
    /// One endpoint, a host running Clumit Endpoint, that the detection is
    /// about.
    ///
    /// The event's `sensor` must be the endpoint id, as a lowercase
    /// hyphenated UUID string ([`DetectionEvent::validate`] rule 11).
    ///
    /// `ips`, `default_route_ip` and `net_state_source` are copied unchanged,
    /// with no filtering or reordering, from the host header
    /// ([`EndpointHeader`]) of the bundled raw event with the latest raw
    /// event time, ties going to the one the engine received last. When no
    /// bundled raw event has a header, the detection model's own
    /// specification decides the values, and failing that they are an empty
    /// list, `None` and [`NetStateSource::Unknown`].
    Endpoint {
        /// The endpoint's id, [`EndpointHeader::endpoint_id`].
        endpoint_id: Uuid,
        /// The endpoint's addresses, [`EndpointHeader::ips`]; not capped.
        ips: Vec<IpAddr>,
        /// The endpoint's default route address,
        /// [`EndpointHeader::default_route_ip`].
        default_route_ip: Option<IpAddr>,
        /// How the endpoint's network state was obtained,
        /// [`EndpointHeader::net_state_source`].
        net_state_source: NetStateSource,
        /// Whether the endpoint is the actor or the target of the threat.
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
    LabelDbMatch(LabelDbMatchDetail),
    FarOutlier(FarOutlierDetail),
    WindowOutlier(WindowOutlierDetail),
    EtSignature(SignatureMatchDetail),
    EtPolicySignature(SignatureMatchDetail),
    SigmaSignature(SignatureMatchDetail),
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
            Self::LabelDbMatch(_) => DetectionModel::LabelDbMatch,
            Self::FarOutlier(_) => DetectionModel::FarOutlier,
            Self::WindowOutlier(_) => DetectionModel::WindowOutlier,
            Self::EtSignature(_) => DetectionModel::EtSignature,
            Self::EtPolicySignature(_) => DetectionModel::EtPolicySignature,
            Self::SigmaSignature(_) => DetectionModel::SigmaSignature,
        }
    }

    /// Returns the id of the time series the detection is about, if the
    /// detail carries one.
    ///
    /// Receivers use it to find the time-series generation policy behind a
    /// time-series detection: the id is `<policy id>/<IP>`. It is `Some` for
    /// [`Detail::WindowOutlier`] and `None` for every other variant.
    #[must_use]
    pub fn time_series_id(&self) -> Option<&str> {
        match self {
            Self::WindowOutlier(detail) => Some(&detail.time_series_id),
            Self::WatchlistMatch(_)
            | Self::CryptocurrencyMiningPool(_)
            | Self::LockyRansomware
            | Self::SuspiciousTlsTraffic
            | Self::PortScan(_)
            | Self::MultiHostPortScan(_)
            | Self::ExternalDdos(_)
            | Self::RdpBruteForce(_)
            | Self::FtpBruteForce(_)
            | Self::LdapBruteForce(_)
            | Self::RepeatedHttpSessions(_)
            | Self::FtpPlainText
            | Self::LdapPlainText
            | Self::NonBrowser
            | Self::TorExitNode
            | Self::DomainGenerationAlgorithm
            | Self::DnsCovertChannel
            | Self::UnusualDestinationPattern(_)
            | Self::LabelDbMatch(_)
            | Self::FarOutlier(_)
            | Self::EtSignature(_)
            | Self::EtPolicySignature(_)
            | Self::SigmaSignature(_) => None,
        }
    }
}

/// The detail of a [`DetectionModel::WatchlistMatch`] detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WatchlistMatchDetail {
    /// The id of the matched watchlist entry.
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

/// The detail of a [`DetectionModel::LabelDbMatch`] detection.
///
/// `Debug` is derived: `matched_to` is printed as is, because RFC 0008 leaves
/// its classification and masking to RFC 0010 D112.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LabelDbMatchDetail {
    /// The name of the label DB that holds the matched rule.
    ///
    /// Rule ids are assigned per label DB, so the name is needed to identify
    /// the rule.
    pub label_db: String,
    /// The matched rule's id within [`label_db`](Self::label_db).
    pub rule_id: u32,
    /// The matched rule's name.
    pub rule_name: String,
    /// The signature that matched.
    pub matched_to: String,
    /// The cluster of the round that the raw event belongs to.
    pub cluster_id: u32,
    /// The rule's confidence, 0–1; `None` when the rule has none.
    pub rule_confidence: Option<f32>,
    /// How well the rule matched, 0–1.
    ///
    /// For token rules it is the share of the rule's tokens that matched. For
    /// exact, URL, IP and regex rules it is 1.0.
    pub match_score: f32,
}

/// The detail of a [`DetectionModel::FarOutlier`] detection, one variant per
/// approach that measures how far the outlier is.
///
/// `Debug` is derived: `nearest_signature` and `diverged_token` are printed
/// as is, because RFC 0008 leaves their classification and masking to
/// RFC 0010 D112.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FarOutlierDetail {
    /// The prefix-approach form, measured against the best prefix that
    /// [`DetectionModel::FarOutlier`] defines. Other approaches may add
    /// variants later.
    Prefix {
        /// The cluster of the best prefix; `None` when there is no cluster
        /// prefix.
        nearest_cluster_id: Option<u32>,
        /// The signature of the best prefix's cluster; `None` when there is
        /// no cluster prefix.
        nearest_signature: Option<String>,
        /// The number of leading tokens of the outlier's pattern equal to the
        /// best prefix's.
        ///
        /// It is also the 0-based position where the two diverge.
        matched_tokens: u32,
        /// The best prefix's length in tokens.
        prefix_len: u32,
        /// The outlier's token at the position
        /// [`matched_tokens`](Self::Prefix::matched_tokens) names; `None`
        /// when the pattern has no token there.
        diverged_token: Option<String>,
        /// The number of the round's raw events with this pattern, counted
        /// before the exclusion-list filter.
        pattern_count: u64,
        /// The number of this pattern's detection events dropped by the
        /// per-pattern cap, counted after the exclusion-list filter.
        ///
        /// Events dropped by the per-round cap are not counted here. The
        /// round's [`DetectionModelStatus::truncated`] counts the drops of
        /// both caps.
        ///
        /// [`DetectionModelStatus::truncated`]: super::DetectionModelStatus::truncated
        truncated_in_pattern: u64,
    },
}

/// The detail of a [`DetectionModel::WindowOutlier`] detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WindowOutlierDetail {
    /// The time series the window belongs to, `<policy id>/<IP>`, with the IP
    /// in the form Rust's [`IpAddr`] `Display` prints.
    pub time_series_id: String,
    /// The start of the window that is the outlier.
    #[serde(with = "jiff::fmt::serde::timestamp::nanosecond::required")]
    pub window_start: jiff::Timestamp,
    /// The cluster whose centroid is nearest to the window.
    pub nearest_cluster_id: u32,
    /// The Euclidean distance from the window, after the time-series type's
    /// input transform, to the centroid of
    /// [`nearest_cluster_id`](Self::nearest_cluster_id).
    pub distance: f64,
    /// At most 3 slots of the window that differ most from the centroid.
    pub top_slots: Vec<SlotDeviation>,
    /// The number of [`DetectionModel::WindowOutlier`] detections of this
    /// round and this policy that the per-round output cap cut.
    pub truncated: u64,
    /// The number of sessions in the detection's time window that were not
    /// requested as PCAP because of the PCAP request cap; `None` when the
    /// session lookup failed.
    pub pcap_truncated: Option<u64>,
}

/// The publisher of a signature rule set.
///
/// A source is serialized as its number in every format, never as its name or
/// declaration index. The numbers are permanent once released; a later source
/// is appended with the next unused number.
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
pub enum SignatureSource {
    /// Emerging Threats Open.
    EtOpen = 0,
    /// The `SigmaHQ` rule releases.
    SigmaHq = 1,
    /// The `SigmaHQ` emerging threats rules.
    SigmaHqEmerging = 2,
}

/// The detail of a [`DetectionModel::EtSignature`],
/// [`DetectionModel::EtPolicySignature`] or [`DetectionModel::SigmaSignature`]
/// detection: the rule that matched and where it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureMatchDetail {
    /// The source of the rule set that holds the matched rule.
    pub source: SignatureSource,
    /// The version of the source's rule set the rule was taken from.
    pub source_version: String,
    /// The version of the converter that compiled the rule set.
    pub converter_version: String,
    /// The matched rule's id: the ET `sid` or the Sigma `id`.
    pub rule_id: String,
    /// The matched rule's revision: the ET `rev`; `None` for Sigma.
    pub rule_revision: Option<String>,
    /// The matched rule's title.
    pub rule_title: String,
    /// The matched rule's classification, if it has one.
    pub classification: Option<String>,
    /// The MITRE ATT&CK technique ids the rule names, such as `T1059.001`.
    pub techniques: Vec<String>,
    /// The rule's own severity value, verbatim.
    pub severity: String,
    /// The rule's author, if it names one.
    pub author: Option<String>,
    /// The names of the fields whose conditions were true; never their
    /// values.
    ///
    /// Producers send at most 16 names. The limit is not checked here.
    pub matched_fields: Vec<String>,
    /// Whether the rule's home network was replaced by the private address
    /// ranges when the rule was matched.
    pub home_net_fallback: bool,
    /// The Windows event log channel of the matched record.
    ///
    /// Reserved for matches on Windows event log records; `None` otherwise.
    pub event_channel: Option<String>,
    /// The Windows event ID of the matched record.
    ///
    /// Reserved for matches on Windows event log records; `None` otherwise.
    pub event_id: Option<u32>,
}

/// One slot of a [`WindowOutlierDetail`]'s window and how far it lies from
/// the nearest centroid.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlotDeviation {
    /// The slot's start.
    #[serde(with = "jiff::fmt::serde::timestamp::nanosecond::required")]
    pub slot_start: jiff::Timestamp,
    /// The slot's value, before the time-series type's input transform.
    pub value: f64,
    /// The nearest centroid's value for this slot, with the input transform
    /// reversed.
    pub centroid_value: f64,
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
    /// 7. For [`Target::RawEvent`]: `time` equals the raw event's time, the
    ///    Giganto key timestamp in that target's `time`.
    ///
    /// Rules 8 and 9 are not checked here: they are the checks `REview` makes
    /// on receipt, against its own state.
    ///
    /// 10. For [`Detail::WindowOutlier`]: the target is [`Target::Subject`]
    ///     with a [`PrimarySubject::Host`] primary subject; `top_slots` has at
    ///     most 3 entries; and `time_series_id` contains `/`, the part after
    ///     the first `/` parses as an [`IpAddr`], and that address equals the
    ///     host's `ip`. The part before `/` is not checked.
    /// 11. For [`PrimarySubject::Endpoint`]: `sensor` is `Some` and equals
    ///     `endpoint_id` as a lowercase hyphenated UUID string
    ///     (`endpoint_id.to_string()`).
    /// 12. For [`Target::RawEvent`] whose body has a host header (a Sysmon
    ///     body whose `endpoint` is `Some`, or a [`WindowsEventLog`],
    ///     [`Journald`] or [`Auditd`] body): `sensor` equals the header's
    ///     `endpoint_id` as a lowercase hyphenated UUID string. A Sysmon body
    ///     whose `endpoint` is `None` is not checked by this rule, and a
    ///     Sysmon body's `agent_id` is never compared.
    ///
    /// Rules 11 and 12 compare strings exactly: an uppercase or unhyphenated
    /// form of the same UUID breaks them.
    ///
    /// Rule 13 is not checked here either; like rules 8 and 9 it is a check
    /// the receiver makes against its own state:
    ///
    /// 13. The receiver accepts an event with a [`PrimarySubject::Endpoint`]
    ///     subject only when the endpoint is registered, its customer is the
    ///     sending engine node's current customer, and that customer has no
    ///     customer data deletion job.
    ///
    /// It accepts [`PrimarySubject::Network`] and [`PrimarySubject::Cluster`]
    /// subjects: whether to take those depends on the connection and request,
    /// which the receiver checks. A [`PrimarySubject::Endpoint`] subject falls
    /// under none of rules 3, 8 and 9; rules 4 to 6 apply to it as to every
    /// subject.
    ///
    /// [`WindowsEventLog`]: super::raw_event::WindowsEventLog
    /// [`Journald`]: super::raw_event::Journald
    /// [`Auditd`]: super::raw_event::Auditd
    ///
    /// # Errors
    ///
    /// Returns the first rule, in the order 1 to 7, 10, 11, 12, that the
    /// event breaks.
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
        if let Detail::WindowOutlier(detail) = &self.detail {
            validate_window_outlier(&self.target, detail)?;
        }
        if let Target::Subject {
            primary: PrimarySubject::Endpoint { endpoint_id, .. },
            ..
        } = &self.target
            && !self
                .sensor
                .as_deref()
                .is_some_and(|sensor| names_endpoint(sensor, endpoint_id))
        {
            return Err(DetectionEventError::EndpointSensorMismatch {
                endpoint_id: *endpoint_id,
                sensor: self.sensor.clone(),
            });
        }
        if let Target::RawEvent { body, .. } = &self.target
            && let Some(header) = raw_event_body_endpoint(body)
            && let Some(sensor) = &self.sensor
            && !names_endpoint(sensor, &header.endpoint_id)
        {
            return Err(DetectionEventError::RawEventEndpointSensorMismatch {
                endpoint_id: header.endpoint_id,
                sensor: sensor.clone(),
            });
        }
        Ok(())
    }
}

/// Returns whether `sensor` is `endpoint_id` as a lowercase hyphenated UUID
/// string, the form rules 11 and 12 of [`DetectionEvent::validate`] require.
fn names_endpoint(sensor: &str, endpoint_id: &Uuid) -> bool {
    sensor
        == endpoint_id
            .hyphenated()
            .encode_lower(&mut Uuid::encode_buffer())
}

/// Checks rule 10 of [`DetectionEvent::validate`] for a
/// [`Detail::WindowOutlier`] event.
fn validate_window_outlier(
    target: &Target,
    detail: &WindowOutlierDetail,
) -> Result<(), DetectionEventError> {
    let Target::Subject { primary, .. } = target else {
        return Err(DetectionEventError::InvalidWindowOutlier(
            WindowOutlierViolation::NotSubjectTarget,
        ));
    };
    let PrimarySubject::Host { ip: host, .. } = primary else {
        return Err(DetectionEventError::InvalidWindowOutlier(
            WindowOutlierViolation::NotHostSubject,
        ));
    };
    if detail.top_slots.len() > MAX_TOP_SLOTS {
        return Err(DetectionEventError::InvalidWindowOutlier(
            WindowOutlierViolation::TooManyTopSlots {
                count: detail.top_slots.len(),
            },
        ));
    }
    let Some((_, ip)) = detail.time_series_id.split_once('/') else {
        return Err(DetectionEventError::InvalidWindowOutlier(
            WindowOutlierViolation::TimeSeriesIdWithoutSlash,
        ));
    };
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return Err(DetectionEventError::InvalidWindowOutlier(
            WindowOutlierViolation::TimeSeriesIdWithoutIp,
        ));
    };
    if ip != *host {
        return Err(DetectionEventError::InvalidWindowOutlier(
            WindowOutlierViolation::TimeSeriesIpMismatch {
                time_series_ip: ip,
                host: *host,
            },
        ));
    }
    Ok(())
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
        RawEventBody::DriverLoad(_) => RawEventKind::DriverLoad,
        RawEventBody::CreateRemoteThread(_) => RawEventKind::CreateRemoteThread,
        RawEventBody::RawAccessRead(_) => RawEventKind::RawAccessRead,
        RawEventBody::ProcessAccess(_) => RawEventKind::ProcessAccess,
        RawEventBody::RegistryObjectAddDel(_) => RawEventKind::RegistryObjectAddDel,
        RawEventBody::WindowsEventLog(_) => RawEventKind::WindowsEventLog,
        RawEventBody::Journald(_) => RawEventKind::Journald,
        RawEventBody::Auditd(_) => RawEventKind::Auditd,
    }
}

/// Returns the host header of a raw event body: the `endpoint` of a Sysmon
/// body when it is `Some`, and that of a log body always. The match has no
/// wildcard, so a variant added to `RawEventBody` must be handled here.
fn raw_event_body_endpoint(body: &RawEventBody) -> Option<&EndpointHeader> {
    match body {
        RawEventBody::Conn(_)
        | RawEventBody::Dns(_)
        | RawEventBody::Http(_)
        | RawEventBody::Rdp(_)
        | RawEventBody::Smtp(_)
        | RawEventBody::Ntlm(_)
        | RawEventBody::Kerberos(_)
        | RawEventBody::Ssh(_)
        | RawEventBody::DceRpc(_)
        | RawEventBody::Ftp(_)
        | RawEventBody::Mqtt(_)
        | RawEventBody::Ldap(_)
        | RawEventBody::Tls(_)
        | RawEventBody::Smb(_)
        | RawEventBody::Nfs(_)
        | RawEventBody::Bootp(_)
        | RawEventBody::Dhcp(_)
        | RawEventBody::Radius(_)
        | RawEventBody::MalformedDns(_)
        | RawEventBody::Icmp(_)
        | RawEventBody::Netflow5(_)
        | RawEventBody::Netflow9(_) => None,
        RawEventBody::ProcessCreate(body) => body.endpoint.as_ref(),
        RawEventBody::FileCreateTime(body) => body.endpoint.as_ref(),
        RawEventBody::NetworkConnect(body) => body.endpoint.as_ref(),
        RawEventBody::ProcessTerminate(body) => body.endpoint.as_ref(),
        RawEventBody::ImageLoad(body) => body.endpoint.as_ref(),
        RawEventBody::FileCreate(body) => body.endpoint.as_ref(),
        RawEventBody::RegistryValueSet(body) => body.endpoint.as_ref(),
        RawEventBody::RegistryKeyRename(body) => body.endpoint.as_ref(),
        RawEventBody::FileCreateStreamHash(body) => body.endpoint.as_ref(),
        RawEventBody::PipeEvent(body) => body.endpoint.as_ref(),
        RawEventBody::DnsQuery(body) => body.endpoint.as_ref(),
        RawEventBody::FileDelete(body) => body.endpoint.as_ref(),
        RawEventBody::ProcessTamper(body) => body.endpoint.as_ref(),
        RawEventBody::FileDeleteDetected(body) => body.endpoint.as_ref(),
        RawEventBody::DriverLoad(body) => body.endpoint.as_ref(),
        RawEventBody::CreateRemoteThread(body) => body.endpoint.as_ref(),
        RawEventBody::RawAccessRead(body) => body.endpoint.as_ref(),
        RawEventBody::ProcessAccess(body) => body.endpoint.as_ref(),
        RawEventBody::RegistryObjectAddDel(body) => body.endpoint.as_ref(),
        RawEventBody::WindowsEventLog(body) => Some(&body.endpoint),
        RawEventBody::Journald(body) => Some(&body.endpoint),
        RawEventBody::Auditd(body) => Some(&body.endpoint),
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
    /// Rule 10: a [`Detail::WindowOutlier`] event breaks a requirement of
    /// that detail.
    InvalidWindowOutlier(WindowOutlierViolation),
    /// Rule 11: a [`PrimarySubject::Endpoint`] event's `sensor` is not the
    /// endpoint id as a lowercase hyphenated UUID string.
    EndpointSensorMismatch {
        /// The primary subject's `endpoint_id`.
        endpoint_id: Uuid,
        /// The event's `sensor`.
        sensor: Option<String>,
    },
    /// Rule 12: a [`Target::RawEvent`] event whose body has a host header
    /// has a `sensor` that is not the header's endpoint id as a lowercase
    /// hyphenated UUID string.
    RawEventEndpointSensorMismatch {
        /// The header's `endpoint_id`.
        endpoint_id: Uuid,
        /// The event's `sensor`.
        sensor: String,
    },
}

/// The requirement of rule 10 of [`DetectionEvent::validate`] that a
/// [`Detail::WindowOutlier`] event breaks.
#[derive(Clone, Debug, PartialEq)]
pub enum WindowOutlierViolation {
    /// The target is a [`Target::RawEvent`], not a [`Target::Subject`].
    NotSubjectTarget,
    /// The primary subject is not a [`PrimarySubject::Host`].
    NotHostSubject,
    /// `top_slots` has more than 3 entries.
    TooManyTopSlots {
        /// The number of entries in `top_slots`.
        count: usize,
    },
    /// `time_series_id` contains no `/`.
    TimeSeriesIdWithoutSlash,
    /// The part of `time_series_id` after the first `/` is not an IP address.
    TimeSeriesIdWithoutIp,
    /// The IP in `time_series_id` differs from the host's IP.
    TimeSeriesIpMismatch {
        /// The IP parsed from `time_series_id`.
        time_series_ip: IpAddr,
        /// The primary subject's host IP.
        host: IpAddr,
    },
}

impl fmt::Display for WindowOutlierViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSubjectTarget => {
                f.write_str("a WindowOutlier detail requires a subject target")
            }
            Self::NotHostSubject => {
                f.write_str("a WindowOutlier detail requires a host primary subject")
            }
            Self::TooManyTopSlots { count } => {
                write!(f, "{count} top slots exceed the maximum of {MAX_TOP_SLOTS}")
            }
            Self::TimeSeriesIdWithoutSlash => f.write_str("time_series_id contains no '/'"),
            Self::TimeSeriesIdWithoutIp => {
                f.write_str("the part of time_series_id after '/' is not an IP address")
            }
            Self::TimeSeriesIpMismatch {
                time_series_ip,
                host,
            } => write!(
                f,
                "time_series_id IP {time_series_ip} differs from the host IP {host}"
            ),
        }
    }
}

impl DetectionEventError {
    /// Returns the number of the rule of [`DetectionEvent::validate`] that
    /// failed: 1 to 7, 10, 11 or 12.
    ///
    /// Numbers 8, 9 and 13 are never returned: they name the checks the
    /// receiver makes on receipt, which `validate` does not make.
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
            Self::InvalidWindowOutlier(_) => 10,
            Self::EndpointSensorMismatch { .. } => 11,
            Self::RawEventEndpointSensorMismatch { .. } => 12,
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
            Self::InvalidWindowOutlier(violation) => violation.fmt(f),
            Self::EndpointSensorMismatch {
                endpoint_id,
                sensor,
            } => write!(
                f,
                "the endpoint primary subject {endpoint_id} is not the sensor {sensor:?}"
            ),
            Self::RawEventEndpointSensorMismatch {
                endpoint_id,
                sensor,
            } => write!(
                f,
                "the raw event's endpoint header {endpoint_id} is not the sensor {sensor}"
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
    pub(super) const TABLE: [(DetectionModel, u32); 24] = [
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
        (DetectionModel::LabelDbMatch, 18),
        (DetectionModel::FarOutlier, 19),
        (DetectionModel::WindowOutlier, 20),
        (DetectionModel::EtSignature, 21),
        (DetectionModel::EtPolicySignature, 22),
        (DetectionModel::SigmaSignature, 23),
    ];

    /// The signature sources and numbers the schema commits to.
    pub(super) const SOURCES: [(SignatureSource, u32); 3] = [
        (SignatureSource::EtOpen, 0),
        (SignatureSource::SigmaHq, 1),
        (SignatureSource::SigmaHqEmerging, 2),
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

    /// A [`LabelDbMatchDetail`] whose `Option` field is `Some`.
    pub(super) fn label_db_match() -> LabelDbMatchDetail {
        LabelDbMatchDetail {
            label_db: "ldb".to_string(),
            rule_id: 300,
            rule_name: "r".to_string(),
            matched_to: "sig".to_string(),
            cluster_id: 7,
            rule_confidence: Some(0.5),
            match_score: 1.0,
        }
    }

    /// An ET Open signature match with every optional field set.
    pub(super) fn et_signature() -> SignatureMatchDetail {
        SignatureMatchDetail {
            source: SignatureSource::EtOpen,
            source_version: "10813".to_string(),
            converter_version: "1.2.0".to_string(),
            rule_id: "2013028".to_string(),
            rule_revision: Some("7".to_string()),
            rule_title: "ET POLICY curl User-Agent Outbound".to_string(),
            classification: Some("attempted-recon".to_string()),
            techniques: vec!["T1071.001".to_string(), "T1105".to_string()],
            severity: "2".to_string(),
            author: Some("Emerging Threats".to_string()),
            matched_fields: vec!["user_agent".to_string(), "resp_port".to_string()],
            home_net_fallback: true,
            event_channel: Some("Security".to_string()),
            event_id: Some(4625),
        }
    }

    /// A Sigma signature match with every optional field `None`.
    pub(super) fn sigma_signature() -> SignatureMatchDetail {
        SignatureMatchDetail {
            source: SignatureSource::SigmaHqEmerging,
            source_version: "r2026-11-01".to_string(),
            converter_version: "0.9.1".to_string(),
            rule_id: "5f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".to_string(),
            rule_revision: None,
            rule_title: "Suspicious PowerShell Download".to_string(),
            classification: None,
            techniques: Vec::new(),
            severity: "high".to_string(),
            author: None,
            matched_fields: Vec::new(),
            home_net_fallback: false,
            event_channel: None,
            event_id: None,
        }
    }

    /// A [`FarOutlierDetail::Prefix`] whose `Option` fields are `Some`.
    pub(super) fn far_outlier() -> FarOutlierDetail {
        FarOutlierDetail::Prefix {
            nearest_cluster_id: Some(5),
            nearest_signature: Some("ab".to_string()),
            matched_tokens: 2,
            prefix_len: 4,
            diverged_token: Some("x".to_string()),
            pattern_count: 1000,
            truncated_in_pattern: 3,
        }
    }

    /// A [`FarOutlierDetail::Prefix`] whose `Option` fields are `None`: no
    /// cluster prefix and no token at the divergence.
    pub(super) fn far_outlier_without_prefix() -> FarOutlierDetail {
        FarOutlierDetail::Prefix {
            nearest_cluster_id: None,
            nearest_signature: None,
            matched_tokens: 0,
            prefix_len: 0,
            diverged_token: None,
            pattern_count: 1,
            truncated_in_pattern: 0,
        }
    }

    /// A slot of [`window_outlier`]'s window, starting `offset` ns after
    /// [`NANOS`].
    fn slot(offset: i128, value: f64, centroid_value: f64) -> SlotDeviation {
        SlotDeviation {
            slot_start: at(NANOS + offset),
            value,
            centroid_value,
        }
    }

    /// A [`WindowOutlierDetail`] of the series of [`host`]'s IP, with three
    /// top slots and `pcap_truncated` `Some`.
    pub(super) fn window_outlier() -> WindowOutlierDetail {
        WindowOutlierDetail {
            time_series_id: "7/192.0.2.9".to_string(),
            window_start: at(NANOS),
            nearest_cluster_id: 5,
            distance: 2.5,
            top_slots: vec![
                slot(0, 1.0, 0.5),
                slot(60_000_000_000, 40.0, 2.0),
                slot(120_000_000_000, 0.0, 3.25),
            ],
            truncated: 3,
            pcap_truncated: Some(250),
        }
    }

    /// A [`WindowOutlierDetail`] with no top slots and `pcap_truncated`
    /// `None`.
    pub(super) fn window_outlier_without_slots() -> WindowOutlierDetail {
        WindowOutlierDetail {
            top_slots: Vec::new(),
            truncated: 0,
            pcap_truncated: None,
            ..window_outlier()
        }
    }

    /// Returns [`window_outlier`] cut to each number of top slots from 0 to
    /// 3, each with `pcap_truncated` `Some(0)`, `Some(u64::MAX)` and `None`.
    pub(super) fn window_outlier_variants() -> Vec<WindowOutlierDetail> {
        let mut variants = Vec::new();
        for count in 0..=MAX_TOP_SLOTS {
            for pcap_truncated in [Some(0), Some(u64::MAX), None] {
                let mut detail = window_outlier();
                detail.top_slots.truncate(count);
                detail.pcap_truncated = pcap_truncated;
                variants.push(detail);
            }
        }
        variants
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
            Detail::LabelDbMatch(label_db_match()),
            Detail::FarOutlier(far_outlier()),
            Detail::WindowOutlier(window_outlier()),
            Detail::EtSignature(et_signature()),
            Detail::EtPolicySignature(et_signature()),
            Detail::SigmaSignature(sigma_signature()),
        ]
    }

    /// A valid `WindowOutlier` detection event about [`host`] carrying
    /// `detail`, whose window spans the three top slots of
    /// [`window_outlier`].
    pub(super) fn window_outlier_event(detail: WindowOutlierDetail) -> DetectionEvent {
        DetectionEvent {
            time: detail.window_start,
            sensor: None,
            detection_model: DetectionModel::WindowOutlier,
            raw_event_kind: RawEventKind::Tls,
            category: None,
            target: Target::Subject {
                primary: host(),
                related_ips: Vec::new(),
                window: TimeWindow {
                    start: at(NANOS),
                    end: at(NANOS + 180_000_000_000 - 1),
                },
            },
            score: detail.distance,
            detail: Detail::WindowOutlier(detail),
        }
    }

    fn window_outlier_detail(event: &mut DetectionEvent) -> &mut WindowOutlierDetail {
        match &mut event.detail {
            Detail::WindowOutlier(detail) => detail,
            _ => unreachable!("the event has a WindowOutlier detail"),
        }
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

    /// The id of [`endpoint`]'s endpoint.
    const ENDPOINT_ID: &str = "6f1d7a52-93c4-4b8e-a0f5-2c7e9b41d308";

    pub(super) fn endpoint() -> PrimarySubject {
        PrimarySubject::Endpoint {
            endpoint_id: ENDPOINT_ID.parse().expect("the test UUID parses"),
            ips: vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x30)),
            ],
            default_route_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30))),
            net_state_source: NetStateSource::Observed,
            role: ThreatRole::Actor,
        }
    }

    /// A valid event about [`endpoint`], whose `sensor` is the endpoint id.
    fn endpoint_event() -> DetectionEvent {
        let mut event = subject(endpoint());
        event.sensor = Some(ENDPOINT_ID.to_string());
        event
    }

    /// The forms of [`ENDPOINT_ID`] other than its lowercase hyphenated one,
    /// and other values, that rules 11 and 12 reject.
    fn not_endpoint_ids(endpoint_id: &str) -> Vec<String> {
        vec![
            endpoint_id.to_uppercase(),
            endpoint_id.replace('-', ""),
            format!("{{{endpoint_id}}}"),
            format!("urn:uuid:{endpoint_id}"),
            "00000000-0000-4000-8000-000000000000".to_string(),
            "sensor-1".to_string(),
            String::new(),
        ]
    }

    /// Returns a valid raw event detection event carrying `body`, whose
    /// `sensor` is the body's endpoint id when it has a host header.
    fn raw_event_with(body: RawEventBody) -> DetectionEvent {
        let mut event = raw_event_target();
        event.raw_event_kind = raw_event_body_kind(&body);
        if let Some(header) = raw_event_body_endpoint(&body) {
            event.sensor = Some(header.endpoint_id.to_string());
        }
        event.target = Target::RawEvent {
            time: event.time,
            body,
        };
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
                "numbers are 0-23 with no gap"
            );
            assert_eq!(DetectionModel::try_from(*number).ok(), Some(*model));
        }
        assert_eq!(u32::from(DetectionModel::LabelDbMatch), 18);
        assert_eq!(u32::from(DetectionModel::FarOutlier), 19);
        assert_eq!(u32::from(DetectionModel::WindowOutlier), 20);
        assert_eq!(u32::from(DetectionModel::EtSignature), 21);
        assert_eq!(u32::from(DetectionModel::EtPolicySignature), 22);
        assert_eq!(u32::from(DetectionModel::SigmaSignature), 23);
        assert_eq!(
            DetectionModel::try_from(21_u32).ok(),
            Some(DetectionModel::EtSignature)
        );
        assert_eq!(
            DetectionModel::try_from(22_u32).ok(),
            Some(DetectionModel::EtPolicySignature)
        );
        assert_eq!(
            DetectionModel::try_from(23_u32).ok(),
            Some(DetectionModel::SigmaSignature)
        );
        assert!(DetectionModel::try_from(24_u32).is_err());
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
        assert_eq!(
            serde_json::to_string(&DetectionModel::LabelDbMatch).expect("serializes"),
            "18"
        );
        assert_eq!(
            serde_json::to_string(&DetectionModel::FarOutlier).expect("serializes"),
            "19"
        );
        assert_eq!(
            serde_json::from_str::<DetectionModel>("18").ok(),
            Some(DetectionModel::LabelDbMatch)
        );
        assert_eq!(
            serde_json::from_str::<DetectionModel>("19").ok(),
            Some(DetectionModel::FarOutlier)
        );
        assert_eq!(
            serde_json::to_string(&DetectionModel::WindowOutlier).expect("serializes"),
            "20"
        );
        assert_eq!(
            serde_json::from_str::<DetectionModel>("20").ok(),
            Some(DetectionModel::WindowOutlier)
        );
        for (model, json) in [
            (DetectionModel::EtSignature, "21"),
            (DetectionModel::EtPolicySignature, "22"),
            (DetectionModel::SigmaSignature, "23"),
        ] {
            assert_eq!(serde_json::to_string(&model).expect("serializes"), json);
            assert_eq!(
                serde_json::from_str::<DetectionModel>(json).ok(),
                Some(model)
            );
        }
        assert!(serde_json::from_str::<DetectionModel>("24").is_err());
        assert!(serde_json::from_str::<DetectionModel>("\"PortScan\"").is_err());
    }

    #[test]
    fn signature_source_numbers_match_table() {
        for (source, number) in SOURCES {
            assert_eq!(u32::from(source), number, "{source:?}");
            assert_eq!(SignatureSource::try_from(number).ok(), Some(source));
            let json = serde_json::to_string(&source).expect("serializes");
            assert_eq!(json, number.to_string(), "{source:?}");
            assert_eq!(
                serde_json::from_str::<SignatureSource>(&json).ok(),
                Some(source)
            );
        }
        assert!(SignatureSource::try_from(3_u32).is_err());
        assert!(serde_json::from_str::<SignatureSource>("3").is_err());
        assert!(serde_json::from_str::<SignatureSource>("\"EtOpen\"").is_err());
    }

    #[test]
    fn signature_details_name_their_models() {
        for (detail, model) in [
            (
                Detail::EtSignature(et_signature()),
                DetectionModel::EtSignature,
            ),
            (
                Detail::EtPolicySignature(et_signature()),
                DetectionModel::EtPolicySignature,
            ),
            (
                Detail::SigmaSignature(sigma_signature()),
                DetectionModel::SigmaSignature,
            ),
        ] {
            assert_eq!(detail.detection_model(), model);
            assert_eq!(detail.time_series_id(), None);
        }
    }

    #[test]
    fn signature_detail_round_trips_through_json() {
        for detail in [et_signature(), sigma_signature()] {
            let json = serde_json::to_string(&detail).expect("serializes");
            assert_eq!(
                serde_json::from_str::<SignatureMatchDetail>(&json).ok(),
                Some(detail)
            );
        }
        assert_eq!(
            serde_json::to_string(&sigma_signature()).expect("serializes"),
            r#"{"source":2,"source_version":"r2026-11-01","converter_version":"0.9.1","rule_id":"5f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d","rule_revision":null,"rule_title":"Suspicious PowerShell Download","classification":null,"techniques":[],"severity":"high","author":null,"matched_fields":[],"home_net_fallback":false,"event_channel":null,"event_id":null}"#
        );
    }

    #[test]
    fn validate_accepts_signature_events_on_raw_events() {
        for detail in [
            Detail::EtSignature(et_signature()),
            Detail::EtPolicySignature(et_signature()),
            Detail::SigmaSignature(sigma_signature()),
        ] {
            let mut event = raw_event_target();
            event.detection_model = detail.detection_model();
            event.category = EventCategory::from_mitre_tactic_id("TA0011");
            event.score = 0.5;
            event.detail = detail;
            assert_eq!(event.validate(), Ok(()), "{event:?}");
        }
        // The 16-name producer limit is not checked here.
        let mut detail = et_signature();
        detail.matched_fields = (0..17).map(|i| format!("field-{i}")).collect();
        let mut event = raw_event_target();
        event.detection_model = DetectionModel::EtSignature;
        event.detail = Detail::EtSignature(detail);
        assert_eq!(event.validate(), Ok(()));
        // A signature detail under another model breaks rule 1.
        event.detection_model = DetectionModel::SigmaSignature;
        assert_eq!(
            assert_rule(&event, 1),
            DetectionEventError::DetailMismatch {
                detection_model: DetectionModel::SigmaSignature,
                detail: DetectionModel::EtSignature,
            }
        );
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
        endpoint_event().validate().expect("endpoint subject");
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
    fn validate_accepts_new_models_with_their_detail() {
        for detail in [
            Detail::LabelDbMatch(label_db_match()),
            Detail::LabelDbMatch(LabelDbMatchDetail {
                rule_confidence: None,
                ..label_db_match()
            }),
            Detail::FarOutlier(far_outlier()),
            Detail::FarOutlier(far_outlier_without_prefix()),
        ] {
            let mut event = raw_event_target();
            event.detection_model = detail.detection_model();
            event.category = None;
            event.detail = detail;
            assert_eq!(event.validate(), Ok(()), "{event:?}");
        }
    }

    #[test]
    fn validate_rejects_new_model_with_another_models_detail() {
        for (detection_model, detail, detail_model) in [
            (
                DetectionModel::LabelDbMatch,
                Detail::FarOutlier(far_outlier()),
                DetectionModel::FarOutlier,
            ),
            (
                DetectionModel::FarOutlier,
                Detail::LabelDbMatch(label_db_match()),
                DetectionModel::LabelDbMatch,
            ),
            (
                DetectionModel::LabelDbMatch,
                Detail::NonBrowser,
                DetectionModel::NonBrowser,
            ),
            (
                DetectionModel::FarOutlier,
                Detail::NonBrowser,
                DetectionModel::NonBrowser,
            ),
        ] {
            let mut event = raw_event_target();
            event.detection_model = detection_model;
            event.detail = detail;
            let error = assert_rule(&event, 1);
            assert_eq!(
                error,
                DetectionEventError::DetailMismatch {
                    detection_model,
                    detail: detail_model,
                }
            );
        }
    }

    #[test]
    fn validate_rejects_existing_model_with_a_new_detail() {
        for (detail, detail_model) in [
            (
                Detail::LabelDbMatch(label_db_match()),
                DetectionModel::LabelDbMatch,
            ),
            (
                Detail::FarOutlier(far_outlier()),
                DetectionModel::FarOutlier,
            ),
            (
                Detail::WindowOutlier(window_outlier()),
                DetectionModel::WindowOutlier,
            ),
        ] {
            let mut event = raw_event_target();
            event.detail = detail;
            let error = assert_rule(&event, 1);
            assert_eq!(
                error,
                DetectionEventError::DetailMismatch {
                    detection_model: DetectionModel::NonBrowser,
                    detail: detail_model,
                }
            );
        }
        let mut event = raw_event_target();
        event.detail = Detail::FarOutlier(far_outlier());
        assert_eq!(
            assert_rule(&event, 1).to_string(),
            "detection event rule 1: detail is for FarOutlier, but detection_model is NonBrowser"
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
            if let Some(header) = raw_event_body_endpoint(&body) {
                event.sensor = Some(header.endpoint_id.to_string());
            }
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
        assert_eq!(covered.len(), 44, "every raw event kind");
    }

    #[test]
    fn validate_requires_the_endpoint_id_as_sensor() {
        let event = endpoint_event();
        assert_eq!(event.validate(), Ok(()));
        let endpoint_id: Uuid = ENDPOINT_ID.parse().expect("the test UUID parses");
        assert_eq!(endpoint_id.to_string(), ENDPOINT_ID);

        let mut sensors: Vec<Option<String>> = not_endpoint_ids(ENDPOINT_ID)
            .into_iter()
            .map(Some)
            .collect();
        sensors.push(None);
        for sensor in sensors {
            let mut event = endpoint_event();
            event.sensor.clone_from(&sensor);
            let error = assert_rule(&event, 11);
            assert_eq!(
                error,
                DetectionEventError::EndpointSensorMismatch {
                    endpoint_id,
                    sensor: sensor.clone(),
                }
            );
        }

        let mut event = endpoint_event();
        event.sensor = None;
        assert_eq!(
            assert_rule(&event, 11).to_string(),
            "detection event rule 11: the endpoint primary subject \
             6f1d7a52-93c4-4b8e-a0f5-2c7e9b41d308 is not the sensor None"
        );
        event.sensor = Some(ENDPOINT_ID.to_uppercase());
        assert_eq!(
            assert_rule(&event, 11).to_string(),
            "detection event rule 11: the endpoint primary subject \
             6f1d7a52-93c4-4b8e-a0f5-2c7e9b41d308 is not the sensor \
             Some(\"6F1D7A52-93C4-4B8E-A0F5-2C7E9B41D308\")"
        );
    }

    #[test]
    fn validate_requires_the_header_endpoint_id_as_raw_event_sensor() {
        let mut checked = 0;
        for body in raw_event::tests::bodies_with_and_without_endpoint() {
            let event = raw_event_with(body.clone());
            assert_eq!(event.validate(), Ok(()), "{body:?}");
            let Some(header) = raw_event_body_endpoint(&body) else {
                continue;
            };
            checked += 1;
            let endpoint_id = header.endpoint_id.to_string();
            assert_eq!(event.sensor.as_deref(), Some(endpoint_id.as_str()));
            for sensor in not_endpoint_ids(&endpoint_id) {
                let mut event = event.clone();
                event.sensor = Some(sensor.clone());
                let error = assert_rule(&event, 12);
                assert_eq!(
                    error,
                    DetectionEventError::RawEventEndpointSensorMismatch {
                        endpoint_id: header.endpoint_id,
                        sensor: sensor.clone(),
                    }
                );
                assert_eq!(
                    error.to_string(),
                    format!(
                        "detection event rule 12: the raw event's endpoint header \
                         {endpoint_id} is not the sensor {sensor}"
                    )
                );
            }
            // A missing sensor is rule 2's to report, before rule 12.
            let mut event = event.clone();
            event.sensor = None;
            assert_eq!(
                assert_rule(&event, 2),
                DetectionEventError::RawEventWithoutSensor
            );
        }
        // 19 Sysmon bodies with a header, and 3 log bodies.
        assert_eq!(checked, 22);
    }

    #[test]
    fn validate_skips_rule_12_for_sysmon_bodies_without_header() {
        let mut checked = 0;
        for body in raw_event::tests::bodies_with_and_without_endpoint() {
            // The Sysmon kinds are numbered 31 to 56.
            let sysmon = (31..=56).contains(&u32::from(raw_event_body_kind(&body)));
            if !sysmon || raw_event_body_endpoint(&body).is_some() {
                continue;
            }
            checked += 1;
            let mut event = raw_event_with(body);
            // Neither the sensor's form nor the body's `agent_id` is
            // compared.
            for sensor in [
                "sensor-1".to_string(),
                "not a UUID".to_string(),
                ENDPOINT_ID.to_string(),
                ENDPOINT_ID.to_uppercase(),
                String::new(),
            ] {
                event.sensor = Some(sensor);
                assert_eq!(event.validate(), Ok(()));
            }
            event.sensor = None;
            assert_eq!(
                assert_rule(&event, 2),
                DetectionEventError::RawEventWithoutSensor
            );
        }
        // Every Sysmon kind, without its header.
        assert_eq!(checked, 19);
    }

    #[test]
    fn validate_checks_rules_11_and_12_last() {
        // Each event also breaks rule 11, so the lower-numbered rule is the
        // one reported.
        let broken = || {
            let mut event = endpoint_event();
            event.sensor = Some("sensor-1".to_string());
            event
        };
        assert_rule(&broken(), 11);

        let mut mismatch = broken();
        mismatch.detection_model = DetectionModel::FarOutlier;
        assert_rule(&mismatch, 1);

        let mut inverted = broken();
        window_of(&mut inverted).start = at(NANOS + 1);
        assert_rule(&inverted, 4);

        let mut related = broken();
        let Target::Subject {
            related_ips: too_many,
            ..
        } = with_related_ips(MAX_RELATED_IPS + 1).target
        else {
            unreachable!("with_related_ips() builds a subject target");
        };
        let Target::Subject { related_ips, .. } = &mut related.target else {
            unreachable!("the event has a subject target");
        };
        *related_ips = too_many;
        assert_rule(&related, 5);

        let mut score = broken();
        score.score = f64::INFINITY;
        assert_rule(&score, 6);

        // Rule 10 before rule 11: a WindowOutlier detail with an endpoint
        // subject breaks both.
        let mut window = broken();
        window.detection_model = DetectionModel::WindowOutlier;
        window.detail = Detail::WindowOutlier(window_outlier());
        assert_eq!(
            assert_rule(&window, 10),
            DetectionEventError::InvalidWindowOutlier(WindowOutlierViolation::NotHostSubject)
        );

        // Each raw event also breaks rule 12.
        let header_body = raw_event::tests::bodies()
            .into_iter()
            .find(|body| matches!(body, RawEventBody::Journald(_)))
            .expect("bodies() has a Journald body");
        let broken = || {
            let mut event = raw_event_with(header_body.clone());
            event.sensor = Some("sensor-1".to_string());
            event
        };
        assert_rule(&broken(), 12);

        let mut mismatch = broken();
        mismatch.detection_model = DetectionModel::FarOutlier;
        assert_rule(&mismatch, 1);

        let mut kind = broken();
        kind.raw_event_kind = RawEventKind::Auditd;
        assert_rule(&kind, 2);

        let mut score = broken();
        score.score = f64::NAN;
        assert_rule(&score, 6);

        let mut time = broken();
        time.time = at(NANOS + 1);
        assert_rule(&time, 7);

        let mut window = broken();
        window.detection_model = DetectionModel::WindowOutlier;
        window.detail = Detail::WindowOutlier(window_outlier());
        assert_eq!(
            assert_rule(&window, 10),
            DetectionEventError::InvalidWindowOutlier(WindowOutlierViolation::NotSubjectTarget)
        );
    }

    #[test]
    fn rule_numbers_of_the_endpoint_errors() {
        let endpoint_id: Uuid = ENDPOINT_ID.parse().expect("the test UUID parses");
        let rule_11 = DetectionEventError::EndpointSensorMismatch {
            endpoint_id,
            sensor: Some("s".to_string()),
        };
        assert_eq!(rule_11.rule(), 11);
        assert_eq!(
            rule_11.to_string(),
            "detection event rule 11: the endpoint primary subject \
             6f1d7a52-93c4-4b8e-a0f5-2c7e9b41d308 is not the sensor Some(\"s\")"
        );
        let rule_12 = DetectionEventError::RawEventEndpointSensorMismatch {
            endpoint_id,
            sensor: "s".to_string(),
        };
        assert_eq!(rule_12.rule(), 12);
        assert_eq!(
            rule_12.to_string(),
            "detection event rule 12: the raw event's endpoint header \
             6f1d7a52-93c4-4b8e-a0f5-2c7e9b41d308 is not the sensor s"
        );
    }

    #[test]
    fn endpoint_subject_round_trips_through_json() {
        let event = endpoint_event();
        let json = serde_json::to_string(&event).expect("serializes");
        assert!(
            json.contains(
                r#""primary":{"Endpoint":{"endpoint_id":"6f1d7a52-93c4-4b8e-a0f5-2c7e9b41d308","ips":["192.0.2.30","2001:db8::30"],"default_route_ip":"192.0.2.30","net_state_source":"Observed","role":"Actor"}}"#
            ),
            "{json}"
        );
        let decoded: DetectionEvent = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(decoded, event);
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
    fn validate_accepts_window_outlier_events() {
        let v6 = PrimarySubject::Host {
            ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)),
            role: ThreatRole::Target,
        };
        let mut events = Vec::new();
        for detail in window_outlier_variants() {
            events.push(window_outlier_event(detail));
        }
        let mut ipv6 = window_outlier_event(window_outlier());
        window_outlier_detail(&mut ipv6).time_series_id = "12/2001:db8::10".to_string();
        let Target::Subject { primary, .. } = &mut ipv6.target else {
            unreachable!("the event has a subject target");
        };
        *primary = v6.clone();
        events.push(ipv6.clone());
        // Written differently, but the same address as the host's.
        for written in [
            "12/2001:0db8:0000:0000:0000:0000:0000:0010",
            "12/2001:DB8::0:10",
        ] {
            let mut event = ipv6.clone();
            window_outlier_detail(&mut event).time_series_id = written.to_string();
            events.push(event);
        }
        // The part before `/` is not checked, and only the first `/` splits.
        let mut any_policy = window_outlier_event(window_outlier());
        window_outlier_detail(&mut any_policy).time_series_id = "/192.0.2.9".to_string();
        events.push(any_policy);
        let mut empty = window_outlier_event(window_outlier_without_slots());
        *window_of(&mut empty) = TimeWindow {
            start: at(NANOS),
            end: at(NANOS + 3_600_000_000_000 - 1),
        };
        events.push(empty);
        for event in events {
            assert_eq!(event.validate(), Ok(()), "{event:?}");
        }
    }

    #[test]
    fn validate_rejects_window_outlier_breaking_rule_10() {
        let raw = {
            let mut event = window_outlier_event(window_outlier());
            event.sensor = Some("sensor-1".to_string());
            event.raw_event_kind = RawEventKind::Conn;
            event.target = Target::RawEvent {
                time: event.time,
                body: conn(),
            };
            event
        };
        let with_primary = |primary: PrimarySubject| {
            let mut event = window_outlier_event(window_outlier());
            event.sensor = Some("sensor-1".to_string());
            let Target::Subject { primary: p, .. } = &mut event.target else {
                unreachable!("the event has a subject target");
            };
            *p = primary;
            event
        };
        let with_id = |id: &str| {
            let mut event = window_outlier_event(window_outlier());
            window_outlier_detail(&mut event).time_series_id = id.to_string();
            event
        };
        let mut four_slots = window_outlier_event(window_outlier());
        window_outlier_detail(&mut four_slots)
            .top_slots
            .push(slot(180_000_000_000, 1.0, 1.0));

        let cases = [
            (raw, WindowOutlierViolation::NotSubjectTarget),
            (
                with_primary(PrimarySubject::Sensor),
                WindowOutlierViolation::NotHostSubject,
            ),
            (
                with_primary(PrimarySubject::Cluster {
                    clustering_model: 4,
                    cluster_id: 17,
                }),
                WindowOutlierViolation::NotHostSubject,
            ),
            (
                with_primary(PrimarySubject::Network {
                    customer: 2,
                    name: "office".to_string(),
                    role: ThreatRole::Actor,
                }),
                WindowOutlierViolation::NotHostSubject,
            ),
            (
                four_slots,
                WindowOutlierViolation::TooManyTopSlots { count: 4 },
            ),
            (
                with_id("192.0.2.9"),
                WindowOutlierViolation::TimeSeriesIdWithoutSlash,
            ),
            (
                with_id("7/host-a"),
                WindowOutlierViolation::TimeSeriesIdWithoutIp,
            ),
            (with_id("7/"), WindowOutlierViolation::TimeSeriesIdWithoutIp),
            (
                with_id("7/192.0.2.9/24"),
                WindowOutlierViolation::TimeSeriesIdWithoutIp,
            ),
            (
                with_id("7/192.0.2.10"),
                WindowOutlierViolation::TimeSeriesIpMismatch {
                    time_series_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                    host: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
                },
            ),
            (
                with_id("7/::ffff:192.0.2.9"),
                WindowOutlierViolation::TimeSeriesIpMismatch {
                    time_series_ip: IpAddr::V6(Ipv4Addr::new(192, 0, 2, 9).to_ipv6_mapped()),
                    host: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
                },
            ),
        ];
        for (event, violation) in cases {
            let error = assert_rule(&event, 10);
            assert_eq!(
                error,
                DetectionEventError::InvalidWindowOutlier(violation),
                "{event:?}"
            );
        }
    }

    #[test]
    fn validate_describes_each_rule_10_violation() {
        for (violation, message) in [
            (
                WindowOutlierViolation::NotSubjectTarget,
                "a WindowOutlier detail requires a subject target",
            ),
            (
                WindowOutlierViolation::NotHostSubject,
                "a WindowOutlier detail requires a host primary subject",
            ),
            (
                WindowOutlierViolation::TooManyTopSlots { count: 4 },
                "4 top slots exceed the maximum of 3",
            ),
            (
                WindowOutlierViolation::TimeSeriesIdWithoutSlash,
                "time_series_id contains no '/'",
            ),
            (
                WindowOutlierViolation::TimeSeriesIdWithoutIp,
                "the part of time_series_id after '/' is not an IP address",
            ),
            (
                WindowOutlierViolation::TimeSeriesIpMismatch {
                    time_series_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                    host: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
                },
                "time_series_id IP 192.0.2.10 differs from the host IP 192.0.2.9",
            ),
        ] {
            let error = DetectionEventError::InvalidWindowOutlier(violation);
            assert_eq!(error.rule(), 10);
            assert_eq!(
                error.to_string(),
                format!("detection event rule 10: {message}")
            );
        }
    }

    #[test]
    fn validate_checks_rule_10_after_rules_1_to_7() {
        // Each event also breaks rule 10 (its IP differs from the host's),
        // so the lower-numbered rule is the one reported.
        let broken = || {
            let mut event = window_outlier_event(window_outlier());
            window_outlier_detail(&mut event).time_series_id = "7/192.0.2.10".to_string();
            event
        };
        assert_rule(&broken(), 10);

        let mut mismatch = broken();
        mismatch.detection_model = DetectionModel::FarOutlier;
        assert_rule(&mismatch, 1);

        let mut raw = broken();
        raw.raw_event_kind = RawEventKind::Conn;
        raw.target = Target::RawEvent {
            time: raw.time,
            body: conn(),
        };
        assert_rule(&raw, 2);
        raw.sensor = Some("sensor-1".to_string());
        raw.time = at(NANOS + 1);
        assert_rule(&raw, 7);

        let mut sensor = broken();
        let Target::Subject { primary, .. } = &mut sensor.target else {
            unreachable!("the event has a subject target");
        };
        *primary = PrimarySubject::Sensor;
        assert_rule(&sensor, 3);

        let mut inverted = broken();
        window_of(&mut inverted).start = at(NANOS + 180_000_000_000);
        assert_rule(&inverted, 4);

        let mut related = broken();
        let Target::Subject {
            related_ips: too_many,
            ..
        } = with_related_ips(MAX_RELATED_IPS + 1).target
        else {
            unreachable!("with_related_ips() builds a subject target");
        };
        let Target::Subject { related_ips, .. } = &mut related.target else {
            unreachable!("the event has a subject target");
        };
        *related_ips = too_many;
        assert_rule(&related, 5);

        let mut score = broken();
        score.score = f64::NAN;
        assert_rule(&score, 6);
    }

    #[test]
    fn time_series_id_names_the_series_of_window_outlier_only() {
        let details = details();
        for detail in &details {
            let expected = match detail {
                Detail::WindowOutlier(_) => Some("7/192.0.2.9"),
                _ => None,
            };
            assert_eq!(detail.time_series_id(), expected, "{detail:?}");
        }
        assert!(
            details
                .iter()
                .any(|detail| matches!(detail, Detail::WindowOutlier(_)))
        );
        for detail in window_outlier_variants() {
            let id = detail.time_series_id.clone();
            assert_eq!(
                Detail::WindowOutlier(detail).time_series_id(),
                Some(id.as_str())
            );
        }
    }

    #[test]
    fn window_outlier_times_encode_as_nanosecond_number_in_json() {
        let expected = serde_json::Value::from(
            i64::try_from(NANOS).expect("the test timestamp fits i64 nanoseconds"),
        );
        let event = window_outlier_event(window_outlier());
        let value = serde_json::to_value(&event).expect("serializes");
        let detail = &value["detail"]["WindowOutlier"];
        assert_eq!(detail["window_start"], expected);
        assert_eq!(detail["top_slots"][0]["slot_start"], expected);
        assert_eq!(
            detail["top_slots"][1]["slot_start"],
            serde_json::Value::from(
                i64::try_from(NANOS + 60_000_000_000).expect("fits i64 nanoseconds")
            )
        );

        let mut wide = window_outlier();
        wide.window_start = at(WIDE_NANOS);
        wide.top_slots = vec![SlotDeviation {
            slot_start: at(-WIDE_NANOS),
            value: 1.0,
            centroid_value: 0.5,
        }];
        let json = serde_json::to_string(&wide).expect("serializes");
        assert!(
            json.contains(r#""window_start":200000000000000000000,"#),
            "{json}"
        );
        assert!(
            json.contains(r#""slot_start":-200000000000000000000,"#),
            "{json}"
        );
        assert_eq!(
            serde_json::from_str::<WindowOutlierDetail>(&json).expect("deserializes"),
            wide
        );
        let decoded: DetectionEvent =
            serde_json::from_str(&serde_json::to_string(&event).expect("serializes"))
                .expect("deserializes");
        assert_eq!(decoded, event);
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
    fn new_details_debug_print_their_strings_as_is() {
        assert_eq!(
            format!("{:?}", label_db_match()),
            r#"LabelDbMatchDetail { label_db: "ldb", rule_id: 300, rule_name: "r", matched_to: "sig", cluster_id: 7, rule_confidence: Some(0.5), match_score: 1.0 }"#
        );
        assert_eq!(
            format!("{:?}", far_outlier()),
            r#"Prefix { nearest_cluster_id: Some(5), nearest_signature: Some("ab"), matched_tokens: 2, prefix_len: 4, diverged_token: Some("x"), pattern_count: 1000, truncated_in_pattern: 3 }"#
        );
    }

    #[test]
    fn new_details_encode_as_json() {
        for (detail, json) in [
            (
                Detail::LabelDbMatch(label_db_match()),
                r#"{"LabelDbMatch":{"label_db":"ldb","rule_id":300,"rule_name":"r","matched_to":"sig","cluster_id":7,"rule_confidence":0.5,"match_score":1.0}}"#,
            ),
            (
                Detail::LabelDbMatch(LabelDbMatchDetail {
                    rule_confidence: None,
                    ..label_db_match()
                }),
                r#"{"LabelDbMatch":{"label_db":"ldb","rule_id":300,"rule_name":"r","matched_to":"sig","cluster_id":7,"rule_confidence":null,"match_score":1.0}}"#,
            ),
            (
                Detail::FarOutlier(far_outlier()),
                r#"{"FarOutlier":{"Prefix":{"nearest_cluster_id":5,"nearest_signature":"ab","matched_tokens":2,"prefix_len":4,"diverged_token":"x","pattern_count":1000,"truncated_in_pattern":3}}}"#,
            ),
            (
                Detail::FarOutlier(far_outlier_without_prefix()),
                r#"{"FarOutlier":{"Prefix":{"nearest_cluster_id":null,"nearest_signature":null,"matched_tokens":0,"prefix_len":0,"diverged_token":null,"pattern_count":1,"truncated_in_pattern":0}}}"#,
            ),
            (
                Detail::WindowOutlier(window_outlier()),
                r#"{"WindowOutlier":{"time_series_id":"7/192.0.2.9","window_start":1773586804120000000,"nearest_cluster_id":5,"distance":2.5,"top_slots":[{"slot_start":1773586804120000000,"value":1.0,"centroid_value":0.5},{"slot_start":1773586864120000000,"value":40.0,"centroid_value":2.0},{"slot_start":1773586924120000000,"value":0.0,"centroid_value":3.25}],"truncated":3,"pcap_truncated":250}}"#,
            ),
            (
                Detail::WindowOutlier(window_outlier_without_slots()),
                r#"{"WindowOutlier":{"time_series_id":"7/192.0.2.9","window_start":1773586804120000000,"nearest_cluster_id":5,"distance":2.5,"top_slots":[],"truncated":0,"pcap_truncated":null}}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&detail).expect("serializes"), json);
            let decoded: Detail = serde_json::from_str(json).expect("deserializes");
            assert_eq!(decoded, detail);
        }
    }

    #[test]
    fn every_detail_round_trips_through_json() {
        let window_outliers = window_outlier_variants()
            .into_iter()
            .map(Detail::WindowOutlier);
        for detail in details().into_iter().chain(window_outliers) {
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

    use super::tests::{
        NANOS, SOURCES, TABLE, WIDE_NANOS, at, conn, details, endpoint, et_signature, far_outlier,
        far_outlier_without_prefix, label_db_match, sigma_signature, window_outlier,
        window_outlier_event, window_outlier_variants, window_outlier_without_slots,
    };
    use super::*;
    use crate::types::raw_event;

    /// `test::detection_events()` as of tag `0.32.0`, each event encoded and
    /// the encodings concatenated.
    const RELEASED_EVENTS: &[u8] =
        include_bytes!("../../tests/fixtures/0.32.0/detection-events.bin");

    /// One raw event detection event per network and Netflow body of
    /// `raw_event::tests::bodies()` as of tag `0.32.0`, built by
    /// [`released_raw_event`], each encoded and the encodings concatenated.
    const RELEASED_RAW_EVENTS: &[u8] =
        include_bytes!("../../tests/fixtures/0.32.0/raw-event-detection-events.bin");

    /// The raw event detection event [`released_raw_event`] builds for the
    /// `Http` body of `raw_event::tests::bodies()`, in the layout protocol
    /// `0.53.0` gives the body: the `0.32.0` capture of that event with the
    /// six request header fields inserted after `state`.
    const HTTP_EVENT: &[u8] =
        include_bytes!("../../tests/fixtures/current/http-detection-event.bin");

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

    /// Builds the raw event detection event the `0.32.0` fixture holds for
    /// `body`.
    fn released_raw_event(body: RawEventBody) -> DetectionEvent {
        DetectionEvent {
            time: at(NANOS),
            sensor: Some("sensor-1".to_string()),
            detection_model: DetectionModel::NonBrowser,
            raw_event_kind: raw_event_body_kind(&body),
            category: Some(EventCategory::CommandAndControl),
            target: Target::RawEvent {
                time: at(NANOS),
                body,
            },
            score: 0.75,
            detail: Detail::NonBrowser,
        }
    }

    /// Returns whether a body's variant was released with its current
    /// fields: every network and Netflow body except `Http`. A Sysmon body
    /// gained its header in protocol `0.52.0`, the log bodies are new, and
    /// `Http` gained six request header fields in protocol `0.53.0`.
    fn released_unchanged(body: &RawEventBody) -> bool {
        match body {
            RawEventBody::Conn(_)
            | RawEventBody::Dns(_)
            | RawEventBody::Rdp(_)
            | RawEventBody::Smtp(_)
            | RawEventBody::Ntlm(_)
            | RawEventBody::Kerberos(_)
            | RawEventBody::Ssh(_)
            | RawEventBody::DceRpc(_)
            | RawEventBody::Ftp(_)
            | RawEventBody::Mqtt(_)
            | RawEventBody::Ldap(_)
            | RawEventBody::Tls(_)
            | RawEventBody::Smb(_)
            | RawEventBody::Nfs(_)
            | RawEventBody::Bootp(_)
            | RawEventBody::Dhcp(_)
            | RawEventBody::Radius(_)
            | RawEventBody::MalformedDns(_)
            | RawEventBody::Icmp(_)
            | RawEventBody::Netflow5(_)
            | RawEventBody::Netflow9(_) => true,
            RawEventBody::Http(_)
            | RawEventBody::ProcessCreate(_)
            | RawEventBody::FileCreateTime(_)
            | RawEventBody::NetworkConnect(_)
            | RawEventBody::ProcessTerminate(_)
            | RawEventBody::ImageLoad(_)
            | RawEventBody::FileCreate(_)
            | RawEventBody::RegistryValueSet(_)
            | RawEventBody::RegistryKeyRename(_)
            | RawEventBody::FileCreateStreamHash(_)
            | RawEventBody::PipeEvent(_)
            | RawEventBody::DnsQuery(_)
            | RawEventBody::FileDelete(_)
            | RawEventBody::ProcessTamper(_)
            | RawEventBody::FileDeleteDetected(_)
            | RawEventBody::DriverLoad(_)
            | RawEventBody::CreateRemoteThread(_)
            | RawEventBody::RawAccessRead(_)
            | RawEventBody::ProcessAccess(_)
            | RawEventBody::RegistryObjectAddDel(_)
            | RawEventBody::WindowsEventLog(_)
            | RawEventBody::Journald(_)
            | RawEventBody::Auditd(_) => false,
        }
    }

    /// Checks that `events` encode, one after another, to exactly `fixture`.
    fn assert_encodes_to(events: &[DetectionEvent], fixture: &[u8]) {
        let mut rest = fixture;
        for (index, event) in events.iter().enumerate() {
            let bytes = encode(event);
            let Some((released, after)) = rest.split_at_checked(bytes.len()) else {
                panic!("the fixture ends inside event {index}: {event:?}");
            };
            assert_eq!(bytes, released, "event {index}: {event:?}");
            assert_eq!(&decode::<DetectionEvent>(released), event);
            rest = after;
        }
        assert!(rest.is_empty(), "the fixture holds more events");
    }

    #[test]
    fn released_detection_events_keep_their_bytes() {
        let mut events = crate::test::detection_events();
        assert!(matches!(
            events.get(crate::test::RELEASED_DETECTION_EVENTS),
            Some(DetectionEvent {
                target: Target::Subject {
                    primary: PrimarySubject::Endpoint { .. },
                    ..
                },
                ..
            })
        ));
        events.truncate(crate::test::RELEASED_DETECTION_EVENTS);
        assert_encodes_to(&events, RELEASED_EVENTS);
    }

    #[test]
    fn released_raw_event_bodies_keep_their_bytes() {
        let events: Vec<_> = raw_event::tests::bodies()
            .into_iter()
            .filter(released_unchanged)
            .map(released_raw_event)
            .collect();
        assert_eq!(events.len(), 21);
        for event in &events {
            assert_eq!(event.validate(), Ok(()));
        }
        assert_encodes_to(&events, RELEASED_RAW_EVENTS);
    }

    #[test]
    fn http_body_encodes_its_request_headers_after_state() {
        let events: Vec<_> = raw_event::tests::bodies()
            .into_iter()
            .filter(|body| matches!(body, RawEventBody::Http(_)))
            .map(released_raw_event)
            .collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].validate(), Ok(()));
        assert_encodes_to(&events, HTTP_EVENT);

        // The six fields are the last bytes of the body, after `state`
        // ("done"), and before the score and detail.
        let RawEventBody::Http(http) = raw_event::tests::bodies()
            .into_iter()
            .find(|body| matches!(body, RawEventBody::Http(_)))
            .expect("bodies() has an Http body")
        else {
            unreachable!("the Http body was found");
        };
        let mut tail = encode(&http.state);
        tail.extend(encode(&http.request_header_names));
        tail.extend(encode(&http.accept));
        tail.extend(encode(&http.connection));
        tail.extend(encode(&http.accept_encoding));
        tail.extend(encode(&http.accept_language));
        tail.extend(encode(&http.pragma));
        tail.extend(0.75_f64.to_le_bytes());
        tail.push(13);
        assert!(HTTP_EVENT.ends_with(&tail));
    }

    #[test]
    fn endpoint_subject_encodes_after_every_existing_variant() {
        let mut expected = vec![4];
        expected.extend([
            16, 0x6f, 0x1d, 0x7a, 0x52, 0x93, 0xc4, 0x4b, 0x8e, 0xa0, 0xf5, 0x2c, 0x7e, 0x9b, 0x41,
            0xd3, 0x08,
        ]);
        expected.extend([2, 0, 192, 0, 2, 30, 1]);
        expected.extend([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30,
        ]);
        expected.extend([1, 0, 192, 0, 2, 30]);
        expected.extend([0, 0]);
        let primary = endpoint();
        assert_eq!(encode(&primary), expected);
        assert_eq!(decode::<PrimarySubject>(&expected), primary);

        let PrimarySubject::Endpoint {
            endpoint_id, role, ..
        } = primary
        else {
            unreachable!("endpoint() is an endpoint subject");
        };
        for (net_state_source, tag) in [
            (NetStateSource::Observed, vec![0]),
            (NetStateSource::Inferred, vec![1]),
            (NetStateSource::Unknown, vec![2]),
            (NetStateSource::Other("x".to_string()), vec![3, 1, b'x']),
        ] {
            let primary = PrimarySubject::Endpoint {
                endpoint_id,
                ips: Vec::new(),
                default_route_ip: None,
                net_state_source,
                role,
            };
            let mut expected = vec![4];
            expected.extend(encode(&endpoint_id));
            expected.extend([0, 0]);
            expected.extend(tag);
            expected.push(0);
            assert_eq!(encode(&primary), expected);
            assert_eq!(decode::<PrimarySubject>(&expected), primary);
        }
    }

    #[test]
    fn model_serializes_as_number_in_bincode() {
        for (model, number) in TABLE {
            let bytes = encode(&model);
            assert_eq!(bytes, encode(&number), "{model:?}");
            assert_eq!(decode::<DetectionModel>(&bytes), model);
        }
        assert_eq!(encode(&DetectionModel::UnusualDestinationPattern), [17]);
        assert_eq!(encode(&DetectionModel::LabelDbMatch), [18]);
        assert_eq!(encode(&DetectionModel::FarOutlier), [19]);
        assert_eq!(
            decode::<DetectionModel>(&[18]),
            DetectionModel::LabelDbMatch
        );
        assert_eq!(decode::<DetectionModel>(&[19]), DetectionModel::FarOutlier);
        assert_eq!(encode(&DetectionModel::WindowOutlier), [20]);
        assert_eq!(
            decode::<DetectionModel>(&[20]),
            DetectionModel::WindowOutlier
        );
        assert_eq!(encode(&DetectionModel::EtSignature), [21]);
        assert_eq!(encode(&DetectionModel::EtPolicySignature), [22]);
        assert_eq!(encode(&DetectionModel::SigmaSignature), [23]);
        assert_eq!(decode::<DetectionModel>(&[21]), DetectionModel::EtSignature);
        assert_eq!(
            decode::<DetectionModel>(&[22]),
            DetectionModel::EtPolicySignature
        );
        assert_eq!(
            decode::<DetectionModel>(&[23]),
            DetectionModel::SigmaSignature
        );
        assert!(
            bincode::serde::decode_from_slice::<DetectionModel, _>(
                &encode(&24_u32),
                bincode::config::standard(),
            )
            .is_err()
        );
    }

    #[test]
    fn signature_source_serializes_as_number_in_bincode() {
        for (source, number) in SOURCES {
            assert_eq!(encode(&source), encode(&number), "{source:?}");
            assert_eq!(decode::<SignatureSource>(&encode(&number)), source);
        }
        assert_eq!(encode(&SignatureSource::SigmaHqEmerging), [2]);
        assert!(
            bincode::serde::decode_from_slice::<SignatureSource, _>(
                &encode(&3_u32),
                bincode::config::standard(),
            )
            .is_err()
        );
    }

    #[test]
    fn signature_details_encode_after_every_existing_variant() {
        let mut sigma = vec![1, 2];
        for text in [
            "r2026-11-01",
            "0.9.1",
            "5f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
        ] {
            sigma.extend(encode(text));
        }
        sigma.push(0);
        sigma.extend(encode("Suspicious PowerShell Download"));
        sigma.extend([0, 0]);
        sigma.extend(encode("high"));
        sigma.extend([0, 0, 0, 0, 0]);
        let detail = sigma_signature();
        assert_eq!(encode(&detail), sigma[1..]);
        assert_eq!(decode::<SignatureMatchDetail>(&sigma[1..]), detail);
        sigma[0] = 23;
        let detail = Detail::SigmaSignature(sigma_signature());
        assert_eq!(encode(&detail), sigma);
        assert_eq!(decode::<Detail>(&sigma), detail);

        let mut et = vec![0];
        for text in ["10813", "1.2.0", "2013028"] {
            et.extend(encode(text));
        }
        et.push(1);
        et.extend(encode("7"));
        et.extend(encode("ET POLICY curl User-Agent Outbound"));
        et.push(1);
        et.extend(encode("attempted-recon"));
        et.push(2);
        et.extend(encode("T1071.001"));
        et.extend(encode("T1105"));
        et.extend(encode("2"));
        et.push(1);
        et.extend(encode("Emerging Threats"));
        et.push(2);
        et.extend(encode("user_agent"));
        et.extend(encode("resp_port"));
        et.push(1);
        et.push(1);
        et.extend(encode("Security"));
        et.extend([1, 0xfb, 0x11, 0x12]);
        let detail = et_signature();
        assert_eq!(encode(&detail), et);
        assert_eq!(decode::<SignatureMatchDetail>(&et), detail);
        for (tag, detail) in [
            (21, Detail::EtSignature(et_signature())),
            (22, Detail::EtPolicySignature(et_signature())),
        ] {
            let mut expected = vec![tag];
            expected.extend(&et);
            assert_eq!(encode(&detail), expected, "{detail:?}");
            assert_eq!(decode::<Detail>(&expected), detail);
        }
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
    fn existing_detail_encodings_are_unchanged() {
        // The released encodings: each variant's tag is its declaration
        // index, a one-byte varint, followed by its payload.
        let expected: [&[u8]; 18] = [
            &[
                0, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 12, 3, 1,
            ],
            &[1, 2, 3, b'x', b'm', b'r', 3, b'b', b't', b'c'],
            &[2],
            &[3],
            &[4, 3, 22, 80, 0xfb, 0xbb, 0x01, 6],
            &[5, 0xfb, 0xbd, 0x01, 6, 1],
            &[6, 17, 9],
            &[7, 6, 0],
            &[
                8, 21, 6, 2, 6, b'u', b's', b'e', b'r', b'-', b'a', 6, b'u', b's', b'e', b'r',
                b'-', b'b', 0,
            ],
            &[
                9, 0xfb, 0x85, 0x01, 6, 1, 6, b'u', b's', b'e', b'r', b'-', b'a', 9, b's', b'y',
                b'n', b't', b'h', b'e', b't', b'i', b'c',
            ],
            &[10, 0xfb, 0x50, 0xc3, 0xfb, 0x90, 0x1f, 6],
            &[11],
            &[12],
            &[13],
            &[14],
            &[15],
            &[16],
            &[
                17, 40, 0, 0, 0, 0, 0, 0, 0x04, 0x40, 0, 0, 0, 0, 0, 0, 0xf4, 0x3f, 0, 0, 0, 0, 0,
                0, 0x3e, 0x40, 2,
            ],
        ];
        let details = details();
        for (detail, bytes) in details.iter().zip(expected) {
            assert_eq!(encode(detail), bytes, "{detail:?}");
            assert_eq!(&decode::<Detail>(bytes), detail);
        }
    }

    #[test]
    fn new_details_encode_after_every_existing_variant() {
        for (detail, bytes) in [
            (
                Detail::LabelDbMatch(label_db_match()),
                &[
                    18, 3, b'l', b'd', b'b', 0xfb, 0x2c, 0x01, 1, b'r', 3, b's', b'i', b'g', 7, 1,
                    0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x80, 0x3f,
                ][..],
            ),
            (
                Detail::LabelDbMatch(LabelDbMatchDetail {
                    rule_confidence: None,
                    ..label_db_match()
                }),
                &[
                    18, 3, b'l', b'd', b'b', 0xfb, 0x2c, 0x01, 1, b'r', 3, b's', b'i', b'g', 7, 0,
                    0x00, 0x00, 0x80, 0x3f,
                ][..],
            ),
            (
                Detail::FarOutlier(far_outlier()),
                &[
                    19, 0, 1, 5, 1, 2, b'a', b'b', 2, 4, 1, 1, b'x', 0xfb, 0xe8, 0x03, 3,
                ][..],
            ),
            (
                Detail::FarOutlier(far_outlier_without_prefix()),
                &[19, 0, 0, 0, 0, 0, 0, 1, 0][..],
            ),
        ] {
            assert_eq!(encode(&detail), bytes, "{detail:?}");
            assert_eq!(decode::<Detail>(bytes), detail);
        }
    }

    #[test]
    fn window_outlier_encodes_after_every_existing_variant() {
        let slot = |offset: i128, value: f64, centroid_value: f64| {
            let mut bytes = encode(&(NANOS + offset));
            bytes.extend(value.to_le_bytes());
            bytes.extend(centroid_value.to_le_bytes());
            bytes
        };
        let mut prefix = vec![20, 11];
        prefix.extend(b"7/192.0.2.9");
        prefix.extend(NANOS_BYTES);
        prefix.push(5);
        prefix.extend([0, 0, 0, 0, 0, 0, 0x04, 0x40]);

        let mut full = prefix.clone();
        full.push(3);
        full.extend(NANOS_BYTES);
        full.extend([0, 0, 0, 0, 0, 0, 0xf0, 0x3f, 0, 0, 0, 0, 0, 0, 0xe0, 0x3f]);
        full.extend(slot(60_000_000_000, 40.0, 2.0));
        full.extend(slot(120_000_000_000, 0.0, 3.25));
        full.extend([3, 1, 250]);

        let mut empty = prefix;
        empty.extend([0, 0, 0]);

        for (detail, bytes) in [
            (Detail::WindowOutlier(window_outlier()), full),
            (Detail::WindowOutlier(window_outlier_without_slots()), empty),
        ] {
            assert_eq!(encode(&detail), bytes, "{detail:?}");
            assert_eq!(decode::<Detail>(&bytes), detail);
        }
    }

    #[test]
    fn window_outlier_times_encode_as_nanosecond_i128() {
        let mut detail = window_outlier();
        detail.window_start = at(WIDE_NANOS);
        detail.top_slots.truncate(1);
        detail.top_slots[0].slot_start = at(WIDE_NANOS);
        let mut expected = vec![20, 11];
        expected.extend(b"7/192.0.2.9");
        expected.extend(WIDE_NANOS_BYTES);
        expected.push(5);
        expected.extend(2.5_f64.to_le_bytes());
        expected.push(1);
        expected.extend(WIDE_NANOS_BYTES);
        expected.extend(1.0_f64.to_le_bytes());
        expected.extend(0.5_f64.to_le_bytes());
        expected.extend([3, 1, 250]);
        let detail = Detail::WindowOutlier(detail);
        assert_eq!(encode(&detail), expected);
        assert_eq!(decode::<Detail>(&expected), detail);
    }

    #[test]
    fn every_detail_round_trips_through_bincode() {
        let window_outliers = window_outlier_variants()
            .into_iter()
            .map(Detail::WindowOutlier);
        for detail in details().into_iter().chain(window_outliers) {
            assert_eq!(decode::<Detail>(&encode(&detail)), detail);
        }
    }

    #[test]
    fn shared_detection_events_are_valid_and_carry_window_outlier() {
        let events = crate::test::detection_events();
        for (index, event) in events.iter().enumerate() {
            assert_eq!(
                event.validate().is_err(),
                index == crate::test::INVALID_DETECTION_EVENT,
                "{index}: {event:?}"
            );
        }
        let pcap_truncated: Vec<_> = events
            .iter()
            .filter_map(|event| match &event.detail {
                Detail::WindowOutlier(detail) => Some(detail.pcap_truncated.is_some()),
                _ => None,
            })
            .collect();
        assert_eq!(pcap_truncated, [true, false]);

        // Every primary subject variant appears, by its encoded tag.
        let mut subjects = Vec::new();
        for event in &events {
            if let Target::Subject { primary, .. } = &event.target {
                let index = encode(primary).first().copied();
                if !subjects.contains(&index) {
                    subjects.push(index);
                }
            }
        }
        subjects.sort_unstable();
        assert_eq!(subjects, [Some(0), Some(1), Some(2), Some(3), Some(4)]);
        assert!(matches!(
            events.get(crate::test::RELEASED_DETECTION_EVENTS),
            Some(DetectionEvent {
                target: Target::Subject {
                    primary: PrimarySubject::Endpoint { .. },
                    ..
                },
                ..
            })
        ));

        // Every detail variant appears, by its encoded tag; the three
        // signature events follow the endpoint event.
        let mut tags: Vec<_> = events
            .iter()
            .map(|event| encode(&event.detail).first().copied())
            .collect();
        let signatures = tags.split_off(crate::test::RELEASED_DETECTION_EVENTS + 1);
        assert_eq!(signatures, [Some(21), Some(22), Some(23)]);
        tags.extend(signatures);
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), TABLE.len());
    }

    #[test]
    fn window_outlier_events_round_trip_through_bincode() {
        for detail in window_outlier_variants() {
            let event = window_outlier_event(detail);
            assert_eq!(event.validate(), Ok(()));
            assert_eq!(decode::<DetectionEvent>(&encode(&event)), event);
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
