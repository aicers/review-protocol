//! Device identification (DAI): the observations an agent extracts from
//! sensor records and the per-day address range counts it reports to the
//! manager.
//!
//! An agent reads sensor records, reduces them to observations per 5-minute
//! slot and sends each slot with [`DaiObservationBatch`]. The manager keeps
//! the read cursors ([`DaiCursors`]) and decides which devices own which IP
//! addresses. Per sensor and per UTC day, the agent also counts the private
//! and CGNAT addresses it saw outside the customer's registered networks and
//! sends them with [`DaiRangeDay`], so the manager can propose unregistered
//! internal ranges.
//!
//! # Units
//!
//! Every time is an `i64` count of nanoseconds since the UNIX epoch, and
//! every date an `i32` count of days since the UNIX epoch, in UTC.
//!
//! # Sensor lists
//!
//! `get_dai_extractor_config` and `get_dai_cursors` take the names of the
//! sensors the agent takes. A list that is exactly `["all"]` stands for every
//! sensor that belongs to a customer. Any other list is answered for only the
//! named sensors that belong to a customer; the other names are left out of
//! the answer, not reported as errors.
//!
//! # Hashes
//!
//! This crate computes none of the values below; the agent and the manager
//! do, by these rules. "The encoding" of a value is its bincode 2 serde
//! encoding under `bincode::config::standard()`, the encoding of every
//! request of this protocol.
//!
//! - **Identifier hash** of an observation: the first 16 bytes of SHA-256
//!   over the encoding of the tuple of its body's identifier fields (see
//!   [`DaiObservationBody`]), in declaration order. The kind is not part of
//!   it.
//! - **Config revision** ([`DaiExtractorConfig::revision`], and
//!   `config_revision` in every [`DaiStoreAck`]): the first 8 bytes of
//!   SHA-256, read as a little-endian `u64`, over the encoding of the
//!   `sensors` list of the config returned to that agent, that is, the
//!   config without `revision`.
//! - **Network digest** (`network_digest`): the first 8 bytes of SHA-256,
//!   read as a little-endian `u64`, over the encoding of the tuple
//!   `(internal, registered)` of the sensor's customer (see
//!   [`DaiSensorConfig`]), after sorting each list inside both groups
//!   ascending — `hosts` and `networks` by their `Ord`, `ip_ranges` by
//!   `(start, end)` — without removing duplicates.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use super::HostNetworkGroup;

/// The extractor configuration the manager answers to
/// `get_dai_extractor_config`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiExtractorConfig {
    /// The config revision: the first 8 bytes of SHA-256, read as a
    /// little-endian `u64`, over the bincode 2 standard-config serde encoding
    /// of `sensors`. Every [`DaiStoreAck`] carries the manager's current
    /// value as `config_revision`, so an agent sees when to refetch.
    pub revision: u64,
    /// One entry per sensor that belongs to a customer, of those the request
    /// named (or of all such sensors for `["all"]`), sorted by `sensor`
    /// ascending, so the same content always gives the same `revision`.
    pub sensors: Vec<DaiSensorConfig>,
}

/// The configuration of one sensor in a [`DaiExtractorConfig`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiSensorConfig {
    /// The sensor name.
    pub sensor: String,
    /// The sensor's configuration epoch. It rises by one whenever the
    /// sensor's customer, site, enabled flag or networks change, and never
    /// falls.
    pub config_epoch: u64,
    /// The network digest of the sensor's customer: the first 8 bytes of
    /// SHA-256, read as a little-endian `u64`, over the bincode 2
    /// standard-config serde encoding of the tuple `(internal, registered)`,
    /// after sorting each list inside both groups ascending (`hosts` and
    /// `networks` by their `Ord`, `ip_ranges` by `(start, end)`), without
    /// removing duplicates.
    pub network_digest: u64,
    /// The customer the sensor belongs to.
    pub customer_id: u32,
    /// The sensor's site.
    pub site: String,
    /// Whether extraction is enabled for the sensor.
    pub enabled: bool,
    /// The customer's Intranet and Gateway networks.
    pub internal: HostNetworkGroup,
    /// All of the customer's registered networks, of any kind.
    pub registered: HostNetworkGroup,
}

/// The read cursors the manager answers to `get_dai_cursors`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiCursors {
    /// The manager's restore generation. Every send carries the value the
    /// agent held; a different one is answered with a resync.
    pub restore_generation: u64,
    /// One entry per (sensor, kind).
    pub entries: Vec<DaiCursorEntry>,
    /// The range days the agent still has to collect or recollect.
    ///
    /// Only days within the last 30 days are listed, and of those only days
    /// that carry a recollect mark or are not stored yet, that are after the
    /// sensor's first cursor date, and whose end plus the allowed delay plus
    /// one hour has passed.
    pub range_days: Vec<DaiRangeDayState>,
}

/// The cursor of one (sensor, kind) in [`DaiCursors`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiCursorEntry {
    /// The sensor name.
    pub sensor: String,
    /// The observation kind.
    pub kind: DaiObservationKind,
    /// The slot boundary up to which every slot of this (sensor, kind) is
    /// stored. Nanoseconds since the UNIX epoch.
    pub cursor: i64,
    /// The time before which the agent counts no record. Nanoseconds since
    /// the UNIX epoch.
    pub read_floor: i64,
    /// The slots marked for re-extraction, with their marks.
    pub reextract: Vec<DaiReextractMark>,
}

/// A slot marked for re-extraction, and the mark it carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiReextractMark {
    /// The observation kind of the slot.
    pub kind: DaiObservationKind,
    /// The start of the slot. Nanoseconds since the UNIX epoch.
    pub slot_start: i64,
    /// The mark. A batch that re-extracts this slot carries it as
    /// [`DaiObservationBatch::reextract_mark`].
    pub mark: u64,
}

/// A range day listed in [`DaiCursors::range_days`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiRangeDayState {
    /// The sensor name.
    pub sensor: String,
    /// The day. Days since the UNIX epoch, in UTC.
    pub date: i32,
    /// The evidence the day is counted from.
    pub evidence: DaiRangeEvidence,
    /// The recollect mark the day carries, if any. A [`DaiRangeDay`] that
    /// recollects the day carries the mark it had here at the start of the
    /// round.
    pub mark: Option<u64>,
    /// The version stored for the day, if any.
    pub stored_version: Option<u64>,
}

/// One part of one send of the observations of one slot, the argument of
/// `send_dai_observations`.
///
/// One send of one slot has one random `send_id` and parts
/// `0..part_count`. `last_record_time`, `late_slots`, `reextract_mark`,
/// `lost_before` and `counted_from` are identical across the parts of a
/// send.
///
/// # Receiver filtering
///
/// The receiver drops, one observation at a time, an observation whose body
/// variant disagrees with `kind`, whose times fall outside the slot, or that
/// has a string field longer than 512 bytes, and keeps the rest of the
/// batch. The sender trims [`DaiObservationBody::SoftwareString`]'s `text`
/// and cuts it at 512 bytes; any other string field over 512 bytes is not
/// cut, and its observation is dropped by this rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiObservationBatch {
    /// The restore generation the agent held when it counted the slot.
    pub restore_generation: u64,
    /// The sensor's config epoch the agent held when it counted the slot.
    pub config_epoch: u64,
    /// The network digest the agent held when it counted the slot.
    pub network_digest: u64,
    /// The sensor name.
    pub sensor: String,
    /// The observation kind of every observation in the batch.
    pub kind: DaiObservationKind,
    /// The start of the slot. Nanoseconds since the UNIX epoch.
    pub slot_start: i64,
    /// The slot length in seconds (300).
    pub slot_len_secs: u32,
    /// The random identifier of this send, shared by all its parts.
    pub send_id: u64,
    /// The index of this part, in `0..part_count`.
    pub part: u32,
    /// The number of parts of this send.
    pub part_count: u32,
    /// The observations of this part.
    pub observations: Vec<DaiObservation>,
    /// The time of the last record the agent received from the sensor.
    /// Nanoseconds since the UNIX epoch.
    pub last_record_time: Option<i64>,
    /// Slots to be re-extracted because a record for them arrived after they
    /// were closed or counted.
    pub late_slots: Vec<DaiLateSlot>,
    /// Set when the batch is the result of re-extracting a slot, to that
    /// slot's mark (from [`DaiCursorEntry::reextract`]).
    pub reextract_mark: Option<u64>,
    /// Set when the agent skipped everything before this time. Nanoseconds
    /// since the UNIX epoch.
    pub lost_before: Option<i64>,
    /// The later of `slot_start` and the read floor the agent used.
    /// Nanoseconds since the UNIX epoch.
    pub counted_from: i64,
}

/// A slot to be re-extracted, listed in [`DaiObservationBatch::late_slots`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiLateSlot {
    /// The observation kind of the slot.
    pub kind: DaiObservationKind,
    /// The start of the slot. Nanoseconds since the UNIX epoch.
    pub slot_start: i64,
    /// The difference between the receive time and the record time of the
    /// late record. In nanoseconds.
    pub delay_ns: i64,
}

/// One observation in a slot.
///
/// Observations with the same (sensor, kind, identifier) in one slot are
/// sent once, with their values merged: `first_seen` is the minimum,
/// `last_seen` the maximum, `count` the sum, and
/// [`DaiObservationBody::Service`]'s `external_client` the logical OR. A
/// [`DaiObservationBody::DhcpLease`] is not merged: it is one observation
/// per record, with `first_seen` = `last_seen` = its `time` and `count` 1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiObservation {
    /// The time of the earliest record merged into this observation.
    /// Nanoseconds since the UNIX epoch.
    pub first_seen: i64,
    /// The time of the latest record merged into this observation.
    /// Nanoseconds since the UNIX epoch.
    pub last_seen: i64,
    /// The number of records merged into this observation.
    pub count: u32,
    /// What was observed.
    pub body: DaiObservationBody,
}

/// The kind of a [`DaiObservationBody`].
///
/// A kind is serialized as its number in every format, never as its name or
/// declaration index, and an unknown number fails to deserialize. The
/// numbers are fixed and only appended to; number 36 is reserved for a later
/// stage.
#[derive(
    Clone, Copy, Debug, Deserialize_repr, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize_repr,
)]
#[repr(u8)]
pub enum DaiObservationKind {
    /// [`DaiObservationBody::DhcpLease`].
    DhcpLease = 1,
    /// [`DaiObservationBody::DhcpServer`].
    DhcpServer = 3,
    /// [`DaiObservationBody::Kerberos`].
    Kerberos = 4,
    /// [`DaiObservationBody::Ntlm`].
    Ntlm = 5,
    /// [`DaiObservationBody::Service`].
    Service = 7,
    /// [`DaiObservationBody::SoftwareString`].
    SoftwareString = 8,
    /// [`DaiObservationBody::DnsName`].
    DnsName = 22,
    /// [`DaiObservationBody::IpActivity`].
    IpActivity = 34,
}

/// What an observation saw.
///
/// Each variant's fields split into the identifier and the values. In
/// `DhcpLease` the identifier is `time` through `giaddr`, and `client_id`,
/// `hostname`, `lease_secs`, `subnet_mask` and `routers` are values. In
/// `Service`, `external_client` is a value and the other fields are the
/// identifier. In every other variant all fields are the identifier.
///
/// The identifier hash is the first 16 bytes of SHA-256 over the bincode 2
/// standard-config serde encoding of the tuple of the identifier fields, in
/// declaration order; the kind is not part of it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DaiObservationBody {
    /// A DHCP message about a lease, one observation per record.
    DhcpLease {
        /// The record time. Nanoseconds since the UNIX epoch.
        time: i64,
        /// The DHCP message.
        msg: DaiDhcpMsg,
        /// The leased address.
        ip: IpAddr,
        /// The client hardware address.
        chaddr: Vec<u8>,
        /// The transaction ID.
        xid: u32,
        /// The address of the server that sent the message.
        server_ip: IpAddr,
        /// The server identifier option, if present.
        server_id: Option<IpAddr>,
        /// The relay agent address.
        giaddr: IpAddr,
        /// The client identifier option, if present. A value.
        client_id: Option<Vec<u8>>,
        /// The host name option, if present. A value.
        hostname: Option<String>,
        /// The lease time in seconds, if present. A value.
        lease_secs: Option<u32>,
        /// The subnet mask option, if present. A value.
        subnet_mask: Option<IpAddr>,
        /// The router option. A value.
        routers: Vec<IpAddr>,
    },
    /// A DHCP server.
    DhcpServer {
        /// The server's address.
        server_ip: IpAddr,
        /// The server identifier option, if present.
        server_id: Option<IpAddr>,
    },
    /// A Kerberos exchange.
    Kerberos {
        /// The client's address.
        client_ip: IpAddr,
        /// The realm.
        realm: String,
        /// The client principal name components.
        cname: Vec<String>,
        /// The service principal name components.
        sname: Vec<String>,
        /// The Kerberos message type.
        msg_type: u8,
        /// Whether the exchange was accepted.
        accepted: bool,
        /// The pre-authentication type.
        preauth: u8,
        /// The Kerberos error code, if the exchange failed.
        error_code: Option<u32>,
    },
    /// An NTLM authentication.
    Ntlm {
        /// The client's address.
        ip: IpAddr,
        /// The workstation name.
        workstation: String,
        /// The user name.
        user: String,
        /// The domain name.
        domain: String,
        /// Whether the authentication succeeded.
        success: bool,
    },
    /// A service a host answered on.
    Service {
        /// The server's address.
        server_ip: IpAddr,
        /// The server port.
        port: u16,
        /// The IP protocol number.
        proto: u8,
        /// A value: true if any record in the slot had a client outside the
        /// customer's registered networks. Merged with the logical OR.
        external_client: bool,
    },
    /// A software identification string.
    SoftwareString {
        /// The address of the host the string identifies.
        ip: IpAddr,
        /// Which side of the connection the host was.
        side: DaiSide,
        /// Where the string came from.
        source: DaiSoftwareSource,
        /// The string, trimmed and cut at 512 bytes by the sender.
        text: String,
    },
    /// A DNS name resolved to an address.
    DnsName {
        /// The name.
        name: String,
        /// The address.
        ip: IpAddr,
    },
    /// Activity of an address.
    IpActivity {
        /// The address.
        ip: IpAddr,
        /// Which side of the connection the address was.
        side: DaiSide,
    },
}

/// The DHCP message a [`DaiObservationBody::DhcpLease`] records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DaiDhcpMsg {
    /// DHCPACK to a DHCPREQUEST.
    Ack,
    /// DHCPACK to a DHCPINFORM.
    InformAck,
    /// DHCPRELEASE.
    Release,
    /// DHCPDECLINE.
    Decline,
}

/// The side of a connection a host was on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DaiSide {
    /// The client side.
    Client,
    /// The server side.
    Server,
}

/// Where a [`DaiObservationBody::SoftwareString`] came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DaiSoftwareSource {
    /// An SSH version string.
    Ssh,
    /// An HTTP `User-Agent` header.
    HttpUserAgent,
    /// A TLS certificate subject.
    TlsCertSubject,
}

/// The manager's answer to `send_dai_observations` and `send_dai_range_day`.
///
/// Every variant carries the manager's current restore generation and
/// config revision. The config revision is computed as
/// [`DaiExtractorConfig::revision`] is, over the config the manager returns
/// to that agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaiStoreAck {
    /// The part was accepted and the send is not complete yet; cursors and
    /// marks are unchanged. Used only for observation sends.
    Staged {
        /// The manager's restore generation.
        restore_generation: u64,
        /// The manager's config revision.
        config_revision: u64,
    },
    /// The send is complete and the slot (or day) is stored.
    Stored {
        /// The manager's restore generation.
        restore_generation: u64,
        /// The manager's config revision.
        config_revision: u64,
        /// The marks assigned to the send's `late_slots`. A repeated part of
        /// a completed send gets the same marks again.
        marks: Vec<DaiReextractMark>,
    },
    /// Nothing advanced; retry after `retry_after_ms`.
    Wait {
        /// How long to wait before retrying, in milliseconds.
        retry_after_ms: u32,
        /// The manager's restore generation.
        restore_generation: u64,
        /// The manager's config revision.
        config_revision: u64,
    },
    /// Nothing was written; the agent refetches cursors or config and
    /// recounts.
    ///
    /// The manager answers this when the restore generation, the sensor's
    /// config epoch or the network digest differs from its own, or when a
    /// part's `part_count` or send metadata differs from the earlier parts of
    /// the same send; on such a part mismatch the send's earlier parts are
    /// also discarded.
    Resync {
        /// The manager's restore generation.
        restore_generation: u64,
        /// The manager's config revision.
        config_revision: u64,
    },
}

/// The evidence a range day is counted from.
///
/// It has one variant now; later variants are appended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DaiRangeEvidence {
    /// The sensor's own records.
    Sensor,
}

/// A range day: one sensor, one UTC day, one kind of evidence.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DaiRangeUnit {
    /// The sensor name.
    pub sensor: String,
    /// The day. Days since the UNIX epoch, in UTC.
    pub date: i32,
    /// The evidence the day is counted from.
    pub evidence: DaiRangeEvidence,
}

/// The manager's answer to `begin_dai_range_day`.
///
/// A granted round raises the unit's version and grants a lease with a fresh
/// random `lease_token`. While the round runs, the agent renews the lease
/// with `renew_dai_range_day`, which answers the new lease end, or `None`
/// when the token is no longer the unit's current one; the agent then stops.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaiRangeGrant {
    /// The round is granted.
    Granted {
        /// The unit's new version, carried by the [`DaiRangeDay`] of this
        /// round.
        version: u64,
        /// The lease token, carried by the [`DaiRangeDay`] of this round and
        /// by every renewal.
        lease_token: u64,
        /// When the lease ends. Nanoseconds since the UNIX epoch.
        lease_expires_at: i64,
    },
    /// Another agent holds a live lease on the unit.
    InProgress {
        /// When that lease ends. Nanoseconds since the UNIX epoch.
        lease_expires_at: i64,
    },
    /// The restore generation differs from the manager's.
    Resync,
}

/// The counts of one range day, the argument of `send_dai_range_day`.
///
/// It always carries the whole day's `blocks` and `subnets`. The manager
/// answers [`DaiStoreAck::Stored`] also for a result from a superseded
/// lease, which it discards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiRangeDay {
    /// The restore generation the agent held when it counted the day.
    pub restore_generation: u64,
    /// The sensor's config epoch the agent held when it counted the day.
    pub config_epoch: u64,
    /// The network digest the agent held when it counted the day.
    pub network_digest: u64,
    /// The range day.
    pub unit: DaiRangeUnit,
    /// The `version` of the grant.
    pub version: u64,
    /// When the round recollects a marked day, the `mark` the day had in
    /// [`DaiCursors::range_days`] at the start of the round; `None`
    /// otherwise.
    pub mark: Option<u64>,
    /// The `lease_token` of the grant.
    pub lease_token: u64,
    /// The address blocks seen outside the customer's registered networks.
    pub blocks: Vec<DaiRangeBlock>,
    /// The subnets seen outside the customer's registered networks.
    pub subnets: Vec<IpNet>,
}

/// The counts of one address block in a [`DaiRangeDay`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiRangeBlock {
    /// The block.
    pub block: IpNet,
    /// The number of distinct addresses seen in the block.
    pub distinct_addrs: u32,
    /// The number of connections seen in the block.
    pub conns: u64,
    /// Whether the distinct address count reached its limit.
    pub saturated: bool,
}

/// Records that arrived after their range day was counted, the argument of
/// `report_dai_range_late`.
///
/// The manager answers the marks it assigned to `late_days`; `late_subnets`
/// are recorded without a mark. An `Err` answer (for example when the
/// restore generation differs) means nothing was recorded, and the agent
/// calls `get_dai_cursors` again before reporting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiRangeLate {
    /// The restore generation the agent held.
    pub restore_generation: u64,
    /// The sensor name.
    pub sensor: String,
    /// The days a late record arrived for.
    pub late_days: Vec<DaiLateDay>,
    /// The subnets late records were seen in.
    pub late_subnets: Vec<DaiLateSubnet>,
}

/// A range day a late record arrived for, listed in
/// [`DaiRangeLate::late_days`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiLateDay {
    /// The day. Days since the UNIX epoch, in UTC.
    pub date: i32,
    /// The evidence the day is counted from.
    pub evidence: DaiRangeEvidence,
    /// The difference between the receive time and the record time of the
    /// late record. In nanoseconds.
    pub delay_ns: i64,
}

/// A subnet a late record was seen in, listed in
/// [`DaiRangeLate::late_subnets`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiLateSubnet {
    /// The day. Days since the UNIX epoch, in UTC.
    pub date: i32,
    /// The subnet.
    pub subnet: IpNet,
}

/// A recollect mark the manager assigned to a late range day, answered by
/// `report_dai_range_late`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaiRangeMark {
    /// The day. Days since the UNIX epoch, in UTC.
    pub date: i32,
    /// The evidence the day is counted from.
    pub evidence: DaiRangeEvidence,
    /// The mark.
    pub mark: u64,
}

#[cfg(all(test, any(feature = "client", feature = "server")))]
mod bincode_tests {
    use std::fmt::Debug;

    use serde::{Serialize, de::DeserializeOwned};

    use super::*;
    use crate::test::{
        dai_cursors, dai_extractor_config, dai_observation_batches, dai_observations,
        dai_range_days, dai_range_grants, dai_range_late, dai_range_marks, dai_range_unit,
        dai_sensors, dai_store_acks,
    };

    /// Every kind with its fixed number.
    const KINDS: [(DaiObservationKind, u8); 8] = [
        (DaiObservationKind::DhcpLease, 1),
        (DaiObservationKind::DhcpServer, 3),
        (DaiObservationKind::Kerberos, 4),
        (DaiObservationKind::Ntlm, 5),
        (DaiObservationKind::Service, 7),
        (DaiObservationKind::SoftwareString, 8),
        (DaiObservationKind::DnsName, 22),
        (DaiObservationKind::IpActivity, 34),
    ];

    fn encode<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
        bincode::serde::encode_to_vec(value, bincode::config::standard())
            .expect("serialization should succeed")
    }

    /// Encodes `value`, decodes it back as `T`, and asserts the result equals
    /// `value` and consumed every byte.
    fn round_trip<T: Serialize + DeserializeOwned + Debug + PartialEq>(value: &T) {
        let bytes = encode(value);
        let (decoded, len): (T, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("deserialization should succeed");
        assert_eq!(len, bytes.len());
        assert_eq!(&decoded, value);
    }

    #[test]
    fn kind_serializes_as_its_number() {
        for (kind, number) in KINDS {
            assert_eq!(encode(&kind), [number], "{kind:?}");
            round_trip(&kind);
        }
        for number in [0_u8, 2, 18, 36, u8::MAX] {
            assert!(
                bincode::serde::decode_from_slice::<DaiObservationKind, _>(
                    &[number],
                    bincode::config::standard(),
                )
                .is_err(),
                "{number} must not decode as a kind"
            );
        }
    }

    #[test]
    fn kind_serializes_as_its_number_in_json() {
        for (kind, number) in KINDS {
            assert_eq!(serde_json::to_string(&kind).unwrap(), number.to_string());
        }
        assert!(serde_json::from_str::<DaiObservationKind>("36").is_err());
    }

    /// The samples carry every `DaiObservationBody` variant, so a missing
    /// one fails here rather than going untested.
    #[test]
    fn samples_cover_every_body_variant() {
        let mut kinds: Vec<DaiObservationKind> = dai_observations()
            .iter()
            .map(|observation| match observation.body {
                DaiObservationBody::DhcpLease { .. } => DaiObservationKind::DhcpLease,
                DaiObservationBody::DhcpServer { .. } => DaiObservationKind::DhcpServer,
                DaiObservationBody::Kerberos { .. } => DaiObservationKind::Kerberos,
                DaiObservationBody::Ntlm { .. } => DaiObservationKind::Ntlm,
                DaiObservationBody::Service { .. } => DaiObservationKind::Service,
                DaiObservationBody::SoftwareString { .. } => DaiObservationKind::SoftwareString,
                DaiObservationBody::DnsName { .. } => DaiObservationKind::DnsName,
                DaiObservationBody::IpActivity { .. } => DaiObservationKind::IpActivity,
            })
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds, KINDS.map(|(kind, _)| kind));
    }

    #[test]
    fn request_arguments_round_trip() {
        round_trip(&dai_sensors());
        round_trip(&vec!["all".to_string()]);
        for batch in dai_observation_batches() {
            round_trip(&batch);
        }
        for observation in dai_observations() {
            round_trip(&observation);
        }
        round_trip(&(dai_range_unit(), 5_u64));
        round_trip(&(dai_range_unit(), u64::MAX));
        for day in dai_range_days() {
            round_trip(&day);
        }
        round_trip(&dai_range_late());
        round_trip(&DaiRangeLate {
            restore_generation: 0,
            sensor: String::new(),
            late_days: Vec::new(),
            late_subnets: Vec::new(),
        });
    }

    #[test]
    fn replies_round_trip() {
        round_trip(&Ok::<_, String>(dai_extractor_config()));
        round_trip(&Ok::<_, String>(DaiExtractorConfig {
            revision: 0,
            sensors: Vec::new(),
        }));
        round_trip(&Ok::<_, String>(dai_cursors()));
        for ack in dai_store_acks() {
            round_trip(&Ok::<_, String>(ack));
        }
        for grant in dai_range_grants() {
            round_trip(&Ok::<_, String>(grant));
        }
        round_trip(&Ok::<Option<i64>, String>(Some(i64::MIN)));
        round_trip(&Ok::<Option<i64>, String>(None));
        round_trip(&Ok::<_, String>(dai_range_marks()));
        round_trip(&Err::<DaiStoreAck, _>("not supported".to_string()));
    }

    /// The samples carry every `DaiStoreAck` and `DaiRangeGrant` variant.
    #[test]
    fn samples_cover_every_ack_and_grant_variant() {
        let acks = dai_store_acks();
        assert!(matches!(
            acks.as_slice(),
            [
                DaiStoreAck::Staged { .. },
                DaiStoreAck::Stored { .. },
                DaiStoreAck::Wait { .. },
                DaiStoreAck::Resync { .. },
            ]
        ));
        let grants = dai_range_grants();
        assert!(matches!(
            grants.as_slice(),
            [
                DaiRangeGrant::Granted { .. },
                DaiRangeGrant::InProgress { .. },
                DaiRangeGrant::Resync,
            ]
        ));
    }

    /// Fields are encoded in declaration order with no framing between
    /// them: a range unit is its sensor, its date and its evidence index.
    #[test]
    fn range_unit_wire_bytes_are_pinned() {
        let unit = DaiRangeUnit {
            sensor: "s".to_string(),
            date: -1,
            evidence: DaiRangeEvidence::Sensor,
        };
        assert_eq!(encode(&unit), [1, b's', 1, 0]);
        assert_eq!(encode(&(unit, 300_u64)), [1, b's', 1, 0, 251, 44, 1]);
    }
}
