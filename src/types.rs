//! Data types used by the protocol.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    ops::RangeInclusive,
    time::Duration,
};

use ipnet::IpNet;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
pub use structured::ColumnStatistics;

mod dai;
mod detection;
pub mod raw_event;

pub use self::dai::{
    DaiCursorEntry, DaiCursors, DaiDhcpMsg, DaiExtractorConfig, DaiLateDay, DaiLateSlot,
    DaiLateSubnet, DaiObservation, DaiObservationBatch, DaiObservationBody, DaiObservationKind,
    DaiRangeBlock, DaiRangeDay, DaiRangeDayState, DaiRangeEvidence, DaiRangeGrant, DaiRangeLate,
    DaiRangeMark, DaiRangeUnit, DaiReextractMark, DaiSensorConfig, DaiSide, DaiSoftwareSource,
    DaiStoreAck,
};
pub use self::detection::{
    CryptocurrencyMiningPoolDetail, Detail, DetectionEvent, DetectionEventError, DetectionModel,
    EndpointRole, ExternalDdosDetail, FarOutlierDetail, FtpBruteForceDetail, LabelDbMatchDetail,
    LdapBruteForceDetail, MAX_RELATED_IPS, MultiHostPortScanDetail, PortScanDetail, PrimarySubject,
    RdpBruteForceDetail, RelatedIp, RepeatedHttpSessionsDetail, SignatureMatchDetail,
    SignatureSource, SlotDeviation, Target, ThreatRole, TimeWindow,
    UnusualDestinationPatternDetail, WatchlistMatchDetail, WindowOutlierDetail,
    WindowOutlierViolation,
};

/// A request to delete data belonging to a customer from a service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerDataDeletionRequest {
    /// An opaque identifier that must be returned unchanged in the report.
    pub id: u32,
    /// The FQDN of the service that must delete the customer data.
    pub host_fqdn: String,
}

/// The final result of processing a customer-data deletion request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerDataDeletionReport {
    /// The opaque identifier copied from the original deletion request.
    pub id: u32,
    /// The service FQDN copied from the original deletion request.
    pub host_fqdn: String,
    /// The completion or recorded failure timestamp.
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

/// A request to an Unsupervised Engine to start a training run.
///
/// The run creates the model named [`model`](Self::model), or replaces it,
/// and the engine uploads the result with the client's `upload_run_model`
/// under [`run_id`](Self::run_id).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainModelRequest {
    /// The identifier the Central Manager issued for this run.
    pub run_id: u32,
    /// The name of the model the run creates or replaces.
    pub model: String,
    /// The training definition, a TOML document.
    ///
    /// This crate carries the definition verbatim and never parses or
    /// validates it. It does own the definition's schema, which is stated
    /// here in full, and is the single statement of it: the Unsupervised
    /// Engine parses the definition against this text, review-web validates
    /// it against it, and Clumit Security Web writes it against it.
    ///
    /// Every table refuses unknown keys, so a key not listed below is
    /// refused, including any path field (a `local` input, `export_path`,
    /// `log_path`, `[auth]` or `[review]`). The definition carries no `name`
    /// key: the name of the model is [`model`](Self::model) only.
    ///
    /// A definition carries every value its method uses. The engine has no
    /// default for any key. Each key below has a value type and, under each
    /// `method`, one of these statuses:
    ///
    /// - **required**: absent is refused.
    /// - **absent means none**: an absent key means the feature is not used.
    /// - **refused**: the method does not use the key, so it is refused when
    ///   present.
    ///
    /// | Key | Value | `multidimension` | `prefix` | `timeseries` |
    /// | --- | --- | --- | --- | --- |
    /// | `type` | string: a clustering model type id, or `"custom"` | required | required | required |
    /// | `type_version` | u32 | required for a type id, refused for `"custom"` | required for a type id, refused for `"custom"` | required for a type id, refused for `"custom"` |
    /// | `raw_event_kind` | string | required: a Giganto raw event kind in snake case that has a clustering model type | required, always `"log"` | required: one of the 20 network raw event kinds in snake case, the source policies' kind (for example `"tls"`); the engine records it on the model and on detection events, and always reads Giganto's periodic time-series kind whatever this value is |
    /// | `log_kind` | string | refused | required: a Giganto log kind name, not one of Giganto's other raw event kind names | refused |
    /// | `method` | string: `"multidimension"`, `"prefix"` or `"timeseries"` | required | required | required |
    /// | `sources` | non-empty array of strings, no repeats | required | required | required |
    /// | `window_start` | string: RFC 3339 with offset; inclusive | required | required | required |
    /// | `window_end` | string: RFC 3339 with offset; exclusive; after `window_start` | required | required | required |
    /// | `[data_store]` | table: `address`, a socket address `"ip:port"`, and `server_name`, a string; both required | required | required | required |
    /// | `batch_size` | usize (total events read) | required | required | required |
    /// | `max_event_id_num` | u32; capped at 100 | required | required | required |
    /// | `suspicious_tokens` | string: an indicator NAME, never a path | absent means none | absent means none | absent means none |
    /// | `algorithm` | string: `"dbscan"`, `"hdbscan"` or `"optics"` | required | refused | required |
    /// | `eps` | f64 | required | refused | required |
    /// | `precision` | i32 | required | refused | required |
    /// | `numbers_of_top_n` | array of usize; filled as stated below | required | refused | required |
    /// | `min_token_length` | usize | required | required | refused |
    /// | `long_pattern_len` | usize | required | required | refused |
    /// | `max_data_len` | usize | absent means no limit | absent means no limit | refused |
    /// | `max_token_length` | usize; ignored with a warning when < 2 * `min_token_length` | refused | absent means no limit | refused |
    /// | `group_by` | string: `"source"` or `"destination"` (`EndpointRole` in snake case) | refused | refused | required for a type id; for `"custom"`, present exactly when the source policies split by an endpoint, and then equal to theirs |
    /// | `slot_size` | u32 (seconds); equals the source policies' slot size | refused | refused | required |
    /// | `threat_role` | string: `"actor"` or `"target"` | refused | refused | required for a type id, refused for `"custom"` |
    /// | `min_cluster_size` | usize | refused | refused | required |
    /// | `transform` | string: `"none"` or `"log1p"` | refused | refused | required |
    /// | `[csv]` | table: the keys below | required | refused | refused |
    ///
    /// `[csv]`, which only the multidimension method takes, has these keys:
    ///
    /// | Key | Value | Status |
    /// | --- | --- | --- |
    /// | `reader` | inline table `{ delimiter, quote }`: both keys u8, both required | required |
    /// | `format` | array, one entry per column, in column order; each entry has `data_type`: `"int64"`, `"float64"`, `"datetime"`, `"ipaddr"`, `"enum"`, `"utf8"` or `"binary"`; `weight`: f64, required; `name`: optional string; `format`: optional string (a datetime parse format) | required |
    /// | `slot_sizes` | array of u32 (seconds) | filled as stated below when absent or short |
    /// | `time_column` | usize | absent means none |
    /// | `count_columns` | array of usize | absent means none |
    /// | `prefix_columns` | array of usize | absent means none: without it the clustering uses the centroid approach |
    ///
    /// A multidimension definition:
    ///
    /// ```toml
    /// type = "custom"
    /// raw_event_kind = "http"
    /// method = "multidimension"
    /// sources = ["piglet.node2.example.com"]
    /// window_start = "2026-10-14T00:00:00Z"
    /// window_end = "2026-10-21T00:00:00Z"
    /// batch_size = 1000000
    /// max_event_id_num = 25
    /// algorithm = "dbscan"
    /// eps = 2.0
    /// precision = 2
    /// numbers_of_top_n = [30, 30]
    /// min_token_length = 3
    /// long_pattern_len = 16000
    /// max_data_len = 30
    /// suspicious_tokens = "indicator-name"
    ///
    /// [data_store]
    /// address = "10.0.0.5:38371"
    /// server_name = "001.giganto.node1.example.com"
    ///
    /// [csv]
    /// reader = { delimiter = 9, quote = 0 }
    /// format = [
    ///   { data_type = "utf8", weight = 0.0, name = "time" },
    ///   { data_type = "utf8", weight = 1.0, name = "host" },
    /// ]
    /// time_column = 0
    /// count_columns = [0]
    /// prefix_columns = [1]
    /// ```
    ///
    /// A prefix definition:
    ///
    /// ```toml
    /// type = "custom"
    /// raw_event_kind = "log"
    /// log_kind = "web-access"
    /// method = "prefix"
    /// sources = ["piglet.node2.example.com"]
    /// window_start = "2026-10-14T00:00:00Z"
    /// window_end = "2026-10-21T00:00:00Z"
    /// batch_size = 1000000
    /// max_event_id_num = 25
    /// min_token_length = 3
    /// max_token_length = 10
    /// long_pattern_len = 16000
    ///
    /// [data_store]
    /// address = "10.0.0.5:38371"
    /// server_name = "001.giganto.node1.example.com"
    /// ```
    ///
    /// A timeseries definition:
    ///
    /// ```toml
    /// type = "custom"
    /// raw_event_kind = "tls"
    /// method = "timeseries"
    /// sources = ["piglet.node2.example.com"]
    /// window_start = "2026-10-14T00:00:00Z"
    /// window_end = "2026-10-21T00:00:00Z"
    /// batch_size = 1000000
    /// max_event_id_num = 25
    /// algorithm = "dbscan"
    /// eps = 0.5
    /// precision = 2
    /// numbers_of_top_n = []
    /// group_by = "source"
    /// slot_size = 3600
    /// min_cluster_size = 5
    /// transform = "log1p"
    ///
    /// [data_store]
    /// address = "10.0.0.5:38371"
    /// server_name = "001.giganto.node1.example.com"
    /// ```
    ///
    /// - `log_kind` is present exactly when `raw_event_kind = "log"`.
    /// - `[csv]` is exactly `crate::remake::csv::Config` (columns
    ///   `ColumnDescription`, `reader` = `structured::csv::Config`,
    ///   `data_type` = `structured::ColumnType`), with `deny_unknown_fields`
    ///   added; the statuses above apply to its keys.
    /// - `event_type` is derived from `method` as in E1 (multidimension →
    ///   `csv`, prefix → `log`, timeseries → `timeseries`).
    /// - **Fill values.** These are contract values, not engine defaults.
    ///   Changing them changes the contract.
    ///   - When `slot_sizes` is absent or shorter than the number of
    ///     `datetime` columns, each remaining `datetime` column gets 3600
    ///     seconds.
    ///   - For the multidimension method, when `numbers_of_top_n` is shorter
    ///     than the number of columns (an empty list included), each
    ///     remaining `datetime` column gets 336 and each other remaining
    ///     column gets 30.
    ///   - For the timeseries method, when `numbers_of_top_n` is shorter than
    ///     the number of slots in a window (an empty list included), each
    ///     remaining slot gets 30.
    /// - The engine refuses a definition that does not parse, lacks a key its
    ///   method requires, carries a key its method refuses, has
    ///   `type_version` with `type = "custom"` or lacks it with a type id,
    ///   has `log_kind` when `raw_event_kind` is not `"log"` or lacks it when
    ///   `raw_event_kind = "log"`, has empty `sources`, repeats a
    ///   source in `sources`, has `window_end` not after `window_start`, has
    ///   `method = "multidimension"` without `[csv]`, has `[csv]` with
    ///   another method, has `method = "timeseries"` and `type = "custom"`
    ///   with `threat_role`, or has `method = "timeseries"` and a type id
    ///   without `threat_role` or without `group_by`.
    /// - These checks belong to review-web, not the engine: the type id is
    ///   known, its version is current, and `method`, `raw_event_kind` and
    ///   the type's fixed values equal the type's; operator values are in
    ///   range (§5.2); a multidimension `raw_event_kind` has a clustering
    ///   model type; a prefix `log_kind` is a log kind name; a timeseries
    ///   `raw_event_kind` is a network kind; for a timeseries `"custom"`
    ///   definition, `raw_event_kind`, `group_by` and `slot_size` equal the
    ///   source policies' values.
    pub definition: String,
}

/// A request to an Unsupervised Engine to clone a model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneModelRequest {
    /// The identifier the Central Manager issued for this run.
    pub run_id: u32,
    /// The name of the model to clone.
    pub source: String,
    /// The name of the clone.
    pub target_name: String,
    /// Whether the engine drops every stored event from the clone, as it
    /// must for a clone to another customer.
    pub strip_events: bool,
}

/// The state of a run, as an Unsupervised Engine reports it.
///
/// There is no succeeded state: the Central Manager ends a run as succeeded
/// itself when it accepts the run's model upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportedRunState {
    /// The engine started the run.
    Started,
    /// The run failed.
    Failed,
    /// The run was cancelled.
    Cancelled,
}

/// The status of a detector of an Unsupervised Engine.
///
/// The engine reports it after every round and whenever it loads a
/// configuration document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorStatusReport {
    /// The `id` of the detector's `[[detectors]]` entry in the engine's
    /// configuration document.
    pub detector_id: i32,
    /// Why the detector does or does not run.
    pub state: DetectorState,
    /// When the last round ended, in nanoseconds since the Unix epoch;
    /// `None` before the detector's first round.
    pub finished_at: Option<i64>,
    /// The outcome of the last round; `None` before the detector's first
    /// round.
    pub outcome: Option<RoundOutcome>,
    /// The failure reason of the last round.
    pub reason: Option<String>,
    /// The number of events the last round analysed.
    pub events: u64,
    /// The state of each of the detector's sources in the last round.
    pub sources: Vec<SourceStatus>,
    /// The status of each detection model in the last round.
    pub detection_models: Vec<DetectionModelStatus>,
    /// The raw events the last round skipped because they matched an
    /// exclusion-list entry, counted per entry and UTC date.
    pub excluded: Vec<ExcludedCount>,
}

/// The status of one detection model in a detector's round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionModelStatus {
    /// The model.
    pub detection_model: DetectionModel,
    /// Why the model was skipped in the round; `None` when it ran.
    pub skipped: Option<String>,
    /// How many detection events the maximum emitted count cut.
    pub truncated: u64,
}

/// The number of raw events skipped on one UTC date because they matched one
/// exclusion-list entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExcludedCount {
    /// The id of the matched exclusion-list entry.
    pub entry: u64,
    /// The UTC date the skipped raw events fall on.
    pub day: jiff::civil::Date,
    /// The number of raw events skipped.
    pub count: u64,
}

/// The raw events a Semi-supervised Engine skipped before detection because
/// they matched an exclusion-list entry.
///
/// The engine sends it with request 52. Each count covers one exclusion-list
/// entry and one UTC date.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineExclusionReport {
    /// The skipped raw events, counted per entry and UTC date.
    pub counts: Vec<ExcludedCount>,
}

/// The signature rule sets a Semi-supervised Engine matches raw events
/// against.
///
/// The Central Manager pushes it to an engine with agent request 27, and an
/// engine pulls it with server request 56.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureRules {
    /// The Central Manager's revision of the rule sets, which an engine
    /// passes back to request 56 as its known revision.
    pub revision: u64,
    /// The compiled rule sets.
    pub sets: Vec<SignatureRuleSet>,
    /// The rules not to match, each named by its source and rule id.
    pub disabled_rules: Vec<(SignatureSource, String)>,
}

/// One compiled signature rule set of a [`SignatureRules`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureRuleSet {
    /// The source the rules come from.
    pub source: SignatureSource,
    /// The version of the source's rule set.
    pub source_version: String,
    /// The version of the converter that compiled the rule set.
    pub converter_version: String,
    /// The rule compiler's serialized bundle, opaque to this crate.
    pub rules: Vec<u8>,
}

/// The status of a Semi-supervised Engine's signature matching.
///
/// The engine sends it with server request 57.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureStatusReport {
    /// The rule sets the engine has loaded.
    pub loaded: Vec<LoadedSignatureSet>,
    /// The detection events the engine cut, counted per model, rule,
    /// originator address and window.
    ///
    /// Producers send at most 1,000 entries. The limit is not checked here.
    pub truncated: Vec<TruncatedCount>,
    /// The sum of the counts beyond the entries in
    /// [`truncated`](Self::truncated).
    pub truncated_overflow: u64,
    /// The records that OS-specific rules skipped for lack of a host header,
    /// counted per raw event kind.
    pub os_gated_skipped: Vec<(RawEventKind, u64)>,
    /// Whether the home network was replaced by the private address ranges.
    pub home_net_fallback: bool,
}

/// One signature rule set a Semi-supervised Engine has loaded, in a
/// [`SignatureStatusReport`].
///
/// When [`load_error`](Self::load_error) is set, the entry's other fields are
/// those of the snapshot still in use: with no earlier snapshot, the version
/// strings are empty and [`rules`](Self::rules) and
/// [`failed_compile`](Self::failed_compile) are 0. The reason text names the
/// source version of the bundle that could not be read. It returns to `None`
/// when a bundle of that source is next published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedSignatureSet {
    /// The source the rules come from.
    pub source: SignatureSource,
    /// The version of the source's rule set.
    pub source_version: String,
    /// The version of the converter that compiled the rule set.
    pub converter_version: String,
    /// The number of rules compiled and in use.
    pub rules: u64,
    /// The number of rules that failed to compile.
    pub failed_compile: u64,
    /// Why the bundle could not be read; `None` when it could.
    pub load_error: Option<String>,
}

/// The number of detection events of one model and rule, about one
/// originator address, that a Semi-supervised Engine cut in one window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruncatedCount {
    /// The model whose detection events were cut.
    pub detection_model: DetectionModel,
    /// The source of the rule.
    pub source: SignatureSource,
    /// The rule's id within its source.
    pub rule_id: String,
    /// The originator address of the cut detection events.
    pub orig_addr: IpAddr,
    /// The start of the window, in nanoseconds since the Unix epoch, UTC.
    pub window_start: i64,
    /// The number of detection events cut.
    pub count: u64,
}

/// Why a detector does or does not run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectorState {
    /// The detector is scheduled and runs its rounds.
    Running,
    /// The detector is disabled.
    Disabled,
    /// The detector has no model to run.
    NoModel,
    /// The detector is paused for a run of its model.
    PausedForRun,
}

/// The outcome of a detector's round.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoundOutcome {
    /// The round succeeded.
    Succeeded,
    /// The round failed; the report's `reason` says why.
    Failed,
}

/// The state of one of a detector's sources in a round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceStatus {
    /// The source's name.
    pub source: String,
    /// The source's state in the round.
    pub state: SourceState,
    /// Why the source failed, when it did.
    pub reason: Option<String>,
}

/// The state of a detector's source in a round.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceState {
    /// A Data Store node served the source's events.
    Served,
    /// No Data Store node served the source; the round goes on and the
    /// source keeps its read position.
    ServedByNoNode,
    /// Reading the source's events failed, which fails the round.
    Failed,
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

/// An entry of the exclusion list or the watchlist.
///
/// Every list surface delivers every item in the order supplied, without
/// sorting, merging or deduplicating. A receiver of the exclusion list attributes
/// a skipped raw event to the first matching entry in received order.
///
/// Protocol `0.50.0` replaced the `0.49.0` exclusion-list and watchlist payload, a
/// bare [`HostNetworkGroup`], with a list of these items, and bincode 2 does
/// not describe its own layout. The list surfaces refuse a payload that leaves
/// bytes over, which catches a `0.49.0` group with no explicit hosts, but some
/// `0.49.0` groups are also complete, valid item lists: for some addresses, a
/// group holding one IPv4 host decodes as one item with an invented id and
/// name and an empty group, and the host is lost without an error.
///
/// The library's suggested floor, `MIN_PROTOCOL_VERSION_REQ`, still admits
/// `0.49.0`, so the list surfaces that hold the handshake versions check them:
///
/// - The session agent's `get_exclusion_list` and `get_watchlist`, and the legacy
///   `client::Connection`'s, refuse locally, sending nothing, unless both the
///   protocol version the agent advertised and the manager's handshake reply
///   are `0.50.0` or later.
/// - A session manager's request stream, in both its runner and its
///   low-level `next`, answers an exclusion-list or watchlist pull from an agent
///   that advertised an earlier version with an error and does not invoke the
///   handler.
///
/// The other surfaces hold no handshake version, and keeping `0.49.0` peers
/// away from them is the caller's responsibility: the legacy
/// `server::Connection`'s `send_exclusion_list` and `send_watchlist`, the legacy
/// server dispatcher's pull handlers and the legacy agent request
/// dispatcher's push handlers. A manager admits only agents that advertise
/// `0.50.0` or later, by passing a `>=0.50.0` requirement to its handshake, or
/// checks the agent's advertised `protocol_version` (the `AgentInfo` the
/// handshake returns) before it pushes a list or answers a pull. An agent
/// advertises the protocol version it speaks, and dispatches pushes only on a
/// connection whose handshake reply is `0.50.0` or later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkListItem {
    /// The entry's id.
    pub id: u64,
    /// The entry's name.
    pub name: String,
    /// The hosts, networks and ranges the entry covers.
    pub group: HostNetworkGroup,
}

/// A time-series generation policy: what a generator counts, how it splits
/// the counts into series, and how it slots and windows them.
///
/// One policy produces one series per internal IP of the endpoint named by
/// [`group_by`](Self::group_by), or a single series when that is `None`.
/// Every field but [`internal_networks`](Self::internal_networks) belongs to
/// the generation spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeSeriesGenerationPolicy {
    /// The policy's id.
    pub id: u32,
    /// The raw event kind the policy counts. The type admits any kind;
    /// consumers accept only the network kinds.
    pub raw_event_kind: RawEventKind,
    /// The value counted per slot.
    pub measure: Measure,
    /// The endpoint whose IP splits the series. `None` means one series for
    /// the whole policy.
    pub group_by: Option<EndpointRole>,
    /// The unit [`group_by`](Self::group_by) splits by.
    pub group_by_unit: GroupByUnit,
    /// A filter on whether the other endpoint is inside
    /// [`internal_networks`](Self::internal_networks).
    pub counterpart_scope: CounterpartScope,
    /// The length of one slot.
    pub slot_size: Duration,
    /// The length of one window, which is one series sample.
    pub window_size: Duration,
    /// The offset from UTC, in seconds, that aligns window boundaries to
    /// local time.
    pub utc_offset: i32,
    /// The source IP a raw event must have to be counted, if any.
    pub src_ip: Option<IpAddr>,
    /// The destination IP a raw event must have to be counted, if any.
    pub dst_ip: Option<IpAddr>,
    /// One or more sensor names. More than one means the sensors observe
    /// disjoint parts of the same network.
    pub sensors: Vec<String>,
    /// The catalog type the policy was made from. `None` means a custom
    /// policy.
    pub time_series_type: Option<TimeSeriesTypeRef>,
    /// The customer's internal ranges, Intranet and Gateway merged.
    ///
    /// The Central Manager fills it when it sends the policy. It is not part
    /// of the generation spec.
    pub internal_networks: HostNetworkGroup,
}

/// The value a [`TimeSeriesGenerationPolicy`] counts per slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Measure {
    /// Counts raw events.
    Count,
    /// Sums the given Conn field.
    Sum(ConnField),
}

/// A numeric field of a Conn raw event that [`Measure::Sum`] can sum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnField {
    /// The duration of the connection.
    Duration,
    /// The bytes the originator sent.
    OrigBytes,
    /// The bytes the responder sent.
    RespBytes,
    /// The packets the originator sent.
    OrigPkts,
    /// The packets the responder sent.
    RespPkts,
}

/// The unit a [`TimeSeriesGenerationPolicy`] splits its series by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupByUnit {
    /// Splits by single IP.
    Ip,
    /// Reserved for a later per-network unit. The Central Manager does not
    /// accept it yet.
    OwnedNetwork,
}

/// A filter on whether the other endpoint of a raw event is inside the
/// policy's [`internal_networks`](TimeSeriesGenerationPolicy::internal_networks).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CounterpartScope {
    /// No filter.
    Any,
    /// Counts only raw events whose other endpoint is inside the internal
    /// networks.
    Internal,
    /// Counts only raw events whose other endpoint is outside the internal
    /// networks.
    External,
}

/// A reference to the catalog time-series type a policy was made from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeSeriesTypeRef {
    /// The type's id, in snake case.
    pub id: String,
    /// The type's version.
    pub version: u32,
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

impl EventCategory {
    /// Returns the id of the MITRE ATT&CK tactic this category is, such as
    /// `TA0011` for [`CommandAndControl`](Self::CommandAndControl).
    #[must_use]
    pub fn mitre_tactic_id(self) -> &'static str {
        match self {
            Self::Reconnaissance => "TA0043",
            Self::ResourceDevelopment => "TA0042",
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::Exfiltration => "TA0010",
            Self::CommandAndControl => "TA0011",
            Self::Impact => "TA0040",
        }
    }

    /// Returns the category of the MITRE ATT&CK tactic `id`, the inverse of
    /// [`mitre_tactic_id`](Self::mitre_tactic_id).
    ///
    /// `id` must be written exactly as `mitre_tactic_id` returns it: any other
    /// string, including a lowercase form, returns `None`.
    #[must_use]
    pub fn from_mitre_tactic_id(id: &str) -> Option<Self> {
        match id {
            "TA0043" => Some(Self::Reconnaissance),
            "TA0042" => Some(Self::ResourceDevelopment),
            "TA0001" => Some(Self::InitialAccess),
            "TA0002" => Some(Self::Execution),
            "TA0003" => Some(Self::Persistence),
            "TA0004" => Some(Self::PrivilegeEscalation),
            "TA0005" => Some(Self::DefenseEvasion),
            "TA0006" => Some(Self::CredentialAccess),
            "TA0007" => Some(Self::Discovery),
            "TA0008" => Some(Self::LateralMovement),
            "TA0009" => Some(Self::Collection),
            "TA0010" => Some(Self::Exfiltration),
            "TA0011" => Some(Self::CommandAndControl),
            "TA0040" => Some(Self::Impact),
            _ => None,
        }
    }
}

/// The kind of a raw event, a subset of giganto-client's `RawEventKind` with
/// the same names and numbers.
///
/// The numbering has intentional gaps: each variant keeps giganto-client's
/// explicit number, and the kinds left out of this subset leave theirs unused.
/// A kind is serialized as that number in every format, never as its name or
/// declaration index.
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
pub enum RawEventKind {
    // Network
    Conn = 0,
    Dns = 1,
    Http = 3,
    Rdp = 4,
    Smtp = 6,
    Ntlm = 7,
    Kerberos = 8,
    Ssh = 9,
    DceRpc = 10,
    Ftp = 14,
    Mqtt = 15,
    Ldap = 16,
    Tls = 17,
    Smb = 18,
    Nfs = 19,
    Bootp = 21,
    Dhcp = 22,
    Radius = 23,
    MalformedDns = 24,
    Icmp = 25,

    // Windows Sysmon
    ProcessCreate = 31,
    FileCreateTime = 32,
    NetworkConnect = 33,
    ProcessTerminate = 35,
    DriverLoad = 36,
    ImageLoad = 37,
    CreateRemoteThread = 38,
    RawAccessRead = 39,
    ProcessAccess = 40,
    FileCreate = 41,
    RegistryObjectAddDel = 42,
    RegistryValueSet = 43,
    RegistryKeyRename = 44,
    FileCreateStreamHash = 45,
    PipeEvent = 47,
    DnsQuery = 52,
    FileDelete = 53,
    ProcessTamper = 55,
    FileDeleteDetected = 56,

    // Netflow
    Netflow5 = 60,
    Netflow9 = 61,

    // Endpoint logs
    WindowsEventLog = 80,
    Journald = 81,
    Auditd = 82,
}

/// The body of a raw event, one variant per [`RawEventKind`] holding the
/// [`raw_event`] struct of the same name.
///
/// A variant is serialized as its declaration index, so a variant added later
/// is appended after every existing one, never inserted among them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawEventBody {
    Conn(raw_event::Conn),
    Dns(raw_event::Dns),
    Http(raw_event::Http),
    Rdp(raw_event::Rdp),
    Smtp(raw_event::Smtp),
    Ntlm(raw_event::Ntlm),
    Kerberos(raw_event::Kerberos),
    Ssh(raw_event::Ssh),
    DceRpc(raw_event::DceRpc),
    Ftp(raw_event::Ftp),
    Mqtt(raw_event::Mqtt),
    Ldap(raw_event::Ldap),
    Tls(raw_event::Tls),
    Smb(raw_event::Smb),
    Nfs(raw_event::Nfs),
    Bootp(raw_event::Bootp),
    Dhcp(raw_event::Dhcp),
    Radius(raw_event::Radius),
    MalformedDns(raw_event::MalformedDns),
    Icmp(raw_event::Icmp),
    ProcessCreate(raw_event::ProcessCreate),
    FileCreateTime(raw_event::FileCreateTime),
    NetworkConnect(raw_event::NetworkConnect),
    ProcessTerminate(raw_event::ProcessTerminate),
    ImageLoad(raw_event::ImageLoad),
    FileCreate(raw_event::FileCreate),
    RegistryValueSet(raw_event::RegistryValueSet),
    RegistryKeyRename(raw_event::RegistryKeyRename),
    FileCreateStreamHash(raw_event::FileCreateStreamHash),
    PipeEvent(raw_event::PipeEvent),
    DnsQuery(raw_event::DnsQuery),
    FileDelete(raw_event::FileDelete),
    ProcessTamper(raw_event::ProcessTamper),
    FileDeleteDetected(raw_event::FileDeleteDetected),
    Netflow5(raw_event::Netflow5),
    Netflow9(raw_event::Netflow9),
    DriverLoad(raw_event::DriverLoad),
    CreateRemoteThread(raw_event::CreateRemoteThread),
    RawAccessRead(raw_event::RawAccessRead),
    ProcessAccess(raw_event::ProcessAccess),
    RegistryObjectAddDel(raw_event::RegistryObjectAddDel),
    WindowsEventLog(raw_event::WindowsEventLog),
    Journald(raw_event::Journald),
    Auditd(raw_event::Auditd),
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Status {
    Ready,
    Idle,
}

/// Capability tags that this crate knows about.
///
/// The capability set on [`AgentInfo`](crate::AgentInfo) is **open**: these are
/// known values, not a closed set. A decoder validates the tags it knows and
/// preserves the rest untouched, so a peer advertising a tag that is not listed
/// here is neither an error nor a reason to drop the unrecognized tag.
///
/// The tags are namespaced strings rather than a struct of booleans so that a
/// new capability needs no wire change and one agent can hold several roles at
/// once.
///
/// Security-sensitive tags are **advertised, not authoritative**. `REGISTRAR`
/// and the `colocated:` tags are claims the manager corroborates elsewhere
/// before granting anything; this crate transports them and must not treat them
/// as grants.
pub mod capability {
    /// The agent runs the registrar.
    pub const REGISTRAR: &str = "registrar";

    /// The agent is co-located with review.
    pub const COLOCATED_REVIEW: &str = "colocated:review";

    /// The agent is co-located with aice-web-next.
    pub const COLOCATED_AICE_WEB_NEXT: &str = "colocated:aice-web-next";

    /// The agent supports the `node.package` request family.
    pub const NODE_PACKAGE: &str = "node.package";

    /// The agent supports the `node.enroll` request family.
    pub const NODE_ENROLL: &str = "node.enroll";

    /// The self-update rollback supervisor is present on the host, so a
    /// rollback-on-failure request is honoured rather than silently downgraded
    /// to a hold.
    pub const ROLLBACK_SUPERVISOR: &str = "rollback-supervisor";
}

/// The inclusive range of package-manifest `format_version` values a peer can
/// decode.
///
/// Both ends are inclusive: a peer reporting `min = 1` and `max = 2` decodes
/// manifests of format version 1 and 2, and nothing else.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ManifestFormatRange {
    /// The lowest `format_version` the peer can decode.
    pub min: u32,
    /// The highest `format_version` the peer can decode.
    pub max: u32,
}

impl ManifestFormatRange {
    /// Returns `true` if `format_version` falls within the inclusive range.
    #[must_use]
    pub fn contains(self, format_version: u32) -> bool {
        self.min <= format_version && format_version <= self.max
    }
}

/// Digests of the rendered provisioning file.
///
/// The digests are the **enforcing daemon's** reading of the file, relayed by
/// the agent rather than computed by it, so a comparison cannot come out green
/// while the enforcer acts on something else.
///
/// The reading is structured rather than a single whole-file hash so that a
/// consumer can name what diverged: a benign new component entry and a changed
/// domain are different events, and only the latter mints certificates no peer
/// will verify.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProvisioningFingerprint {
    /// Per-component digest of the rendered provisioning entry, keyed by
    /// component.
    pub components: BTreeMap<String, String>,
    /// The rendered `domain`, compared separately from the component digests.
    pub domain: String,
}

/// The audit store's health, as reported by its local endpoint.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditHealth {
    /// Whether the audit store is at or below its low-water mark.
    pub below_low_water: bool,
    /// Count of audit intents recorded with no matching outcome.
    pub intent_without_outcome: u64,
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

/// Types for the `node` agent family, grouping host-control and
/// host-observation functionality under stable feature families.
///
/// Each feature family is represented by a request/response enum pair.
/// Callers construct a request variant, send it through the protocol
/// layer, and receive the corresponding response variant.
///
/// # The reserved `"trust"` package target
///
/// The `node.package` family carries one reserved target. An
/// [`Install`](node::NodePackageRequest::Install) with `target = "trust"`
/// delivers a **release-signing trust-set generation** — the public keys by
/// key id, the revoked-key list and the withdrawn-build list — rather than an
/// installable component. It is how keys, revocations and withdrawals are
/// updated at runtime once the original provisioning tool is gone, which makes
/// it the highest-privilege channel in the family.
///
/// The value is reserved: it is never routed from an install or update action
/// in a UI, and it is not part of any UI-facing package registry. A trust
/// generation nonetheless streams over the ordinary install path, like any
/// other package.
///
/// - It carries **no**
///   [`bootstrap_material`](node::NodePackageRequest::Install::bootstrap_material).
/// - It is verified against the **current active** trust generation, then
///   activated as the next generation.
/// - The generation carries a signed, strictly-monotonic `epoch`. The agent
///   activates it **only if** that epoch is strictly greater than the active
///   generation's; otherwise it rejects with
///   [`StaleTrustSet`](node::NodePackageError::StaleTrustSet). This is what
///   stops an older, validly signed generation from being replayed to restore
///   a revoked key or drop a withdrawn build.
/// - A trust generation carries a **package identity like any other package**:
///   its in-package manifest sets the component to `"trust"`, the version to
///   the generation's decimal epoch, and the commit to the generation digest.
///   The ordinary identity check — signature, then hashes, then identity
///   mismatch — therefore applies unchanged to the highest-privilege channel.
///   Without this, `trust` would be the one package the identity check does
///   not cover.
/// - Raising the manifest format fleet-wide requires every agent binary to be
///   updated **first**, delivered in a package of the **old** format, with the
///   trust plane held at the minimum format any live host supports. The trust
///   plane is the channel that carries revocations, so it must stay readable
///   by the laggiest host.
///
/// A trust apply answers with one of three outcomes, and all three carry the
/// agent's active epoch:
/// [`NodePackageResponse::TrustActive`](node::NodePackageResponse::TrustActive),
/// [`NodePackageError::StaleTrustSet`](node::NodePackageError::StaleTrustSet)
/// and
/// [`UnsupportedManifestFormat`](node::NodePackageError::UnsupportedManifestFormat).
/// A manager reads that epoch from any of them with
/// [`NodePackageResponse::active_trust_epoch`](node::NodePackageResponse::active_trust_epoch),
/// without consulting its own delivery bookkeeping:
///
/// ```
/// use review_protocol::types::node::{NodePackageError, NodePackageResponse};
///
/// // The epoch of the generation the manager streamed to the host.
/// let delivered = 42;
///
/// // The agent activated it: the host is now on the delivered epoch.
/// let resp = NodePackageResponse::TrustActive { active_epoch: delivered };
/// assert_eq!(resp.active_trust_epoch(), Some(42));
///
/// // The agent rejected it as not newer, and reports where it stands.
/// let resp = NodePackageResponse::Failed(NodePackageError::StaleTrustSet {
///     active_epoch: 43,
/// });
/// assert_eq!(resp.active_trust_epoch(), Some(43));
///
/// // A non-trust outcome reports no epoch at all.
/// let resp = NodePackageResponse::Failed(NodePackageError::MissingBootstrapMaterial);
/// assert_eq!(resp.active_trust_epoch(), None);
/// ```
///
/// The epoch these outcomes carry is **agent-asserted**, so it bounds the
/// host's status **downward only**: a consumer clamps it against its own
/// active epoch, where a report at or below that epoch may mark the host
/// caught up, and a report **above** it is treated as un-confirmed, never as
/// confirmed. This crate does not implement the clamp.
///
/// These per-apply readings are **complementary** to the connect-time
/// [`AgentInfo::active_trust_epoch`](crate::AgentInfo::active_trust_epoch),
/// not a duplicate of it. The handshake field is exchanged once per
/// connection and so cannot report an activation that happens later; an agent
/// that stays connected for weeks would never announce a newly activated epoch
/// that way. These outcomes are what make the ground-truth reading usable on a
/// long-lived connection.
///
/// This crate implements none of the trust activation itself: no epoch
/// comparison, signature verification, trust-tree manipulation, key revocation
/// or withdrawal handling lives here. It defines the outcomes the agent
/// reports and documents the rule the agent must follow.
///
/// # Stability
///
/// Low-level wire-format details such as field layout, byte order, or
/// serialization encoding are **not** part of the public contract and
/// may change without notice.
pub mod node {
    use std::{collections::BTreeMap, fmt, net::SocketAddr, time::Duration};

    use num_enum::{FromPrimitive, IntoPrimitive};
    use serde::{Deserialize, Serialize};

    use super::{ManifestFormatRange, Process, ResourceUsage};

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
    /// [`Status`](Self::Status) reports whether the time synchronization
    /// service is enabled, whether the host is synchronized, the source in
    /// use and the last measured offset, and [`Done`](Self::Done) confirms a
    /// mutating operation succeeded.
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub enum NodeTimeSyncResponse {
        /// Current NTP server list, or `None` if not configured.
        Get { servers: Option<Vec<String>> },
        /// Current synchronization status.
        Status {
            /// The host's time synchronization service is enabled.
            enabled: bool,
            /// The host's clock is synchronized to the source it is meant to
            /// follow, as of a recent measurement.
            synchronized: bool,
            /// The source in use; none when there is none or it is the host's
            /// own clock.
            server: Option<String>,
            /// This host's clock minus its source's at the last measurement, in
            /// microseconds; none when unknown.
            offset_micros: Option<i64>,
        },
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

    // ── package management ──────────────────────────────────────

    /// Request for installing, removing, listing or inspecting
    /// packages on a node.
    ///
    /// [`Install`](Self::Install) carries the routing and sizing
    /// information and, for a templated component, the configuration-template
    /// id for a package whose signed `.pkg` bytes follow on the same
    /// bi-stream.  It deliberately carries neither the
    /// manifest nor the signature: the single source of trust is the
    /// manifest and signature *inside* the `.pkg`, and the
    /// `target`/`version`/`commit` fields exist only to be compared
    /// against it.
    ///
    /// # Wire compatibility
    ///
    /// bincode encodes enum variants by declaration order and struct
    /// fields by declaration position, so any later variant must be
    /// **appended** at the end and any later field of a variant must
    /// be appended after that variant's last field.  Never insert
    /// either in the middle or reorder the existing ones.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::{collections::BTreeMap, net::SocketAddr};
    ///
    /// use review_protocol::types::node::{FailurePolicy, NodePackageRequest};
    ///
    /// let req = NodePackageRequest::Install {
    ///     target: "sensor".into(),
    ///     instance: Some(1),
    ///     version: "1.2.3".into(),
    ///     commit: "0123456789abcdef".into(),
    ///     size: 4_194_304,
    ///     idempotency_key: "b6f0…".into(),
    ///     bootstrap_material: None,
    ///     on_failure: FailurePolicy::Rollback,
    ///     bind_addrs: Some(BTreeMap::from([(
    ///         "graphql_srv_addr".to_string(),
    ///         "0.0.0.0:8442".parse::<SocketAddr>().unwrap(),
    ///     )])),
    ///     config_template: None,
    ///     privilege_profile: None,
    /// };
    /// assert!(matches!(req, NodePackageRequest::Install { .. }));
    /// ```
    // A request is decoded once per stream and handed straight to its
    // handler, never held in bulk, so the size of `Install` costs
    // nothing; boxing its `bootstrap_material` to satisfy the lint
    // would instead change a public field type for every caller.
    #[allow(clippy::large_enum_variant)]
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodePackageRequest {
        /// Install or update a package.  The signed `.pkg` bytes
        /// follow on the same bi-stream; the request carries
        /// routing, size and — on a first install — the enrollment
        /// material and configuration-template id for a templated
        /// component, but deliberately NOT the manifest or signature.
        Install {
            /// The component this package places on the host.
            ///
            /// The value `"trust"` is **reserved**. It delivers a
            /// release-signing trust-set generation — the public keys
            /// by key id, the revoked-key list and the withdrawn-build
            /// list — rather than an installable component, and is
            /// never routed from an install or update action in a UI
            /// nor listed in any UI-facing package registry. It
            /// nonetheless streams over this same install path.
            ///
            /// A `"trust"` install carries no
            /// [`bootstrap_material`](Self::Install::bootstrap_material).
            /// The generation is verified against the current active
            /// generation and then activated as the next one, and it
            /// carries a package identity like any other package: its
            /// in-package manifest sets the component to `"trust"`,
            /// the version to the generation's decimal epoch and the
            /// commit to the generation digest, so the ordinary
            /// identity check applies unchanged to the
            /// highest-privilege channel.
            ///
            /// The generation's signed `epoch` is strictly monotonic.
            /// The agent activates it **only if** that epoch is
            /// strictly greater than the active generation's,
            /// answering [`NodePackageResponse::TrustActive`];
            /// otherwise it rejects with
            /// [`NodePackageError::StaleTrustSet`], which is what
            /// stops an older, validly signed generation from being
            /// replayed to restore a revoked key or drop a withdrawn
            /// build. An agent that cannot decode the generation's
            /// manifest format answers
            /// [`NodePackageError::UnsupportedManifestFormat`]
            /// instead. See the [module
            /// documentation](crate::types::node) for the full
            /// semantics of the reserved target.
            target: String,
            /// Which instance of `target` to place, or `None` when
            /// the component's class has no instance dimension.
            /// The number is allocated by the manager; this crate
            /// carries it and never derives, defaults or validates
            /// it.
            instance: Option<u32>,
            /// The package version, to be compared against the
            /// in-package manifest.
            version: String,
            /// The package build commit, to be compared against the
            /// in-package manifest.
            commit: String,
            /// The size in bytes of the `.pkg` payload that follows.
            size: u64,
            /// An opaque key that makes a repeated request a no-op.
            idempotency_key: String,
            /// The enrollment material for a first install, or
            /// `None` when the package already has an identity on
            /// this host.
            bootstrap_material: Option<BootstrapMaterial>,
            /// What the agent does when the apply fails.
            on_failure: FailurePolicy,
            /// The listening addresses this instance must bind, by
            /// the configuration key that carries each one.
            ///
            /// Populated by the manager for a component that
            /// declares listening addresses; `None` for every
            /// component that binds nothing.  The agent writes these
            /// values into the rendered configuration **verbatim**
            /// and never substitutes another: a bind that fails is
            /// reported, not retried at a different address.
            ///
            /// Honoured on a **first install only**.  An `Install`
            /// that is an update carrying a map is refused with
            /// [`InstallPreflight::BindAddrsOnUpdate`], not obeyed
            /// and not dropped: obeying it would revert what the
            /// operator set through the config plane, and dropping
            /// it would let the manager and the operator believe an
            /// address changed when it did not.
            ///
            /// Keyed by configuration key rather than by a
            /// component-specific struct, so a component that gains
            /// a listener needs no wire change.
            bind_addrs: Option<BTreeMap<String, SocketAddr>>,
            /// The id of a deploy-core configuration template that the
            /// agent renders as this instance's configuration file.
            ///
            /// `None` for every component except one whose catalog requires
            /// a template (today only `reconverge`). The manager sets it on
            /// a first install only and never on an update. Catalog ids are
            /// unique within their component and match
            /// `[a-z0-9][a-z0-9-]{0,62}`; templates hold no secret, and their
            /// content never changes under an existing id. These are
            /// deploy-core's invariants, not checks performed by this crate.
            ///
            /// Carried verbatim: this crate never parses, defaults or
            /// validates it. Deliberately unlike the `bind_addrs` idiom,
            /// `Some("")` is an id like any other, refused by the agent as
            /// unknown rather than collapsed to `None`.
            ///
            /// Honoured on a **first install only**. An update carrying an
            /// id is refused with [`InstallPreflight::ConfigTemplateOnUpdate`]
            /// without examining the id. On a first install, an id the
            /// agent's catalog does not hold for `target` is refused with
            /// [`InstallPreflight::UnknownConfigTemplate`].
            ///
            /// Appended last, after `bind_addrs`, because declaration
            /// position is the wire encoding.
            config_template: Option<String>,
            /// The serialized name of one of the privilege profiles the
            /// package's unit declares, selecting how the agent renders
            /// the unit.
            ///
            /// Allowed on a first install **and** on an update, unlike
            /// [`bind_addrs`](Self::Install::bind_addrs) and
            /// [`config_template`](Self::Install::config_template).
            ///
            /// `None` is the only accepted value for a package whose unit
            /// declares no profiles. On an update of a package that
            /// declares profiles, `None` keeps the profile the instance
            /// last applied, which is what
            /// [`PackageState::privilege_profile`] reports.
            ///
            /// An `Install` of the build already installed whose profile
            /// is `Some` and differs from the profile the instance last
            /// applied is a full apply of that build with the new
            /// profile, never [`InstallPreflight::AlreadyApplied`].
            ///
            /// A [reserved `"trust"`](Self::Install::target) install
            /// carries `None`.
            ///
            /// Carried verbatim: this crate never parses, defaults or
            /// validates it. `Some("")` is a name like any other, refused
            /// by the agent as undeclared rather than collapsed to `None`.
            ///
            /// Its refusals are
            /// [`NodePackageError::UndeclaredPrivilegeProfile`],
            /// [`NodePackageError::UnexpectedPrivilegeProfile`] and
            /// [`NodePackageError::MissingPrivilegeProfile`], decided
            /// after the package is opened; it is not judged in
            /// preflight.
            ///
            /// Appended last, after `config_template`, because
            /// declaration position is the wire encoding.
            privilege_profile: Option<String>,
        },
        /// Remove one installed instance.
        Remove {
            /// The component to remove.
            target: String,
            /// Which instance of `target` to remove, or `None` when
            /// the component's class has no instance dimension.
            instance: Option<u32>,
            /// An opaque key that makes a repeated request a no-op.
            idempotency_key: String,
        },
        /// List installed packages and their build ids.
        ListInstalled,
        /// Report install/lifecycle state of one installed instance.
        Status {
            /// The component to report on.
            target: String,
            /// Which instance of `target` to report on, or `None`
            /// when the component's class has no instance dimension.
            instance: Option<u32>,
        },
        /// Report every local port in use on this host, so the
        /// manager can choose bind addresses that do not collide.
        ///
        /// Host-wide, so it carries no `target` and no `instance`:
        /// what may be *allocated* is module-scoped, but what
        /// *occupies* a port is everything on the machine.  A
        /// separate request from [`ListInstalled`](Self::ListInstalled)
        /// because occupancy is a different question asked at a
        /// different time.
        ///
        /// Answered with [`NodePackageResponse::HostPorts`], or
        /// refused with
        /// [`NodePackageError::ObservationUnavailable`].
        ListHostPorts,
    }

    /// What the agent does when an apply fails.
    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum FailurePolicy {
        /// Restore the previous installation.
        Rollback,
        /// Leave the failed installation in place for inspection.
        Hold,
    }

    /// The outcome of the checks an agent runs before it accepts
    /// package bytes.
    ///
    /// # Wire compatibility
    ///
    /// bincode encodes enum variants by declaration order, so any
    /// later variant must be **appended** at the end.  Never insert
    /// a variant in the middle or reorder the existing ones.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum InstallPreflight {
        /// The agent is ready to receive the package bytes.
        Proceed,
        /// The requested package is already installed; nothing to do.
        AlreadyApplied,
        /// The target filesystem cannot hold the package.
        InsufficientDiskSpace {
            /// The filesystem that is short of space.
            filesystem: String,
            /// The space in bytes the install needs.
            required: u64,
            /// The space in bytes currently available.
            available: u64,
        },
        /// The request is an update and it carried
        /// [`bind_addrs`](NodePackageRequest::Install::bind_addrs).
        ///
        /// Addresses are fixed at first install: obeying the map
        /// would revert what the operator set through the config
        /// plane, and dropping it would let the manager and the
        /// operator believe an address changed when it did not.
        /// Decidable from the request alone, so no bytes move;
        /// terminal and **not** retryable.
        BindAddrsOnUpdate,
        /// The agent's per-host configuration carries no product
        /// namespace, so it cannot compose a single managed path.
        ///
        /// Terminal and **not** retryable: retrying cannot add a
        /// field to a file the agent does not write.
        NamespaceUnconfigured,
        /// The agent does not advertise the enrollment capability,
        /// and this is a first install carrying
        /// [`bootstrap_material`](NodePackageRequest::Install::bootstrap_material).
        ///
        /// Terminal for **this attempt** and not retryable — the
        /// agent answers identically until a different build is
        /// deployed — so the manager discharges the attempt's owed
        /// cleanup rather than holding it open.
        EnrollmentUnsupported,
        /// The request is an update and it carried
        /// [`config_template`](NodePackageRequest::Install::config_template).
        ///
        /// A template is rendered once, at first install: obeying it would
        /// overwrite the configuration the instance has run with since,
        /// and dropping it would let the manager believe a template was
        /// applied when it was not. Decided before any bytes move, from
        /// the request and the agent's installed-build record; terminal
        /// and **not** retryable. The id is never examined on an update,
        /// so even an unknown id gets this verdict rather than
        /// [`UnknownConfigTemplate`](Self::UnknownConfigTemplate).
        ConfigTemplateOnUpdate,
        /// A first install whose
        /// [`config_template`](NodePackageRequest::Install::config_template)
        /// names an id the agent's compiled-in catalog does not hold for
        /// `target`, including a component with no templates and the empty
        /// string.
        ///
        /// Decided before any bytes move, from the request and the agent's
        /// compiled-in template catalog; terminal and **not** retryable.
        /// The agent answers identically until a build linking a catalog
        /// that holds the id is deployed.
        UnknownConfigTemplate {
            /// The refused id, returned unchanged so the manager can name
            /// it without correlating back to the attempt.
            id: String,
        },
    }

    /// Response from a package-management operation.
    ///
    /// [`Installed`](Self::Installed) answers
    /// [`NodePackageRequest::ListInstalled`], [`State`](Self::State)
    /// answers [`NodePackageRequest::Status`],
    /// [`HostPorts`](Self::HostPorts) answers
    /// [`NodePackageRequest::ListHostPorts`], and
    /// [`Failed`](Self::Failed) carries a typed package-operation
    /// failure — an apply failure, but also a refusal from a
    /// non-apply request.
    /// [`TrustActive`](Self::TrustActive) is the terminal success of a
    /// [reserved `"trust"` target](crate::types::node) apply, the one
    /// outcome that reports an epoch rather than a package result.
    ///
    /// # Wire compatibility
    ///
    /// bincode encodes enum variants by declaration order, so any
    /// later variant must be **appended** at the end.  Never insert
    /// a variant in the middle or reorder the existing ones.
    ///
    /// # Examples
    ///
    /// ```
    /// use review_protocol::types::node::{
    ///     NodePackageError, NodePackageResponse, PackageIdentity,
    /// };
    ///
    /// let resp = NodePackageResponse::Failed(NodePackageError::TargetMismatch {
    ///     expected: PackageIdentity {
    ///         target: "sensor".into(),
    ///         version: "1.2.3".into(),
    ///         commit: "0123456789abcdef".into(),
    ///     },
    ///     found: PackageIdentity {
    ///         target: "collector".into(),
    ///         version: "1.2.3".into(),
    ///         commit: "0123456789abcdef".into(),
    ///     },
    /// });
    ///
    /// // A typed failure is classified by matching on it, not by
    /// // parsing a string.
    /// let NodePackageResponse::Failed(NodePackageError::TargetMismatch { found, .. }) = &resp
    /// else {
    ///     panic!("expected a target mismatch");
    /// };
    /// assert_eq!(found.target, "collector");
    /// ```
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodePackageResponse {
        /// The operation completed successfully.
        Done,
        /// The agent accepted the request and is applying it.
        Accepted,
        /// The packages installed on this host.
        Installed(Vec<InstalledPackage>),
        /// The state of the queried instance.
        State(PackageState),
        /// A typed package-operation failure — an apply failure, but
        /// also a refusal from a non-apply request, such as
        /// [`ObservationUnavailable`](NodePackageError::ObservationUnavailable)
        /// from [`NodePackageRequest::ListHostPorts`].
        ///
        /// Success-shaped on the wire — a decode success still means
        /// "the agent answered", and the manager classifies the
        /// refusal by matching on the error rather than by parsing a
        /// string; the `Result<_, String>` channel is left to
        /// transport and parse failures.
        Failed(NodePackageError),
        /// Terminal success of a [reserved `"trust"`
        /// target](crate::types::node) apply.
        ///
        /// The epoch carried here is the one the agent is ACTIVE ON
        /// after activating, so a rollout is confirmed
        /// in-connection rather than at the next handshake: the
        /// connect-time [`AgentInfo::active_trust_epoch`] is
        /// exchanged once per connection and cannot report an
        /// activation that happens later on a still-open one.  The
        /// two readings are complementary, not redundant.
        ///
        /// The value is agent-asserted, so it bounds the host's
        /// status **downward only**: a consumer clamps it against
        /// its own active epoch, where a report at or below that
        /// epoch may mark the host caught up, and a report **above**
        /// it is treated as un-confirmed, never as confirmed.  This
        /// crate does not implement the clamp.
        ///
        /// [`AgentInfo::active_trust_epoch`]: crate::AgentInfo::active_trust_epoch
        TrustActive {
            /// The trust-set generation epoch the agent is active on
            /// after this apply.
            active_epoch: u64,
        },
        /// The ports taken on this host, answering
        /// [`NodePackageRequest::ListHostPorts`].
        ///
        /// A **deduplicated** set of `(transport, port)` pairs: one
        /// entry per taken port, not per socket, and deduplicated
        /// across the sources the agent reads as well as within each
        /// of them.  The same port under TCP and under UDP is two
        /// legitimate entries, not a duplicate.
        ///
        /// `Vec<HostPort>` cannot enforce that, and this crate
        /// produces no occupancy — it only carries it.  Producing
        /// the set without duplicates is the answering agent's
        /// obligation.
        HostPorts(Vec<HostPort>),
    }

    /// One port taken on a host, as
    /// [`NodePackageRequest::ListHostPorts`] reports it.
    ///
    /// Deliberately **not an address**.  The manager's conflict
    /// model is `(transport, port)` and address-blind by decision: a
    /// wildcard bind conflicts with every specific one, wildcard is
    /// what these components use, and a precise model would need
    /// address-overlap rules the manager cannot verify against what
    /// is actually bound.  An address carried here would be carried
    /// and never read.
    ///
    /// Deliberately **not one entry per socket** either.  With no
    /// owner netting anywhere in the design, nothing counts sockets:
    /// two `SO_REUSEPORT` sockets on one port make that port taken
    /// exactly once over.
    ///
    /// [`Ord`] and [`Hash`](std::hash::Hash) are derived so that a
    /// producing agent can collect into a `BTreeSet` or `HashSet`
    /// and satisfy the deduplication contract of
    /// [`NodePackageResponse::HostPorts`] without a hand-written
    /// key.
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct HostPort {
        /// The transport the port is taken on.
        pub transport: Transport,
        /// The port number.
        pub port: u16,
    }

    /// The transport a port is taken on.
    ///
    /// TCP and UDP are separate spaces, so one number may be taken
    /// on one and free on the other.
    ///
    /// # Wire compatibility
    ///
    /// bincode encodes enum variants by declaration order, so any
    /// later variant must be **appended** at the end.  Never insert
    /// a variant in the middle or reorder the existing ones.
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub enum Transport {
        /// TCP.
        Tcp,
        /// UDP.
        Udp,
    }

    /// One installed package instance and its state.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct InstalledPackage {
        /// The installed component.
        pub target: String,
        /// Which instance of `target` this is, or `None` when the
        /// component's class has no instance dimension.
        pub instance: Option<u32>,
        /// The state of this instance.
        pub state: PackageState,
    }

    /// The install and lifecycle state of one package instance.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct PackageState {
        /// The installed version.
        pub version: String,
        /// The installed build commit.
        pub commit: String,
        /// Where the instance is in its lifecycle.
        pub lifecycle: Lifecycle,
        /// The addresses the instance is **actually listening on**,
        /// each named by its configuration key.
        ///
        /// This field is **observed, never intent**: it records
        /// where the instance IS, read from the host's live sockets,
        /// and the agent never derives it from the rendered
        /// configuration.  That distinction is load-bearing — an
        /// instance that failed to bind must read as *not bound*,
        /// and a value derived from configuration would report the
        /// address it was told to use whether or not it got it.
        ///
        /// The manager chooses these addresses and sends them on
        /// [`Install`](NodePackageRequest::Install) as
        /// [`bind_addrs`](NodePackageRequest::Install::bind_addrs).
        /// That does not make this field intent: the manager knows
        /// what it assigned without reading it back, and what this
        /// reports is whether the host agrees.
        ///
        /// Empty for a component that listens on nothing.
        pub bound_addrs: Vec<BoundAddr>,
        /// The serialized name of the privilege profile the instance's
        /// unit was rendered with at its last committed apply — after a
        /// rollback, the restored one.
        ///
        /// `None` for an instance whose package declares no profiles,
        /// for a target that is not a module, and for an instance that
        /// is not installed. Agent-reported and carried verbatim. It is
        /// the profile an update whose
        /// [`privilege_profile`](NodePackageRequest::Install::privilege_profile)
        /// is `None` keeps.
        ///
        /// Appended last, after `bound_addrs`, because declaration
        /// position is the wire encoding.
        pub privilege_profile: Option<String>,
    }

    /// An address an instance is bound to, named by the
    /// configuration key it was read from.
    ///
    /// The name is carried alongside the address so that a reader
    /// matches addresses by name rather than by position.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct BoundAddr {
        /// The configuration key the address came from.
        pub name: String,
        /// The address as **observed** on the host's live sockets,
        /// as `host:port`.
        ///
        /// Never derived from the rendered configuration: an
        /// instance that failed to bind must read as not bound,
        /// whereas a value taken from configuration would report the
        /// address it was told to use whether or not it got it.
        pub addr: String,
    }

    /// Where a package instance is in its lifecycle.
    ///
    /// # Wire compatibility
    ///
    /// This is encoded as its `u8` discriminant, and a discriminant
    /// this build does not recognize decodes to
    /// [`Unknown`](Self::Unknown) rather than failing the decode, so
    /// a newer agent may report a state an older manager has never
    /// heard of.
    ///
    /// The discriminants are local to this wire.  A consumer
    /// repository's identically named type is encoded independently
    /// and the manager maps between the two; no code may read a
    /// number written on one side as meaning the same on the other.
    #[derive(
        Clone, Copy, Debug, Deserialize, Eq, FromPrimitive, IntoPrimitive, PartialEq, Serialize,
    )]
    #[serde(from = "u8", into = "u8")]
    #[repr(u8)]
    pub enum Lifecycle {
        /// No installation exists.
        NotInstalled = 0,
        /// An install is in progress.
        Installing = 1,
        /// The instance is running.
        Running = 2,
        /// The instance is installed but not running.
        Stopped = 3,
        /// The instance failed.
        Failed = 4,
        /// A removal is in progress.
        Removing = 5,
        /// The reported discriminant is not one this build knows.
        #[num_enum(default)]
        Unknown = u8::MAX,
    }

    /// The enrollment material a first install needs.
    ///
    /// This type is defined once here and shared: the `node.enroll`
    /// family returns it from its register call and
    /// [`NodePackageRequest::Install`] relays it.
    ///
    /// [`Debug`] is hand-written rather than derived, so that neither
    /// `wrapped_secret_id` nor `bootstrap_artifact` can reach a log
    /// through it.
    #[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub struct BootstrapMaterial {
        /// The role the wrapped secret authenticates as.
        pub role_id: String,
        /// The wrapped one-time secret identifier.
        ///
        /// This is a live one-time credential; it is redacted from
        /// the [`Debug`] output and must not be logged.
        pub wrapped_secret_id: String,
        /// The trust anchor the enrolling package validates against.
        pub ca_anchor: Vec<u8>,
        /// The GRANTED absolute deadline of the wrapped secret,
        /// after the registrar applied any clamp to the requested
        /// TTL.
        #[serde(with = "jiff::fmt::serde::timestamp::nanosecond::required")]
        pub expires_at: jiff::Timestamp,
        /// The bootstrap artifact bootroot produced for this
        /// enrollment — its own `bootstrap.json` — carried verbatim.
        ///
        /// The bytes are opaque to this crate: they are transported,
        /// never parsed, and never validated.  The artifact carries
        /// members the other fields do not, such as the registration
        /// identifier, and those are derived by the registrar alone;
        /// relaying what bootroot produced keeps a single producer and
        /// a single consumer, and a later addition to the artifact
        /// needs no wire change here.
        ///
        /// The member is required rather than optional, deliberately.
        /// No peer exchanged this type when it was added, so requiring
        /// it broke nothing that existed.  And a value carrying the
        /// other members without the artifact is not a weaker form of
        /// enrollment material but an unusable one: they cannot be
        /// turned into a bootstrap invocation on their own.  An
        /// optional member would admit that meaningless value and
        /// make every consumer handle it.
        ///
        /// The artifact accompanies the live one-time credential in
        /// `wrapped_secret_id`, so it is redacted from the [`Debug`]
        /// output the same way and must not be logged.
        pub bootstrap_artifact: Vec<u8>,
    }

    /// `wrapped_secret_id` is a live one-time credential, and
    /// `bootstrap_artifact` accompanies it, so both are redacted
    /// rather than derived: `BootstrapMaterial` travels inside
    /// [`NodePackageRequest::Install`], whose derived `Debug` would
    /// otherwise print them into a caller's logs.
    impl fmt::Debug for BootstrapMaterial {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("BootstrapMaterial")
                .field("role_id", &self.role_id)
                .field("wrapped_secret_id", &"<redacted>")
                .field("ca_anchor", &self.ca_anchor)
                .field("expires_at", &self.expires_at)
                .field("bootstrap_artifact", &"<redacted>")
                .finish()
        }
    }

    /// The three parts of a package identity, as they appear on this
    /// wire.
    ///
    /// The parts are carried separately and are never composed into
    /// a single string by this crate.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct PackageIdentity {
        /// The component name.
        pub target: String,
        /// The version.
        pub version: String,
        /// The build commit.
        pub commit: String,
    }

    /// Typed package-operation failures, carried by
    /// [`NodePackageResponse::Failed`] — an apply failure, but also a
    /// refusal from a non-apply request, such as
    /// [`ObservationUnavailable`](Self::ObservationUnavailable) from
    /// [`NodePackageRequest::ListHostPorts`].
    ///
    /// This is data, not an error type: the manager matches on it
    /// rather than printing it, so it implements neither
    /// `std::error::Error` nor `Display`.
    ///
    /// # Wire compatibility
    ///
    /// bincode encodes enum variants by declaration order, so any
    /// later variant must be **appended** at the end.  Never insert
    /// a variant in the middle or reorder the existing ones.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodePackageError {
        /// The in-package manifest's `component`/`version`/`commit`
        /// disagree with the request's `target`/`version`/`commit`.
        TargetMismatch {
            /// The request's identity.
            expected: PackageIdentity,
            /// The manifest's identity, with the manifest's
            /// `component` carried in [`PackageIdentity::target`].
            found: PackageIdentity,
        },
        /// A first install of a package with no existing identity
        /// arrived with `bootstrap_material: None`.
        MissingBootstrapMaterial,
        /// The wrapped credential's TTL lapsed before it was
        /// consumed.
        ///
        /// This is a unit variant on purpose: it means "re-mint and
        /// resume", and the manager already holds the deadline it
        /// persisted from [`BootstrapMaterial::expires_at`].  It is
        /// distinct from a generic enrollment failure — the identity
        /// is intact and only the wrapped credential lapsed.
        BootstrapMaterialExpired,
        /// Raised before the first mutation; not retryable without
        /// operator action.
        InsufficientDiskSpace {
            /// The filesystem that is short of space.
            filesystem: String,
            /// The space in bytes the install needs.
            required: u64,
            /// The space in bytes currently available.
            available: u64,
        },
        /// The delivered [reserved `"trust"`
        /// target](crate::types::node) generation's epoch is not
        /// strictly greater than the active one, so it was rejected.
        ///
        /// The epoch carried here is the agent's CURRENT active one.
        /// That makes a rejection-on-equal an explicit
        /// already-at-this-epoch confirmation rather than an
        /// inference from what the manager believed it delivered, and
        /// it is what stops an older, validly signed generation from
        /// being replayed to restore a revoked key or drop a
        /// withdrawn build.
        ///
        /// Reading the epoch here rather than at the next handshake
        /// is what makes it usable: the connect-time
        /// [`AgentInfo::active_trust_epoch`] is exchanged once per
        /// connection and cannot report a later activation, so the
        /// two readings are complementary, not redundant.
        ///
        /// The value is agent-asserted, so it bounds the host's
        /// status **downward only**: a consumer clamps it against
        /// its own active epoch, where a report at or below that
        /// epoch may mark the host caught up, and a report **above**
        /// it is treated as un-confirmed, never as confirmed.  This
        /// crate does not implement the clamp.
        ///
        /// [`AgentInfo::active_trust_epoch`]: crate::AgentInfo::active_trust_epoch
        StaleTrustSet {
            /// The trust-set generation epoch the agent is currently
            /// active on, which it kept.
            active_epoch: u64,
        },
        /// The agent cannot decode the delivered [reserved `"trust"`
        /// target](crate::types::node) generation's manifest format.
        ///
        /// This is **terminal for this host**: re-sending the same
        /// generation cannot succeed, so the manager stops re-pushing
        /// it rather than re-sending forever.  The field pair is what
        /// makes that possible — `active_epoch` says where the host
        /// actually stands and `supported` says which manifest
        /// formats it can read, so the manager can name the cause
        /// instead of marking the host generically exposed, and can
        /// tell that raising the fleet-wide manifest format needs
        /// this host's agent binary updated first.
        ///
        /// Reading the epoch here rather than at the next handshake
        /// is what makes it usable: the connect-time
        /// [`AgentInfo::active_trust_epoch`] is exchanged once per
        /// connection and cannot report a later activation, so the
        /// two readings are complementary, not redundant.
        ///
        /// The value is agent-asserted, so it bounds the host's
        /// status **downward only**: a consumer clamps it against
        /// its own active epoch, where a report at or below that
        /// epoch may mark the host caught up, and a report **above**
        /// it is treated as un-confirmed, never as confirmed.  This
        /// crate does not implement the clamp.
        ///
        /// [`AgentInfo::active_trust_epoch`]: crate::AgentInfo::active_trust_epoch
        UnsupportedManifestFormat {
            /// The trust-set generation epoch the agent is currently
            /// active on, which it kept.
            active_epoch: u64,
            /// The inclusive range of manifest `format_version`
            /// values this agent can decode.
            supported: ManifestFormatRange,
        },
        /// A required occupancy read failed — a socket table, or a
        /// container runtime that is present and could not be
        /// queried — so **no** occupancy is reported rather than a
        /// short list, which would be indistinguishable from a host
        /// with fewer listeners.
        ///
        /// Answers [`NodePackageRequest::ListHostPorts`], not an
        /// apply.  **Retryable.**
        ObservationUnavailable,
        /// The instance is present on the host but the agent holds
        /// no installed-build record for it, so it cannot treat the
        /// apply as a first install without re-rendering
        /// configuration it did not write.
        ///
        /// Distinct from
        /// [`MissingBootstrapMaterial`](Self::MissingBootstrapMaterial),
        /// which says "you forgot the material" when the truth is
        /// "this instance is not one I manage".  Terminal and **not**
        /// retryable: the state is a standing property of the host.
        UnmanagedInstancePresent,
        /// The privilege profile in effect for the apply is not one the
        /// package's unit declares.
        ///
        /// Raised after the package is opened and verified and before
        /// the first mutation, so nothing on the host changed. Terminal
        /// and **not** retryable with the same request.
        UndeclaredPrivilegeProfile {
            /// The profile that was refused: the request's
            /// [`privilege_profile`](NodePackageRequest::Install::privilege_profile),
            /// or, on an update carrying `None`, the profile the
            /// instance last applied, which the new build no longer
            /// declares. A string that is no profile name at all,
            /// including `""`, is refused this way.
            profile: String,
            /// The profile names the package's unit declares, in
            /// declared order, so the manager can name what is allowed.
            declared: Vec<String>,
        },
        /// The request carries a privilege profile for an apply that
        /// takes none: a package whose unit declares no profiles, a
        /// package with no unit, or a target the agent applies no
        /// profile to — anything that is not a module, including the
        /// [reserved `"trust"` target](crate::types::node) and the
        /// agent's own update.
        ///
        /// Raised after the package is opened and verified and before
        /// the first mutation, so nothing on the host changed. Terminal
        /// and **not** retryable with the same request.
        UnexpectedPrivilegeProfile {
            /// The profile the request carried.
            profile: String,
        },
        /// The package's unit declares privilege profiles and the apply
        /// has none in effect: the request carries `None` on a first
        /// install, or on an update of an instance with no recorded
        /// profile.
        ///
        /// Raised after the package is opened and verified and before
        /// the first mutation, so nothing on the host changed. Terminal
        /// and **not** retryable with the same request.
        MissingPrivilegeProfile,
        /// The apply's journal committed and the new build did not end
        /// healthy: its start failed, the apply did not complete, or the
        /// build failed its health gate.
        ///
        /// Terminal for the attempt: re-sending the same request repeats
        /// the same apply, so the manager concludes the exchange on this
        /// frame instead of re-sending it.
        ///
        /// It reports a verdict on the build. An end the agent itself
        /// interrupted, such as a gate cut short by the agent's own
        /// shutdown, is not reported this way.
        AppliedButUnhealthy {
            /// What the agent left in place after the failure.
            disposition: UnhealthyDisposition,
            /// Agent-asserted, human-readable display text, carried
            /// verbatim. A consumer logs or shows it and never branches
            /// on it.
            cause: String,
        },
    }

    /// What the agent left in place after an apply that committed and
    /// did not end healthy, as reported by
    /// [`NodePackageError::AppliedButUnhealthy`].
    ///
    /// # Wire compatibility
    ///
    /// bincode encodes enum variants by declaration order, so any
    /// later variant must be **appended** at the end.  Never insert
    /// a variant in the middle or reorder the existing ones.
    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum UnhealthyDisposition {
        /// The prior build was restored.
        ///
        /// This holds whether or not the restored build then passed a
        /// fresh health gate; the error's `cause` says which.
        RolledBack,
        /// The new build is kept installed under the
        /// [`Hold`](FailurePolicy::Hold) failure policy.
        Held,
        /// A first install was unwound; the target is not installed.
        Unwound,
        /// Reversing the apply failed or was blocked, so the agent kept
        /// its journal and the state is not yet the prior one.
        ///
        /// The agent's next operation on the target settles it first,
        /// so a re-send would settle it and then repeat the same apply.
        NotReversed,
    }

    impl NodePackageError {
        /// Returns the agent's active release-signing trust epoch if this
        /// error reports one, or `None` for a non-trust failure.
        ///
        /// The epoch is agent-asserted and bounds the host's status
        /// **downward only**; see the variant docs for the clamp a consumer
        /// applies.
        ///
        /// # Examples
        ///
        /// ```
        /// use review_protocol::types::node::NodePackageError;
        ///
        /// let err = NodePackageError::StaleTrustSet { active_epoch: 42 };
        /// assert_eq!(err.active_trust_epoch(), Some(42));
        ///
        /// let err = NodePackageError::MissingBootstrapMaterial;
        /// assert_eq!(err.active_trust_epoch(), None);
        /// ```
        #[must_use]
        pub fn active_trust_epoch(&self) -> Option<u64> {
            match self {
                Self::StaleTrustSet { active_epoch }
                | Self::UnsupportedManifestFormat { active_epoch, .. } => Some(*active_epoch),
                // Listed explicitly rather than caught by `_`, so a future
                // epoch-carrying variant fails the build instead of silently
                // reading as `None`.
                Self::TargetMismatch { .. }
                | Self::MissingBootstrapMaterial
                | Self::BootstrapMaterialExpired
                | Self::InsufficientDiskSpace { .. }
                | Self::ObservationUnavailable
                | Self::UnmanagedInstancePresent
                | Self::UndeclaredPrivilegeProfile { .. }
                | Self::UnexpectedPrivilegeProfile { .. }
                | Self::MissingPrivilegeProfile
                | Self::AppliedButUnhealthy { .. } => None,
            }
        }
    }

    impl NodePackageResponse {
        /// Returns the agent's active release-signing trust epoch if this
        /// outcome reports one — including the trust apply errors reached
        /// through [`Failed`](Self::Failed) — or `None` otherwise.
        ///
        /// One call covers all three outcomes of a [reserved `"trust"`
        /// target](crate::types::node) apply, so a consumer computes a host's
        /// true epoch by matching on the outcome rather than by consulting
        /// its own delivery bookkeeping.  The name matches the connect-time
        /// [`AgentInfo::active_trust_epoch`], the complementary reading that
        /// a long-lived connection cannot refresh.
        ///
        /// The epoch is agent-asserted and bounds the host's status
        /// **downward only**; see the variant docs for the clamp a consumer
        /// applies.
        ///
        /// # Examples
        ///
        /// ```
        /// use review_protocol::types::ManifestFormatRange;
        /// use review_protocol::types::node::{NodePackageError, NodePackageResponse};
        ///
        /// let outcomes = [
        ///     NodePackageResponse::TrustActive { active_epoch: 43 },
        ///     NodePackageResponse::Failed(NodePackageError::StaleTrustSet {
        ///         active_epoch: 43,
        ///     }),
        ///     NodePackageResponse::Failed(NodePackageError::UnsupportedManifestFormat {
        ///         active_epoch: 43,
        ///         supported: ManifestFormatRange { min: 1, max: 2 },
        ///     }),
        /// ];
        /// for outcome in &outcomes {
        ///     assert_eq!(outcome.active_trust_epoch(), Some(43));
        /// }
        ///
        /// // A non-trust outcome reports no epoch at all.
        /// let resp = NodePackageResponse::Failed(NodePackageError::BootstrapMaterialExpired);
        /// assert_eq!(resp.active_trust_epoch(), None);
        /// assert_eq!(NodePackageResponse::Done.active_trust_epoch(), None);
        /// ```
        ///
        /// [`AgentInfo::active_trust_epoch`]: crate::AgentInfo::active_trust_epoch
        #[must_use]
        pub fn active_trust_epoch(&self) -> Option<u64> {
            match self {
                Self::TrustActive { active_epoch } => Some(*active_epoch),
                Self::Failed(err) => err.active_trust_epoch(),
                // Listed explicitly rather than caught by `_`, so a future
                // epoch-carrying variant fails the build instead of silently
                // reading as `None`.
                Self::Done
                | Self::Accepted
                | Self::Installed(_)
                | Self::State(_)
                | Self::HostPorts(_) => None,
            }
        }
    }

    // ── service enrollment ──────────────────────────────────────

    /// Request for minting or tearing down a service identity.
    ///
    /// The family is directed at the **registrar** agent — the one
    /// co-located with the identity store — and is unary: one request
    /// frame, one response frame, no streaming.
    ///
    /// The request carries the identity's **parts**, never a composed
    /// name.  The registrar derives both the certificate name and the
    /// namespace key from `service_name`, `host` and `instance`; this
    /// crate never composes, parses or validates them.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use review_protocol::types::node::{
    ///     DeliveryMode, NodeEnrollRequest, ReloadHook, ServiceSpec,
    /// };
    ///
    /// let req = NodeEnrollRequest::Register {
    ///     service_name: "sensor".into(),
    ///     delivery_mode: DeliveryMode::RemoteBootstrap,
    ///     host: "host01".into(),
    ///     instance: Some(1),
    ///     spec: ServiceSpec {
    ///         component: "sensor".into(),
    ///         service_name: "sensor".into(),
    ///         reload: ReloadHook("reload-sensor".into()),
    ///         cert_group: None,
    ///     },
    ///     wrap_ttl: Duration::from_mins(10),
    ///     idempotency_key: "b6f0".into(),
    /// };
    /// assert!(matches!(req, NodeEnrollRequest::Register { .. }));
    /// ```
    ///
    /// # Wire compatibility
    ///
    /// bincode encodes enum variants by declaration order, so any
    /// later variant must be **appended** at the end.  Never insert
    /// a variant in the middle or reorder the existing ones.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeEnrollRequest {
        /// Register a new service and return its bootstrap material.
        /// Used for both per-service install and new-host onboarding.
        ///
        /// This is idempotent in **effect**, not in response bytes.
        /// For an identity that already exists with a matching
        /// [`ServiceSpec`], the existing role and policy are reused
        /// and **fresh** wrapped material is returned; for one that
        /// exists with a different spec the registrar answers
        /// [`ServiceSpecConflict`](NodeEnrollError::ServiceSpecConflict)
        /// and mints nothing.
        Register {
            /// The component's PLAIN keyword — a single DNS label,
            /// never host- or instance-qualified.
            ///
            /// This is the *identity* being registered, together with
            /// `host` and `instance`.  It is not derived from
            /// [`spec.service_name`](ServiceSpec::service_name) and
            /// does not derive it; see [`spec`](Self::Register::spec).
            service_name: String,
            /// How the minted material reaches the target.
            delivery_mode: DeliveryMode,
            /// The target host's single DNS label.
            host: String,
            /// Which instance of `service_name` on `host` this is, or
            /// `None` when the component's multiplicity class has no
            /// instance dimension.  The number is allocated by the
            /// manager; this crate carries it and never derives,
            /// defaults or validates it.
            instance: Option<u32>,
            /// What the identity is registered *as*.
            ///
            /// This mirrors the registrar's own registration record,
            /// which carries its own `component` and `service_name`,
            /// and the registrar compares it **as a whole** against
            /// the one already bound to the identity.  Its
            /// `service_name` and this request's are filled
            /// independently by the manager: neither is derived from
            /// the other, and this crate neither reconciles nor
            /// rejects a request whose two values differ.
            spec: ServiceSpec,
            /// Requested lifetime of the wrapped material.  The
            /// registrar MAY clamp it; the GRANTED absolute deadline
            /// comes back in the material's
            /// [`expires_at`](BootstrapMaterial::expires_at).
            wrap_ttl: Duration,
            /// An opaque key that correlates a re-driven request with
            /// the operation it retries.
            ///
            /// It is a correlation handle, **not** a response cache:
            /// the wrapped secret is single-use, short-TTL and is not
            /// persisted anywhere, so the same bytes cannot be
            /// returned on a re-drive.  The key exists only so that a
            /// retry of one logical operation is recorded as the same
            /// operation rather than a second one.
            idempotency_key: String,
        },
        /// Deregister a service on uninstall: tear down its role,
        /// policy, per-service store and state entry.
        ///
        /// This is idempotent: a teardown of an already-absent
        /// identity **for the matching host** answers
        /// [`Done`](NodeEnrollResponse::Done) rather than an error, so
        /// an owed teardown can be re-driven after a crash.  A
        /// `Deregister` whose `host` is not the identity's bound host
        /// is refused with
        /// [`ServiceHostMismatch`](NodeEnrollError::ServiceHostMismatch)
        /// and tears nothing down.
        Deregister {
            /// The component's PLAIN keyword, as on
            /// [`Register`](Self::Register).
            service_name: String,
            /// The target host's single DNS label.
            host: String,
            /// Which instance to tear down, with the same meaning as
            /// on [`Register`](Self::Register).
            instance: Option<u32>,
            /// An opaque key that correlates a re-driven request with
            /// the operation it retries, with the same meaning as on
            /// [`Register`](Self::Register).
            idempotency_key: String,
        },
    }

    /// The registration shape the registrar applies and compares.
    ///
    /// These four fields are the whole shape.  There is deliberately
    /// **no** privilege field: a service's authority is derived from
    /// a fixed per-service policy on the registrar side, so no
    /// component differs on that dimension.
    ///
    /// # Examples
    ///
    /// ```
    /// use review_protocol::types::node::{CertGroup, ReloadHook, ServiceSpec};
    ///
    /// let spec = ServiceSpec {
    ///     component: "sensor".into(),
    ///     service_name: "sensor".into(),
    ///     reload: ReloadHook("reload-sensor".into()),
    ///     cert_group: Some(CertGroup("internal".into())),
    /// };
    /// assert_eq!(spec.cert_group.as_ref().map(|g| g.0.as_str()), Some("internal"));
    /// ```
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct ServiceSpec {
        /// The component's canonical package id.
        pub component: String,
        /// The component's plain keyword.
        pub service_name: String,
        /// How the service is reloaded after a certificate rotation.
        pub reload: ReloadHook,
        /// The certificate group the material belongs to, if any.
        pub cert_group: Option<CertGroup>,
    }

    /// How the service is reloaded after its certificate is rotated.
    ///
    /// Opaque to this crate: the value is carried verbatim to the
    /// registrar, which validates it against its own safe-set.  It is
    /// never parsed, normalised, enumerated or rejected here, and this
    /// type deliberately has no validating constructor — an
    /// unacceptable value is the registrar's business, not a decode
    /// failure.
    ///
    /// serde encodes a newtype struct as its inner value, so this is
    /// byte-identical on the wire to the bare [`String`] it wraps.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct ReloadHook(pub String);

    /// The certificate group the service's material belongs to.
    ///
    /// Opaque to this crate on the same terms as [`ReloadHook`], and
    /// byte-identical on the wire to the bare [`String`] it wraps.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct CertGroup(pub String);

    /// How the minted material reaches the target.
    ///
    /// # Wire compatibility
    ///
    /// bincode encodes enum variants by declaration order, so any
    /// later variant must be **appended** at the end.  Never insert
    /// a variant in the middle or reorder the existing ones.
    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum DeliveryMode {
        /// Material placed on the host out of band.
        LocalFile,
        /// Remote enrollment via the on-host agent.
        RemoteBootstrap,
    }

    /// Response from a service-enrollment operation.
    ///
    /// [`Material`](Self::Material) answers a
    /// [`Register`](NodeEnrollRequest::Register),
    /// [`Done`](Self::Done) answers a
    /// [`Deregister`](NodeEnrollRequest::Deregister), and
    /// [`Failed`](Self::Failed) carries a typed registrar failure.
    ///
    /// [`Debug`] is derived, so the `Material` payload is rendered by
    /// [`BootstrapMaterial`]'s own hand-written implementation and
    /// keeps its redaction of the wrapped one-time credential.
    ///
    /// # Wire compatibility
    ///
    /// bincode encodes enum variants by declaration order, so any
    /// later variant must be **appended** at the end.  Never insert
    /// a variant in the middle or reorder the existing ones.
    ///
    /// # Examples
    ///
    /// ```
    /// use review_protocol::types::node::{
    ///     NodeEnrollError, NodeEnrollResponse, RegistrarUnavailableReason,
    /// };
    ///
    /// let resp = NodeEnrollResponse::Failed(NodeEnrollError::RegistrarUnavailable {
    ///     reason: RegistrarUnavailableReason::NotProvisioned,
    /// });
    ///
    /// // A typed failure is classified by matching on it, not by
    /// // parsing a string.
    /// let NodeEnrollResponse::Failed(NodeEnrollError::RegistrarUnavailable { reason }) = &resp
    /// else {
    ///     panic!("expected a registrar-unavailable failure");
    /// };
    /// assert_eq!(*reason, RegistrarUnavailableReason::NotProvisioned);
    /// ```
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeEnrollResponse {
        /// Wrapped bootstrap material the target consumes to obtain
        /// its certificate.  Returned for
        /// [`Register`](NodeEnrollRequest::Register).
        ///
        /// The material's
        /// [`expires_at`](BootstrapMaterial::expires_at) is the
        /// GRANTED absolute deadline, which may correspond to a
        /// shorter lifetime than the requested
        /// [`wrap_ttl`](NodeEnrollRequest::Register::wrap_ttl).  A
        /// consumer must never assume the grant equals the request.
        Material(BootstrapMaterial),
        /// The teardown completed.  Returned for
        /// [`Deregister`](NodeEnrollRequest::Deregister).
        Done,
        /// A typed registrar failure.  Success-shaped on the wire — a
        /// decode success still means "the registrar answered"; the
        /// `Result<_, String>` channel is left to transport and parse
        /// failures.
        Failed(NodeEnrollError),
    }

    /// Typed registrar failures, carried by
    /// [`NodeEnrollResponse::Failed`].
    ///
    /// This is data, not an error type: the manager matches on it
    /// rather than printing it, so it implements neither
    /// `std::error::Error` nor `Display`.
    ///
    /// Exactly one of these is retryable —
    /// [`RegistrarBusy`](Self::RegistrarBusy) — and exactly one
    /// leaves a registrar identity behind:
    /// [`RegistrarUnavailable`](Self::RegistrarUnavailable) with
    /// [`PostMintUnrecordable`](RegistrarUnavailableReason::PostMintUnrecordable).
    /// Read both properties through
    /// [`retry_after`](Self::retry_after) and
    /// [`leaves_teardown_owed`](Self::leaves_teardown_owed) rather
    /// than re-deriving them from the variant list.
    ///
    /// # Wire compatibility
    ///
    /// bincode encodes enum variants by declaration order, so any
    /// later variant must be **appended** at the end.  Never insert
    /// a variant in the middle or reorder the existing ones.
    /// [`ServiceLabelInvalid`](Self::ServiceLabelInvalid) is the
    /// worked example: it reads as a sibling of the other `Service*`
    /// variants but was added after they were settled, so it is last.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum NodeEnrollError {
        /// The identity already exists on the same bound host,
        /// registered with a **different [`ServiceSpec`]**.
        ///
        /// The comparison is over the spec **as a whole**: any of its
        /// four fields may be the one that differs.  `reload` and
        /// `cert_group` are the two that differ in practice, but they
        /// are examples rather than the whole rule — a differing
        /// `component` or `spec.service_name` is the same conflict.
        /// Nothing is minted.
        ServiceSpecConflict,
        /// The derived registration identity is already bound to a
        /// **different** host.
        ///
        /// Raised **before** any spec comparison, so it is never
        /// reported as a [`ServiceSpecConflict`](Self::ServiceSpecConflict).
        ServiceNameCollision,
        /// `instance` contradicts the component's multiplicity:
        /// present for a component that has no instance dimension, or
        /// absent for one that does.
        ///
        /// A component with **no entry in the multiplicity table** is
        /// also reported here.  That is an intentional second meaning
        /// of this variant, not a gap covered by
        /// [`ServiceLabelInvalid`](Self::ServiceLabelInvalid).
        ///
        /// Raised before any mint, so nothing is created.
        ServiceInstanceMismatch,
        /// A [`Deregister`](NodeEnrollRequest::Deregister) whose
        /// `host` is not the identity's bound host.
        ///
        /// The teardown is refused, so a cleanup aimed at one host can
        /// never remove another host's identity.
        ServiceHostMismatch,
        /// A fail-closed condition on the registrar, with a closed
        /// reason set.
        RegistrarUnavailable {
            /// Which fail-closed condition was hit.
            reason: RegistrarUnavailableReason,
        },
        /// The registrar's rate limit was hit.
        ///
        /// This is the **only** retryable failure in the family: it
        /// clears on its own, and the delay to honour travels with it.
        RegistrarBusy {
            /// The delay to honour before re-driving the request.
            retry_after: Duration,
        },
        /// The `service_name` or the `host` in the request is not a
        /// single DNS label, so the registrar refused **before** it
        /// could derive the registration identity at all.
        ///
        /// Nothing is minted and nothing is probed.  The refusal is
        /// pre-derivation, so it is neither
        /// [`ServiceNameCollision`](Self::ServiceNameCollision), which
        /// compares an identity that was already derived, nor
        /// [`ServiceInstanceMismatch`](Self::ServiceInstanceMismatch),
        /// which is about multiplicity.
        ///
        /// It carries no payload: no discriminator for which of the
        /// two parts was rejected, and no echo of the offending
        /// string, which the registrar keeps escaped in its own audit
        /// record.
        ServiceLabelInvalid,
    }

    /// Why the registrar is unavailable, carried by
    /// [`NodeEnrollError::RegistrarUnavailable`].
    ///
    /// # Wire compatibility
    ///
    /// This is an ordinary bincode enum: it is encoded as its
    /// declaration index, so any later variant must be **appended**
    /// at the end, and a value this build does not recognize is a
    /// **decode error**.  Unlike [`Lifecycle`], it has no tolerant
    /// fallback variant — the reason set is fixed by the registrar
    /// contract, so a reason this build has never heard of is a
    /// protocol violation the manager must see rather than a value it
    /// silently accepts.
    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum RegistrarUnavailableReason {
        /// The registrar's client certificate has lapsed or was
        /// rejected by the endpoint.
        CredentialInvalid,
        /// The rendered file carrying the safe-set, the multiplicity
        /// map and the domain is missing or unreadable.
        NotProvisioned,
        /// The audit intent record could not be written, so the verb
        /// refused before creating anything.
        AuditUnwritable,
        /// The identity-store daemon endpoint is down or not
        /// listening.
        EndpointUnreachable,
        /// The outcome audit record could not be written **after** a
        /// successful mint.
        ///
        /// This is the one reason that leaves the identity created, so
        /// a compensating
        /// [`Deregister`](NodeEnrollRequest::Deregister) is still
        /// owed; see
        /// [`NodeEnrollError::leaves_teardown_owed`].
        PostMintUnrecordable,
        /// The manager could not reach the registrar agent at all.
        ///
        /// Every other reason is a *response*, so this one is
        /// synthesized by the manager when the registrar agent is not
        /// connected and there is nothing to respond.
        RegistrarUnreachable,
    }

    impl NodeEnrollError {
        /// Returns the delay to honour before re-driving the request if
        /// this failure is transient, or `None` if it must never be
        /// retried.
        ///
        /// The delay comes back from the same call as the yes/no answer,
        /// so a caller cannot discover that a failure is retryable and
        /// then have to guess the interval.
        ///
        /// # Examples
        ///
        /// ```
        /// use std::time::Duration;
        ///
        /// use review_protocol::types::node::NodeEnrollError;
        ///
        /// let err = NodeEnrollError::RegistrarBusy {
        ///     retry_after: Duration::from_secs(30),
        /// };
        /// assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
        ///
        /// let err = NodeEnrollError::ServiceLabelInvalid;
        /// assert_eq!(err.retry_after(), None);
        /// ```
        #[must_use]
        pub fn retry_after(&self) -> Option<Duration> {
            match self {
                Self::RegistrarBusy { retry_after } => Some(*retry_after),
                // Listed explicitly rather than caught by `_`, so a future
                // retryable variant fails the build instead of silently
                // reading as `None`.
                Self::ServiceSpecConflict
                | Self::ServiceNameCollision
                | Self::ServiceInstanceMismatch
                | Self::ServiceHostMismatch
                | Self::RegistrarUnavailable { .. }
                | Self::ServiceLabelInvalid => None,
            }
        }

        /// Returns whether this failure left a registrar identity
        /// created, so a compensating
        /// [`Deregister`](NodeEnrollRequest::Deregister) is still owed.
        ///
        /// # Examples
        ///
        /// ```
        /// use review_protocol::types::node::{NodeEnrollError, RegistrarUnavailableReason};
        ///
        /// let err = NodeEnrollError::RegistrarUnavailable {
        ///     reason: RegistrarUnavailableReason::PostMintUnrecordable,
        /// };
        /// assert!(err.leaves_teardown_owed());
        ///
        /// // Every other reason failed before anything was created.
        /// let err = NodeEnrollError::RegistrarUnavailable {
        ///     reason: RegistrarUnavailableReason::AuditUnwritable,
        /// };
        /// assert!(!err.leaves_teardown_owed());
        /// assert!(!NodeEnrollError::ServiceLabelInvalid.leaves_teardown_owed());
        /// ```
        #[must_use]
        pub fn leaves_teardown_owed(&self) -> bool {
            match self {
                Self::RegistrarUnavailable { reason } => match reason {
                    RegistrarUnavailableReason::PostMintUnrecordable => true,
                    // Listed explicitly rather than caught by `_`, so a
                    // future reason fails the build instead of silently
                    // reading as `false`.
                    RegistrarUnavailableReason::CredentialInvalid
                    | RegistrarUnavailableReason::NotProvisioned
                    | RegistrarUnavailableReason::AuditUnwritable
                    | RegistrarUnavailableReason::EndpointUnreachable
                    | RegistrarUnavailableReason::RegistrarUnreachable => false,
                },
                // Listed explicitly rather than caught by `_`, so a future
                // variant fails the build instead of silently reading as
                // `false`.
                Self::ServiceSpecConflict
                | Self::ServiceNameCollision
                | Self::ServiceInstanceMismatch
                | Self::ServiceHostMismatch
                | Self::RegistrarBusy { .. }
                | Self::ServiceLabelInvalid => false,
            }
        }
    }

    impl NodeEnrollResponse {
        /// Returns the delay to honour before re-driving the request if
        /// this outcome is a transient failure, or `None` otherwise.
        ///
        /// A success reports `None`, and so does every non-retryable
        /// failure reached through [`Failed`](Self::Failed), so a
        /// manager classifies the value it actually received in one
        /// call.
        ///
        /// # Examples
        ///
        /// ```
        /// use std::time::Duration;
        ///
        /// use review_protocol::types::node::{NodeEnrollError, NodeEnrollResponse};
        ///
        /// let resp = NodeEnrollResponse::Failed(NodeEnrollError::RegistrarBusy {
        ///     retry_after: Duration::from_secs(5),
        /// });
        /// assert_eq!(resp.retry_after(), Some(Duration::from_secs(5)));
        ///
        /// assert_eq!(NodeEnrollResponse::Done.retry_after(), None);
        /// let resp = NodeEnrollResponse::Failed(NodeEnrollError::ServiceNameCollision);
        /// assert_eq!(resp.retry_after(), None);
        /// ```
        #[must_use]
        pub fn retry_after(&self) -> Option<Duration> {
            match self {
                Self::Failed(err) => err.retry_after(),
                // Listed explicitly rather than caught by `_`, so a future
                // variant fails the build instead of silently reading as
                // `None`.
                Self::Material(_) | Self::Done => None,
            }
        }

        /// Returns whether this outcome left a registrar identity
        /// created without the caller being told so, leaving a
        /// compensating [`Deregister`](NodeEnrollRequest::Deregister)
        /// owed.
        ///
        /// # Examples
        ///
        /// ```
        /// use review_protocol::types::node::{
        ///     NodeEnrollError, NodeEnrollResponse, RegistrarUnavailableReason,
        /// };
        ///
        /// let resp = NodeEnrollResponse::Failed(NodeEnrollError::RegistrarUnavailable {
        ///     reason: RegistrarUnavailableReason::PostMintUnrecordable,
        /// });
        /// assert!(resp.leaves_teardown_owed());
        ///
        /// assert!(!NodeEnrollResponse::Done.leaves_teardown_owed());
        /// ```
        #[must_use]
        pub fn leaves_teardown_owed(&self) -> bool {
            match self {
                Self::Failed(err) => err.leaves_teardown_owed(),
                // Listed explicitly rather than caught by `_`, so a future
                // variant fails the build instead of silently reading as
                // `false`.
                Self::Material(_) | Self::Done => false,
            }
        }
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

            let resp = NodeTimeSyncResponse::Status {
                enabled: true,
                synchronized: true,
                server: Some("cm.example.com".into()),
                offset_micros: Some(-1_234),
            };
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeTimeSyncResponse::Status {
                enabled: false,
                synchronized: false,
                server: None,
                offset_micros: None,
            };
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

        /// Helper: bincode encoding under the crate's configuration.
        fn encode<T: Serialize>(value: &T) -> Vec<u8> {
            bincode::serde::encode_to_vec(
                value,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .expect("serialization should succeed")
        }

        /// Helper: decode from raw bytes, returning the bincode error
        /// so that a test can assert a decode succeeds.
        fn decode<T: serde::de::DeserializeOwned>(
            bytes: &[u8],
        ) -> Result<T, bincode::error::DecodeError> {
            bincode::serde::decode_from_slice(
                bytes,
                bincode::config::standard().with_fixed_int_encoding(),
            )
            .map(|(value, _)| value)
        }

        /// Helper: the enum variant index bincode wrote at the front
        /// of an encoded enum value.
        fn variant_index(bytes: &[u8]) -> u32 {
            let head: [u8; 4] = bytes
                .get(..4)
                .expect("an encoded enum starts with a 4-byte variant index")
                .try_into()
                .expect("slice of length 4 converts to [u8; 4]");
            u32::from_le_bytes(head)
        }

        /// A marker inside the artifact that must never reach a
        /// `Debug` rendering.
        const ARTIFACT_MARKER: &str = "svc-7f2a";

        /// Helper: bootstrap artifact bytes that are not valid UTF-8,
        /// so that a round trip proves the member is carried as opaque
        /// bytes rather than as text.
        fn bootstrap_artifact() -> Vec<u8> {
            let mut artifact =
                format!("{{\"registration_id\":\"{ARTIFACT_MARKER}\"}}").into_bytes();
            artifact.extend_from_slice(&[0xff, 0xfe, 0x00, 0xc3, 0x28]);
            assert!(std::str::from_utf8(&artifact).is_err());
            artifact
        }

        /// Helper: a `BootstrapMaterial` with a fixed, sub-second
        /// deadline.
        fn bootstrap_material() -> BootstrapMaterial {
            BootstrapMaterial {
                role_id: "sensor-installer".into(),
                wrapped_secret_id: "s.9f3c1b".into(),
                ca_anchor: vec![0x30, 0x82, 0x01, 0x0a],
                expires_at: "2026-01-02T03:04:05.123456789Z"
                    .parse()
                    .expect("literal is a valid timestamp"),
                bootstrap_artifact: bootstrap_artifact(),
            }
        }

        /// Helper: a `PackageState` with the given lifecycle and
        /// bound addresses.
        fn package_state(lifecycle: Lifecycle, bound_addrs: Vec<BoundAddr>) -> PackageState {
            PackageState {
                version: "1.2.3".into(),
                commit: "0123456789abcdef".into(),
                lifecycle,
                bound_addrs,
                privilege_profile: None,
            }
        }

        #[test]
        fn serde_roundtrip_node_package_request() {
            for instance in [None, Some(7)] {
                for material in [None, Some(bootstrap_material())] {
                    for on_failure in [FailurePolicy::Rollback, FailurePolicy::Hold] {
                        let req = NodePackageRequest::Install {
                            target: "sensor".into(),
                            instance,
                            version: "1.2.3".into(),
                            commit: "0123456789abcdef".into(),
                            size: 4_194_304,
                            idempotency_key: "b6f0".into(),
                            bootstrap_material: material.clone(),
                            on_failure,
                            bind_addrs: None,
                            config_template: Some("reconverge-baseline".into()),
                            privilege_profile: None,
                        };
                        assert_eq!(req, roundtrip(&req));
                    }
                }

                let req = NodePackageRequest::Remove {
                    target: "sensor".into(),
                    instance,
                    idempotency_key: "b6f0".into(),
                };
                assert_eq!(req, roundtrip(&req));

                let req = NodePackageRequest::Status {
                    target: "sensor".into(),
                    instance,
                };
                assert_eq!(req, roundtrip(&req));
            }

            let req = NodePackageRequest::ListInstalled;
            assert_eq!(req, roundtrip(&req));

            let req = NodePackageRequest::ListHostPorts;
            assert_eq!(req, roundtrip(&req));
        }

        /// Helper: an `Install` carrying `bind_addrs`, with every
        /// other field fixed.
        fn install_with_bind_addrs(
            bind_addrs: Option<BTreeMap<String, SocketAddr>>,
        ) -> NodePackageRequest {
            install_with_config_template(bind_addrs, None, None)
        }

        /// Helper: an `Install` carrying both configuration inputs and
        /// the privilege profile.
        fn install_with_config_template(
            bind_addrs: Option<BTreeMap<String, SocketAddr>>,
            config_template: Option<String>,
            privilege_profile: Option<String>,
        ) -> NodePackageRequest {
            NodePackageRequest::Install {
                target: "giganto".into(),
                instance: Some(1),
                version: "1.2.3".into(),
                commit: "0123456789abcdef".into(),
                size: 4_194_304,
                idempotency_key: "b6f0".into(),
                bootstrap_material: None,
                on_failure: FailurePolicy::Rollback,
                bind_addrs,
                config_template,
                privilege_profile,
            }
        }

        /// Helper: the `bind_addrs` map of an `Install`.
        fn bind_addrs_of(req: &NodePackageRequest) -> Option<&BTreeMap<String, SocketAddr>> {
            let NodePackageRequest::Install { bind_addrs, .. } = req else {
                panic!("expected an install");
            };
            bind_addrs.as_ref()
        }

        /// `bind_addrs` survives the wire both ways, and the map's
        /// contents survive unchanged: this crate carries what the
        /// manager assigned and validates none of it.
        #[test]
        fn node_package_install_bind_addrs_roundtrip() {
            // Absent: the shape a component that binds nothing takes.
            let req = install_with_bind_addrs(None);
            let decoded = roundtrip(&req);
            assert_eq!(req, decoded);
            assert_eq!(bind_addrs_of(&decoded), None);

            // An empty map is distinct from `None` and stays so.
            let req = install_with_bind_addrs(Some(BTreeMap::new()));
            let decoded = roundtrip(&req);
            assert_eq!(req, decoded);
            assert_eq!(bind_addrs_of(&decoded), Some(&BTreeMap::new()));

            // Two keys whose ports differ: what the conflict model
            // permits, and what a component with two listeners
            // actually gets.
            let distinct = BTreeMap::from([
                (
                    "graphql_srv_addr".to_string(),
                    "0.0.0.0:8442".parse::<SocketAddr>().expect("valid"),
                ),
                (
                    "ingest_srv_addr".to_string(),
                    "0.0.0.0:38370".parse::<SocketAddr>().expect("valid"),
                ),
            ]);
            let req = install_with_bind_addrs(Some(distinct.clone()));
            let decoded = roundtrip(&req);
            assert_eq!(req, decoded);
            assert_eq!(bind_addrs_of(&decoded), Some(&distinct));

            // Two keys on the SAME `SocketAddr`. Legal on the wire and
            // refused by the manager, not here: this crate carries the
            // map and neither rejects nor collapses it.
            let same = BTreeMap::from([
                (
                    "graphql_srv_addr".to_string(),
                    "0.0.0.0:8442".parse::<SocketAddr>().expect("valid"),
                ),
                (
                    "publish_srv_addr".to_string(),
                    "0.0.0.0:8442".parse::<SocketAddr>().expect("valid"),
                ),
            ]);
            let req = install_with_bind_addrs(Some(same.clone()));
            let decoded = roundtrip(&req);
            assert_eq!(req, decoded);
            let decoded_map = bind_addrs_of(&decoded).expect("the map survives");
            assert_eq!(decoded_map, &same);
            assert_eq!(decoded_map.len(), 2, "neither key is collapsed into one");

            // The address itself is carried verbatim, IPv6 and a
            // specific IPv4 address included: nothing here rewrites
            // an address into a wildcard or back.
            let verbatim = BTreeMap::from([
                (
                    "graphql_srv_addr".to_string(),
                    "[::1]:8442".parse::<SocketAddr>().expect("valid"),
                ),
                (
                    "ingest_srv_addr".to_string(),
                    "10.1.2.3:38370".parse::<SocketAddr>().expect("valid"),
                ),
            ]);
            let req = install_with_bind_addrs(Some(verbatim.clone()));
            let decoded = roundtrip(&req);
            assert_eq!(req, decoded);
            assert_eq!(bind_addrs_of(&decoded), Some(&verbatim));
        }

        /// The template id is carried verbatim, including an empty id,
        /// and may coexist with bind addresses on the wire.
        #[test]
        fn node_package_install_config_template_roundtrip() {
            for config_template in [
                None,
                Some("reconverge-baseline".into()),
                Some(String::new()),
            ] {
                for bind_addrs in [
                    None,
                    Some(BTreeMap::from([(
                        "graphql_srv_addr".to_string(),
                        "0.0.0.0:8442".parse::<SocketAddr>().expect("valid"),
                    )])),
                ] {
                    let req =
                        install_with_config_template(bind_addrs, config_template.clone(), None);
                    let decoded = roundtrip(&req);
                    assert_eq!(req, decoded);
                    let NodePackageRequest::Install {
                        config_template: decoded_id,
                        ..
                    } = decoded
                    else {
                        panic!("expected an install");
                    };
                    assert_eq!(decoded_id, config_template);
                }
            }
        }

        /// The privilege profile is carried verbatim, including an
        /// empty, miscased or unknown name, and may coexist with a
        /// template id on the wire.
        #[test]
        fn node_package_install_privilege_profile_roundtrip() {
            for privilege_profile in [
                None,
                Some("dpdk".to_string()),
                Some(String::new()),
                Some("Root".to_string()),
                Some("no-such-profile".to_string()),
            ] {
                for config_template in [None, Some("reconverge-baseline".to_string())] {
                    let req = install_with_config_template(
                        None,
                        config_template.clone(),
                        privilege_profile.clone(),
                    );
                    let decoded = roundtrip(&req);
                    assert_eq!(req, decoded);
                    let NodePackageRequest::Install {
                        config_template: decoded_id,
                        privilege_profile: decoded_profile,
                        ..
                    } = decoded
                    else {
                        panic!("expected an install");
                    };
                    assert_eq!(decoded_id, config_template);
                    assert_eq!(decoded_profile, privilege_profile);
                }
            }
        }

        /// Field POSITION is the wire contract just as variant order
        /// is, so `privilege_profile` has to be the tail field of
        /// `Install`, after `config_template`, which follows
        /// `bind_addrs`.
        ///
        /// Reordering fields or inserting a later one ahead of
        /// `privilege_profile` changes the wire encoding and breaks this
        /// test.
        #[test]
        fn node_package_install_field_order_is_pinned() {
            let bind_addrs = BTreeMap::from([(
                "graphql_srv_addr".to_string(),
                "0.0.0.0:8442".parse::<SocketAddr>().expect("valid"),
            )]);

            let id = "reconverge-baseline".to_string();

            // The variant index, then every field in declaration
            // order, each encoded on its own.  bincode writes exactly
            // this concatenation.
            let expected = [
                encode(&0_u32),
                encode(&"giganto".to_string()),
                encode(&Some(1_u32)),
                encode(&"1.2.3".to_string()),
                encode(&"0123456789abcdef".to_string()),
                encode(&4_194_304_u64),
                encode(&"b6f0".to_string()),
                encode(&Option::<BootstrapMaterial>::None),
                encode(&FailurePolicy::Rollback),
                encode(&Some(bind_addrs.clone())),
                encode(&Some(id.clone())),
                encode(&Some("af-packet".to_string())),
            ]
            .concat();
            assert_eq!(
                encode(&install_with_config_template(
                    Some(bind_addrs),
                    Some(id),
                    Some("af-packet".into())
                )),
                expected,
                "`privilege_profile` is the tail field, after `config_template`"
            );
        }

        /// Widening the accepted instance range later needs no wire
        /// change: distinct instances differ only in payload.
        #[test]
        fn node_package_install_instance_is_payload_only() {
            let install = |instance| NodePackageRequest::Install {
                target: "sensor".into(),
                instance: Some(instance),
                version: "1.2.3".into(),
                commit: "0123456789abcdef".into(),
                size: 4_194_304,
                idempotency_key: "b6f0".into(),
                bootstrap_material: None,
                on_failure: FailurePolicy::Rollback,
                bind_addrs: None,
                config_template: None,
                privilege_profile: None,
            };

            let one = install(1);
            let two = install(2);
            assert_eq!(one, roundtrip(&one));
            assert_eq!(two, roundtrip(&two));

            let (encoded_one, encoded_two) = (encode(&one), encode(&two));
            assert_eq!(
                encoded_one.len(),
                encoded_two.len(),
                "instance value must not change the encoded shape"
            );
            assert_ne!(encoded_one, encoded_two);
        }

        #[test]
        fn serde_roundtrip_install_preflight() {
            let preflight = InstallPreflight::Proceed;
            assert_eq!(preflight, roundtrip(&preflight));

            let preflight = InstallPreflight::AlreadyApplied;
            assert_eq!(preflight, roundtrip(&preflight));

            let preflight = InstallPreflight::InsufficientDiskSpace {
                filesystem: "/var".into(),
                required: 8_388_608,
                available: 1_048_576,
            };
            assert_eq!(preflight, roundtrip(&preflight));

            for preflight in [
                InstallPreflight::BindAddrsOnUpdate,
                InstallPreflight::NamespaceUnconfigured,
                InstallPreflight::EnrollmentUnsupported,
                InstallPreflight::ConfigTemplateOnUpdate,
                InstallPreflight::UnknownConfigTemplate {
                    id: "no-such-template".into(),
                },
                InstallPreflight::UnknownConfigTemplate { id: String::new() },
            ] {
                assert_eq!(preflight, roundtrip(&preflight));
            }
        }

        /// Declaration order is the wire order: a later insertion,
        /// rather than an append, breaks this test.
        #[test]
        fn install_preflight_variant_order_is_pinned() {
            assert_eq!(variant_index(&encode(&InstallPreflight::Proceed)), 0);
            assert_eq!(variant_index(&encode(&InstallPreflight::AlreadyApplied)), 1);
            assert_eq!(
                variant_index(&encode(&InstallPreflight::InsufficientDiskSpace {
                    filesystem: "/var".into(),
                    required: 8_388_608,
                    available: 1_048_576,
                })),
                2
            );
            assert_eq!(
                variant_index(&encode(&InstallPreflight::BindAddrsOnUpdate)),
                3
            );
            assert_eq!(
                variant_index(&encode(&InstallPreflight::NamespaceUnconfigured)),
                4
            );
            assert_eq!(
                variant_index(&encode(&InstallPreflight::EnrollmentUnsupported)),
                5
            );
            assert_eq!(
                variant_index(&encode(&InstallPreflight::ConfigTemplateOnUpdate)),
                6
            );
            assert_eq!(
                variant_index(&encode(&InstallPreflight::UnknownConfigTemplate {
                    id: "no-such-template".into(),
                })),
                7
            );
        }

        /// Declaration order is the wire order for the request too.
        #[test]
        fn node_package_request_variant_order_is_pinned() {
            assert_eq!(variant_index(&encode(&install_with_bind_addrs(None))), 0);
            assert_eq!(
                variant_index(&encode(&NodePackageRequest::Remove {
                    target: "sensor".into(),
                    instance: Some(1),
                    idempotency_key: "b6f0".into(),
                })),
                1
            );
            assert_eq!(
                variant_index(&encode(&NodePackageRequest::ListInstalled)),
                2
            );
            assert_eq!(
                variant_index(&encode(&NodePackageRequest::Status {
                    target: "sensor".into(),
                    instance: Some(1),
                })),
                3
            );
            assert_eq!(
                variant_index(&encode(&NodePackageRequest::ListHostPorts)),
                4
            );
        }

        #[test]
        fn serde_roundtrip_node_package_response() {
            let resp = NodePackageResponse::Done;
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodePackageResponse::Accepted;
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodePackageResponse::Installed(vec![InstalledPackage {
                target: "sensor".into(),
                instance: Some(1),
                state: package_state(
                    Lifecycle::Running,
                    vec![BoundAddr {
                        name: "ingest_address".into(),
                        addr: "0.0.0.0:38370".into(),
                    }],
                ),
            }]);
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodePackageResponse::Installed(Vec::new());
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodePackageResponse::State(package_state(Lifecycle::Stopped, Vec::new()));
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodePackageResponse::Failed(NodePackageError::MissingBootstrapMaterial);
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodePackageResponse::HostPorts(Vec::new());
            assert_eq!(resp, roundtrip(&resp));
        }

        /// Field POSITION is the wire contract, so `privilege_profile`
        /// has to be the tail field of `PackageState`, after
        /// `bound_addrs`, and both its values survive the wire alone and
        /// inside every response that carries a `PackageState`.
        ///
        /// Reordering fields or inserting a later one ahead of
        /// `privilege_profile` changes the wire encoding and breaks this
        /// test.
        #[test]
        fn package_state_field_order_is_pinned() {
            let bound_addrs = vec![BoundAddr {
                name: "ingest_address".into(),
                addr: "0.0.0.0:38370".into(),
            }];
            let state = PackageState {
                privilege_profile: Some("replay".into()),
                ..package_state(Lifecycle::Running, bound_addrs.clone())
            };

            let expected = [
                encode(&"1.2.3".to_string()),
                encode(&"0123456789abcdef".to_string()),
                encode(&Lifecycle::Running),
                encode(&bound_addrs),
                encode(&Some("replay".to_string())),
            ]
            .concat();
            assert_eq!(
                encode(&state),
                expected,
                "`privilege_profile` is the tail field, after `bound_addrs`"
            );

            for privilege_profile in [None, Some("replay".to_string())] {
                let state = PackageState {
                    privilege_profile: privilege_profile.clone(),
                    ..package_state(Lifecycle::Running, bound_addrs.clone())
                };
                let decoded = roundtrip(&state);
                assert_eq!(state, decoded);
                assert_eq!(decoded.privilege_profile, privilege_profile);

                let resp = NodePackageResponse::State(state.clone());
                assert_eq!(resp, roundtrip(&resp));

                let resp = NodePackageResponse::Installed(vec![
                    InstalledPackage {
                        target: "sensor".into(),
                        instance: Some(1),
                        state: state.clone(),
                    },
                    InstalledPackage {
                        target: "sensor".into(),
                        instance: Some(2),
                        state,
                    },
                ]);
                assert_eq!(resp, roundtrip(&resp));
            }
        }

        #[test]
        fn serde_roundtrip_node_package_payload_types() {
            let addr = BoundAddr {
                name: "ingest_address".into(),
                addr: "0.0.0.0:38370".into(),
            };
            assert_eq!(addr, roundtrip(&addr));

            // `bound_addrs` survives both empty and populated.
            let state = package_state(Lifecycle::Running, Vec::new());
            assert_eq!(state, roundtrip(&state));

            let state = package_state(
                Lifecycle::Running,
                vec![
                    addr.clone(),
                    BoundAddr {
                        name: "publish_address".into(),
                        addr: "0.0.0.0:38371".into(),
                    },
                ],
            );
            let decoded = roundtrip(&state);
            assert_eq!(state, decoded);
            assert_eq!(
                decoded
                    .bound_addrs
                    .iter()
                    .find(|a| a.name == "publish_address")
                    .map(|a| a.addr.as_str()),
                Some("0.0.0.0:38371"),
                "an address is found by name, not by position"
            );

            let installed = InstalledPackage {
                target: "sensor".into(),
                instance: None,
                state,
            };
            assert_eq!(installed, roundtrip(&installed));

            let material = bootstrap_material();
            assert_eq!(material, roundtrip(&material));

            let identity = PackageIdentity {
                target: "sensor".into(),
                version: "1.2.3".into(),
                commit: "0123456789abcdef".into(),
            };
            assert_eq!(identity, roundtrip(&identity));
        }

        /// `expires_at` keeps nanosecond precision across the wire.
        #[test]
        fn bootstrap_material_subsecond_precision_survives() {
            let material = bootstrap_material();
            let decoded = roundtrip(&material);
            assert_eq!(material, decoded);
            assert_eq!(
                decoded.expires_at.as_nanosecond(),
                material.expires_at.as_nanosecond()
            );
            assert_eq!(decoded.expires_at.subsec_nanosecond(), 123_456_789);
        }

        /// The bootstrap artifact is opaque bytes: a value that is not
        /// UTF-8 survives the wire byte for byte.
        #[test]
        fn bootstrap_material_artifact_survives_byte_identical() {
            let material = bootstrap_material();
            let decoded = roundtrip(&material);
            assert_eq!(decoded.bootstrap_artifact, bootstrap_artifact());
            assert_eq!(encode(&decoded), encode(&material));
        }

        /// A payload that omits the artifact is refused, not decoded
        /// as a present-but-empty one.
        #[test]
        fn bootstrap_material_without_artifact_is_refused() {
            let material = bootstrap_material();
            let without_artifact = [
                encode(&material.role_id),
                encode(&material.wrapped_secret_id),
                encode(&material.ca_anchor),
                encode(&material.expires_at.as_nanosecond()),
            ]
            .concat();
            let with_artifact = [
                without_artifact.clone(),
                encode(&material.bootstrap_artifact),
            ]
            .concat();
            assert_eq!(
                encode(&material),
                with_artifact,
                "`bootstrap_artifact` is the tail field, after `expires_at`"
            );

            assert!(decode::<BootstrapMaterial>(&without_artifact).is_err());
        }

        /// Neither the wrapped credential nor the bootstrap artifact
        /// that accompanies it reaches a log through a `Debug` of the
        /// material or of the request carrying it.
        #[test]
        fn bootstrap_material_debug_redacts_the_wrapped_secret() {
            let artifact = bootstrap_artifact();
            let assert_redacted = |rendered: &str| {
                assert!(!rendered.contains("s.9f3c1b"), "{rendered}");
                assert!(!rendered.contains(ARTIFACT_MARKER), "{rendered}");
                assert!(!rendered.contains("registration_id"), "{rendered}");
                assert!(
                    !rendered.contains(&String::from_utf8_lossy(&artifact).into_owned()),
                    "{rendered}"
                );
                assert!(!rendered.contains(&format!("{artifact:?}")), "{rendered}");
            };

            let material = bootstrap_material();
            let rendered = format!("{material:?}");
            assert_redacted(&rendered);
            assert!(rendered.contains("<redacted>"), "{rendered}");
            assert!(rendered.contains("sensor-installer"), "{rendered}");
            assert!(rendered.contains("bootstrap_artifact"), "{rendered}");

            let req = NodePackageRequest::Install {
                target: "sensor".into(),
                instance: Some(1),
                version: "1.2.3".into(),
                commit: "0123456789abcdef".into(),
                size: 4_194_304,
                idempotency_key: "b6f0".into(),
                bootstrap_material: Some(material),
                on_failure: FailurePolicy::Rollback,
                bind_addrs: None,
                config_template: None,
                privilege_profile: None,
            };
            let rendered = format!("{req:?}");
            assert_redacted(&rendered);
            assert!(rendered.contains("<redacted>"), "{rendered}");
        }

        /// The wire bytes of a `BootstrapMaterial`, under the
        /// configuration the wire uses (`bincode::config::standard()`),
        /// are pinned, so that a `jiff` upgrade cannot change how
        /// `expires_at` is encoded.
        #[test]
        fn bootstrap_material_wire_bytes_are_pinned() {
            const EXPECTED: &[u8] = &[
                0x10, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x2d, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6c,
                0x6c, 0x65, 0x72, 0x08, 0x73, 0x2e, 0x39, 0x66, 0x33, 0x63, 0x31, 0x62, 0x04, 0x30,
                0x82, 0x01, 0x0a, 0xfd, 0x2a, 0xfe, 0xe3, 0x47, 0xe4, 0x95, 0x0d, 0x31, 0x23, 0x7b,
                0x22, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f,
                0x69, 0x64, 0x22, 0x3a, 0x22, 0x73, 0x76, 0x63, 0x2d, 0x37, 0x66, 0x32, 0x61, 0x22,
                0x7d, 0xff, 0xfe, 0x00, 0xc3, 0x28,
            ];

            let material = bootstrap_material();
            let bytes = bincode::serde::encode_to_vec(&material, bincode::config::standard())
                .expect("serialization should succeed");
            assert_eq!(bytes, EXPECTED, "{bytes:?}");

            let (decoded, read): (BootstrapMaterial, usize) =
                bincode::serde::decode_from_slice(EXPECTED, bincode::config::standard())
                    .expect("deserialization should succeed");
            assert_eq!(read, EXPECTED.len());
            assert_eq!(decoded.expires_at, material.expires_at);
            assert_eq!(decoded, material);
        }

        /// The `Debug` text of a `BootstrapMaterial`, including the
        /// rendering of its sub-second `expires_at`, is pinned.
        #[test]
        fn bootstrap_material_debug_is_pinned() {
            const EXPECTED: &str = "BootstrapMaterial { role_id: \"sensor-installer\", wrapped_secret_id: \"<redacted>\", ca_anchor: [48, 130, 1, 10], expires_at: 2026-01-02T03:04:05.123456789Z, bootstrap_artifact: \"<redacted>\" }";

            let rendered = format!("{:?}", bootstrap_material());
            assert_eq!(rendered, EXPECTED);
        }

        #[test]
        fn serde_roundtrip_node_package_error() {
            let identities = || {
                (
                    PackageIdentity {
                        target: "sensor".into(),
                        version: "1.2.3".into(),
                        commit: "0123456789abcdef".into(),
                    },
                    PackageIdentity {
                        target: "collector".into(),
                        version: "9.8.7".into(),
                        commit: "fedcba9876543210".into(),
                    },
                )
            };
            let (expected, found) = identities();
            let err = NodePackageError::TargetMismatch { expected, found };
            assert_eq!(err, roundtrip(&err));

            let err = NodePackageError::MissingBootstrapMaterial;
            assert_eq!(err, roundtrip(&err));

            let err = NodePackageError::BootstrapMaterialExpired;
            assert_eq!(err, roundtrip(&err));

            let err = NodePackageError::InsufficientDiskSpace {
                filesystem: "/var".into(),
                required: 8_388_608,
                available: 1_048_576,
            };
            assert_eq!(err, roundtrip(&err));

            let err = NodePackageError::StaleTrustSet { active_epoch: 43 };
            assert_eq!(err, roundtrip(&err));

            let err = NodePackageError::UnsupportedManifestFormat {
                active_epoch: 43,
                supported: ManifestFormatRange { min: 1, max: 3 },
            };
            assert_eq!(err, roundtrip(&err));

            for err in [
                NodePackageError::ObservationUnavailable,
                NodePackageError::UnmanagedInstancePresent,
                NodePackageError::UndeclaredPrivilegeProfile {
                    profile: "Root".into(),
                    declared: Vec::new(),
                },
                NodePackageError::UndeclaredPrivilegeProfile {
                    profile: String::new(),
                    declared: vec!["root".into(), "replay".into()],
                },
                NodePackageError::UnexpectedPrivilegeProfile {
                    profile: "dpdk".into(),
                },
                NodePackageError::MissingPrivilegeProfile,
                NodePackageError::AppliedButUnhealthy {
                    disposition: UnhealthyDisposition::RolledBack,
                    cause: "piglet.service failed to start".into(),
                },
                NodePackageError::AppliedButUnhealthy {
                    disposition: UnhealthyDisposition::Held,
                    cause: "health gate timed out after 60s".into(),
                },
                NodePackageError::AppliedButUnhealthy {
                    disposition: UnhealthyDisposition::Unwound,
                    cause: "apply did not complete".into(),
                },
                NodePackageError::AppliedButUnhealthy {
                    disposition: UnhealthyDisposition::NotReversed,
                    cause: String::new(),
                },
            ] {
                assert_eq!(err.active_trust_epoch(), None);
                assert_eq!(err, roundtrip(&err));
                // Each travels in the same success-shaped frame as any
                // other apply failure, and reports no trust epoch.
                let resp = NodePackageResponse::Failed(err.clone());
                assert_eq!(resp, roundtrip(&resp));
                assert_eq!(resp.active_trust_epoch(), None);
            }
        }

        /// Every apply error that predates the reserved `"trust"` target, one
        /// of each variant, for checking the new outcomes against all of them.
        fn pre_existing_apply_errors() -> [NodePackageError; 4] {
            [
                NodePackageError::TargetMismatch {
                    expected: PackageIdentity {
                        target: "sensor".into(),
                        version: "1.2.3".into(),
                        commit: "0123456789abcdef".into(),
                    },
                    found: PackageIdentity {
                        target: "collector".into(),
                        version: "9.8.7".into(),
                        commit: "fedcba9876543210".into(),
                    },
                },
                NodePackageError::MissingBootstrapMaterial,
                NodePackageError::BootstrapMaterialExpired,
                NodePackageError::InsufficientDiskSpace {
                    filesystem: "/var".into(),
                    required: 8_388_608,
                    available: 1_048_576,
                },
            ]
        }

        /// The three outcomes of a reserved `"trust"` target apply survive
        /// the wire, and the two apply errors are told apart from each other
        /// and from every pre-existing apply error by pattern-matching.
        #[test]
        fn serde_roundtrip_trust_outcomes() {
            let resp = NodePackageResponse::TrustActive { active_epoch: 43 };
            assert_eq!(resp, roundtrip(&resp));

            let stale =
                NodePackageResponse::Failed(NodePackageError::StaleTrustSet { active_epoch: 42 });
            let decoded_stale = roundtrip(&stale);
            assert_eq!(stale, decoded_stale);

            // `min` and `max` differ, so a decode that collapsed or swapped
            // them would not survive.
            let unsupported =
                NodePackageResponse::Failed(NodePackageError::UnsupportedManifestFormat {
                    active_epoch: 42,
                    supported: ManifestFormatRange { min: 1, max: 3 },
                });
            let decoded_unsupported = roundtrip(&unsupported);
            assert_eq!(unsupported, decoded_unsupported);

            let NodePackageResponse::Failed(NodePackageError::UnsupportedManifestFormat {
                supported,
                ..
            }) = &decoded_unsupported
            else {
                panic!("expected an UnsupportedManifestFormat failure");
            };
            assert_eq!(supported.min, 1);
            assert_eq!(supported.max, 3);

            // The two trust errors are distinguishable from each other …
            assert!(matches!(
                decoded_stale,
                NodePackageResponse::Failed(NodePackageError::StaleTrustSet { .. })
            ));
            assert!(!matches!(
                decoded_stale,
                NodePackageResponse::Failed(NodePackageError::UnsupportedManifestFormat { .. })
            ));
            assert!(!matches!(
                decoded_unsupported,
                NodePackageResponse::Failed(NodePackageError::StaleTrustSet { .. })
            ));

            // … and from every pre-existing apply error.
            for err in pre_existing_apply_errors() {
                let decoded = roundtrip(&err);
                assert_eq!(decoded, err);
                assert!(!matches!(decoded, NodePackageError::StaleTrustSet { .. }));
                assert!(!matches!(
                    decoded,
                    NodePackageError::UnsupportedManifestFormat { .. }
                ));
            }
        }

        /// A consumer computes a host's true active epoch from any one of the
        /// three trust outcomes alone, with no reference to what the manager
        /// believed it had delivered.
        #[test]
        fn active_trust_epoch_is_read_from_the_outcome_alone() {
            for resp in [
                NodePackageResponse::TrustActive { active_epoch: 43 },
                NodePackageResponse::Failed(NodePackageError::StaleTrustSet { active_epoch: 43 }),
                NodePackageResponse::Failed(NodePackageError::UnsupportedManifestFormat {
                    active_epoch: 43,
                    supported: ManifestFormatRange { min: 1, max: 3 },
                }),
            ] {
                // The reading survives the wire, so it is the agent's, not a
                // local construction.
                assert_eq!(roundtrip(&resp).active_trust_epoch(), Some(43));
            }

            // The two errors read the same directly, for a consumer holding
            // only a bare `NodePackageError` handed on from the site that
            // matched `Failed`.
            for err in [
                NodePackageError::StaleTrustSet { active_epoch: 43 },
                NodePackageError::UnsupportedManifestFormat {
                    active_epoch: 43,
                    supported: ManifestFormatRange { min: 1, max: 3 },
                },
            ] {
                assert_eq!(err.active_trust_epoch(), Some(43));
            }

            // Every non-trust outcome reports no epoch, including a `Failed`
            // carrying any one of the pre-existing apply errors.
            for resp in [
                NodePackageResponse::Done,
                NodePackageResponse::Accepted,
                NodePackageResponse::Installed(Vec::new()),
                NodePackageResponse::State(package_state(Lifecycle::Running, Vec::new())),
                NodePackageResponse::HostPorts(Vec::new()),
            ]
            .into_iter()
            .chain(pre_existing_apply_errors().map(NodePackageResponse::Failed))
            {
                assert_eq!(resp.active_trust_epoch(), None);
            }

            // Every pre-existing apply error reads the same way directly.
            for err in pre_existing_apply_errors() {
                assert_eq!(err.active_trust_epoch(), None);
            }
        }

        /// A `StaleTrustSet` whose `active_epoch` equals the delivered
        /// generation's epoch is an explicit already-at-this-epoch
        /// confirmation: the value needed to reach that conclusion travels in
        /// the response itself.
        #[test]
        fn stale_trust_set_on_equal_epoch_confirms_the_host_is_already_there() {
            const DELIVERED_EPOCH: u64 = 43;

            let resp = NodePackageResponse::Failed(NodePackageError::StaleTrustSet {
                active_epoch: DELIVERED_EPOCH,
            });
            let decoded = roundtrip(&resp);

            // The whole reading comes from the decoded response. Nothing here
            // consults what the manager believed it had delivered; the
            // constant only names the epoch the assertion compares against.
            let reported = decoded
                .active_trust_epoch()
                .expect("a StaleTrustSet response reports the agent's active epoch");
            assert_eq!(
                reported, DELIVERED_EPOCH,
                "the host is already on the delivered epoch"
            );

            // A rejection at a *higher* epoch is a different reading from the
            // same variant: the host moved past the delivered generation.
            let ahead = roundtrip(&NodePackageResponse::Failed(
                NodePackageError::StaleTrustSet {
                    active_epoch: DELIVERED_EPOCH + 1,
                },
            ));
            assert_eq!(ahead.active_trust_epoch(), Some(DELIVERED_EPOCH + 1));
        }

        /// A typed failure is reached through a *successful* decode,
        /// and the two identities of a `TargetMismatch` survive
        /// independently and unswapped.
        #[test]
        fn node_package_failed_carries_distinguishable_errors() {
            let (expected, found) = (
                PackageIdentity {
                    target: "sensor".into(),
                    version: "1.2.3".into(),
                    commit: "0123456789abcdef".into(),
                },
                PackageIdentity {
                    target: "collector".into(),
                    version: "9.8.7".into(),
                    commit: "fedcba9876543210".into(),
                },
            );
            let resp = NodePackageResponse::Failed(NodePackageError::TargetMismatch {
                expected: expected.clone(),
                found: found.clone(),
            });
            let decoded = roundtrip(&resp);
            assert_eq!(resp, decoded);

            let NodePackageResponse::Failed(NodePackageError::TargetMismatch {
                expected: decoded_expected,
                found: decoded_found,
            }) = decoded
            else {
                panic!("expected a TargetMismatch failure");
            };
            assert_eq!(decoded_expected, expected);
            assert_eq!(decoded_found, found);
            assert_ne!(decoded_expected, decoded_found);

            let disk = NodePackageResponse::Failed(NodePackageError::InsufficientDiskSpace {
                filesystem: "/var".into(),
                required: 8_388_608,
                available: 1_048_576,
            });
            let decoded_disk = roundtrip(&disk);
            assert!(matches!(
                decoded_disk,
                NodePackageResponse::Failed(NodePackageError::InsufficientDiskSpace { .. })
            ));
            assert!(!matches!(
                decoded_disk,
                NodePackageResponse::Failed(NodePackageError::TargetMismatch { .. })
            ));

            for err in [
                NodePackageError::MissingBootstrapMaterial,
                NodePackageError::BootstrapMaterialExpired,
            ] {
                let resp = NodePackageResponse::Failed(err.clone());
                assert_eq!(roundtrip(&resp), NodePackageResponse::Failed(err));
            }
        }

        /// Declaration order is the wire order: a later insertion,
        /// rather than an append, breaks this test.
        #[test]
        fn node_package_response_variant_order_is_pinned() {
            assert_eq!(variant_index(&encode(&NodePackageResponse::Done)), 0);
            assert_eq!(variant_index(&encode(&NodePackageResponse::Accepted)), 1);
            assert_eq!(
                variant_index(&encode(&NodePackageResponse::Installed(Vec::new()))),
                2
            );
            assert_eq!(
                variant_index(&encode(&NodePackageResponse::State(package_state(
                    Lifecycle::Running,
                    Vec::new()
                )))),
                3
            );
            assert_eq!(
                variant_index(&encode(&NodePackageResponse::Failed(
                    NodePackageError::MissingBootstrapMaterial
                ))),
                4
            );
            assert_eq!(
                variant_index(&encode(&NodePackageResponse::TrustActive {
                    active_epoch: 43
                })),
                5
            );
            assert_eq!(
                variant_index(&encode(&NodePackageResponse::HostPorts(Vec::new()))),
                6
            );
        }

        /// Declaration order is the wire order for the transport too.
        #[test]
        fn transport_variant_order_is_pinned() {
            assert_eq!(variant_index(&encode(&Transport::Tcp)), 0);
            assert_eq!(variant_index(&encode(&Transport::Udp)), 1);
        }

        /// `HostPort` carries a transport and a port and nothing
        /// else: no address, and no socket count.
        ///
        /// The exhaustive destructuring is the assertion — a field
        /// added later stops this from compiling, so a "just add the
        /// address" cannot pass review by accident.  The encoded
        /// length pins the same thing on the wire.
        #[test]
        fn host_port_carries_transport_and_port_only() {
            let host_port = HostPort {
                transport: Transport::Tcp,
                port: 8442,
            };
            let HostPort { transport, port } = host_port;
            assert_eq!(transport, Transport::Tcp);
            assert_eq!(port, 8442);

            assert_eq!(host_port, roundtrip(&host_port));
            assert_eq!(
                encode(&host_port).len(),
                encode(&(Transport::Tcp, 8442_u16)).len(),
                "a `HostPort` is exactly its transport and its port"
            );
        }

        /// A `HostPorts` answer round-trips, and the same port under
        /// both transports is two legitimate entries rather than a
        /// duplicate: TCP and UDP are separate spaces.
        ///
        /// That a response is PRODUCED without duplicates is not
        /// testable here — `Vec<HostPort>` cannot enforce uniqueness,
        /// and this crate produces no occupancy, it only carries it.
        #[test]
        fn host_ports_response_roundtrip_keeps_both_transports() {
            let ports = vec![
                HostPort {
                    transport: Transport::Tcp,
                    port: 8442,
                },
                HostPort {
                    transport: Transport::Udp,
                    port: 8442,
                },
                HostPort {
                    transport: Transport::Tcp,
                    port: 38_370,
                },
            ];
            let resp = NodePackageResponse::HostPorts(ports.clone());
            let decoded = roundtrip(&resp);
            assert_eq!(resp, decoded);

            let NodePackageResponse::HostPorts(decoded_ports) = decoded else {
                panic!("expected a host-ports answer");
            };
            assert_eq!(decoded_ports, ports, "order and contents survive");
            assert_eq!(
                decoded_ports.iter().filter(|p| p.port == 8442).count(),
                2,
                "one port taken on both transports is two entries"
            );
            assert_eq!(
                decoded_ports
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                ports.len(),
                "the entries are distinct as `(transport, port)` pairs"
            );

            // The empty answer is a host with nothing taken, not an
            // error.
            let resp = NodePackageResponse::HostPorts(Vec::new());
            assert_eq!(resp, roundtrip(&resp));
        }

        /// Declaration order is the wire order: a later insertion,
        /// rather than an append, breaks this test.
        #[test]
        fn node_package_error_variant_order_is_pinned() {
            let identity = || PackageIdentity {
                target: "sensor".into(),
                version: "1.2.3".into(),
                commit: "0123456789abcdef".into(),
            };
            assert_eq!(
                variant_index(&encode(&NodePackageError::TargetMismatch {
                    expected: identity(),
                    found: identity(),
                })),
                0
            );
            assert_eq!(
                variant_index(&encode(&NodePackageError::MissingBootstrapMaterial)),
                1
            );
            assert_eq!(
                variant_index(&encode(&NodePackageError::BootstrapMaterialExpired)),
                2
            );
            assert_eq!(
                variant_index(&encode(&NodePackageError::InsufficientDiskSpace {
                    filesystem: "/var".into(),
                    required: 8_388_608,
                    available: 1_048_576,
                })),
                3
            );
            assert_eq!(
                variant_index(&encode(&NodePackageError::StaleTrustSet {
                    active_epoch: 43
                })),
                4
            );
            assert_eq!(
                variant_index(&encode(&NodePackageError::UnsupportedManifestFormat {
                    active_epoch: 43,
                    supported: ManifestFormatRange { min: 1, max: 3 },
                })),
                5
            );
            assert_eq!(
                variant_index(&encode(&NodePackageError::ObservationUnavailable)),
                6
            );
            assert_eq!(
                variant_index(&encode(&NodePackageError::UnmanagedInstancePresent)),
                7
            );
            assert_eq!(
                variant_index(&encode(&NodePackageError::UndeclaredPrivilegeProfile {
                    profile: "dpdk".into(),
                    declared: vec!["root".into(), "replay".into()],
                })),
                8
            );
            assert_eq!(
                variant_index(&encode(&NodePackageError::UnexpectedPrivilegeProfile {
                    profile: "dpdk".into(),
                })),
                9
            );
            assert_eq!(
                variant_index(&encode(&NodePackageError::MissingPrivilegeProfile)),
                10
            );
            assert_eq!(
                variant_index(&encode(&NodePackageError::AppliedButUnhealthy {
                    disposition: UnhealthyDisposition::RolledBack,
                    cause: "piglet.service failed to start".into(),
                })),
                11
            );
        }

        /// Declaration order is the wire order: a later insertion,
        /// rather than an append, breaks this test.
        #[test]
        fn unhealthy_disposition_variant_order_is_pinned() {
            for (disposition, index) in [
                (UnhealthyDisposition::RolledBack, 0),
                (UnhealthyDisposition::Held, 1),
                (UnhealthyDisposition::Unwound, 2),
                (UnhealthyDisposition::NotReversed, 3),
            ] {
                assert_eq!(variant_index(&encode(&disposition)), index);
                assert_eq!(disposition, roundtrip(&disposition));
            }
        }

        /// `Lifecycle` rides the wire as its `u8` discriminant, and a
        /// discriminant this build does not know decodes to
        /// `Unknown` instead of failing.
        #[test]
        fn lifecycle_encodes_discriminant_and_tolerates_unknown() {
            for (lifecycle, discriminant) in [
                (Lifecycle::NotInstalled, 0u8),
                (Lifecycle::Installing, 1),
                (Lifecycle::Running, 2),
                (Lifecycle::Stopped, 3),
                (Lifecycle::Failed, 4),
                (Lifecycle::Removing, 5),
                (Lifecycle::Unknown, u8::MAX),
            ] {
                assert_eq!(encode(&lifecycle), vec![discriminant]);
                assert_eq!(lifecycle, roundtrip(&lifecycle));
            }

            let decoded: Lifecycle =
                decode(&[200]).expect("an unrecognized discriminant must still decode");
            assert_eq!(decoded, Lifecycle::Unknown);

            // The fallback survives inside an enclosing payload too.
            // `lifecycle` is the single byte preceding the empty
            // `bound_addrs`, whose length prefix is a fixed 8 bytes,
            // followed by the 1-byte `None` tag of `privilege_profile`.
            let mut bytes = encode(&package_state(Lifecycle::Running, Vec::new()));
            let position = bytes.len() - 10;
            assert_eq!(
                bytes.get(position),
                Some(&2),
                "the lifecycle discriminant should sit just before the bound_addrs length"
            );
            bytes[position] = 200;
            let decoded: PackageState =
                decode(&bytes).expect("an unrecognized discriminant must still decode");
            assert_eq!(decoded.lifecycle, Lifecycle::Unknown);
        }

        // ── node.enroll ─────────────────────────────────────────

        /// Helper: a `ServiceSpec` with the given certificate group.
        fn service_spec(cert_group: Option<CertGroup>) -> ServiceSpec {
            ServiceSpec {
                component: "sensor".into(),
                service_name: "sensor".into(),
                reload: ReloadHook("reload-sensor".into()),
                cert_group,
            }
        }

        /// Helper: a `Register` request with the given identity parts.
        fn register(
            instance: Option<u32>,
            delivery_mode: DeliveryMode,
            wrap_ttl: Duration,
        ) -> NodeEnrollRequest {
            NodeEnrollRequest::Register {
                service_name: "sensor".into(),
                delivery_mode,
                host: "host01".into(),
                instance,
                spec: service_spec(Some(CertGroup("internal".into()))),
                wrap_ttl,
                idempotency_key: "b6f0".into(),
            }
        }

        /// Helper: one of each `NodeEnrollError`, in declaration
        /// order, so a table-driven test covers all seven.
        fn every_enroll_error() -> [NodeEnrollError; 7] {
            [
                NodeEnrollError::ServiceSpecConflict,
                NodeEnrollError::ServiceNameCollision,
                NodeEnrollError::ServiceInstanceMismatch,
                NodeEnrollError::ServiceHostMismatch,
                NodeEnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::CredentialInvalid,
                },
                NodeEnrollError::RegistrarBusy {
                    retry_after: Duration::from_secs(30),
                },
                NodeEnrollError::ServiceLabelInvalid,
            ]
        }

        /// Helper: every `RegistrarUnavailableReason`, in declaration
        /// order.
        fn every_unavailable_reason() -> [RegistrarUnavailableReason; 6] {
            [
                RegistrarUnavailableReason::CredentialInvalid,
                RegistrarUnavailableReason::NotProvisioned,
                RegistrarUnavailableReason::AuditUnwritable,
                RegistrarUnavailableReason::EndpointUnreachable,
                RegistrarUnavailableReason::PostMintUnrecordable,
                RegistrarUnavailableReason::RegistrarUnreachable,
            ]
        }

        #[test]
        fn serde_roundtrip_node_enroll_request() {
            for instance in [None, Some(7)] {
                for delivery_mode in [DeliveryMode::LocalFile, DeliveryMode::RemoteBootstrap] {
                    let wrap_ttl = Duration::from_millis(90_500);
                    let req = register(instance, delivery_mode, wrap_ttl);
                    let decoded = roundtrip(&req);
                    assert_eq!(req, decoded);

                    let NodeEnrollRequest::Register {
                        wrap_ttl: decoded_ttl,
                        instance: decoded_instance,
                        ..
                    } = decoded
                    else {
                        panic!("expected a Register request");
                    };
                    assert_eq!(decoded_ttl, wrap_ttl);
                    assert_eq!(decoded_instance, instance);
                }

                let req = NodeEnrollRequest::Deregister {
                    service_name: "sensor".into(),
                    host: "host01".into(),
                    instance,
                    idempotency_key: "b6f0".into(),
                };
                assert_eq!(req, roundtrip(&req));
            }
        }

        /// The identity's `service_name` and the spec's are filled
        /// independently, so both survive unchanged even when they
        /// differ: this crate neither reconciles nor rejects the pair.
        #[test]
        fn node_enroll_register_keeps_both_service_names() {
            let req = NodeEnrollRequest::Register {
                service_name: "sensor".into(),
                delivery_mode: DeliveryMode::RemoteBootstrap,
                host: "host01".into(),
                instance: Some(1),
                spec: ServiceSpec {
                    component: "sensor-pkg".into(),
                    service_name: "collector".into(),
                    reload: ReloadHook("reload-sensor".into()),
                    cert_group: None,
                },
                wrap_ttl: Duration::from_mins(10),
                idempotency_key: "b6f0".into(),
            };
            let decoded = roundtrip(&req);
            assert_eq!(req, decoded);

            let NodeEnrollRequest::Register {
                service_name, spec, ..
            } = decoded
            else {
                panic!("expected a Register request");
            };
            assert_eq!(service_name, "sensor");
            assert_eq!(spec.service_name, "collector");
            assert_ne!(service_name, spec.service_name);
        }

        #[test]
        fn serde_roundtrip_service_spec() {
            for cert_group in [None, Some(CertGroup("internal".into()))] {
                let spec = service_spec(cert_group);
                assert_eq!(spec, roundtrip(&spec));
            }
        }

        /// A newtype over `String` is encoded as its inner value, so
        /// both opaque transport types cost nothing on the wire and a
        /// later move to a modelled type is a source-level break only.
        #[test]
        fn reload_hook_and_cert_group_encode_as_bare_strings() {
            let hook = ReloadHook("reload-sensor".into());
            assert_eq!(hook, roundtrip(&hook));
            assert_eq!(encode(&hook), encode(&"reload-sensor".to_string()));

            let group = CertGroup("internal".into());
            assert_eq!(group, roundtrip(&group));
            assert_eq!(encode(&group), encode(&"internal".to_string()));
        }

        #[test]
        fn serde_roundtrip_node_enroll_response() {
            let resp = NodeEnrollResponse::Material(bootstrap_material());
            assert_eq!(resp, roundtrip(&resp));

            let resp = NodeEnrollResponse::Done;
            assert_eq!(resp, roundtrip(&resp));

            // A typed failure survives as a *response*, not merely as
            // a bare error, including the two that carry a payload.
            for err in [
                NodeEnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::PostMintUnrecordable,
                },
                NodeEnrollError::RegistrarBusy {
                    retry_after: Duration::from_millis(2_500),
                },
            ] {
                let resp = NodeEnrollResponse::Failed(err);
                let decoded = roundtrip(&resp);
                assert_eq!(resp, decoded);
                assert!(matches!(decoded, NodeEnrollResponse::Failed(_)));
            }

            let resp = NodeEnrollResponse::Failed(NodeEnrollError::RegistrarUnavailable {
                reason: RegistrarUnavailableReason::PostMintUnrecordable,
            });
            let NodeEnrollResponse::Failed(NodeEnrollError::RegistrarUnavailable { reason }) =
                roundtrip(&resp)
            else {
                panic!("expected a registrar-unavailable failure response");
            };
            assert_eq!(reason, RegistrarUnavailableReason::PostMintUnrecordable);

            let resp = NodeEnrollResponse::Failed(NodeEnrollError::RegistrarBusy {
                retry_after: Duration::from_millis(2_500),
            });
            let NodeEnrollResponse::Failed(NodeEnrollError::RegistrarBusy { retry_after }) =
                roundtrip(&resp)
            else {
                panic!("expected a registrar-busy failure response");
            };
            assert_eq!(retry_after, Duration::from_millis(2_500));
        }

        /// The granted deadline travels as received.  A grant shorter
        /// than the requested `wrap_ttl` survives untouched, so a
        /// consumer can never assume the two agree.
        #[test]
        fn node_enroll_material_carries_the_granted_deadline() {
            const WRAP_TTL: Duration = Duration::from_hours(1);

            let requested_at: jiff::Timestamp = "2026-01-02T03:00:00Z"
                .parse()
                .expect("literal is a valid timestamp");
            let requested_deadline = requested_at
                + jiff::SignedDuration::from_secs(
                    i64::try_from(WRAP_TTL.as_secs()).expect("an hour fits in an i64"),
                );

            // The registrar clamped the requested hour to ten minutes.
            let granted: jiff::Timestamp = "2026-01-02T03:10:00Z"
                .parse()
                .expect("literal is a valid timestamp");
            assert!(granted < requested_deadline);

            let resp = NodeEnrollResponse::Material(BootstrapMaterial {
                expires_at: granted,
                ..bootstrap_material()
            });
            let decoded = roundtrip(&resp);
            assert_eq!(resp, decoded);

            let NodeEnrollResponse::Material(material) = decoded else {
                panic!("expected a Material response");
            };
            assert_eq!(material.expires_at, granted);
            assert!(material.expires_at < requested_deadline);
        }

        /// `NodeEnrollResponse` derives `Debug`, so the `Material`
        /// payload keeps `BootstrapMaterial`'s own redaction.
        #[test]
        fn node_enroll_response_debug_redacts_the_wrapped_secret() {
            let resp = NodeEnrollResponse::Material(bootstrap_material());
            let rendered = format!("{resp:?}");
            assert!(!rendered.contains("s.9f3c1b"), "{rendered}");
            assert!(!rendered.contains(ARTIFACT_MARKER), "{rendered}");
            assert!(rendered.contains("<redacted>"), "{rendered}");
            assert!(rendered.contains("sensor-installer"), "{rendered}");
        }

        /// Every one of the seven errors survives the wire and matches
        /// only its own pattern.
        #[test]
        fn serde_roundtrip_node_enroll_error() {
            for err in every_enroll_error() {
                let decoded = roundtrip(&err);
                assert_eq!(decoded, err);
                for other in every_enroll_error() {
                    assert_eq!(
                        decoded == other,
                        err == other,
                        "{err:?} must be distinguishable from {other:?}"
                    );
                }
            }

            // The two payload-carrying variants keep their payloads.
            for reason in every_unavailable_reason() {
                let err = NodeEnrollError::RegistrarUnavailable { reason };
                assert_eq!(err, roundtrip(&err));
            }
            let err = NodeEnrollError::RegistrarBusy {
                retry_after: Duration::from_millis(1_250),
            };
            assert_eq!(err, roundtrip(&err));
        }

        /// `RegistrarBusy` is the only retryable failure, and the
        /// delay comes back from the same call.
        #[test]
        fn node_enroll_retry_after_is_registrar_busy_alone() {
            for err in every_enroll_error() {
                let expected = match &err {
                    NodeEnrollError::RegistrarBusy { retry_after } => Some(*retry_after),
                    _ => None,
                };
                assert_eq!(err.retry_after(), expected, "{err:?}");
                assert_eq!(roundtrip(&err).retry_after(), expected, "{err:?}");
                assert_eq!(
                    NodeEnrollResponse::Failed(err.clone()).retry_after(),
                    expected,
                    "{err:?}"
                );
            }

            let busy = NodeEnrollError::RegistrarBusy {
                retry_after: Duration::from_millis(4_500),
            };
            assert_eq!(busy.retry_after(), Some(Duration::from_millis(4_500)));

            // A reason never makes `RegistrarUnavailable` retryable.
            for reason in every_unavailable_reason() {
                assert_eq!(
                    NodeEnrollError::RegistrarUnavailable { reason }.retry_after(),
                    None
                );
            }

            // A success is not a retry candidate either.
            assert_eq!(NodeEnrollResponse::Done.retry_after(), None);
            assert_eq!(
                NodeEnrollResponse::Material(bootstrap_material()).retry_after(),
                None
            );
        }

        /// A teardown is owed for exactly one reason of exactly one
        /// variant.
        #[test]
        fn node_enroll_teardown_is_owed_only_after_a_mint() {
            for err in every_enroll_error() {
                assert!(!err.leaves_teardown_owed(), "{err:?}");
                assert!(
                    !NodeEnrollResponse::Failed(err.clone()).leaves_teardown_owed(),
                    "{err:?}"
                );
            }

            for reason in every_unavailable_reason() {
                let err = NodeEnrollError::RegistrarUnavailable { reason };
                let owed = reason == RegistrarUnavailableReason::PostMintUnrecordable;
                assert_eq!(err.leaves_teardown_owed(), owed, "{reason:?}");
                assert_eq!(roundtrip(&err).leaves_teardown_owed(), owed, "{reason:?}");
                assert_eq!(
                    NodeEnrollResponse::Failed(err).leaves_teardown_owed(),
                    owed,
                    "{reason:?}"
                );
            }

            // A pre-derivation refusal never leaves a manager tearing
            // down an identity that was never created.
            assert!(!NodeEnrollError::ServiceLabelInvalid.leaves_teardown_owed());

            assert!(!NodeEnrollResponse::Done.leaves_teardown_owed());
            assert!(!NodeEnrollResponse::Material(bootstrap_material()).leaves_teardown_owed());
        }

        /// The reason set is closed: a value one past the last variant
        /// is a decode error, not a silent fallback.
        #[test]
        fn registrar_unavailable_reason_roundtrips_and_rejects_unknown() {
            for reason in every_unavailable_reason() {
                assert_eq!(reason, roundtrip(&reason));
            }

            let one_past_the_end = 6u32.to_le_bytes();
            let decoded: Result<RegistrarUnavailableReason, _> = decode(&one_past_the_end);
            assert!(
                decoded.is_err(),
                "an unrecognized reason must fail the decode, not fall back"
            );
        }

        /// Declaration order is the wire order: a later insertion,
        /// rather than an append, breaks this test.
        #[test]
        fn node_enroll_error_variant_order_is_pinned() {
            for (position, err) in every_enroll_error().iter().enumerate() {
                assert_eq!(
                    variant_index(&encode(err)),
                    u32::try_from(position).expect("seven variants fit in a u32"),
                    "{err:?}"
                );
            }
            assert_eq!(
                variant_index(&encode(&NodeEnrollError::ServiceLabelInvalid)),
                6,
                "the newest variant is appended, never grouped with the other Service* errors"
            );
        }

        /// Declaration order is the wire order for the reason set too.
        #[test]
        fn registrar_unavailable_reason_variant_order_is_pinned() {
            for (position, reason) in every_unavailable_reason().iter().enumerate() {
                assert_eq!(
                    variant_index(&encode(reason)),
                    u32::try_from(position).expect("six variants fit in a u32"),
                    "{reason:?}"
                );
            }
        }

        /// Declaration order is the wire order for the response too.
        #[test]
        fn node_enroll_response_variant_order_is_pinned() {
            assert_eq!(
                variant_index(&encode(&NodeEnrollResponse::Material(bootstrap_material()))),
                0
            );
            assert_eq!(variant_index(&encode(&NodeEnrollResponse::Done)), 1);
            assert_eq!(
                variant_index(&encode(&NodeEnrollResponse::Failed(
                    NodeEnrollError::ServiceSpecConflict
                ))),
                2
            );
        }

        /// A manager synthesizes `RegistrarUnreachable` itself when the
        /// registrar agent is not connected at all, so no registrar
        /// response is needed to produce it.
        #[test]
        fn registrar_unreachable_is_constructed_without_a_response() {
            let err = NodeEnrollError::RegistrarUnavailable {
                reason: RegistrarUnavailableReason::RegistrarUnreachable,
            };
            assert!(matches!(
                err,
                NodeEnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::RegistrarUnreachable
                }
            ));
            assert_eq!(err.retry_after(), None);
            assert!(!err.leaves_teardown_owed());
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "client", feature = "server"))]
    use super::*;

    /// Every category with its MITRE ATT&CK tactic id, one to one.
    const MITRE_TACTIC_IDS: [(super::EventCategory, &str); 14] = [
        (super::EventCategory::Reconnaissance, "TA0043"),
        (super::EventCategory::ResourceDevelopment, "TA0042"),
        (super::EventCategory::InitialAccess, "TA0001"),
        (super::EventCategory::Execution, "TA0002"),
        (super::EventCategory::Persistence, "TA0003"),
        (super::EventCategory::PrivilegeEscalation, "TA0004"),
        (super::EventCategory::DefenseEvasion, "TA0005"),
        (super::EventCategory::CredentialAccess, "TA0006"),
        (super::EventCategory::Discovery, "TA0007"),
        (super::EventCategory::LateralMovement, "TA0008"),
        (super::EventCategory::Collection, "TA0009"),
        (super::EventCategory::Exfiltration, "TA0010"),
        (super::EventCategory::CommandAndControl, "TA0011"),
        (super::EventCategory::Impact, "TA0040"),
    ];

    #[test]
    fn event_categories_map_to_mitre_tactic_ids_one_to_one() {
        use super::EventCategory;

        for (category, id) in MITRE_TACTIC_IDS {
            assert_eq!(category.mitre_tactic_id(), id, "{category:?}");
            assert_eq!(EventCategory::from_mitre_tactic_id(id), Some(category));
            assert_eq!(
                EventCategory::from_mitre_tactic_id(category.mitre_tactic_id()),
                Some(category)
            );
        }
        // The 14 entries name 14 distinct categories and ids, so every
        // category of the 14 is in the table once.
        for (index, (category, id)) in MITRE_TACTIC_IDS.iter().enumerate() {
            for (other_category, other_id) in MITRE_TACTIC_IDS.iter().skip(index + 1) {
                assert_ne!(category, other_category);
                assert_ne!(id, other_id);
            }
        }
        for id in [
            "",
            "ta0011",
            "Ta0011",
            "TA011",
            "TA00110",
            " TA0011",
            "TA0011 ",
            "TA0041",
            "TA0000",
            "T1059",
            "CommandAndControl",
        ] {
            assert_eq!(EventCategory::from_mitre_tactic_id(id), None, "{id:?}");
        }
    }

    /// Encodes a `TimeCount` under the wire configuration, asserts the
    /// bytes equal `expected`, and decodes `expected` back.
    #[cfg(any(feature = "client", feature = "server"))]
    fn assert_time_count_wire_bytes(time: jiff::civil::DateTime, expected: &[u8]) {
        let time_count = TimeCount { time, count: 42 };
        let bytes = bincode::serde::encode_to_vec(&time_count, bincode::config::standard())
            .expect("serialization should succeed");
        assert_eq!(bytes, expected, "{bytes:?}");

        let (decoded, read): (TimeCount, usize) =
            bincode::serde::decode_from_slice(expected, bincode::config::standard())
                .expect("deserialization should succeed");
        assert_eq!(read, expected.len());
        assert_eq!(decoded.time, time);
        assert_eq!(decoded.count, time_count.count);
    }

    /// The wire bytes of a `TimeCount` with a sub-second `time` are
    /// pinned; `civil::DateTime` is carried as a string whose fraction
    /// `jiff` formats.
    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn time_count_wire_bytes_are_pinned() {
        assert_time_count_wire_bytes(
            jiff::civil::DateTime::new(2026, 3, 15, 15, 0, 4, 120_000_000)
                .expect("2026-03-15T15:00:04.12 is a valid civil datetime"),
            &[
                0x16, 0x32, 0x30, 0x32, 0x36, 0x2d, 0x30, 0x33, 0x2d, 0x31, 0x35, 0x54, 0x31, 0x35,
                0x3a, 0x30, 0x30, 0x3a, 0x30, 0x34, 0x2e, 0x31, 0x32, 0x2a,
            ],
        );
    }

    /// The wire bytes of a `TimeCount` with a whole-second `time` are
    /// pinned, since the string form trims a zero fraction.
    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn time_count_whole_second_wire_bytes_are_pinned() {
        assert_time_count_wire_bytes(
            jiff::civil::DateTime::new(2026, 3, 15, 15, 0, 4, 0)
                .expect("2026-03-15T15:00:04 is a valid civil datetime"),
            &[
                0x13, 0x32, 0x30, 0x32, 0x36, 0x2d, 0x30, 0x33, 0x2d, 0x31, 0x35, 0x54, 0x31, 0x35,
                0x3a, 0x30, 0x30, 0x3a, 0x30, 0x34, 0x2a,
            ],
        );
    }

    /// The derived `Debug` text of a `TimeCount`, which a caller can
    /// log, is pinned with a sub-second and a whole-second `time`.
    #[test]
    fn time_count_debug_is_pinned() {
        use super::TimeCount;

        let fractional = TimeCount {
            time: jiff::civil::DateTime::new(2026, 3, 15, 15, 0, 4, 120_000_000)
                .expect("2026-03-15T15:00:04.12 is a valid civil datetime"),
            count: 42,
        };
        let whole = TimeCount {
            time: jiff::civil::DateTime::new(2026, 3, 15, 15, 0, 4, 0)
                .expect("2026-03-15T15:00:04 is a valid civil datetime"),
            count: 42,
        };

        assert_eq!(
            format!("{fractional:?}"),
            "TimeCount { time: 2026-03-15T15:00:04.12, count: 42 }"
        );
        assert_eq!(
            format!("{whole:?}"),
            "TimeCount { time: 2026-03-15T15:00:04, count: 42 }"
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

    #[test]
    fn manifest_format_range_contains_both_ends() {
        use super::ManifestFormatRange;

        let range = ManifestFormatRange { min: 2, max: 4 };

        assert!(!range.contains(1));
        assert!(range.contains(2));
        assert!(range.contains(3));
        assert!(range.contains(4));
        assert!(!range.contains(5));

        let single = ManifestFormatRange { min: 1, max: 1 };
        assert!(single.contains(1));
        assert!(!single.contains(0));
        assert!(!single.contains(2));
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn manifest_format_range_round_trip() {
        use super::ManifestFormatRange;

        let range = ManifestFormatRange { min: 1, max: 3 };
        let config = bincode::config::standard();
        let encoded = bincode::serde::encode_to_vec(range, config).unwrap();
        let (decoded, len): (ManifestFormatRange, usize) =
            bincode::serde::decode_from_slice(&encoded, config).unwrap();

        assert_eq!(decoded, range);
        assert_eq!(len, encoded.len());
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn provisioning_fingerprint_round_trip() {
        use std::collections::BTreeMap;

        use super::ProvisioningFingerprint;

        let config = bincode::config::standard();

        let empty = ProvisioningFingerprint::default();
        let encoded = bincode::serde::encode_to_vec(&empty, config).unwrap();
        let (decoded, _len): (ProvisioningFingerprint, usize) =
            bincode::serde::decode_from_slice(&encoded, config).unwrap();
        assert_eq!(decoded, empty);
        assert!(decoded.components.is_empty());

        let multi = ProvisioningFingerprint {
            components: BTreeMap::from([
                ("review".to_string(), "sha256:aaa".to_string()),
                ("roxyd".to_string(), "sha256:bbb".to_string()),
            ]),
            domain: "example.test".to_string(),
        };
        let encoded = bincode::serde::encode_to_vec(&multi, config).unwrap();
        let (decoded, _len): (ProvisioningFingerprint, usize) =
            bincode::serde::decode_from_slice(&encoded, config).unwrap();
        assert_eq!(decoded, multi);
    }

    /// Returns time-series generation policies that together cover every
    /// variant of every policy enum and both states of every optional field.
    fn time_series_generation_policies() -> Vec<super::TimeSeriesGenerationPolicy> {
        use std::{
            net::{IpAddr, Ipv4Addr, Ipv6Addr},
            time::Duration,
        };

        use super::{
            ConnField, CounterpartScope, EndpointRole, GroupByUnit, HostNetworkGroup, Measure,
            RawEventKind, TimeSeriesGenerationPolicy, TimeSeriesTypeRef,
        };

        let measures = [
            Measure::Count,
            Measure::Sum(ConnField::Duration),
            Measure::Sum(ConnField::OrigBytes),
            Measure::Sum(ConnField::RespBytes),
            Measure::Sum(ConnField::OrigPkts),
            Measure::Sum(ConnField::RespPkts),
        ];
        let group_bys = [
            None,
            Some(EndpointRole::Source),
            Some(EndpointRole::Destination),
        ];
        let units = [GroupByUnit::Ip, GroupByUnit::OwnedNetwork];
        let scopes = [
            CounterpartScope::Any,
            CounterpartScope::Internal,
            CounterpartScope::External,
        ];

        measures
            .into_iter()
            .enumerate()
            .map(|(i, measure)| {
                let id = u32::try_from(i).expect("fewer measures than u32::MAX");
                let custom = i % 2 == 0;
                TimeSeriesGenerationPolicy {
                    id,
                    raw_event_kind: if custom {
                        RawEventKind::Tls
                    } else {
                        RawEventKind::Conn
                    },
                    measure,
                    group_by: group_bys[i % group_bys.len()],
                    group_by_unit: units[i % units.len()],
                    counterpart_scope: scopes[i % scopes.len()],
                    slot_size: Duration::from_mins(10),
                    window_size: Duration::from_hours(24),
                    utc_offset: -18_000,
                    src_ip: custom.then_some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                    dst_ip: (!custom).then_some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                    sensors: vec!["sensor1".to_string(), "sensor2".to_string()],
                    time_series_type: (!custom).then(|| TimeSeriesTypeRef {
                        id: "outbound_bytes".to_string(),
                        version: 2,
                    }),
                    internal_networks: HostNetworkGroup {
                        hosts: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
                        networks: vec!["192.168.0.0/16".parse().unwrap()],
                        ip_ranges: vec![
                            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))
                                ..=IpAddr::V4(Ipv4Addr::new(172, 16, 0, 9)),
                        ],
                    },
                }
            })
            .collect()
    }

    #[test]
    fn time_series_generation_policy_json_round_trip() {
        let policies = time_series_generation_policies();
        let json = serde_json::to_string(&policies).unwrap();
        let decoded: Vec<super::TimeSeriesGenerationPolicy> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, policies);
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn time_series_generation_policy_bincode_round_trip() {
        let config = bincode::config::standard();
        for policy in time_series_generation_policies() {
            let encoded = bincode::serde::encode_to_vec(&policy, config).unwrap();
            let (decoded, len): (TimeSeriesGenerationPolicy, usize) =
                bincode::serde::decode_from_slice(&encoded, config).unwrap();
            assert_eq!(decoded, policy);
            assert_eq!(len, encoded.len());
        }
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn column_statistics_update_wire_bytes_are_pinned() {
        use structured::{ColumnStatistics, Description, Element, ElementCount, NLargestCount};

        let stats = ColumnStatistics {
            description: Description::new(
                2,
                Some(10.5),
                Some(1.5),
                Some(Element::Int(1)),
                Some(Element::Int(9)),
            ),
            n_largest_count: NLargestCount::new(
                2,
                vec![ElementCount {
                    value: Element::Int(1),
                    count: 2,
                }],
                Some(Element::Int(1)),
            ),
        };
        let update = ColumnStatisticsUpdate {
            cluster_id: 7,
            column_statistics: vec![stats],
        };
        let config = bincode::config::standard();
        let encoded =
            bincode::serde::encode_to_vec(&update, config).expect("serialization should succeed");
        let expected = [
            7, 1, 2, 1, 0, 0, 0, 0, 0, 0, 37, 64, 1, 0, 0, 0, 0, 0, 0, 248, 63, 1, 0, 2, 1, 0, 18,
            2, 1, 0, 2, 2, 1, 0, 2,
        ];
        assert_eq!(encoded, expected, "{encoded:?}");
        let (decoded, len): (ColumnStatisticsUpdate, usize) =
            bincode::serde::decode_from_slice(&encoded, config).expect("decoding should succeed");
        assert_eq!(len, encoded.len());
        assert_eq!(decoded.cluster_id, update.cluster_id);
        assert_eq!(decoded.column_statistics, update.column_statistics);
    }

    #[cfg(any(feature = "client", feature = "server"))]
    #[test]
    fn audit_health_round_trip() {
        use super::AuditHealth;

        let config = bincode::config::standard();
        let health = AuditHealth {
            below_low_water: true,
            intent_without_outcome: 7,
        };
        let encoded = bincode::serde::encode_to_vec(health, config).unwrap();
        let (decoded, _len): (AuditHealth, usize) =
            bincode::serde::decode_from_slice(&encoded, config).unwrap();

        assert_eq!(decoded, health);
        assert_eq!(AuditHealth::default().intent_without_outcome, 0);
        assert!(!AuditHealth::default().below_low_water);
    }
}
