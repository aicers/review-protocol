# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added the `common.delete_customer_data` (`DeleteCustomerData`) request,
  including the `CustomerDataDeletionRequest` type,
  `server::Connection::send_delete_customer_data_cmd` and
  `request::Handler::delete_customer_data`, so services can delete
  customer-owned filesystem data. Its payload contains an opaque ID and
  target service FQDN. The service implementation remains responsible for
  the actual deletion.
- Added customer-data deletion result reporting, including the
  `CustomerDataDeletionReport`, `CustomerDataDeletionReporter`, and
  `CustomerDataDeletionOutcome` types, the
  `server.customer_data_deletion.report` service identifier (request code 40),
  the typed `Connection::report_customer_data_deletion` client API, and the
  `Handler::report_customer_data_deletion` server hook.
- Added the `node.package` wire vocabulary: the `NodePackageRequest`,
  `NodePackageResponse`, `NodePackageError`, `InstallPreflight`,
  `InstalledPackage`, `PackageState`, `PackageIdentity`, `BoundAddr`,
  `BootstrapMaterial`, `Lifecycle` and `FailurePolicy` types in
  `types::node`, together with the `node.package`, `node.package.install`,
  `node.package.remove`, `node.package.list` and `node.package.status`
  service identifiers and `NodePackageRequest::service_id()`. `Lifecycle`
  travels as its `u8` discriminant and decodes an unrecognized value to
  `Lifecycle::Unknown`, so a newer agent can report a state an older reader
  has never heard of. Apply failures are carried by
  `NodePackageResponse::Failed` as structured data rather than through the
  string error channel, so a caller classifies them by pattern-matching.
  `BootstrapMaterial` redacts its wrapped one-time credential from its
  `Debug` output, so logging a request that relays it cannot leak it. The
  request family is not dispatched yet: an agent answers a `node.package`
  request as an unknown request code.
- Added five conditionally decoded tail fields to `AgentInfo`, appended in this
  order: `capabilities`, `active_trust_epoch`, `manifest_formats`,
  `provisioning_fingerprint` and `audit_health`. An agent uses them to advertise
  the optional request families and roles it carries, plus readings a manager
  cannot obtain any other way. The order is contractual and the fields decode
  conditionally: a decoder reads the base struct and then each tail field from
  whatever bytes are left over, each field consuming exactly its own bytes, so
  it may stop at any field boundary. A peer that sends no tail is decoded with
  an empty capability set and an unknown reading for the rest, and a peer that
  sends the full tail is decoded by an older base-only peer that ignores the
  trailing bytes. A tail that is present but does not decode fails the
  handshake rather than being read as an absent tail, so a missing-but-expected
  claim cannot pass unnoticed. Future fields follow the same discipline.
- Added the `ManifestFormatRange`, `ProvisioningFingerprint` and `AuditHealth`
  types in `types`, carried by the new `AgentInfo` fields.
- Added `types::capability`, naming the capability tags this crate knows about:
  `registrar`, `colocated:review`, `colocated:aice-web-next`, `node.package`,
  `node.enroll` and `rollback-supervisor`. These are known values, not a closed
  set — a decoder validates the tags it knows and preserves the rest untouched.
  This is unrelated to `auth::ProtocolMetadata::capabilities`, which stays a
  separate field on a separate type.
- Added `ConnectionBuilder::capabilities`,
  `ConnectionBuilder::active_trust_epoch`,
  `ConnectionBuilder::manifest_formats`,
  `ConnectionBuilder::provisioning_fingerprint` and
  `ConnectionBuilder::audit_health` to report the new fields. They default to
  advertising nothing, so a caller that sets none of them is unaffected.

### Changed

- Renamed handshake metadata fields from `app_name` / `version` to
  `agent_name` / `agent_version` in `ConnectionBuilder` and `AgentInfo`.
- `AgentInfo` now has five more public fields, so code that builds one with a
  struct literal must initialize them.
- `AgentInfo` and `Status` now implement `PartialEq` and `Eq`.

### Removed

- `client::send_err`, `client::send_ok`, and `client::send_request` are no
  longer part of the public API. Downstream crates should use the typed
  client APIs (for example `client::Connection` methods) instead of calling
  these low-level message helpers directly.
- `unary_request` is no longer part of the public API; it remains available
  internally for crate use. Downstream crates should use the typed client and
  server APIs (for example `client::Connection` methods or
  `server::Connection` helpers) instead of calling `unary_request` directly.

## [0.19.0] - 2026-05-19

### Added

- `NodePowerOutcome` enum to distinguish between no-response sends
  (`Sent`) and request/response operations (`Response`).  Immediate
  power operations (`Reboot`, `Shutdown`) return `Sent`; graceful
  operations (`GracefulReboot`, `GracefulShutdown`) return
  `Response(NodePowerResponse)`.
- `Node::reboot()` and `Node::shutdown()` convenience methods that
  send the request and return immediately without waiting for a
  response.  The agent may close the connection while processing
  the command.
- `Node::reboot_authorized()`, `Node::shutdown_authorized()`,
  `Node::reboot_with_context()`, and
  `Node::shutdown_with_context()` authorization variants for the
  new immediate power methods.
- `Connection::accept_uni` on the server-side `Connection` wrapper,
  mirroring `open_bi`, so callers no longer need `as_quinn` to reach
  the underlying `quinn::Connection::accept_uni`.

### Changed

- Client-side `NodePower` dispatch (`handle` and `handle_node`) no
  longer sends a response for immediate operations (`Reboot`,
  `Shutdown`). Graceful operations (`GracefulReboot`,
  `GracefulShutdown`) continue to use the request/response path.
  This matches the server-side fire-and-forget semantics introduced
  in PR #195.
- `Node::power()` now returns `anyhow::Result<NodePowerOutcome>`
  instead of `anyhow::Result<NodePowerResponse>`.  Immediate
  operations (`Reboot`, `Shutdown`) write the request frame,
  finish the send stream, and return `Sent` without waiting for a
  response.  Graceful operations continue to use the normal
  request/response path.
- `Connection::node_power()`, `Connection::node_power_authorized()`,
  and `Connection::node_power_with_context()` now return
  `NodePowerOutcome` with the same semantics.
- `EventStreamHandler` trait methods (`handle_event`, `on_error`,
  `on_stream_end`) now return `std::io::Result<()>` instead of
  `Result<(), String>`. Implementors must update their return types
  and convert errors via `std::io::Error::other`.
- `EventStreamHandler::on_error`'s default implementation is now a
  no-op. The previous default wrote to stderr via `eprintln!`, which
  bypassed the application's logging setup. Override the method to
  route stream-level errors into your own logger / metrics.
- Bumped `rcgen` (optional and dev-dependency) from 0.13 to 0.14.
  Users of the `rcgen` / `test-support` feature must update calls to
  the rcgen 0.14 API (e.g. `signing_key` instead of `key_pair`,
  `Issuer::from_params` for chained signing).

### Removed

- Removed redundant legacy flat API methods from `Connection`:
  `get_process_list`, `get_resource_usage`, `send_reboot_cmd`, and
  `send_shutdown_cmd`. Callers should use the `Node` handle (`conn.node()`)
  instead. See the `Node` module docs for migration examples.
- `Connection::accept_event_streams`. The bundled spawn loop hard-coded
  `eprintln!` for per-stream errors and flattened connection-close
  variants into a single `Ok(())`, hiding diagnostics from the caller.
  Drive `Connection::accept_uni` and dispatch each stream to
  `Connection::handle_event_stream` inside a `tokio::spawn` instead;
  bound concurrency with a `tokio::sync::Semaphore` if needed. The
  caller now owns the spawn lifetime, concurrency policy, and error
  handling. See the updated `README.md` and the module-level docs in
  `src/server.rs`.

## [0.18.1] - 2026-03-30

### Changed

- Derive `Hash` for `ThreatLevel`, enabling its use as a
  `HashMap`/`HashSet` key.

## [0.18.0] - 2026-03-30

### Added

- Documentation, examples, and tests for
  `AuthorizationContext` and the migration path from
  `Authorizer` to `AuthorizerV2`. Includes expanded rustdoc
  covering what belongs (and does not belong) in the context,
  security guidance, copy-pastable doctests for constructing
  contexts, implementing `AuthorizerV2`, and wrapping legacy
  authorizers with `AuthorizerV2Adapter`. Crate-level docs
  now describe the richer-context authorization model and
  confirm that existing `PeerContext` flows are unchanged.
- `AuthorizerV2` trait in `auth` module that receives an
  `AuthorizationContext` (instead of a bare `PeerContext`)
  at authorization decision points. Existing `Authorizer`
  implementations are unchanged and can be wrapped with
  the new `AuthorizerV2Adapter` to satisfy `AuthorizerV2`.
- `AuthorizerV2Adapter<T>` adapter that wraps any existing
  `Authorizer` as an `AuthorizerV2` by deriving a
  `PeerContext` from the `AuthorizationContext`.
- `AuthorizationContext::to_peer_context()` method for
  round-tripping back to `PeerContext`.
- `server::handle_authorized_with_context` function that
  accepts `AuthorizationContext` and `AuthorizerV2` for
  richer server-side authorization.
- Nine `_with_context` methods on `server::Connection`
  (`node_service_with_context`,
  `node_network_interface_with_context`,
  `node_hostname_with_context`,
  `node_time_sync_with_context`,
  `node_logging_with_context`,
  `node_remote_access_with_context`,
  `node_power_with_context`,
  `node_observation_with_context`,
  `node_version_with_context`) and corresponding methods
  on `server::node::Node`, accepting `AuthorizationContext`
  and `AuthorizerV2`.
- `AuthorizationContext` type in `auth` module that carries
  richer authenticated peer metadata (`PeerIdentity`,
  optional `AgentKind`, roles, `ProtocolMetadata`, and an
  authenticated attributes map) without changing the wire
  format. Includes `From<&PeerContext>` conversion,
  `from_peer_context` and `from_authenticated_inputs`
  constructors. `ServiceId` remains separate.
- `PeerIdentity` type that extracts certificate-backed
  identity fields from `PeerContext` for use in
  `AuthorizationContext`.
- `AgentKind` enum (`Agent`, `Proxy`, `Other(String)`) for
  classifying authenticated peers.
- `ProtocolMetadata` struct with optional `version` and
  `capabilities` fields for protocol-level policy decisions.
- `request::handle_node()` dispatch entry point that accepts
  `NodeHandler` directly, allowing a node-focused agent to serve
  node-family requests without implementing the full `Handler`
  trait. This is additive and does not replace `request::handle()`.
- `protocol_error` module with `ProtocolErrorKind`, a semantic
  taxonomy of protocol-level error categories (`NotSupported`,
  `Forbidden`, `InvalidArgs`, `VersionMismatch`, `Other`).
  This is an internal classification type — it does not affect
  wire encodings. Includes `From<AuthorizationError>` and
  `From<HandshakeError>` conversions.
- `ProtocolErrorKind::of_io_error` method that extracts the
  semantic classification from an `io::Error` returned by
  `handle_authorized`. Errors produced by the dispatch loop
  (authorization denials, unknown request codes) carry an
  embedded classification; other `io::Error` values are
  classified by their `ErrorKind`.
- `AuthorizationError::kind()` method that returns
  `ProtocolErrorKind::Forbidden`. Used by the dispatch loop
  to classify authorization denials.
- `ProtocolErrorKind` adopted in representative request
  handlers in both `server::handler` and `request` modules.
  Argument parse failures in selected paths are now
  classified as `InvalidArgs` internally. Wire behavior is
  unchanged.
- `HandlerError::kind()` method on the agent-side handler
  error type, returning the `ProtocolErrorKind` classification
  extracted from the underlying `io::Error`.
- `request::NodeHandler` preparatory trait that groups the nine
  node feature-family methods under their own handler surface. A
  blanket `impl<T: Handler> NodeHandler for T` preserves full
  compatibility so existing `Handler` implementations continue to
  work unchanged. The dispatch path still requires `Handler`; a
  future release may accept `NodeHandler` directly.
- `server::node` module with a `Node` handle that groups all
  node-family API calls under a single, discoverable namespace.
  Obtain a handle via `Connection::node()` and call methods
  such as `node.power(req)` or `node.power_authorized(req,
  peer, authorizer)`. Existing `Connection::node_*` methods
  and legacy flat wrappers remain available and unchanged.
- `auth` module with authorization hooks for request dispatch.
  Provides `PeerContext` (certificate-backed peer identity),
  `Authorizer` trait (allow/deny hook keyed by `ServiceId`),
  `NoopAuthorizer` (default allow-all), and
  `AuthorizationError`. Policy decisions remain outside the
  crate; only the dispatch plumbing is included.
- `server::handle_authorized` function that checks each incoming
  request against an `Authorizer` before dispatching. Denied
  requests receive a stable `"authorization denied"` error
  response and the handler returns
  `io::ErrorKind::PermissionDenied`.
- Authorized variants of each `server::Connection` node method
  (`node_service_authorized`, `node_network_interface_authorized`,
  `node_hostname_authorized`, `node_time_sync_authorized`,
  `node_logging_authorized`, `node_remote_access_authorized`,
  `node_power_authorized`, `node_observation_authorized`,
  `node_version_authorized`) that check the `Authorizer` before
  sending REview-to-agent node requests. Each authorized method
  resolves the **method-level** `ServiceId` from the typed request
  (e.g. `node.power.reboot`, not just `node.power`), enabling
  fine-grained per-operation authorization within a family.
- `service_id()` method on each node request enum
  (`NodePowerRequest`, `NodeObservationRequest`, etc.) that returns
  the method-level `ServiceId` for the specific variant.
- `service_id` module with stable logical service identifiers
  (`ServiceId`) independent of wire `RequestCode` values. Covers
  all nine node feature families (with both family-level and
  method-level identifiers), legacy common operations, and
  server-side request operations. Includes
  `from_client_request_code` and `from_server_request_code`
  mappings and an `all()` helper for capability reporting.

### Changed

- Changed `TimeSeriesUpdate::cluster_id` field type from
  `String` to `u32`.
- Changed `UpdateClusterRequest::cluster_id` field type from
  `i32` to `u32`.
- Flat host-control APIs (`send_reboot_cmd`, `send_shutdown_cmd`,
  `get_process_list`, `get_resource_usage`) now route through the
  corresponding `node_power` / `node_observation` methods
  internally. Public signatures and behavior are unchanged.
- Default `node_power` implementation delegates `Reboot` and
  `Shutdown` to the flat `reboot` / `shutdown` handler methods,
  and default `node_observation` delegates `ProcessList` and
  `ResourceUsage` to `process_list` / `resource_usage`. Agents
  that implement only the flat methods continue to work.
- Flat request codes (`Reboot`, `Shutdown`, `ProcessList`,
  `ResourceUsage`) are now dispatched through the grouped
  `node_power` / `node_observation` handler methods.

### Fixed

- `ConnectionBuilder` now preserves full client certificate chains
  (leaf + intermediates) instead of using only the first certificate.
- `ConnectionBuilder::root_certs` now loads all certificates from
  each PEM blob instead of only the first one.

## [0.17.0] - 2026-03-25

### Added

- Typed `server::Connection` methods for each `node` feature
  family (`node_service`, `node_network_interface`,
  `node_hostname`, `node_time_sync`, `node_logging`,
  `node_remote_access`, `node_power`, `node_observation`,
  `node_version`). Each accepts the corresponding
  `Node*Request` and returns `Node*Response`, keeping internal
  request-code mappings hidden from callers.
- `Connection::get_sampling_policy_list` to retrieve the sampling
  policy list from the server.
- `Handler::get_sampling_policy_list` to handle sampling policy list
  requests from clients.
- Shared `node` request and response types for nine feature families:
  service control, network interface management, hostname management,
  time synchronization, logging configuration, remote access
  configuration, power control, host observation, and version
  management. Includes auxiliary types `NodeNetworkInterfaceConfig`,
  `NodeNetworkInterface`, `NodeLoggingProtocol`, `NodeLoggingEndpoint`,
  and `NodeRemoteAccessConfig`.
- Internal wire mappings (`RequestCode` variants) for each `node`
  feature family, enabling the transport layer to route typed
  `node` request and response payloads.
- Grouped `node` handler methods on `request::Handler` — one per
  feature family (`node_service`, `node_network_interface`,
  `node_hostname`, `node_time_sync`, `node_logging`,
  `node_remote_access`, `node_power`, `node_observation`,
  `node_version`). Each accepts the corresponding typed
  `Node*Request` and returns `Result<Node*Response, String>`.
  Default implementations return "not supported" for backward
  compatibility.
- Request dispatch now routes each `node` request code through
  the corresponding grouped handler method instead of returning
  a hardcoded error.
- Default `Handler::node_power` now delegates `Reboot` and
  `Shutdown` to the flat `reboot`/`shutdown` methods, and
  default `Handler::node_observation` delegates `ProcessList`
  and `ResourceUsage` to the flat `process_list`/`resource_usage`
  methods. This lets agents that only implement the legacy flat
  handlers accept the new `node` wire requests for the
  overlapping operations (see #144).

### Changed

- Renamed `Tidb` references to `LabelDb` (including request codes/handler-client
  methods) and `TiKind`/`TiRule` to `LabelDbKind`/`LabelDbRule` (Breaking Change).

## [0.16.0] - 2025-12-22

### Changed

- `Handler::get_allowlist` and `Handler::get_blocklist` now accept the peer
  identifier so servers can return customer-specific lists. The server handler
  now forwards the peer when serving allowlist and blocklist requests.
- `Handler::update_host_ports` and `Handler::update_host_user_agents` now
  accept the peer identifier so servers can update host information for
  specific customers. The server handler now forwards the peer when serving
  these requests.

### Fixed

- Fixed server-side deserialization for `InsertModel` and `UpdateModel`
  requests so the raw model payload is correctly decoded before handling.

## [0.15.0] - 2025-12-03

### Added

- `ThreatLevel` enum to represent the threat level of detection events. The enum
  includes five variants: `VeryLow`, `Low`, `Medium`, `High`, and `VeryHigh`.
- New client-side APIs to send host information update requests to the server:
  - `Connection::update_host_ports` updates host opened ports information
  - `Connection::update_host_user_agents` updates host OS and agent software
    information
- New server-side APIs to handle host information update requests from clients:
  - `Handler::update_host_ports` handles host opened ports update requests
  - `Handler::update_host_user_agents` handles host OS and agent software
    update requests
- `UserAgent` struct to represent user agent information with name, header,
  kind, and last modification time
- `UpdateHostOpenedPorts` and `UpdateHostOsAgents` request codes to support
  host information updates

### Changed

- Changed `model_id` parameter type from `i32` to `u32` in the `Handler` trait
  methods: `get_outliers`, `insert_column_statistics`, `insert_event_labels`,
  `insert_time_series`, `update_clusters`, and `update_outliers`. This change
  is also reflected in the corresponding client API methods.
- Changed `UpdateClusterRequest::cluster_id` field type from `String` to `i32`.
- Changed `ColumnStatisticsUpdate::cluster_id` field type from `String` to `u32`.

## [0.14.0] - 2025-11-27

### Changed

- Replaced `chrono` with `jiff` for time stored in `ColumnStatistics`.

## [0.13.0] - 2025-11-16

### Added

- `EventStreamHandler` trait for handling incoming event messages from
  unidirectional streams. This trait provides a standardized interface for
  processing `EventMessage` instances and includes methods for handling events,
  stream closure, and error conditions.
- `process_event_stream()` function for low-level event stream processing.
  This function reads raw unidirectional streams, handles protocol framing,
  deserializes `EventMessage` objects, and calls `EventStreamHandler` trait
  methods appropriately.
- Three new server-side `Connection` methods for handling unidirectional
  event streams:
  - `accept_event_stream()` accepts and handles the next unidirectional
    stream using an `EventStreamHandler`
  - `handle_event_stream()` processes a specific `RecvStream` with a given
    handler (useful for testing or advanced use cases)
  - `accept_event_streams()` continuously accepts multiple unidirectional
    streams with optional concurrency limiting via semaphore
- `BlocklistRadius` variant to `EventKind` enum to support RADIUS blocklist
  events.
- `BlocklistMalformedDns` variant to `EventKind` enum to support malformed DNS
  blocklist events.
- `UnusualDestinationPattern` variant to `EventKind` enum to support detection
  of unusual destination patterns in network traffic.
- Comprehensive integration tests in `tests/unidirectional_streams.rs`
  covering protocol compatibility, error handling, concurrent streams, and
  edge cases
- Performance benchmarks in `benches/unidirectional_streams.rs` for measuring
  event throughput, event sizes, concurrent streams, and deserialization
  overhead
- Complete working example in `examples/event_handler.rs` demonstrating event
  handler implementation with metrics collection and error handling
- Migration guide in `docs/migration-guide.md` to help applications migrate
  from direct stream handling to the encapsulated API
- Enhanced API documentation with usage examples for single streams, multiple
  concurrent streams, and integration patterns

### Changed

- Replaced `chrono` with `jiff` for date/time handling. The `jiff` crate
  provides better maintenance, improved API design, and enhanced timezone
  handling. This changes the types used in the protocol:
  - `TimeCount::time` now uses `jiff::civil::DateTime` instead of
    `chrono::NaiveDateTime`
  - `EventMessage::time` now uses `jiff::Timestamp` instead of
    `chrono::DateTime<Utc>`

## [0.12.1] - 2025-09-25

### Added

- The following client-side APIs to send requests to the server:
  - `Connection::get_model`
  - `Connection::get_model_names`
  - `Connection::insert_column_statistics`
  - `Connection::insert_model`
  - `Connection::insert_time_series`
  - `Connection::remove_model`
  - `Connection::update_clusters`
  - `Connection::update_model`
  - `Connection::update_outliers`
  - `Connection::insert_event_labels`
  - `Connection::insert_data_source`
  - `Connection::get_outliers`
- The following server-side APIs to handle requests from clients:
  - `Handler::get_model`
  - `Handler::get_model_names`
  - `Handler::insert_column_statistics`
  - `Handler::insert_model`
  - `Handler::insert_time_series`
  - `Handler::remove_model`
  - `Handler::update_clusters`
  - `Handler::update_model`
  - `Handler::update_outliers`
  - `Handler::insert_event_labels`
  - `Handler::insert_data_source`
  - `Handler::get_outliers`
- New types for machine learning and data processing:
  - `ColumnStatistics`, `ColumnStatisticsUpdate`
  - `TimeCount`, `TimeSeries`, `TimeSeriesUpdate`
  - `UpdateClusterRequest`
  - `OutlierInfo`
  - `EventMessage`

### Changed

- `server::Handler::handle` requires the `peer` argument, which uniquely
  identifies the client within the application.
- `server::Handler::renew_certificate` and
  `client::Connection::renew_certificate` now take no arguments. The server
  should use the identity from the connection.

## [0.12.0] - 2025-08-28

### Added

- Added `confidence` field of type `Option<f32>` to `TiRule` structure
- Added `kind` field to `TiRule` structure

### Changed

- `ResourceUsage` struct updated for Roxy 0.5.0 compatibility:
  - Memory fields now use bytes instead of KB
  - Replaced `total_disk_space`/`used_disk_space` with
    `disk_used_bytes`/`disk_available_bytes`
- Removed `Unknown` variant from `EventCategory` enum for MITRE compatibility
- Changed `category` fields in `TiRule` and `Tidb` structs to `Option<EventCategory>`

## [0.11.0] - 2025-06-21

### Changed

- Migrated to Rust 2024 edition. It requires a minimum of Rust 1.85.0.
- `server::Handler` handles requests from the following client-side APIs:
  - `Connection::get_model_names`
  - `Connection::get_tor_exit_node_list`
  - `Connection::get_trusted_domain_list`
  - `Connection::get_trusted_user_agent_list`
- Updated the naming conventions for "allowlist" and "blocklist" to use a single
  word instead of separate words. This change affects the following:
  - `AllowList` renamed to `Allowlist`
  - `BlockList` renamed to `Blocklist`
  - `*_allow_list` renamed to `*_allowlist`
  - `*_block_list` renamed to `*_blocklist`
- Modified `EventCategory` to include all MITRE categories - `Collection`,
  `DefenseEvasion`, `Persistence`, `PrivilegeEscalation`, `ResourceDevelopment`
  are added.

### Removed

- `server::Connection::as_quinn` was provided for backward-compatibility and has
  been removed. Server applications using review-protocol should now use the
  `server::Connection` struct directly.

## [0.10.0] - 2025-02-01

### Added

- The following client-side API to send a request to the server:
  - `Connection::get_indicator`

### Changed

- `server::Handler` handles requests from the following client-side APIs:
  - `Connection::get_allow_list`
  - `Connection::get_block_list`
  - `Connection::get_indicator`

## [0.9.0] - 2025-01-20

### Added

- The following server-side APIs to send data to the client:
  - `Connection::get_process_list`
  - `Connection::get_resource_usage`
  - `Connection::send_blocklist`
  - `Connection::send_config_update_cmd`
  - `Connection::send_filtering_rules`
  - `Connection::send_internal_network_list`
  - `Connection::send_ping_cmd`
  - `Connection::send_reboot_cmd`
  - `Connection::send_shutdown_cmd`
  - `Connection::send_sampling_policies`
  - `Connection::send_tor_exit_node_list`
  - `Connection::send_trusted_user_agent_list`

### Changed

- `Handler::sampling_policy_list` and `Handler::delete_sampling_policy` accept
  `[SamplingPolicy]` and `&[u32]`, respectively, instead of raw bytes. This
  makes the API more intuitive and moves serialization concerns from the agent
  to this crate where they belong.
- Updated `client::ConnectionBuilder` and `AgentInfo` structs to accomodate the
  new `status` field, to be used in the handshake process.
  - Introduced `Status` enum to represent the status of agents.

## [0.8.1] - 2024-11-15

### Added

- The server side should call `server::handle` to handle incoming requests from
  a client. This function takes a handler, which should implement the `Handler`
  trait. The handler currently handles the following requests:
  - `GetDataSource`
  - `GetTidbPatterns`
- Types required in the requests handled by `Handler`:
  - `DataSourceKey`, `DataType`, `DataSource`
- `client::Connection` provides the following functions to send requests to the
  server:
  - `get_data_source`
  - `get_pretrained_model`
  - `renew_certificate`

### Deprecated

- `server::send_trusted_domain_list` is deprecated. The server should now call
  `server::Connection::send_trusted_domain_list` to send the list of trusted
  domains to the client.
- `server::respond_with_tidb_patterns` is deprecated. `server::handle` should be
  used to handle incoming requests from the client.

## [0.8.0] - 2024-10-11

### Added

- `server::Connection` encapsulates the QUIC connection from a client and
  provides a protocol-specific connection. This change improves encapsulation
  and makes the API more idiomatic to review-protocol. Currently it provides the
  following APIs:
  - `send_allowlist`
  - `send_trusted_domain_list`

### Changed

- Reverted the format change of `EventCategory` in the previous release to
  maintain compatibility with applications with their own deserialization logic.

## [0.7.0] - 2024-09-28

### Added

- `GetTidbPatterns` is handled by `client::get_tidb_patterns` at the client side
  and `server::respond_with_tidb_patterns` at the server side.

### Removed

- Removed the following config-related items:
  - `Config`, `HogConfig`, `PigletConfig` and `CrusherConfig`
  - `Handler::get_config` and `RequestCode::GetConfig`

## [0.6.0] - 2024-09-18

### Removed

- `client::handshake` was deprecated in version 0.4.1 and has been removed in
  this version. Applications using review-protocol should now create a
  `Connection` instance using `ConnectionBuilder` instead.

### Fixed

- Fixed the `request::Handler::trusted_domain_list` function to correctly parse
  the argument (#39).

## [0.5.0] - 2024-09-05

### Added

- Implemented new client API methods:
  - `get_allow_list`: Retrieves the list of allowed networks
  - `get_block_list`: Retrieves the list of blocked networks
  - `get_internal_network_list`: Retrieves the list of internal networks
  - `get_tor_exit_node_list`: Retrieves the list of Tor exit nodes
  - `get_trusted_domain_list`: Retrieves the list of trusted domains
  - `get_trusted_user_agent_list`: Retrieves the list of trusted user agents
- Implemented a new server API method:
  - `notify_config_update`: Notifies the client that its configuration has been
    updated

### Removed

- `Handler::set_config` is removed. The server should no longer sends a message
  that invokes this method. Instead, the server should sends a message that
  invokes `Handler::update_config`.

### Fixed

- `send_trusted_domain_list` no longer tries to receive a response twice,
  causing the "unexpected end of file" error.

## [0.4.2] - 2024-07-31

### Added

- Introduced a new method `open_uni` in the `Connection` struct. This method
  initiates an outgoing unidirectional stream and directly corresponds to the
  `open_uni` method of the underlying `quinn::Connection`. This addition is for
  backward-compatibility and will be removed when this crate provides all the
  necessary features without exposing quinn's types.

## [0.4.1] - 2024-07-30

### Added

- The `ConnectionBuilder` struct has been enhanced to allow for the setting of
  certificates, private keys, and root certificates. This includes new methods
  to set and replace these components:

  - `ConnectionBuilder::cert` sets the client certificate for the connection.
  - `ConnectionBuilder::key` sets the client's private key for the connection.
  - `root_certs` sets the root certificates for the connection.

  These additions provide more flexibility in managing secure connections by
  allowing certificates and keys to be updated dynamically.

- The `update_config` is added to the `request::Handler` trait. This function
  allows the server to notify agents to take actions to update their
  configuration.

### Deprecated

- The `handshake` function in the `client` module is deprecated. This function
  will be removed in the next major/minor release. Applications using
  review-protocol should now create a `Connection` instance using
  `ConnectionBuilder` instead of calling `quinn::Endpoint::connect` and
  `client::handshake` separately.
- The `reload_config` function in the `request::Handler` trait is deprecated.
  This function will be removed in the next major/minor release. Applications
  using review-protocol should now use the `update_config` function in the
  client API to make agents update their configuration.

## [0.4.0] - 2024-07-22

### Added

- New `ConnectionBuilder` struct in the `client` module for creating customized
  connections. This allows for more flexible configuration of TLS settings and
  root certificates.
  - `ConnectionBuilder::new` function to create a new builder with given remote
    and local configurations.
  - `ConnectionBuilder::add_root_certs` method to add root certificates to the
    endpoint's certificate store.
  - `ConnectionBuilder::local_addr` method to set a specific local address for
    binding.
  - `ConnectionBuilder::connect` method to construct the final `Connection`
    instance. This combines `quinn::Endpoint::connect` and
    `review-protocol::client::handshake`. This simplifies the connection process
    for applications using review-protocol, reducing code duplication.
    Applications using review-protocol should now create a `Connection` instance
    using `ConnectionBuilder` instead of calling `quinn::Endpoint::connect` and
    `client::handshake` separately.
- `Connection` struct in the `client` module. This provides a protocol-specific
  connection, improving encapsulation and making the API more idiomatic to
  review-protocol.
  - Methods like `local_addr`, `remote_addr`, `close_reason`, `open_bi`, and `accept_bi`
    to interact with the connection.
- Introduced `EventCategory` enum to categorize security events.
- New client API `get_config()` to fetch configuration from the server. This
  method allows clients to request and receive configuration data from the
  server. The format of the configuration is left to the caller to interpret.

### Changed

- The `handshake` function in the `client` module no longer returns the
  `SendStream` and `RecvStream` handles. These values were previously returned
  but not used by the caller, so they have been removed to simplify the
  function's return type.
- Minimized dependencies when only default features are used.
  - Made several dependencies optional and tied them to specific features.
    `anyhow`, `async-trait`, `num_enum`, `semver`, and `thiserror` are now
    optional dependencies.
  - Modified `unary_request` function to return `std::io::Result` instead of
    `anyhow::Result`.

### Removed

- Direct dependency on `quinn::Connection` in the public API. The `Connection`
  struct now encapsulates the `quinn::Connection` and `quinn::Endpoint`.
- Removed unused configurations and fields to streamline the crate and improve
  maintainability. These removals are based on the observation that these items
  were not being utilized by any applications depending on review-database.
  - `ReconvergeConfig` has been eliminated.
  - `review_address` field has been removed from `HogConfig`, `PigletConfig`,
    and `CrusherConfig`.

## [0.3.0] - 2024-05-28

### Added

- Added a public API that provides `frame` functionality to avoid exposing `oinq`'s
  `frame`. This change improves the modularity of the `review-protocol`.
- `server::send_trusted_domain_list` to facilitate sending the trusted domain
  list from the server to the client.

## Changed

- `HandshakeError::ReadError` now provides the underlying error as
  `std::io::Error`, which is more informative than the previous custom error
  type.
- Update `oinq` to version `0.13.0`. Updating to this version results in the
  following changes.
  - Bump dependencies.
    - Update quinn to version 0.11.
    - Update rustls to version 0.23.
    - Update rcgen to version 0.13.
  - Fixed the handling of the error types provided by `oinq`. `oinq` has
    changed from providing the `RecvError`/`SendError` error type to providing
    the `std::io::Error` error type. As a result, `review-protocol` has also
    been modified to `std::io::Error` or convert to the correct internally
    defined error type.

## [0.2.0] - 2024-04-04

### Added

- `AgentInfo` to represent the agent's information during the handshake process.
- `request::Handler`, `request::handle`, and other related types needed to
  implement a request handler.

### Changed

- `SendError::MessageTooLarge` no longer contains the underlying error,
  `std::num::TryFromIntError`, since it does not provide any useful information.
- Merge `SendError`'s `MessageTooLarge` and `SerializationFailure`, and
  `HandshakeError`'s `MessageTooLarge` and `SerializationFailure` into
  `MessageTooLarge`, since serialization into a memory buffer fails only when
  the message is too large.

## [0.1.2] - 2024-03-25

### Added

- Types used in the protocol:
  - `Process`
  - `TrafficFilterRule`
- `client::send_ok` and `client::send_err` methods to facilitate sending
  responses from the client to the server.

## [0.1.1] - 2024-03-21

### Added

- Types used in the protocol:
  - `Config`
  - `CrusherConfig`
  - `HogConfig`
  - `HostNetworkGroup`
  - `PigletConfig`
  - `ReconvergeConfig`
  - `ResourceUsage`
- `HandshakeError` for the handshake process.
- `frame` module for low-level protocol communication. This module provides the
  necessary communication primitives and ensures compatibility with the `oinq`
  crate until the protocol's full implementation.
- `client::send_request` method to facilitate initiating requests from the
  client to the server.

## [0.1.0] - 2024-03-15

### Added

- `unary_request` exchanges RPC-like messages between agents.
- The `request` module provides request handlers that an agent needs to
  implement.
- `client::handshake` implements the application-level handshake process for the
  client after a QUIC connection is established.

[Unreleased]: https://github.com/petabi/review-protocol/compare/0.19.0...main
[0.18.1]: https://github.com/petabi/review-protocol/compare/0.18.0...0.18.1
[0.18.0]: https://github.com/petabi/review-protocol/compare/0.17.0...0.18.0
[0.17.0]: https://github.com/petabi/review-protocol/compare/0.16.0...0.17.0
[0.16.0]: https://github.com/petabi/review-protocol/compare/0.15.0...0.16.0
[0.15.0]: https://github.com/petabi/review-protocol/compare/0.14.0...0.15.0
[0.14.0]: https://github.com/petabi/review-protocol/compare/0.13.0...0.14.0
[0.13.0]: https://github.com/petabi/review-protocol/compare/0.12.1...0.13.0
[0.12.1]: https://github.com/petabi/review-protocol/compare/0.12.0...0.12.1
[0.12.0]: https://github.com/petabi/review-protocol/compare/0.11.0...0.12.0
[0.11.0]: https://github.com/petabi/review-protocol/compare/0.10.0...0.11.0
[0.10.0]: https://github.com/petabi/review-protocol/compare/0.9.0...0.10.0
[0.9.0]: https://github.com/petabi/review-protocol/compare/0.8.1...0.9.0
[0.8.1]: https://github.com/petabi/review-protocol/compare/0.8.0...0.8.1
[0.8.0]: https://github.com/petabi/review-protocol/compare/0.7.0...0.8.0
[0.7.0]: https://github.com/petabi/review-protocol/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/petabi/review-protocol/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/petabi/review-protocol/compare/0.4.2...0.5.0
[0.4.2]: https://github.com/petabi/review-protocol/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/petabi/review-protocol/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/petabi/review-protocol/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/petabi/review-protocol/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/petabi/review-protocol/compare/0.1.2...0.2.0
[0.1.2]: https://github.com/petabi/review-protocol/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/petabi/review-protocol/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/petabi/review-protocol/tree/0.1.0
