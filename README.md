# review-protocol

review-protocol serves as an application-level protocol implementation for the
REview ecosystem, utilizing QUIC for communication between agents. It builds
upon the message exchange framework provided by [oinq], focusing on high-level
operations, data manipulation, and protocol-specific features tailored to
facilitate efficient and secure communication within the REview ecosystem.

[![Coverage Status](https://codecov.io/gh/petabi/review-protocol/branch/main/graphs/badge.svg)](https://codecov.io/gh/petabi/review-protocol)

[oinq]: https://github.com/petabi/oinq

## Features

- **Bidirectional Request/Response**: High-level APIs for RPC-style
  communication
- **Unidirectional Event Streams**: Efficient handling of event streams from
  agents with protocol encapsulation
- **Type-safe Protocol**: Strongly typed message formats with Serde
  serialization
- **Connection Management**: Built-in handshake and connection lifecycle
  management
- **Error Handling**: Comprehensive error handling with custom recovery options

## Server session guide

The `session` module runs a protocol server through protocol-owned types: an
application binds, accepts, handshakes, admits, serves and shuts down without
naming a Quinn or oinq type. TLS verification, identity and authorization
policy stay in the application.

[`examples/session_server.rs`](examples/session_server.rs) is a complete,
self-contained server with in-process agents. It generates throwaway TLS
material, refuses one agent and admits another, serves a request stream and an
event stream concurrently, sends an outbound command, reloads TLS and shuts
down:

```bash
cargo run --example session_server --features client,server
```

### Ownership and lifecycle

Each stage has exactly one owner, and the application decides when to move on:

1. `ServerListener` owns the UDP endpoint. `ServerListener::bind` takes the
   address, the application's `rustls::ServerConfig` and
   `ServerListenerOptions`; `ServerListener::from_socket` adopts an
   already-bound socket. `accept` returns a `PendingSession` per connection
   attempt, or `None` once the listener is shut down. The listener spawns no
   application tasks.
2. `PendingSession` owns one attempt before TLS. `remote_addr` returns the
   peer's address as observed when the attempt arrived; read it before
   `handshake`, which consumes the owner, to log a TLS or protocol-handshake
   failure with the peer it came from. `handshake` performs TLS and the
   protocol handshake under one deadline and returns an `UnadmittedSession`.
   Dropping it abandons the attempt.
3. `UnadmittedSession` exposes what admission is decided from:
   `peer_certificates` (the TLS-verified chain) and `agent_claims` (the
   agent's self-reported `AgentInfo`, which grants nothing). `control` returns
   a `ServerSessionControl` to refuse with. Dropping it unadmitted closes the
   connection.
4. `UnadmittedSession::admit` binds an `AuthorizationContext` and a policy and
   returns the admitted owners: a cloneable `ServerHandle` for outbound
   commands, and the unique `ServerIncoming` that accepts the agent's streams
   as `ServerStream::Requests` (run with `ServerRequestStream::run`) or
   `ServerStream::DetectionEvents` (run with `DetectionEventReceiver::run`).

`ServerHandle` sends every manager-to-agent request: the `node_*` operations,
the engine commands, and the configuration and list pushes
`send_exclusion_list`, `send_watchlist`, `send_config_update_cmd`,
`send_delete_customer_data_cmd`, `send_filtering_rules`,
`send_internal_network_list`, `send_time_series_generation_policies`,
`send_tor_exit_node_list`, `send_trusted_domain_list` and
`send_trusted_user_agent_list`. Each push sends its list in the order given and
maps the agent's `Err(text)` to `SessionError::RemoteRejection(text)`.
`send_exclusion_list` and `send_watchlist` return
`SessionError::IncompatibleProtocol`, without sending, to an agent whose
handshake version is below `0.50.0`. There is no `send_ping`: transport
keepalive and the idle timeout in `ServerTransportOptions` cover liveness.

`ServerSessionControl` is a cloneable handle to the connection itself, without
dispatch or commands: `closed` waits for closure and reports a
`ServerSessionClose`, `drain` stops stream acceptance, `close` ends the session
with code zero, and `abort` refuses or aborts it with code one.

### Admission is not the handshake

A successful `handshake` means the agent's protocol version is inside the
listener's window, and the success reply has already been sent. Admission is
the application's separate decision, typically checking the verified
certificate against its enrolment records and the claims against that
identity. It adds no wire message: admitting is a local ownership transfer,
and refusing is closing the connection with `control().abort(reason)` after
the agent has seen handshake success.

### Protocol window, deadlines and frame limits

`ServerListenerOptions` holds every per-listener choice:

- `protocol`: a `ProtocolWindow`, for example
  `ProtocolWindow::new(MIN_PROTOCOL_VERSION_REQ, PROTOCOL_VERSION)`. A peer
  must satisfy the requirement and be at or below the advertised version;
  others get the structured rejection reply.
- `handshake_timeout`: one deadline spanning TLS and the protocol handshake,
  measured from `accept`, so a stalled peer cannot hold a pending slot.
- `session`: `SessionOptions` with a `FrameLimit` for each message family
  (`handshake`, `unary`, `detection_events`, `package_chunks`) and an
  optional `operation_timeout` for outbound operations.
  `SessionOptions::legacy_compatible()` selects the legacy `u32` wire bound
  for every family.
- `transport`: `ServerTransportOptions` for keepalive, idle timeout, stream
  counts and receive and send windows.

### Per-invocation authorization

`admit` binds the `AuthorizationContext` the application built from the
verified identity, together with an `Arc<dyn AuthorizerV2>`.
`ServerRequestStream::run` calls the policy before parsing and dispatching
every request, including several requests on one stream, so a policy change
takes effect on the next request rather than the next connection. A denial
sends one error reply and ends that stream's runner with
`ServerRunError::AuthorizationDenied`; other streams are unaffected.

### Supervision and bounded concurrency

The crate spawns no application tasks, so the application owns every future
and every limit:

- Acquire a permit (for example from a `tokio::sync::Semaphore`) before
  `ServerListener::accept`, and hold it in the task that runs `handshake`.
  This bounds pending handshakes; further attempts wait in the transport.
- Acquire a permit before `ServerIncoming::accept_next` and move it into the
  task that runs the stream, which bounds the runners of one session.
  `drain` wakes only an `accept_next` in progress: a supervisor waiting for a
  permit while every runner holds one does not see it, so give the supervisor
  its own shutdown signal (for example a `tokio::sync::watch` channel) as
  well.
- Keep the tasks in a `JoinSet` or hold their `JoinHandle`s, and join them.
  `ServerListener::accept` and `ServerIncoming::accept_next` are cancel-safe,
  so they can sit in a `tokio::select!` beside `JoinSet::join_next`.

### TLS reload

`ServerListener::reload_tls` installs a new `rustls::ServerConfig`, with its
own certificate, provider and client verification, for connections accepted
afterwards. Established sessions and handshakes already in TLS keep the
configuration they started with. An invalid config returns an error and leaves
the previous one installed.

### Shutdown and drain

Four controls end work, from the gentlest:

- `ServerListener::shutdown` stops acceptance only. Accepted sessions keep
  running.
- `ServerSessionControl::drain` then `ServerSessionControl::close` ends one
  session in order: stop taking streams, let the accepted ones finish, then
  close with code zero.
- `ServerListener::close` closes the endpoint and every connection on it at
  once with code zero, the code of normal shutdown.
- `ServerListener::abort` does the same with code one, the code of refusal.

For an orderly shutdown, use this order:

1. `ServerListener::shutdown` stops acceptance and wakes a pending `accept`,
   which returns `None`. Join the handshake tasks.
2. Call `drain` on each admitted session's `ServerSessionControl`.
   `ServerIncoming::accept_next` returns `None`; streams already accepted keep
   running and outbound commands stay available.
3. Join the session's runner tasks. Both runners return at the peer's clean
   end of stream, so bound the wait and abort what outlives it.
4. `close` the session.
5. `ServerListener::wait_idle` waits until the endpoint's connections have
   finished closing. It does not return while an admitted session is still
   open.

To close before draining instead, call `ServerListener::close` with a reason.
It stops acceptance and closes every connection on the endpoint with code zero
and that reason, so peers can tell normal shutdown from the code-one refusal
of `ServerListener::abort`. Admitted and unadmitted sessions see code zero, and
so do pending sessions whose TLS has completed, whose `handshake` then returns
`SessionError::Transport`. An attempt still in TLS, or accepted and not yet
handshaken, cannot carry an application code; its `handshake` fails no later
than the handshake deadline, and nothing is admitted. Nothing drains: accepted
runners see transport errors, and the application still joins its own tasks.
`ServerSessionControl::closed` reports `ServerSessionClose::Local`, and
`wait_idle` returns once transport shutdown completes. Neither a later `close`
or `abort`, nor closing a session through `ServerSessionControl` or dropping it
right after, changes the code and reason a peer observes; only
`ServerHandle::close`, which takes an explicit code, still applies its own.
`ServerListener::abort` closes the same way with code one; the application still
joins its own tasks.

## Unidirectional Detection Event Stream API

The crate provides a high-level API for handling unidirectional detection event
streams, encapsulating protocol details behind a clean trait-based interface.

### Basic Usage

Implement the `DetectionEventStreamHandler` trait to process detection events:

```rust
use review_protocol::{server::DetectionEventStreamHandler, types::DetectionEvent};

struct MyEventHandler;

#[async_trait::async_trait]
impl DetectionEventStreamHandler for MyEventHandler {
  async fn handle_detection_event(
    &mut self,
    event: DetectionEvent,
  ) -> io::Result<()> {
    println!("Received event: {:?}", event.detection_model);
    Ok(())
  }
}
```

Then handle incoming streams. For a single stream:

```rust
connection.accept_detection_event_stream(MyEventHandler).await?;
```

For multiple concurrent streams, drive `accept_uni` and dispatch each
stream to `Connection::handle_detection_event_stream` inside a `tokio::spawn`.
The caller owns the spawn lifetime, concurrency policy, and error handling:

```rust
use std::sync::Arc;
use review_protocol::server::Connection;

let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
while let Ok(recv) = connection.accept_uni().await {
    let permit = semaphore.clone().acquire_owned().await?;
    let handler = MyEventHandler;
    tokio::spawn(async move {
        let _permit = permit;
        let result = Connection::handle_detection_event_stream(recv, handler).await;
        if let Err(e) = result {
            tracing::warn!(error = %e, "event stream ended with error");
        }
    });
}
```

For more details, see:

- [API Documentation](src/server.rs) - Comprehensive API documentation with
  examples

### Integration Tests

Comprehensive integration tests are available in
`tests/unidirectional_streams.rs`, covering:

- Single and multiple concurrent streams
- Error handling and recovery
- Protocol compatibility verification
- Malformed data handling
- Large event processing
- Concurrency limiting

Run tests with:

```bash
cargo test --features client,server
```

## License

Copyright 2024-2026 Petabi, Inc.
Copyright 2026 ClumL Inc.

Licensed under [Apache License, Version 2.0][apache-license] (the "License");
you may not use this crate except in compliance with the License.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See [LICENSE](LICENSE) for
the specific language governing permissions and limitations under the License.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the [Apache-2.0
license][apache-license], shall be licensed as above, without any additional
terms or conditions.

[apache-license]: http://www.apache.org/licenses/LICENSE-2.0
