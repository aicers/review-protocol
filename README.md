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

## Additive session API

The `session` module offers cloneable role-specific domain handles, unique
incoming stream owners, typed errors and outcome certainty, peer certificate
access, and bounded framing over oinq 0.14.0. Constructors require explicit
`SessionOptions`; `legacy_compatible()` selects the existing `u32` wire bound,
and applications can configure separate limits for each message family.

### Server listener and admission

With the `server` feature, `session::ServerListener::bind` binds a local
address, and `from_socket` adopts a prebound UDP socket. `local_addr` reports
the assigned address. Supply a rustls server configuration, transport
options, explicit frame limits, and a `ProtocolWindow`. For example,
`ProtocolWindow::new(">=0.48.0", "0.49.0")` accepts agents within that range
and sends `0.49.0` in the handshake success reply.

Acquire an application-owned permit before calling `accept`. Each cancel-safe
accept returns a separate `PendingSession` so the application can supervise
handshakes concurrently. The configured handshake deadline covers TLS and
the protocol exchange, measured from acceptance. Drop a pending owner or
cancel its handshake to abandon the attempt.

After a successful protocol exchange, `UnadmittedSession` exposes the TLS
peer certificate chain, agent claims, and a cloneable control handle. The
application interprets certificates and decides whether to admit the agent.
`admit` consumes the owner and binds the supplied authorization context and
policy to `ServerIncoming`. It sends no wire message. The resulting
`ServerHandle` exposes typed outbound operations. Close the control with a
reason to refuse admission immediately, or drop the unadmitted owner to
abort its connection. Control clones can await closure independently.

`reload_tls` applies the supplied verification, crypto-provider, and
client-certificate policy to future connections on the same socket. Existing
connections retain their negotiated configuration, and transport options
continue to apply to new connections.

`shutdown` wakes listener accepts and makes them return `None`. Accepted
sessions remain usable and keep their transport resources after listener
drop. For per-session shutdown, `drain` ends stream acceptance while existing
stream owners finish. `ServerIncoming::accept_next` is cancel-safe and
returns `None` after drain or orderly closure. The existing `accept` returns
a stream or a typed error. The application joins its stream tasks, closes
the connections, and can then await `wait_idle`. Use listener or session
`abort` for immediate closure and cancel supervised work separately.

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
