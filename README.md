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

## Unidirectional Event Stream API

The crate provides a high-level API for handling unidirectional event streams,
encapsulating protocol details behind a clean trait-based interface.

### Basic Usage

Implement the `EventStreamHandler` trait to process events:

```rust
use review_protocol::{server::EventStreamHandler, types::EventMessage};

struct MyEventHandler;

#[async_trait::async_trait]
impl EventStreamHandler for MyEventHandler {
  async fn handle_event(&mut self, event: EventMessage) -> io::Result<()> {
    println!("Received event: {:?}", event.kind);
    Ok(())
  }
}
```

Then handle incoming streams. For a single stream:

```rust
connection.accept_event_stream(MyEventHandler).await?;
```

For multiple concurrent streams, drive `accept_uni` and dispatch each
stream to `Connection::handle_event_stream` inside a `tokio::spawn`. The
caller owns the spawn lifetime, concurrency policy, and error handling:

```rust
use std::sync::Arc;
use review_protocol::server::Connection;

let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
while let Ok(recv) = connection.accept_uni().await {
    let permit = semaphore.clone().acquire_owned().await?;
    let handler = MyEventHandler;
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = Connection::handle_event_stream(recv, handler).await {
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

Copyright 2024-2025 Petabi, Inc.

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
