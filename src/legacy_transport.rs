//! Isolated Quinn compatibility framing for the retained public APIs.
//!
//! These adapters deliberately retain the historical unbounded decoding and
//! error signatures. New sessions use oinq transport wrappers and bounded frames.
pub(crate) use oinq::{frame, message, request};

#[cfg(any(feature = "client", all(test, feature = "server")))]
pub(crate) async fn unary<I: serde::Serialize, O: serde::de::DeserializeOwned>(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    code: u32,
    input: I,
) -> std::io::Result<O> {
    let mut buffer = Vec::new();
    bincode::serde::encode_into_std_write(
        crate::wire::request(code, input),
        &mut buffer,
        bincode::config::standard(),
    )
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    frame::send_raw(send, &buffer).await?;
    frame::recv(recv, &mut buffer).await
}

/// Decodes `bytes` as one `T` and rejects any bytes left over.
///
/// The exclusion-list and watchlist payloads use this instead of the prefix
/// decoding above: a `0.49.0` peer's `HostNetworkGroup` with no explicit hosts
/// starts with the same zero count as an empty `Vec<NetworkListItem>`, and
/// prefix decoding would read it as an empty list and silently clear a
/// populated one. Some other `0.49.0` groups are complete item lists and still
/// decode; only a handshake version check excludes them (see
/// `types::NetworkListItem`).
#[cfg(feature = "client")]
pub(crate) fn decode_exact<'de, T: serde::Deserialize<'de>>(
    bytes: &'de [u8],
) -> std::io::Result<T> {
    let (value, consumed) =
        bincode::serde::borrow_decode_from_slice(bytes, bincode::config::standard())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let trailing = bytes.len().saturating_sub(consumed);
    if trailing != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{trailing} unexpected trailing bytes after the payload"),
        ));
    }
    Ok(value)
}

/// Sends a unary request like [`unary`] and decodes the response with
/// [`decode_exact`].
#[cfg(feature = "client")]
pub(crate) async fn unary_exact<I: serde::Serialize, O: serde::de::DeserializeOwned>(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    code: u32,
    input: I,
) -> std::io::Result<O> {
    let mut buffer = Vec::new();
    bincode::serde::encode_into_std_write(
        crate::wire::request(code, input),
        &mut buffer,
        bincode::config::standard(),
    )
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    frame::send_raw(send, &buffer).await?;
    frame::recv_raw(recv, &mut buffer).await?;
    decode_exact(&buffer)
}
