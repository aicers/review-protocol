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
