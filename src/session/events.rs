//! Owned detection event framing with retained header and frame progress.
use std::sync::Arc;

use oinq::ApplicationCode;
#[cfg(feature = "server")]
use oinq::{RecvStream, frame::FramedReader};
#[cfg(feature = "client")]
use oinq::{SendStream, frame::FramedWriter};
#[cfg(feature = "server")]
use tokio::io::AsyncReadExt;
#[cfg(feature = "client")]
use tokio::io::AsyncWriteExt;

use super::FrameLimit;
#[cfg(feature = "server")]
use super::ServerRunError;
use super::Shared;
use super::{OutcomeCertainty, SessionError};

fn abort_code() -> ApplicationCode {
    ApplicationCode::new(1).expect("exchange abort code fits 62 bits")
}

/// A stream-owning incoming detection event sequence with cancellation-safe
/// progress.
#[cfg(feature = "server")]
pub struct DetectionEventReceiver {
    raw: Option<RecvStream>,
    reader: Option<FramedReader<RecvStream>>,
    header: [u8; 2],
    header_pos: usize,
    limit: FrameLimit,
    /// The session this stream was accepted on. The stream can outlive every
    /// other session owner, so it keeps the session, which repeats a
    /// listener-wide close when it drops last.
    session: Arc<Shared>,
}

#[cfg(feature = "server")]
impl DetectionEventReceiver {
    pub(super) fn new(recv: RecvStream, limit: FrameLimit, session: Arc<Shared>) -> Self {
        Self {
            raw: Some(recv),
            reader: None,
            header: [0; 2],
            header_pos: 0,
            limit,
            session,
        }
    }
    /// Processes this detection event stream with a server detection event
    /// handler.
    ///
    /// Both header bytes are reserved and ignored. Events and decode-error
    /// callbacks run in stream order. A complete frame with malformed event
    /// data is reported through `on_error` before reading the next frame. A
    /// clean frame-boundary EOF calls `on_stream_end` exactly once.
    ///
    /// This future owns the stream and the handler. The application supervises
    /// it and chooses concurrency across streams. Dropping it stops the stream
    /// and cancels any active callback. Effects already performed may remain.
    /// To suspend and resume reads with the receiver retained, use [`Self::next`].
    ///
    /// # Errors
    /// Returns classified framing, truncation, transport, or budget failures,
    /// or [`ServerRunError::DetectionEventHandler`] if a callback returns an I/O
    /// error.
    pub async fn run<H>(mut self, mut handler: H) -> Result<(), ServerRunError>
    where
        H: crate::server::DetectionEventStreamHandler + Send,
    {
        loop {
            match self.read_next().await? {
                Ok(Some(event)) => handler.handle_detection_event(event).await,
                Ok(None) => {
                    return handler
                        .on_stream_end()
                        .await
                        .map_err(ServerRunError::DetectionEventHandler);
                }
                Err(SessionError::Malformed { source, .. }) => {
                    handler.on_error(&format!("decoding error: {source}")).await
                }
                Err(error) => return Err(error.into()),
            }
            .map_err(ServerRunError::DetectionEventHandler)?;
        }
    }

    /// Reads the next bounded detection event, retaining partial progress when
    /// cancelled.
    ///
    /// An event frame that was read completely but cannot be decoded, for example
    /// a detection model added by a newer agent, returns a `Malformed` or
    /// `LimitExceeded` error and leaves the stream aligned: calling `next` again
    /// reads the following event, as the legacy `process_detection_event_stream`
    /// keeps reading after reporting the error. Every other error aborts the
    /// stream. A decoded event is returned as is, without
    /// [`DetectionEvent::validate`](crate::types::DetectionEvent::validate).
    /// # Errors
    /// Returns typed transport, truncation, malformed data, or allocation/payload-limit errors.
    pub async fn next(&mut self) -> Result<Option<crate::types::DetectionEvent>, SessionError> {
        match self.read_next().await {
            Ok(Ok(event)) => Ok(event),
            Ok(Err(undecodable)) => Err(undecodable),
            Err(error) => {
                self.abort();
                Err(error)
            }
        }
    }

    /// Reads the next frame; the inner error is a decoding failure of a frame
    /// that was read completely and recycled, after which the stream is intact.
    async fn read_next(
        &mut self,
    ) -> Result<Result<Option<crate::types::DetectionEvent>, SessionError>, SessionError> {
        while self.header_pos < 2 {
            let recv = self.raw.as_mut().ok_or_else(|| {
                SessionError::frame(oinq::frame::FrameError::Poisoned, OutcomeCertainty::Unknown)
            })?;
            let count = recv
                .read(&mut self.header[self.header_pos..])
                .await
                .map_err(|e| {
                    SessionError::transport(e, OutcomeCertainty::Unknown)
                        .on_connection(&self.session.connection)
                })?;
            if count == 0 {
                return Err(SessionError::transport(
                    std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
                    OutcomeCertainty::Unknown,
                )
                .on_connection(&self.session.connection));
            }
            self.header_pos += count;
        }
        if let Some(recv) = self.raw.take() {
            self.reader = Some(FramedReader::new(recv, self.limit.wire()));
        }
        let reader = self.reader.as_mut().ok_or_else(|| {
            SessionError::frame(oinq::frame::FrameError::Poisoned, OutcomeCertainty::Unknown)
        })?;
        let Some(frame) = reader.read().await.map_err(|e| {
            SessionError::frame(e, OutcomeCertainty::Unknown)
                .on_connection(&self.session.connection)
        })?
        else {
            return Ok(Ok(None));
        };
        let event = super::decode::decode(
            frame.as_bytes(),
            &super::decode::Budget::new(self.limit.get()),
        )
        .map(|(event, _)| Some(event));
        reader.recycle(frame.into_bytes()).map_err(|e| {
            SessionError::frame(e, OutcomeCertainty::Unknown)
                .on_connection(&self.session.connection)
        })?;
        Ok(event)
    }
    fn abort(&mut self) {
        if let Some(mut recv) = self.raw.take() {
            let _ = recv.stop(abort_code());
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.into_inner().stop(abort_code());
        }
    }
}
#[cfg(feature = "server")]
impl Drop for DetectionEventReceiver {
    fn drop(&mut self) {
        self.abort();
    }
}

/// A stream-owning detection event sender with explicit prepare/flush
/// resumption.
#[cfg(feature = "client")]
pub struct DetectionEventSender {
    session: Arc<Shared>,
    raw: Option<SendStream>,
    writer: Option<FramedWriter<SendStream>>,
    header_pos: usize,
    limit: FrameLimit,
}
#[cfg(feature = "client")]
impl DetectionEventSender {
    pub(super) fn new(send: SendStream, limit: FrameLimit, session: Arc<Shared>) -> Self {
        Self {
            session,
            raw: Some(send),
            writer: None,
            header_pos: 0,
            limit,
        }
    }
    /// Prepares a detection event after the stream header has been flushed.
    ///
    /// # Errors
    /// Returns a pending-header error, encoding error, or payload-limit error.
    pub fn start(&mut self, event: &crate::types::DetectionEvent) -> Result<(), SessionError> {
        self.start_serialized(event)
    }

    /// Prepares a value serialized with the peer's event schema.
    ///
    /// Hog's `EventMessage`, for example, contains a timestamp, kind, and byte
    /// fields and is not the same schema as [`DetectionEvent`](crate::types::DetectionEvent).
    ///
    /// # Errors
    /// Returns a pending-header error, encoding error, or payload-limit error.
    pub fn start_serialized<T: serde::Serialize>(&mut self, event: &T) -> Result<(), SessionError> {
        self.writer
            .as_mut()
            .ok_or_else(|| {
                SessionError::frame(oinq::frame::FrameError::Pending, OutcomeCertainty::NotSent)
            })?
            .start(event)
            .map_err(|e| {
                SessionError::frame(e, OutcomeCertainty::NotSent)
                    .on_connection(&self.session.connection)
            })
    }
    /// Flushes the protocol header or pending event; cancelling retains all progress.
    /// # Errors
    /// Returns classified transport errors and aborts the stream on failure.
    pub async fn flush(&mut self) -> Result<(), SessionError> {
        let result = self.flush_inner().await;
        if result.is_err() {
            self.abort();
        }
        result
    }
    async fn flush_inner(&mut self) -> Result<(), SessionError> {
        while self.header_pos < 2 {
            let send = self.raw.as_mut().ok_or_else(|| {
                SessionError::frame(oinq::frame::FrameError::Poisoned, OutcomeCertainty::Unknown)
            })?;
            let count = send.write(&[0, 0][self.header_pos..]).await.map_err(|e| {
                SessionError::transport(e, OutcomeCertainty::Unknown)
                    .on_connection(&self.session.connection)
            })?;
            if count == 0 {
                return Err(SessionError::transport(
                    std::io::Error::from(std::io::ErrorKind::WriteZero),
                    OutcomeCertainty::Unknown,
                )
                .on_connection(&self.session.connection));
            }
            self.header_pos += count;
        }
        if let Some(send) = self.raw.take() {
            self.writer = Some(FramedWriter::new(send, self.limit.wire()));
        }
        self.writer
            .as_mut()
            .ok_or_else(|| {
                SessionError::frame(oinq::frame::FrameError::Poisoned, OutcomeCertainty::Unknown)
            })?
            .flush()
            .await
            .map_err(|e| {
                SessionError::frame(e, OutcomeCertainty::Unknown)
                    .on_connection(&self.session.connection)
            })
    }
    /// Flushes prepared bytes, queues FIN, and waits for receipt of all data and FIN.
    ///
    /// Receipt confirms transport acknowledgment, not application processing.
    /// Dropping this future aborts the stream. No operation deadline is applied;
    /// the caller can impose one with `tokio::time::timeout`.
    ///
    /// # Errors
    /// Returns [`SessionError::StreamStopped`] with the peer's code for a stop
    /// during flushing, finishing, or waiting. Connection loss is classified as
    /// [`SessionError::Transport`].
    pub async fn finish_and_wait(mut self) -> Result<(), SessionError> {
        let flushed = self.flush_inner().await;
        if let Some(writer) = self.writer.take() {
            self.raw = Some(writer.into_inner());
        }
        let send = self.raw.as_mut().ok_or_else(|| {
            SessionError::frame(oinq::frame::FrameError::Poisoned, OutcomeCertainty::Unknown)
        })?;
        let finished = flushed.and_then(|()| {
            send.finish().map_err(|error| {
                SessionError::transport(error, OutcomeCertainty::Unknown)
                    .on_connection(&self.session.connection)
            })
        });
        if let Err(error) = finished {
            // A failed write/FIN can hide STOP_SENDING behind an I/O error.
            // Query the retained stream before resetting it to preserve the code.
            if matches!(error, SessionError::Transport { .. })
                && let Ok(Some(code)) = send.stopped().await
            {
                return Err(SessionError::StreamStopped {
                    code: super::ApplicationCode::from_wire(code),
                });
            }
            return Err(error);
        }
        let receipt = send.stopped().await.map_err(|error| {
            SessionError::transport(error, OutcomeCertainty::Unknown)
                .on_connection(&self.session.connection)
        })?;
        if let Some(code) = receipt {
            return Err(SessionError::StreamStopped {
                code: super::ApplicationCode::from_wire(code),
            });
        }
        self.raw.take();
        Ok(())
    }

    /// Flushes prepared bytes and queues FIN without waiting for receipt.
    /// # Errors
    /// Returns errors from flushing or queuing FIN.
    pub async fn finish(mut self) -> Result<(), SessionError> {
        self.flush().await?;
        if let Some(writer) = self.writer.take() {
            let mut send = writer.into_inner();
            if let Err(error) = send.finish() {
                let _ = send.reset(abort_code());
                return Err(SessionError::transport(error, OutcomeCertainty::Unknown)
                    .on_connection(&self.session.connection));
            }
        }
        Ok(())
    }
    fn abort(&mut self) {
        if let Some(mut send) = self.raw.take() {
            let _ = send.reset(abort_code());
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.into_inner().reset(abort_code());
        }
    }
}
#[cfg(feature = "client")]
impl Drop for DetectionEventSender {
    fn drop(&mut self) {
        self.abort();
    }
}

#[cfg(feature = "client")]
impl super::AgentHandle {
    /// Opens an owned detection event stream; flushes its header before
    /// returning it.
    /// # Errors
    /// Returns classified transport or deadline errors. Cancelling aborts an opened stream.
    pub async fn open_detection_event_stream(&self) -> Result<DetectionEventSender, SessionError> {
        let operation = async {
            let send = self.0.connection.open_uni().await.map_err(|e| {
                SessionError::transport(e, OutcomeCertainty::NotSent)
                    .on_connection(&self.0.connection)
            })?;
            let mut sender =
                DetectionEventSender::new(send, self.0.options.detection_events, self.0.clone());
            sender.flush().await?;
            Ok(sender)
        };
        if let Some(timeout) = self.0.options.operation_timeout {
            tokio::time::timeout(timeout, operation)
                .await
                .map_err(|source| SessionError::Deadline {
                    // Opening the stream submits no domain event yet.
                    certainty: OutcomeCertainty::NotSent,
                    source: Some(source),
                })?
        } else {
            operation.await
        }
    }
}
