//! Owned event framing with retained header and frame progress.
use oinq::{ApplicationCode, frame::FrameLimit};
#[cfg(feature = "server")]
use oinq::{RecvStream, frame::FramedReader};
#[cfg(feature = "client")]
use oinq::{SendStream, frame::FramedWriter};
#[cfg(feature = "server")]
use tokio::io::AsyncReadExt;
#[cfg(feature = "client")]
use tokio::io::AsyncWriteExt;

use super::{OutcomeCertainty, SessionError};

fn abort_code() -> ApplicationCode {
    ApplicationCode::new(1).expect("exchange abort code fits 62 bits")
}

/// A stream-owning incoming event sequence with cancellation-safe progress.
#[cfg(feature = "server")]
pub struct EventReceiver {
    raw: Option<RecvStream>,
    reader: Option<FramedReader<RecvStream>>,
    header: [u8; 2],
    header_pos: usize,
    limit: FrameLimit,
}

#[cfg(feature = "server")]
impl EventReceiver {
    pub(super) fn new(recv: RecvStream, limit: FrameLimit) -> Self {
        Self {
            raw: Some(recv),
            reader: None,
            header: [0; 2],
            header_pos: 0,
            limit,
        }
    }
    /// Reads the next bounded event, retaining partial progress when cancelled.
    /// # Errors
    /// Returns typed transport, truncation, malformed data, or allocation/payload-limit errors.
    pub async fn next(&mut self) -> Result<Option<crate::types::EventMessage>, SessionError> {
        let result = self.read_next().await;
        if result.is_err() {
            self.abort();
        }
        result
    }
    async fn read_next(&mut self) -> Result<Option<crate::types::EventMessage>, SessionError> {
        while self.header_pos < 2 {
            let recv = self.raw.as_mut().ok_or_else(|| {
                SessionError::frame(oinq::frame::FrameError::Poisoned, OutcomeCertainty::Unknown)
            })?;
            let count = recv
                .read(&mut self.header[self.header_pos..])
                .await
                .map_err(|e| SessionError::transport(e, OutcomeCertainty::Unknown))?;
            if count == 0 {
                return Err(SessionError::transport(
                    std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
                    OutcomeCertainty::Unknown,
                ));
            }
            self.header_pos += count;
        }
        if let Some(recv) = self.raw.take() {
            self.reader = Some(FramedReader::new(recv, self.limit));
        }
        let reader = self.reader.as_mut().ok_or_else(|| {
            SessionError::frame(oinq::frame::FrameError::Poisoned, OutcomeCertainty::Unknown)
        })?;
        let Some(frame) = reader
            .read()
            .await
            .map_err(|e| SessionError::frame(e, OutcomeCertainty::Unknown))?
        else {
            return Ok(None);
        };
        let (event, _) = super::decode::decode(
            frame.as_bytes(),
            &super::decode::Budget::new(self.limit.get()),
        )?;
        reader
            .recycle(frame.into_bytes())
            .map_err(|e| SessionError::frame(e, OutcomeCertainty::Unknown))?;
        Ok(Some(event))
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
impl Drop for EventReceiver {
    fn drop(&mut self) {
        self.abort();
    }
}

/// A stream-owning event sender with explicit prepare/flush resumption.
#[cfg(feature = "client")]
pub struct EventSender {
    raw: Option<SendStream>,
    writer: Option<FramedWriter<SendStream>>,
    header_pos: usize,
    limit: FrameLimit,
}
#[cfg(feature = "client")]
impl EventSender {
    pub(super) fn new(send: SendStream, limit: FrameLimit) -> Self {
        Self {
            raw: Some(send),
            writer: None,
            header_pos: 0,
            limit,
        }
    }
    /// Prepares an event after the stream header has been flushed.
    /// # Errors
    /// Returns a pending-header error, encoding error, or payload-limit error.
    pub fn start(&mut self, event: &crate::types::EventMessage) -> Result<(), SessionError> {
        self.writer
            .as_mut()
            .ok_or_else(|| {
                SessionError::frame(oinq::frame::FrameError::Pending, OutcomeCertainty::NotSent)
            })?
            .start(event)
            .map_err(|e| SessionError::frame(e, OutcomeCertainty::NotSent))
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
            let count = send
                .write(&[0, 0][self.header_pos..])
                .await
                .map_err(|e| SessionError::transport(e, OutcomeCertainty::Unknown))?;
            if count == 0 {
                return Err(SessionError::transport(
                    std::io::Error::from(std::io::ErrorKind::WriteZero),
                    OutcomeCertainty::Unknown,
                ));
            }
            self.header_pos += count;
        }
        if let Some(send) = self.raw.take() {
            self.writer = Some(FramedWriter::new(send, self.limit));
        }
        self.writer
            .as_mut()
            .ok_or_else(|| {
                SessionError::frame(oinq::frame::FrameError::Poisoned, OutcomeCertainty::Unknown)
            })?
            .flush()
            .await
            .map_err(|e| SessionError::frame(e, OutcomeCertainty::Unknown))
    }
    /// Finishes the stream after all prepared bytes have been flushed.
    /// # Errors
    /// Returns errors from flushing or queuing FIN.
    pub async fn finish(mut self) -> Result<(), SessionError> {
        self.flush().await?;
        if let Some(writer) = self.writer.take() {
            let mut send = writer.into_inner();
            if let Err(error) = send.finish() {
                let _ = send.reset(abort_code());
                return Err(SessionError::transport(error, OutcomeCertainty::Unknown));
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
impl Drop for EventSender {
    fn drop(&mut self) {
        self.abort();
    }
}

#[cfg(feature = "client")]
impl super::AgentHandle {
    /// Opens an owned event stream; flushes its header before returning it.
    /// # Errors
    /// Returns classified transport or deadline errors. Cancelling aborts an opened stream.
    pub async fn open_event_stream(&self) -> Result<EventSender, SessionError> {
        let operation = async {
            let send = self
                .0
                .connection
                .open_uni()
                .await
                .map_err(|e| SessionError::transport(e, OutcomeCertainty::NotSent))?;
            let mut sender = EventSender::new(send, self.0.options.events);
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
