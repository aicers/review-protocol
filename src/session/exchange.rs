//! Stream ownership and the single bounded request/exchange path.
use oinq::{
    ApplicationCode, Connection, RecvStream, SendStream,
    frame::{Frame, FrameLimit, FramedReader, FramedWriter},
};
use serde::{Serialize, de::DeserializeOwned};

use super::{OutcomeCertainty, SessionError, SessionOptions};

pub(super) struct Exchange {
    reader: Option<FramedReader<RecvStream>>,
    writer: Option<FramedWriter<SendStream>>,
    finishing: Option<SendStream>,
    limit: FrameLimit,
    pub(super) certainty: OutcomeCertainty,
}

impl Exchange {
    pub(super) fn new(send: SendStream, recv: RecvStream, limit: FrameLimit) -> Self {
        Self {
            finishing: None,
            limit,
            reader: Some(FramedReader::new(recv, limit)),
            writer: Some(FramedWriter::new(send, limit)),
            certainty: OutcomeCertainty::NotSent,
        }
    }

    pub(super) fn start<T: Serialize>(&mut self, value: T) -> Result<(), SessionError> {
        self.writer
            .as_mut()
            .ok_or_else(|| SessionError::frame(oinq::frame::FrameError::Poisoned, self.certainty))?
            .start(value)
            .map_err(|e| SessionError::frame(e, self.certainty))
    }

    pub(super) fn start_request<T: Serialize>(
        &mut self,
        code: u32,
        payload: T,
    ) -> Result<(), SessionError> {
        // A fixed byte array has no bincode length prefix; request codes are LE
        // even though bincode's standard integer encoding is variable length.
        self.start(crate::wire::request(code, payload))
    }

    pub(super) async fn flush(&mut self) -> Result<(), SessionError> {
        self.certainty = OutcomeCertainty::Unknown;
        let result = self
            .writer
            .as_mut()
            .ok_or_else(|| SessionError::frame(oinq::frame::FrameError::Poisoned, self.certainty))?
            .flush()
            .await;
        if let Err(e) = result {
            self.abort();
            return Err(SessionError::frame(e, self.certainty));
        }
        Ok(())
    }

    pub(super) async fn frame(&mut self) -> Result<Frame, SessionError> {
        self.next_frame().await?.ok_or_else(|| {
            self.abort();
            SessionError::transport(
                std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
                self.certainty,
            )
        })
    }

    pub(super) async fn next_frame(&mut self) -> Result<Option<Frame>, SessionError> {
        let result = self
            .reader
            .as_mut()
            .ok_or_else(|| SessionError::frame(oinq::frame::FrameError::Poisoned, self.certainty))?
            .read()
            .await;
        match result {
            Ok(frame) => Ok(frame),
            Err(e) => {
                self.abort();
                Err(SessionError::frame(e, self.certainty))
            }
        }
    }

    pub(super) fn cancel(&mut self) {
        self.abort();
    }

    #[cfg(feature = "server")]
    pub(super) fn start_raw(&mut self, bytes: &[u8]) -> Result<(), SessionError> {
        self.writer
            .as_mut()
            .ok_or_else(|| SessionError::frame(oinq::frame::FrameError::Poisoned, self.certainty))?
            .start_raw(bytes)
            .map_err(|e| SessionError::frame(e, self.certainty))
    }

    #[cfg(feature = "client")]
    pub(super) fn recycle_bytes(&mut self, bytes: Vec<u8>) -> Result<(), SessionError> {
        self.reader
            .as_mut()
            .ok_or_else(|| SessionError::frame(oinq::frame::FrameError::Poisoned, self.certainty))?
            .recycle(bytes)
            .map_err(|e| SessionError::frame(e, self.certainty))
    }

    pub(super) fn recycle(&mut self, frame: Frame) -> Result<(), SessionError> {
        self.reader
            .as_mut()
            .ok_or_else(|| SessionError::frame(oinq::frame::FrameError::Poisoned, self.certainty))?
            .recycle(frame.into_bytes())
            .map_err(|e| SessionError::frame(e, self.certainty))
    }

    pub(super) async fn receive<T: DeserializeOwned>(&mut self) -> Result<T, SessionError> {
        let frame = self.frame().await?;
        let result = super::decode::decode(
            frame.as_bytes(),
            &super::decode::Budget::new(self.limit.get()),
        )
        .map(|(value, _)| value);
        self.recycle(frame)?;
        if result.is_err() {
            self.abort();
        }
        result
    }

    #[cfg(feature = "server")]
    pub(super) async fn finish_and_wait(&mut self) -> Result<(), SessionError> {
        if let Some(writer) = self.writer.take() {
            self.finishing = Some(writer.into_inner());
        }
        if let Some(send) = self.finishing.as_mut() {
            send.finish()
                .map_err(|e| SessionError::transport(e, self.certainty))?;
            send.stopped()
                .await
                .map_err(|e| SessionError::transport(e, self.certainty))?;
        }
        self.finishing.take();
        self.finish()
    }

    pub(super) fn complete(&mut self) {
        // A terminal response establishes the domain result. A peer STOP racing
        // with our FIN must not replace that result with a transport failure.
        let _ = self.finish();
    }

    pub(super) fn finish(&mut self) -> Result<(), SessionError> {
        if let Some(writer) = self.writer.take() {
            let mut send = writer.into_inner();
            if let Err(e) = send.finish() {
                let _ = send.reset(abort_code());
                self.abort();
                return Err(SessionError::transport(e, self.certainty));
            }
        }
        if let Some(reader) = self.reader.take() {
            // No additional response is part of this exchange.
            let _ = reader.into_inner().stop(abort_code());
        }
        Ok(())
    }

    pub(super) fn set_limits(&mut self, read_limit: FrameLimit, write_limit: FrameLimit) {
        // Called only at known frame boundaries, never across a suspended read.
        self.limit = read_limit;
        if let Some(reader) = self.reader.take() {
            self.reader = Some(FramedReader::new(reader.into_inner(), read_limit));
        }
        if let Some(writer) = self.writer.take() {
            self.writer = Some(FramedWriter::new(writer.into_inner(), write_limit));
        }
    }

    fn abort(&mut self) {
        if let Some(mut send) = self.finishing.take() {
            let _ = send.reset(abort_code());
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.into_inner().reset(abort_code());
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.into_inner().stop(abort_code());
        }
    }
}

fn abort_code() -> ApplicationCode {
    ApplicationCode::new(1).expect("the reserved exchange-abort code fits 62 bits")
}

impl Drop for Exchange {
    fn drop(&mut self) {
        self.abort();
    }
}

pub(super) async fn unary<I: Serialize, O: DeserializeOwned>(
    connection: &Connection,
    options: &SessionOptions,
    code: u32,
    input: I,
) -> Result<O, SessionError> {
    let mut certainty = OutcomeCertainty::NotSent;
    let operation = async {
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| SessionError::transport(e, certainty))?;
        let mut exchange = Exchange::new(send, recv, options.unary);
        exchange.start_request(code, input)?;
        certainty = OutcomeCertainty::Unknown;
        exchange.flush().await?;
        let response: Result<O, String> = exchange.receive().await?;
        exchange.complete();
        response.map_err(SessionError::RemoteRejection)
    };
    if let Some(timeout) = options.operation_timeout {
        match tokio::time::timeout(timeout, operation).await {
            Ok(result) => result,
            Err(source) => Err(SessionError::Deadline {
                certainty,
                source: Some(source),
            }),
        }
    } else {
        operation.await
    }
}

#[cfg(feature = "server")]
pub(super) async fn send_only<I: Serialize>(
    connection: &Connection,
    options: &SessionOptions,
    code: u32,
    input: I,
) -> Result<(), SessionError> {
    let mut certainty = OutcomeCertainty::NotSent;
    let operation = async {
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| SessionError::transport(e, certainty))?;
        let mut exchange = Exchange::new(send, recv, options.unary);
        exchange.start_request(code, input)?;
        certainty = OutcomeCertainty::Unknown;
        exchange.flush().await?;
        exchange.finish()
    };
    if let Some(timeout) = options.operation_timeout {
        match tokio::time::timeout(timeout, operation).await {
            Ok(result) => result,
            Err(source) => Err(SessionError::Deadline {
                certainty,
                source: Some(source),
            }),
        }
    } else {
        operation.await
    }
}
