//! Typed protocol adapters sharing bounded exchange machinery.
#[cfg(feature = "server")]
use std::collections::HashSet;
use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[cfg(feature = "client")]
use super::exchange::{Decoding, unary_as};
use super::{
    OutcomeCertainty, SessionError, Shared,
    decode::decode,
    exchange::{Exchange, unary},
};
#[cfg(feature = "server")]
use super::{ServerRunError, ServerSessionClose, ServerSessionControl, listener::unsent};
#[cfg(feature = "client")]
use crate::types::node::NodePowerResponse;
use crate::types::node::{
    NodeEnrollRequest, NodeEnrollResponse, NodeHostnameRequest, NodeHostnameResponse,
    NodeLoggingRequest, NodeLoggingResponse, NodeNetworkInterfaceRequest,
    NodeNetworkInterfaceResponse, NodeObservationRequest, NodeObservationResponse,
    NodePackageRequest, NodePackageResponse, NodePowerRequest, NodeRemoteAccessRequest,
    NodeRemoteAccessResponse, NodeServiceRequest, NodeServiceResponse, NodeTimeSyncRequest,
    NodeTimeSyncResponse, NodeVersionRequest, NodeVersionResponse,
};
use crate::types::{
    CloneModelRequest, CustomerDataDeletionReport, DetectorStatusReport, EngineExclusionReport,
    NetworkListItem, ReportedRunState, TrainModelRequest,
};
#[cfg(feature = "server")]
use crate::{
    auth::{AuthorizationContext, AuthorizerV2},
    server::{Handler, RequestCode as ServerCode},
    types::{
        ColumnStatisticsUpdate, CustomerDataDeletionRequest, DaiCursors, DaiExtractorConfig,
        DaiObservationBatch, DaiRangeDay, DaiRangeGrant, DaiRangeLate, DaiRangeMark, DaiRangeUnit,
        DaiStoreAck, DataSource, DataSourceKey, DetectionEvent, HostNetworkGroup, OutlierInfo,
        TimeSeriesGenerationPolicy, TimeSeriesUpdate, TrafficFilterRule, UpdateClusterRequest,
    },
};

/// A single-use typed response capability borrowing its request stream.
///
/// Responding releases the borrow so the stream can read the next request.
/// Dropping this capability or its response future before completion aborts both
/// stream directions. Authorize each request before invoking its handler.
pub struct Reply<'a, T> {
    exchange: ExchangeLease<'a>,
    response: PhantomData<T>,
}
impl<T: Serialize> Reply<'_, T> {
    /// Sends a domain response without ending the request stream.
    /// # Errors
    /// Returns classified encoding, limit, or transport errors.
    pub async fn respond(mut self, response: Result<T, String>) -> Result<(), SessionError> {
        self.exchange.start(response)?;
        self.exchange.flush().await?;
        self.exchange.release();
        Ok(())
    }

    /// Completes an invocation whose wire contract has no response.
    ///
    /// Use this for immediate reboot/shutdown after invoking the handler.
    pub fn complete_without_response(mut self) {
        self.exchange.release();
    }
}

struct ExchangeLease<'a>(Option<&'a mut Exchange>);
impl ExchangeLease<'_> {
    fn release(&mut self) {
        self.0.take();
    }
}
impl Deref for ExchangeLease<'_> {
    type Target = Exchange;
    fn deref(&self) -> &Exchange {
        self.0
            .as_deref()
            .expect("a response holds its exchange until completion")
    }
}
impl DerefMut for ExchangeLease<'_> {
    fn deref_mut(&mut self) -> &mut Exchange {
        self.0
            .as_deref_mut()
            .expect("a response holds its exchange until completion")
    }
}
impl Drop for ExchangeLease<'_> {
    fn drop(&mut self) {
        if let Some(exchange) = self.0.take() {
            exchange.cancel();
        }
    }
}
impl ExchangeLease<'_> {
    /// Decodes the arguments of request `code` and recycles its frame.
    ///
    /// Low-level streams answer undecodable arguments with a rejection
    /// before the stream ends at this frame boundary, so a peer reads
    /// a remote rejection naming the code rather than a reset. The returned error
    /// is the decoding or limit error; a failure to send the answer cannot replace
    /// it. Cancelling the answer aborts the stream, which was ending anyway.
    async fn arguments<T: DeserializeOwned>(
        &mut self,
        code: u32,
        frame: oinq::frame::Frame,
        limit: usize,
    ) -> Result<T, SessionError> {
        let result = arguments(&frame, limit);
        self.recycle(frame)?;
        let error = match result {
            Ok(arguments) => return Ok(arguments),
            Err(error) => error,
        };
        let answer = match error {
            SessionError::LimitExceeded { .. } => format!(
                "request code {code}: the arguments exceed the receiving peer's configured limit"
            ),
            _ => crate::wire::undecodable_args_message(code),
        };
        if self.start(Err::<(), String>(answer)).is_ok() && self.flush().await.is_ok() {
            let _ = self.finish();
        }
        Err(error)
    }

    #[cfg(feature = "server")]
    async fn server_arguments<T: DeserializeOwned>(
        &mut self,
        code: u32,
        frame: oinq::frame::Frame,
        limit: usize,
        report_bad_arguments: bool,
    ) -> Result<T, SessionError> {
        if report_bad_arguments {
            return self.arguments(code, frame, limit).await;
        }

        // The legacy server dispatcher returns argument errors without a response.
        let result = arguments(&frame, limit);
        self.recycle(frame)?;
        if result.is_err() {
            self.complete();
        }
        result
    }
}

fn malformed(message: &'static str) -> SessionError {
    SessionError::malformed(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

struct RequestOwner {
    exchange: Exchange,
    options: super::SessionOptions,
    ended: bool,
    /// An answer to an unserved request code is prepared but not yet flushed.
    answering: bool,
}
impl RequestOwner {
    fn new(send: oinq::SendStream, recv: oinq::RecvStream, options: super::SessionOptions) -> Self {
        Self {
            exchange: Exchange::new(send, recv, options.unary),
            options,
            ended: false,
            answering: false,
        }
    }

    /// Reads the next request whose code `serves` accepts.
    ///
    /// Any other code is answered with `unserved(code)` as a remote rejection,
    /// as the legacy dispatchers do, and the stream continues with the next
    /// frame. The answer's flush resumes on the next call when cancelled.
    async fn next(
        &mut self,
        serves: fn(u32) -> bool,
        unserved: fn(u32) -> String,
    ) -> Result<Option<(u32, oinq::frame::Frame)>, SessionError> {
        loop {
            self.flush_unserved().await?;
            let Some((code, frame)) = self.read_request().await? else {
                return Ok(None);
            };
            if serves(code) {
                return Ok(Some((code, frame)));
            }
            self.refuse(frame, &unserved(code))?;
        }
    }

    /// Prepares `message` as the error answer to the request in `frame`; the
    /// next [`Self::flush_unserved`] sends it.
    fn refuse(&mut self, frame: oinq::frame::Frame, message: &str) -> Result<(), SessionError> {
        self.exchange.recycle(frame)?;
        self.exchange.start(Err::<(), &str>(message))?;
        self.answering = true;
        Ok(())
    }

    async fn flush_unserved(&mut self) -> Result<(), SessionError> {
        if self.answering {
            self.exchange.flush().await?;
            self.answering = false;
        }
        Ok(())
    }

    async fn read_request(&mut self) -> Result<Option<(u32, oinq::frame::Frame)>, SessionError> {
        if self.ended {
            return Ok(None);
        }
        let Some(frame) = self.exchange.next_frame().await? else {
            self.ended = true;
            self.exchange.complete();
            return Ok(None);
        };
        let Some(code) = frame.as_bytes().first_chunk::<4>() else {
            self.exchange.cancel();
            return Err(malformed("request code is truncated"));
        };
        Ok(Some((u32::from_le_bytes(*code), frame)))
    }
}

/// Whether a code is handed back to the caller by the legacy dispatcher.
#[cfg(feature = "server")]
fn server_delegates(code: ServerCode) -> bool {
    matches!(
        code,
        ServerCode::GetMaxEventIdNum | ServerCode::RemoveOutliers | ServerCode::GetDataSourceList
    )
}

#[cfg(feature = "server")]
fn server_unserved(_code: u32) -> String {
    crate::server::UNKNOWN_REQUEST_CODE.to_owned()
}

/// Returns the error a manager answers a list pull with when the agent
/// advertised `version`, earlier than the item lists, or `None` for any other
/// request code.
#[cfg(feature = "server")]
fn server_network_list_refusal(code: u32, blocker: Option<&str>) -> Option<String> {
    let version = blocker?;
    matches!(
        ServerCode::from(code),
        ServerCode::GetExclusionList | ServerCode::GetWatchlist
    )
    .then(|| {
        format!(
            "request code {code} requires protocol {}, but the agent advertised {version}",
            crate::NETWORK_LIST_ITEMS_REQ
        )
    })
}

/// Whether [`AgentRequestStream::next`] dispatches request `code`.
#[cfg(feature = "client")]
fn agent_serves(code: u32) -> bool {
    use crate::client::RequestCode as C;
    matches!(
        C::from(code),
        C::NodeService
            | C::NodeNetworkInterface
            | C::NodeHostname
            | C::NodeTimeSync
            | C::NodeLogging
            | C::NodeRemoteAccess
            | C::NodeObservation
            | C::NodeVersion
            | C::NodeEnroll
            | C::NodePower
            | C::NodePackage
            | C::TrainModel
            | C::CloneModel
            | C::CancelRun
            | C::RunDetectorOnce
    )
}

/// The legacy agent dispatcher's answer to a code it does not serve.
#[cfg(feature = "client")]
fn agent_unserved(code: u32) -> String {
    format!("unknown request code: {code}")
}

fn arguments<'a, T: Deserialize<'a>>(
    frame: &'a oinq::frame::Frame,
    limit: usize,
) -> Result<T, SessionError> {
    let bytes = frame
        .as_bytes()
        .get(4..)
        .ok_or_else(|| malformed("request code is truncated"))?;
    decode(bytes, &super::decode::Budget::new(limit)).map(|(value, _)| value)
}

/// An accepted manager-side stream, ready for application supervision.
///
/// Acceptance does not read a request or event header. A stalled stream therefore
/// does not block acceptance of other streams. Retain and join each runner task.
#[cfg(feature = "server")]
pub enum ServerStream {
    /// A stream containing zero or more sequential requests.
    Requests(ServerRequestStream),
    /// An ordered detection event sequence.
    DetectionEvents(super::DetectionEventReceiver),
}

/// The unique server-side owner of incoming stream acceptance.
///
/// Dropping it ends acceptance and leaves any accepted streams and other
/// handles alive. The application supervises and joins its stream tasks.
#[cfg(feature = "server")]
pub struct ServerIncoming {
    shared: Arc<Shared>,
    control: ServerSessionControl,
    authorization: Option<Arc<ServerAuthorization>>,
}
#[cfg(feature = "server")]
impl ServerIncoming {
    pub(super) fn new(shared: Arc<Shared>) -> Self {
        let control = ServerSessionControl::new(shared.connection.clone());
        Self::with_control(shared, control)
    }

    pub(super) fn with_control(shared: Arc<Shared>, control: ServerSessionControl) -> Self {
        Self {
            shared,
            control,
            authorization: None,
        }
    }

    /// Returns a cloneable handle for draining, closing, or monitoring this session.
    #[must_use]
    pub fn control(&self) -> ServerSessionControl {
        self.control.clone()
    }

    /// Binds the application's authenticated context and policy for subsequently
    /// accepted request streams.
    ///
    /// The transport handshake supplies peer claims. The application interprets
    /// verified credentials and constructs the authorization context. Event
    /// streams have their own application handler. This binding adds no wire
    /// messages.
    #[must_use]
    pub fn with_authorization(
        mut self,
        context: AuthorizationContext,
        policy: Arc<dyn AuthorizerV2>,
    ) -> Self {
        self.authorization = Some(Arc::new(ServerAuthorization { context, policy }));
        self
    }

    /// Accepts the next request or event stream without reading its contents.
    ///
    /// Cancellation consumes no stream. Both directions are polled concurrently;
    /// applications supervise the returned owners independently.
    /// # Errors
    /// Returns a classified transport error when acceptance is drained or the
    /// connection closes. Use [`Self::accept_next`] for clean exhaustion.
    pub async fn accept(&mut self) -> Result<ServerStream, SessionError> {
        self.accept_until_drained().await?.ok_or_else(|| {
            unsent(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "incoming stream acceptance drained",
            ))
        })
    }

    /// Accepts the next stream or returns `None` on clean exhaustion.
    ///
    /// Drain, local closure, or peer closure with application code zero ends
    /// acceptance. An accept that wins a race with drain can still return
    /// its stream. Cancellation consumes no stream.
    ///
    /// # Errors
    /// Returns a typed transport failure for abnormal connection closure.
    pub async fn accept_next(&mut self) -> Result<Option<ServerStream>, SessionError> {
        tokio::select! {
            biased;
            () = self.control.drained() => Ok(None),
            closed = self.control.closed() => exhausted(closed),
            stream = self.accept_stream() => match stream {
                Ok(stream) => Ok(Some(stream)),
                Err(_) => exhausted(self.control.closed().await),
            },
        }
    }

    async fn accept_until_drained(&mut self) -> Result<Option<ServerStream>, SessionError> {
        tokio::select! {
            biased;
            () = self.control.drained() => Ok(None),
            stream = self.accept_stream() => stream.map(Some),
        }
    }

    async fn accept_stream(&self) -> Result<ServerStream, SessionError> {
        tokio::select! {
            result = self.shared.connection.accept_bi() => {
                let (send, recv) = result.map_err(|e| SessionError::transport(e, OutcomeCertainty::NotSent))?;
                Ok(ServerStream::Requests(ServerRequestStream {
                    owner: RequestOwner::new(send, recv, self.shared.options.clone()),
                    authorization: self.authorization.clone(),
                    session: self.shared.clone(),
                }))
            }
            result = self.shared.connection.accept_uni() => {
                let recv = result.map_err(|e| SessionError::transport(e, OutcomeCertainty::NotSent))?;
                Ok(ServerStream::DetectionEvents(super::DetectionEventReceiver::new(
                    recv,
                    self.shared.options.detection_events,
                    self.shared.clone(),
                )))
            }
        }
    }
}

#[cfg(feature = "server")]
fn exhausted(closed: ServerSessionClose) -> Result<Option<ServerStream>, SessionError> {
    match closed {
        ServerSessionClose::Local | ServerSessionClose::Peer { code: 0, .. } => Ok(None),
        ServerSessionClose::Peer { code, reason } => Err(unsent(PeerClosed { code, reason })),
        ServerSessionClose::Transport(error) => Err(error),
    }
}

#[cfg(feature = "server")]
#[derive(Debug, thiserror::Error)]
#[error("peer closed the connection with application code {code} and reason bytes {reason:?}")]
struct PeerClosed {
    code: u64,
    reason: Vec<u8>,
}

#[cfg(feature = "server")]
struct ServerAuthorization {
    context: AuthorizationContext,
    policy: Arc<dyn AuthorizerV2>,
}

/// A manager-side request stream that preserves multiple invocations.
///
/// Each response borrows this owner until completed. Cancelling `next` retains
/// partial framing. Dropping the stream or an unfinished response aborts it.
#[cfg(feature = "server")]
pub struct ServerRequestStream {
    owner: RequestOwner,
    authorization: Option<Arc<ServerAuthorization>>,
    /// The session this stream was accepted on. It supplies the agent's
    /// exclusion-list and watchlist blocker, and, since the stream can outlive
    /// every other session owner, it repeats a listener-wide close when the
    /// stream drops last.
    session: Arc<Shared>,
}

#[cfg(feature = "server")]
impl ServerRequestStream {
    /// Finishes the stream at a request boundary, without waiting for processing acknowledgment.
    ///
    /// # Errors
    /// Returns a classified transport error if FIN cannot be queued.
    pub fn finish(mut self) -> Result<(), SessionError> {
        self.owner.exchange.finish()
    }

    /// Reads the next built-in invocation, returning `None` only at a clean frame boundary EOF.
    ///
    /// This low-level method leaves authorization to the caller. Respond before
    /// reading another request. Unserved codes get an error response and reading
    /// continues. Use [`Self::run`] for the authorized legacy dispatcher, including
    /// its caller handoff and terminal unknown-code behavior.
    ///
    /// An exclusion-list or watchlist pull from an agent that advertised a protocol
    /// earlier than `0.50.0` is answered with an error the same way, and is not
    /// returned: its reply would be an item list the agent can misread.
    ///
    /// # Errors
    /// Returns classified transport, malformed request, or limit errors and aborts the stream.
    pub async fn next(&mut self) -> Result<Option<ServerRequest<'_>>, SessionError> {
        loop {
            let Some((code, frame)) = self.owner.next(server_serves, server_unserved).await? else {
                return Ok(None);
            };
            if let Some(message) =
                server_network_list_refusal(code, self.session.network_list_blocker.as_deref())
            {
                self.owner.refuse(frame, &message)?;
                continue;
            }
            return self
                .decode_low_level_request(code, frame, true)
                .await
                .map(Some);
        }
    }

    /// Processes requests sequentially using the authorization bound to this stream
    /// by [`ServerIncoming::with_authorization`].
    ///
    /// The policy runs before parsing and invoking every recognized request,
    /// including requests delegated to the application. The application supplies
    /// the identity in the authorization context. Handler error strings are
    /// sent unchanged and the stream continues. At clean EOF the response
    /// direction is finished. A delegated request returns ownership to the caller.
    /// An authorized exclusion-list or watchlist pull from an agent that advertised
    /// a protocol earlier than `0.50.0` is answered with an error without
    /// invoking the handler, and the stream continues.
    ///
    /// This future owns the stream and holds a shared handler reference. Poll it
    /// or spawn and join it under application supervision. Dropping the future
    /// resets/stops the stream and cancels any in-progress handler future.
    /// Effects a handler already performed may remain.
    ///
    /// # Errors
    /// Returns [`ServerRunError::MissingAuthorization`] for an unbound stream and
    /// classified errors for denials, unknown codes, malformed input, limits, or
    /// transport failure. A denial or unknown code ends dispatch and attempts
    /// to send one error response. The local rejection is returned even if
    /// sending the response fails. Malformed arguments finish the stream
    /// without a response, matching the legacy server dispatcher.
    pub async fn run<H: Handler + Sync + ?Sized>(
        mut self,
        handler: Arc<H>,
    ) -> Result<ServerRequestOutcome, ServerRunError> {
        let authorization = self
            .authorization
            .clone()
            .ok_or(ServerRunError::MissingAuthorization)?;
        // A caller can hand off a low-level read that suspended while answering
        // an unserved code. Finish that response before reading the next request.
        self.owner.flush_unserved().await?;
        while let Some((code, frame)) = self.owner.read_request().await? {
            let request_code = ServerCode::from(code);
            let Some(service) = crate::service_id::from_server_request_code(request_code) else {
                self.reject(crate::server::UNKNOWN_REQUEST_CODE).await;
                return Err(ServerRunError::UnknownRequestCode { code });
            };
            if let Err(source) = authorization
                .policy
                .authorize_with_context(&authorization.context, &service)
            {
                self.reject(crate::server::AUTHORIZATION_DENIED).await;
                return Err(ServerRunError::AuthorizationDenied { service, source });
            }
            if let Some(message) =
                server_network_list_refusal(code, self.session.network_list_blocker.as_deref())
            {
                self.owner.refuse(frame, &message)?;
                self.owner.flush_unserved().await?;
                continue;
            }
            if server_delegates(request_code) {
                let mut body = frame.into_bytes();
                body.drain(..4);
                return Ok(ServerRequestOutcome::Unhandled(UnhandledServerRequest {
                    code,
                    body,
                    stream: Box::new(self),
                }));
            }
            self.dispatch_runner_request(
                code,
                frame,
                &*handler,
                authorization.context.peer_identity().name(),
            )
            .await?;
        }
        Ok(ServerRequestOutcome::Finished)
    }

    async fn dispatch_label_lookup<H: Handler + Sync + ?Sized>(
        &mut self,
        frame: oinq::frame::Frame,
        handler: &H,
    ) -> Result<(), SessionError> {
        let limit = self.owner.options.unary.get();
        let mut exchange = ExchangeLease(Some(&mut self.owner.exchange));
        // Keep the frame alive through the handler call so the argument vector
        // can borrow the names directly from the guarded decoder.
        let response = {
            let names = match arguments::<Vec<(&str, &str)>>(&frame, limit) {
                Ok(names) => names,
                Err(error) => {
                    exchange.recycle(frame)?;
                    exchange.complete();
                    return Err(error);
                }
            };
            exchange.certainty = OutcomeCertainty::Unknown;
            handler.get_labeldb_patterns(&names).await
        };
        exchange.recycle(frame)?;
        Reply {
            exchange,
            response: PhantomData,
        }
        .respond(response)
        .await
    }

    async fn reject(mut self, message: &str) {
        let exchange = &mut self.owner.exchange;
        // The request was already rejected locally. Failure to notify the peer
        // must not replace that decision, and dropping the exchange aborts it.
        if exchange.start(Err::<(), _>(message)).is_ok() && exchange.flush().await.is_ok() {
            exchange.complete();
        }
    }
}

/// How an owned server request runner completed.
#[cfg(feature = "server")]
pub enum ServerRequestOutcome {
    /// The peer ended its requests at a frame boundary.
    Finished,
    /// The authorized request has a registered code but no built-in handler.
    Unhandled(UnhandledServerRequest),
}

/// An authorized legacy request delegated to the application with its stream.
///
/// Codes 2, 9, and 14 were historically returned to callers of
/// [`crate::server::handle_authorized_with_context`]. The body excludes the
/// request code and frame length. Dropping the handoff aborts its stream.
#[cfg(feature = "server")]
pub struct UnhandledServerRequest {
    code: u32,
    body: Vec<u8>,
    stream: Box<ServerRequestStream>,
}

#[cfg(feature = "server")]
impl UnhandledServerRequest {
    /// Returns the legacy request code.
    #[must_use]
    pub fn code(&self) -> u32 {
        self.code
    }

    /// Returns the opaque request body. Applications decoding it should enforce
    /// their own allocation limits.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the stream at the next request boundary without sending a response.
    /// The bound authorization still applies when the stream is run again.
    #[must_use]
    pub fn into_stream(self) -> ServerRequestStream {
        *self.stream
    }

    /// Sends the application response and returns the stream at the next request boundary.
    ///
    /// # Errors
    /// Returns classified encoding, limit, or transport errors. Dropping this
    /// future before it completes aborts the stream.
    pub async fn respond<T: Serialize>(
        self,
        response: Result<T, String>,
    ) -> Result<ServerRequestStream, SessionError> {
        let mut stream = self.into_stream();
        stream.owner.exchange.certainty = OutcomeCertainty::Unknown;
        stream.owner.exchange.start(response)?;
        stream.owner.exchange.flush().await?;
        Ok(stream)
    }
}

/// The owned, wire-compatible form of [`DataSourceKey`].
#[cfg(feature = "server")]
#[derive(Debug, serde::Deserialize, Serialize)]
enum OwnedDataSourceKey {
    /// Look up a data source by ID.
    Id(u32),
    /// Look up a data source by name.
    Name(String),
}

#[cfg(feature = "server")]
impl OwnedDataSourceKey {
    fn as_key(&self) -> DataSourceKey<'_> {
        match self {
            Self::Id(id) => DataSourceKey::Id(*id),
            Self::Name(name) => DataSourceKey::Name(name),
        }
    }
}

#[cfg(feature = "server")]
macro_rules! server_operations {
    (
        low_level {
            $(
                $low:ident($low_arguments:ty) -> $low_response:ty
                => |$low_handler:ident, $low_peer:ident, $low_request:pat_param| $low_invoke:expr
            ),+ $(,)?
        }
        runner_only {
            $(
                $runner:ident($runner_arguments:ty) -> $runner_response:ty
                => |$runner_handler:ident, $runner_peer:ident, $runner_request:pat_param| $runner_invoke:expr
            ),+ $(,)?
        }
    ) => {
        /// A typed manager-side invocation borrowing its stream until responded to.
        pub enum ServerRequest<'a> {
            $(
                #[doc = concat!("The `", stringify!($low), "` operation.")]
                $low {
                    /// The peer-supplied arguments.
                    request: $low_arguments,
                    /// The response capability borrowing this request stream.
                    reply: Reply<'a, $low_response>,
                },
            )+
        }

        enum RunnerRequest<'a> {
            LowLevel(ServerRequest<'a>),
            $(
                $runner {
                    request: $runner_arguments,
                    reply: Reply<'a, $runner_response>,
                },
            )+
        }

        fn server_serves(code: u32) -> bool {
            matches!(ServerCode::from(code), $(ServerCode::$low)|+)
        }

        impl ServerRequestStream {
            async fn decode_low_level_request(
                &mut self,
                code: u32,
                frame: oinq::frame::Frame,
                report_bad_arguments: bool,
            ) -> Result<ServerRequest<'_>, SessionError> {
                let limit = self.owner.options.unary.get();
                let mut exchange = ExchangeLease(Some(&mut self.owner.exchange));
                match ServerCode::from(code) {
                    $(
                        ServerCode::$low => {
                            let request = exchange
                                .server_arguments(code, frame, limit, report_bad_arguments)
                                .await?;
                            Ok(ServerRequest::$low {
                                request,
                                reply: Reply { exchange, response: PhantomData },
                            })
                        }
                    )+
                    _ => Err(malformed("request code is not served by the low-level stream")),
                }
            }

            async fn dispatch_runner_request<H: Handler + Sync + ?Sized>(
                &mut self,
                code: u32,
                frame: oinq::frame::Frame,
                handler: &H,
                peer: &str,
            ) -> Result<(), SessionError> {
                let limit = self.owner.options.unary.get();
                let request = match ServerCode::from(code) {
                    $(ServerCode::$low)|+ => RunnerRequest::LowLevel(
                        self.decode_low_level_request(code, frame, false).await?,
                    ),
                    ServerCode::GetLabelDbPatterns => {
                        return self.dispatch_label_lookup(frame, handler).await;
                    }
                    $(
                        ServerCode::$runner => {
                            let mut exchange = ExchangeLease(Some(&mut self.owner.exchange));
                            let request = exchange.server_arguments(code, frame, limit, false).await?;
                            RunnerRequest::$runner {
                                request,
                                reply: Reply { exchange, response: PhantomData },
                            }
                        }
                    )+
                    ServerCode::GetMaxEventIdNum | ServerCode::RemoveOutliers
                    | ServerCode::GetDataSourceList | ServerCode::Unknown => {
                        return Err(malformed("request code has no built-in handler"));
                    }
                };
                request.dispatch(handler, peer).await
            }
        }

        impl RunnerRequest<'_> {
            async fn dispatch<H: Handler + Sync + ?Sized>(
                self,
                handler: &H,
                peer: &str,
            ) -> Result<(), SessionError> {
                match self {
                    Self::LowLevel(request) => match request {
                        $(
                            ServerRequest::$low { request: $low_request, mut reply } => {
                                let $low_handler = handler;
                                let $low_peer = peer;
                                reply.exchange.certainty = OutcomeCertainty::Unknown;
                                reply.respond($low_invoke).await
                            }
                        )+
                    },
                    $(
                        Self::$runner { request: $runner_request, mut reply } => {
                            let $runner_handler = handler;
                            let $runner_peer = peer;
                            reply.exchange.certainty = OutcomeCertainty::Unknown;
                            reply.respond($runner_invoke).await
                        }
                    )+
                }
            }
        }
    };
}

#[cfg(feature = "server")]
server_operations! {
    low_level {
        UploadRunModel((u32, Vec<u8>)) -> ()
            => |h, peer, (run_id, model)| h.upload_run_model(peer, run_id, &model).await,
        ReportRun((u32, ReportedRunState, Option<String>)) -> ()
            => |h, peer, (run_id, state, reason)| h.report_run(peer, run_id, state, reason.as_deref()).await,
        ReportActiveRuns(Vec<u32>) -> ()
            => |h, peer, run_ids| h.report_active_runs(peer, &run_ids).await,
        ReportDetectorStatus(DetectorStatusReport) -> ()
            => |h, peer, report| h.report_detector_status(peer, &report).await,
        ReportExclusionCounts(EngineExclusionReport) -> ()
            => |h, peer, report| h.report_exclusion_counts(peer, &report).await,
        GetConfig(()) -> String
            => |h, peer, ()| h.get_config(peer).await,
        GetModel(String) -> Vec<u8>
            => |h, _peer, name| h.get_model(&name).await,
        GetPretrainedModel(String) -> Vec<u8>
            => |h, _peer, name| h.get_pretrained_model(&name).await,
        GetModelNames(()) -> Vec<String>
            => |h, _peer, ()| h.get_model_names().await,
        GetExclusionList(()) -> Vec<NetworkListItem>
            => |h, peer, ()| h.get_exclusion_list(peer).await,
        GetWatchlist(()) -> Vec<NetworkListItem>
            => |h, peer, ()| h.get_watchlist(peer).await,
        InsertModel(Vec<u8>) -> u32
            => |h, _peer, model| h.insert_model(&model).await,
        UpdateModel(Vec<u8>) -> u32
            => |h, _peer, model| h.update_model(&model).await,
        RemoveModel(String) -> ()
            => |h, _peer, name| h.remove_model(&name).await,
        ReportCustomerDataDeletion(CustomerDataDeletionReport) -> ()
            => |h, _peer, report| h.report_customer_data_deletion(&report).await,
    }
    runner_only {
        GetDataSource(OwnedDataSourceKey) -> Option<DataSource>
            => |h, _peer, key| h.get_data_source(&key.as_key()).await,
        GetIndicator(String) -> HashSet<Vec<String>>
            => |h, _peer, name| h.get_indicator(&name).await,
        InsertColumnStatistics((Vec<ColumnStatisticsUpdate>, u32, i64)) -> ()
            => |h, _peer, (statistics, model_id, batch_ts)| h.insert_column_statistics(&statistics, model_id, batch_ts).await,
        InsertTimeSeries((Vec<TimeSeriesUpdate>, u32, i64)) -> ()
            => |h, _peer, (series, model_id, batch_ts)| h.insert_time_series(&series, model_id, batch_ts).await,
        UpdateClusters((Vec<UpdateClusterRequest>, u32)) -> ()
            => |h, _peer, (clusters, model_id)| h.update_clusters(&clusters, model_id).await,
        UpdateOutliers((Vec<OutlierInfo>, u32, i64)) -> ()
            => |h, _peer, (outliers, model_id, timestamp)| h.update_outliers(&outliers, model_id, timestamp).await,
        InsertDetectionEvents((u32, u32, Vec<DetectionEvent>)) -> ()
            => |h, _peer, (model_id, round, events)| h.insert_detection_events(model_id, round, &events).await,
        InsertDataSource(DataSource) -> u32
            => |h, _peer, source| h.insert_data_source(&source).await,
        RenewCertificate(()) -> (String, String)
            => |h, peer, ()| h.renew_certificate(peer).await,
        GetTrustedDomainList(()) -> Vec<String>
            => |h, _peer, ()| h.get_trusted_domain_list().await,
        GetOutliers((u32, i64)) -> Vec<(String, Vec<i64>)>
            => |h, _peer, (model_id, timestamp)| h.get_outliers(model_id, timestamp).await,
        GetTorExitNodeList(()) -> Vec<String>
            => |h, _peer, ()| h.get_tor_exit_node_list().await,
        GetInternalNetworkList(()) -> HostNetworkGroup
            => |h, peer, ()| h.get_internal_network_list(peer).await,
        GetTrustedUserAgentList(()) -> Vec<String>
            => |h, _peer, ()| h.get_trusted_user_agent_list().await,
        GetTimeSeriesGenerationPolicyList(()) -> Vec<TimeSeriesGenerationPolicy>
            => |h, peer, ()| h.get_time_series_generation_policy_list(peer).await,
        GetDaiExtractorConfig(Vec<String>) -> DaiExtractorConfig
            => |h, peer, sensors| h.get_dai_extractor_config(peer, &sensors).await,
        GetDaiCursors(Vec<String>) -> DaiCursors
            => |h, peer, sensors| h.get_dai_cursors(peer, &sensors).await,
        SendDaiObservations(DaiObservationBatch) -> DaiStoreAck
            => |h, peer, batch| h.send_dai_observations(peer, batch).await,
        BeginDaiRangeDay((DaiRangeUnit, u64)) -> DaiRangeGrant
            => |h, peer, (unit, restore_generation)| h.begin_dai_range_day(peer, &unit, restore_generation).await,
        RenewDaiRangeDay((DaiRangeUnit, u64)) -> Option<i64>
            => |h, peer, (unit, lease_token)| h.renew_dai_range_day(peer, &unit, lease_token).await,
        SendDaiRangeDay(DaiRangeDay) -> DaiStoreAck
            => |h, peer, day| h.send_dai_range_day(peer, day).await,
        ReportDaiRangeLate(DaiRangeLate) -> Vec<DaiRangeMark>
            => |h, peer, late| h.report_dai_range_late(peer, &late).await,
    }
}

/// The unique agent-side owner of incoming command stream acceptance.
#[cfg(feature = "client")]
pub struct AgentIncoming(Arc<Shared>);
#[cfg(feature = "client")]
impl AgentIncoming {
    pub(super) fn new(shared: Arc<Shared>) -> Self {
        Self(shared)
    }

    /// Accepts a command stream without waiting for its first request frame.
    ///
    /// Cancellation consumes no stream. Supervise returned stream owners independently.
    /// # Errors
    /// Returns a classified transport error when the connection closes.
    pub async fn accept(&mut self) -> Result<AgentRequestStream, SessionError> {
        let (send, recv) = self
            .0
            .connection
            .accept_bi()
            .await
            .map_err(|e| SessionError::transport(e, OutcomeCertainty::NotSent))?;
        Ok(AgentRequestStream(RequestOwner::new(
            send,
            recv,
            self.0.options.clone(),
        )))
    }
}

/// An agent-side command stream that preserves multiple invocations.
///
/// Each response borrows this owner until completed. Cancelling `next` retains
/// partial framing; dropping the stream or an unfinished response aborts it.
#[cfg(feature = "client")]
pub struct AgentRequestStream(RequestOwner);
#[cfg(feature = "client")]
impl AgentRequestStream {
    /// Finishes the stream at a request boundary, without waiting for processing acknowledgment.
    /// # Errors
    /// Returns a classified transport error if FIN cannot be queued.
    pub fn finish(mut self) -> Result<(), SessionError> {
        self.0.exchange.finish()
    }

    /// Reads the next invocation, returning `None` only at a clean frame boundary EOF.
    ///
    /// Authorize every returned request. Respond before reading another request.
    /// # Errors
    /// Returns classified transport, malformed request, or limit errors and aborts the stream.
    #[allow(clippy::too_many_lines)]
    pub async fn next(&mut self) -> Result<Option<AgentRequest<'_>>, SessionError> {
        let Some((code, frame)) = self.0.next(agent_serves, agent_unserved).await? else {
            return Ok(None);
        };
        let limit = self.0.options.unary.get();
        let mut exchange = ExchangeLease(Some(&mut self.0.exchange));
        let request = match code {
            code if code == u32::from(crate::client::RequestCode::NodeService) => {
                let request: NodeServiceRequest = exchange.arguments(code, frame, limit).await?;
                AgentRequest::Service {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeServiceResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeNetworkInterface) => {
                let request: NodeNetworkInterfaceRequest =
                    exchange.arguments(code, frame, limit).await?;
                AgentRequest::NetworkInterface {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeNetworkInterfaceResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeHostname) => {
                let request: NodeHostnameRequest = exchange.arguments(code, frame, limit).await?;
                AgentRequest::Hostname {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeHostnameResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeTimeSync) => {
                let request: NodeTimeSyncRequest = exchange.arguments(code, frame, limit).await?;
                AgentRequest::TimeSync {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeTimeSyncResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeLogging) => {
                let request: NodeLoggingRequest = exchange.arguments(code, frame, limit).await?;
                AgentRequest::Logging {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeLoggingResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeRemoteAccess) => {
                let request: NodeRemoteAccessRequest =
                    exchange.arguments(code, frame, limit).await?;
                AgentRequest::RemoteAccess {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeRemoteAccessResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeObservation) => {
                let request: NodeObservationRequest =
                    exchange.arguments(code, frame, limit).await?;
                AgentRequest::Observation {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeObservationResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeVersion) => {
                let request: NodeVersionRequest = exchange.arguments(code, frame, limit).await?;
                AgentRequest::Version {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeVersionResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeEnroll) => {
                let request: NodeEnrollRequest = exchange.arguments(code, frame, limit).await?;
                AgentRequest::Enroll {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeEnrollResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodePower) => {
                let request: NodePowerRequest = exchange.arguments(code, frame, limit).await?;
                AgentRequest::Power {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodePowerResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodePackage) => {
                let request: NodePackageRequest = exchange.arguments(code, frame, limit).await?;
                let remaining = match &request {
                    NodePackageRequest::Install { size, .. } => Some(*size),
                    _ => None,
                };
                AgentRequest::Package {
                    request,
                    reply: PackageReply {
                        exchange,
                        remaining,
                        options: self.0.options.clone(),
                        receiving: false,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::TrainModel) => {
                let request: TrainModelRequest = exchange.arguments(code, frame, limit).await?;
                AgentRequest::TrainModel {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::CloneModel) => {
                let request: CloneModelRequest = exchange.arguments(code, frame, limit).await?;
                AgentRequest::CloneModel {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::CancelRun) => {
                let request: u32 = exchange.arguments(code, frame, limit).await?;
                AgentRequest::CancelRun {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::RunDetectorOnce) => {
                let request: i32 = exchange.arguments(code, frame, limit).await?;
                AgentRequest::RunDetectorOnce {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            // `*_serves` admits only the codes matched above.
            _ => return Err(malformed("unknown request code")),
        };
        Ok(Some(request))
    }
}

/// A typed agent-side invocation borrowing its stream until responded to.
#[cfg(feature = "client")]
pub enum AgentRequest<'a> {
    /// The `TrainModel` engine operation.
    TrainModel {
        /// The peer-supplied arguments.
        request: TrainModelRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, ()>,
    },

    /// The `CloneModel` engine operation.
    CloneModel {
        /// The peer-supplied arguments.
        request: CloneModelRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, ()>,
    },

    /// The `CancelRun` engine operation.
    CancelRun {
        /// The peer-supplied arguments.
        request: u32,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, ()>,
    },

    /// The `RunDetectorOnce` engine operation.
    RunDetectorOnce {
        /// The peer-supplied arguments.
        request: i32,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, ()>,
    },

    /// The node service family.
    Service {
        /// The peer-supplied arguments.
        request: NodeServiceRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeServiceResponse>,
    },
    /// The node networkinterface family.
    NetworkInterface {
        /// The peer-supplied arguments.
        request: NodeNetworkInterfaceRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeNetworkInterfaceResponse>,
    },
    /// The node hostname family.
    Hostname {
        /// The peer-supplied arguments.
        request: NodeHostnameRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeHostnameResponse>,
    },
    /// The node timesync family.
    TimeSync {
        /// The peer-supplied arguments.
        request: NodeTimeSyncRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeTimeSyncResponse>,
    },
    /// The node logging family.
    Logging {
        /// The peer-supplied arguments.
        request: NodeLoggingRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeLoggingResponse>,
    },
    /// The node remoteaccess family.
    RemoteAccess {
        /// The peer-supplied arguments.
        request: NodeRemoteAccessRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeRemoteAccessResponse>,
    },
    /// The node observation family.
    Observation {
        /// The peer-supplied arguments.
        request: NodeObservationRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeObservationResponse>,
    },
    /// The node version family.
    Version {
        /// The peer-supplied arguments.
        request: NodeVersionRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeVersionResponse>,
    },
    /// The node enroll family.
    Enroll {
        /// The peer-supplied arguments.
        request: NodeEnrollRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeEnrollResponse>,
    },
    /// The node power family.
    Power {
        /// The peer-supplied arguments.
        request: NodePowerRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodePowerResponse>,
    },
    /// The package family, including the streaming install exchange.
    Package {
        /// The peer-supplied request.
        request: NodePackageRequest,
        /// The package exchange borrowing this request stream.
        reply: PackageReply<'a>,
    },
}

/// Refuses an exclusion-list or watchlist exchange, before anything is sent, on
/// a session whose handshake shows a side earlier than the item lists.
fn check_network_lists(shared: &Shared) -> Result<(), SessionError> {
    match &shared.network_list_blocker {
        None => Ok(()),
        Some(version) => Err(SessionError::IncompatibleProtocol {
            version: version.clone(),
            required: crate::NETWORK_LIST_ITEMS_REQ.to_owned(),
        }),
    }
}

#[cfg(feature = "client")]
impl super::AgentHandle {
    /// Refuses an exclusion-list or watchlist pull, before anything is sent, on a
    /// session whose handshake shows a side earlier than the item lists.
    fn check_network_lists(&self) -> Result<(), SessionError> {
        check_network_lists(&self.0)
    }

    /// Sends the `upload_run_model` engine operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn upload_run_model(&self, run_id: u32, model: &[u8]) -> Result<(), SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::UploadRunModel),
            (run_id, model),
        )
        .await
    }

    /// Sends the `report_run` engine operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn report_run(
        &self,
        run_id: u32,
        state: ReportedRunState,
        reason: Option<&str>,
    ) -> Result<(), SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::ReportRun),
            (run_id, state, reason),
        )
        .await
    }

    /// Sends the `report_active_runs` engine operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn report_active_runs(&self, run_ids: &[u32]) -> Result<(), SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::ReportActiveRuns),
            run_ids,
        )
        .await
    }

    /// Sends the `report_detector_status` engine operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn report_detector_status(
        &self,
        report: &DetectorStatusReport,
    ) -> Result<(), SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::ReportDetectorStatus),
            report,
        )
        .await
    }

    /// Sends the `report_exclusion_counts` engine operation, the raw events
    /// a Semi-supervised Engine skipped before detection because they matched
    /// an exclusion-list entry.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn report_exclusion_counts(
        &self,
        report: &EngineExclusionReport,
    ) -> Result<(), SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::ReportExclusionCounts),
            report,
        )
        .await
    }

    /// Sends the `get_config` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn get_config(&self) -> Result<String, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::GetConfig),
            (),
        )
        .await
    }
    /// Sends the `get_model` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn get_model(&self, request: &str) -> Result<Vec<u8>, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::GetModel),
            request,
        )
        .await
    }
    /// Sends the `get_pretrained_model` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn get_pretrained_model(&self, request: &str) -> Result<Vec<u8>, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::GetPretrainedModel),
            request,
        )
        .await
    }
    /// Sends the `get_model_names` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn get_model_names(&self) -> Result<Vec<String>, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::GetModelNames),
            (),
        )
        .await
    }
    /// Sends the `get_exclusion_list` domain operation.
    ///
    /// Both the protocol version this agent advertised and the manager's
    /// handshake reply must be `0.50.0` or later: a `0.49.0` payload can decode
    /// as a different item list (see [`NetworkListItem`]). Otherwise nothing
    /// is sent.
    /// # Errors
    /// Returns [`SessionError::IncompatibleProtocol`] when either handshake
    /// version is earlier than `0.50.0`, and classified transport, malformed
    /// data, remote rejection, limit, or deadline errors.
    pub async fn get_exclusion_list(&self) -> Result<Vec<NetworkListItem>, SessionError> {
        self.check_network_lists()?;
        unary_as(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::GetExclusionList),
            (),
            Decoding::Exact,
        )
        .await
    }
    /// Sends the `get_watchlist` domain operation.
    ///
    /// Both the protocol version this agent advertised and the manager's
    /// handshake reply must be `0.50.0` or later: a `0.49.0` payload can decode
    /// as a different item list (see [`NetworkListItem`]). Otherwise nothing
    /// is sent.
    /// # Errors
    /// Returns [`SessionError::IncompatibleProtocol`] when either handshake
    /// version is earlier than `0.50.0`, and classified transport, malformed
    /// data, remote rejection, limit, or deadline errors.
    pub async fn get_watchlist(&self) -> Result<Vec<NetworkListItem>, SessionError> {
        self.check_network_lists()?;
        unary_as(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::GetWatchlist),
            (),
            Decoding::Exact,
        )
        .await
    }
    /// Sends the `insert_model` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn insert_model(&self, request: &[u8]) -> Result<u32, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::InsertModel),
            request,
        )
        .await
    }
    /// Sends the `update_model` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn update_model(&self, request: &[u8]) -> Result<u32, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::UpdateModel),
            request,
        )
        .await
    }
    /// Sends the `remove_model` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn remove_model(&self, request: &str) -> Result<(), SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::RemoveModel),
            request,
        )
        .await
    }
    /// Sends the `report_customer_data_deletion` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn report_customer_data_deletion(
        &self,
        request: &CustomerDataDeletionReport,
    ) -> Result<(), SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::ReportCustomerDataDeletion),
            request,
        )
        .await
    }
}

#[cfg(feature = "server")]
impl super::ServerHandle {
    /// Sends the `send_train_model` engine operation.
    ///
    /// Success acknowledges acceptance; subsequent run state arrives in reports.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_train_model(&self, request: &TrainModelRequest) -> Result<(), SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::TrainModel),
            request,
        )
        .await
    }

    /// Sends the `send_clone_model` engine operation.
    ///
    /// Success acknowledges acceptance; subsequent run state arrives in reports.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_clone_model(&self, request: &CloneModelRequest) -> Result<(), SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::CloneModel),
            request,
        )
        .await
    }

    /// Requests cancellation of an engine run.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_cancel_run(&self, run_id: u32) -> Result<(), SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::CancelRun),
            run_id,
        )
        .await
    }

    /// Requests one round of an engine detector.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_run_detector_once(&self, detector_id: i32) -> Result<(), SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::RunDetectorOnce),
            detector_id,
        )
        .await
    }

    /// Pushes the exclusion list to the agent.
    ///
    /// Every item is sent in the order given, without sorting, merging or
    /// deduplicating; the agent attributes a skipped raw event to the first
    /// matching entry in that order. `Ok(())` means the agent accepted the list.
    ///
    /// # Errors
    /// Returns [`SessionError::IncompatibleProtocol`], before anything is sent,
    /// when the agent's handshake version is below `0.50.0`, whose list payload
    /// can decode as a different item list. Otherwise returns classified
    /// transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_exclusion_list(
        &self,
        exclusion_list: &[NetworkListItem],
    ) -> Result<(), SessionError> {
        check_network_lists(&self.0)?;
        self.push(crate::client::RequestCode::ExclusionList, exclusion_list)
            .await
    }

    /// Pushes the watchlist to the agent.
    ///
    /// Every item is sent in the order given, without sorting, merging or
    /// deduplicating. `Ok(())` means the agent accepted the list.
    ///
    /// # Errors
    /// Returns [`SessionError::IncompatibleProtocol`], before anything is sent,
    /// when the agent's handshake version is below `0.50.0`, whose list payload
    /// can decode as a different item list. Otherwise returns classified
    /// transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_watchlist(&self, watchlist: &[NetworkListItem]) -> Result<(), SessionError> {
        check_network_lists(&self.0)?;
        self.push(crate::client::RequestCode::Watchlist, watchlist)
            .await
    }

    /// Tells the agent that its configuration changed and should be fetched again.
    ///
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_config_update_cmd(&self) -> Result<(), SessionError> {
        self.push(crate::client::RequestCode::UpdateConfig, ())
            .await
    }

    /// Asks the agent to delete customer-owned filesystem data.
    ///
    /// The request's opaque ID comes back unchanged in the agent's deletion
    /// report. `Ok(())` acknowledges the command, not the deletion.
    ///
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_delete_customer_data_cmd(
        &self,
        request: &CustomerDataDeletionRequest,
    ) -> Result<(), SessionError> {
        self.push(crate::client::RequestCode::DeleteCustomerData, request)
            .await
    }

    /// Pushes the traffic filtering rules to the agent, in the order given.
    ///
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_filtering_rules(
        &self,
        list: &[TrafficFilterRule],
    ) -> Result<(), SessionError> {
        self.push(crate::client::RequestCode::ReloadFilterRule, list)
            .await
    }

    /// Pushes the internal network list to the agent.
    ///
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_internal_network_list(
        &self,
        list: &HostNetworkGroup,
    ) -> Result<(), SessionError> {
        self.push(crate::client::RequestCode::InternalNetworkList, list)
            .await
    }

    /// Pushes the time-series generation policies to the agent, in the order given.
    ///
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_time_series_generation_policies(
        &self,
        list: &[TimeSeriesGenerationPolicy],
    ) -> Result<(), SessionError> {
        self.push(
            crate::client::RequestCode::TimeSeriesGenerationPolicyList,
            list,
        )
        .await
    }

    /// Pushes the Tor exit node list to the agent, in the order given.
    ///
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_tor_exit_node_list(&self, list: &[String]) -> Result<(), SessionError> {
        self.push(crate::client::RequestCode::TorExitNodeList, list)
            .await
    }

    /// Pushes the trusted domain list to the agent, in the order given.
    ///
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_trusted_domain_list(&self, list: &[String]) -> Result<(), SessionError> {
        self.push(crate::client::RequestCode::TrustedDomainList, list)
            .await
    }

    /// Pushes the trusted user-agent list to the agent, in the order given.
    ///
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_trusted_user_agent_list(&self, list: &[String]) -> Result<(), SessionError> {
        self.push(crate::client::RequestCode::TrustedUserAgentList, list)
            .await
    }

    /// Sends one configuration or list push through the bounded unary exchange,
    /// expecting a `Result<(), String>` acknowledgment.
    async fn push<I: Serialize>(
        &self,
        code: crate::client::RequestCode,
        input: I,
    ) -> Result<(), SessionError> {
        unary(&self.0.connection, &self.0.options, u32::from(code), input).await
    }

    /// Sends a typed node service operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_service(
        &self,
        request: NodeServiceRequest,
    ) -> Result<NodeServiceResponse, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::NodeService),
            request,
        )
        .await
    }
    /// Sends a typed node network interface operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_network_interface(
        &self,
        request: NodeNetworkInterfaceRequest,
    ) -> Result<NodeNetworkInterfaceResponse, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::NodeNetworkInterface),
            request,
        )
        .await
    }
    /// Sends a typed node hostname operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_hostname(
        &self,
        request: NodeHostnameRequest,
    ) -> Result<NodeHostnameResponse, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::NodeHostname),
            request,
        )
        .await
    }
    /// Sends a typed node time sync operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_time_sync(
        &self,
        request: NodeTimeSyncRequest,
    ) -> Result<NodeTimeSyncResponse, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::NodeTimeSync),
            request,
        )
        .await
    }
    /// Sends a typed node logging operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_logging(
        &self,
        request: NodeLoggingRequest,
    ) -> Result<NodeLoggingResponse, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::NodeLogging),
            request,
        )
        .await
    }
    /// Sends a typed node remote access operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_remote_access(
        &self,
        request: NodeRemoteAccessRequest,
    ) -> Result<NodeRemoteAccessResponse, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::NodeRemoteAccess),
            request,
        )
        .await
    }
    /// Sends a typed node observation operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_observation(
        &self,
        request: NodeObservationRequest,
    ) -> Result<NodeObservationResponse, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::NodeObservation),
            request,
        )
        .await
    }
    /// Sends a typed node version operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_version(
        &self,
        request: NodeVersionRequest,
    ) -> Result<NodeVersionResponse, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::NodeVersion),
            request,
        )
        .await
    }
    /// Sends a typed node enroll operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_enroll(
        &self,
        request: NodeEnrollRequest,
    ) -> Result<NodeEnrollResponse, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::NodeEnroll),
            request,
        )
        .await
    }
    /// Sends a typed node package operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_package(
        &self,
        request: NodePackageRequest,
    ) -> Result<NodePackageResponse, SessionError> {
        if matches!(request, NodePackageRequest::Install { .. }) {
            return Err(malformed("use node_package_install for streaming installs"));
        }
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::client::RequestCode::NodePackage),
            request,
        )
        .await
    }
}

/// A borrowed package invocation, including preflight and bounded chunk reads.
///
/// Completion releases the request stream for its next invocation. Abandoning
/// this owner or an owned response future aborts the borrowed stream. Cancelling
/// a borrowed `next_chunk` call retains framing progress on this owner.
#[cfg(feature = "client")]
pub struct PackageReply<'a> {
    exchange: ExchangeLease<'a>,
    remaining: Option<u64>,
    options: super::SessionOptions,
    receiving: bool,
}

#[cfg(feature = "client")]
impl PackageReply<'_> {
    /// Sends an install preflight, returning ownership only when transfer may proceed.
    /// # Errors
    /// Returns malformed-state, limit, encoding, or transport errors.
    pub async fn preflight(
        mut self,
        verdict: Result<crate::types::node::InstallPreflight, String>,
    ) -> Result<Option<Self>, SessionError> {
        if self.remaining.is_none() || self.receiving {
            return Err(malformed("preflight requires a fresh install request"));
        }
        let proceed = matches!(verdict, Ok(crate::types::node::InstallPreflight::Proceed));
        self.exchange.start(verdict)?;
        self.exchange.flush().await?;
        if proceed {
            self.receiving = true;
            self.exchange
                .set_limits(self.options.package_chunks, self.options.unary);
            Ok(Some(self))
        } else {
            self.exchange.release();
            Ok(None)
        }
    }

    /// Receives a package chunk without copying its buffer, retaining partial reads across cancellation.
    ///
    /// The previous buffer is recycled for the next frame. Returns false after
    /// exactly the declared number of bytes, without reading into another frame.
    /// # Errors
    /// Returns malformed-state, oversized, overrun, truncation, or transport errors.
    pub async fn next_chunk(&mut self, buffer: &mut Vec<u8>) -> Result<bool, SessionError> {
        if !self.receiving {
            return Err(malformed("package preflight has not proceeded"));
        }
        let remaining = self
            .remaining
            .as_mut()
            .ok_or_else(|| malformed("chunk reads require an install"))?;
        if *remaining == 0 {
            buffer.clear();
            return Ok(false);
        }
        let frame = self.exchange.frame().await?;
        let length = u64::try_from(frame.as_bytes().len()).map_err(SessionError::malformed)?;
        if length > *remaining {
            self.exchange.cancel();
            return Err(malformed("package chunk exceeds the declared size"));
        }
        *remaining -= length;
        let previous = std::mem::replace(buffer, frame.into_bytes());
        self.exchange.recycle_bytes(previous)?;
        Ok(true)
    }

    /// Sends the terminal package response after a unary request or an install.
    ///
    /// An incomplete install cannot send a terminal success: an `Ok` response
    /// before every declared byte was received is refused and aborts the stream.
    /// An `Err` response, for example because the agent failed to store the
    /// payload, first reads and discards the rest of the declared bytes, as the
    /// legacy dispatcher drains for a failed handler, so the manager receives
    /// the rejection rather than a reset.
    /// # Errors
    /// Returns malformed-state, encoding, limit, or transport errors.
    pub async fn respond(
        mut self,
        response: Result<NodePackageResponse, String>,
    ) -> Result<(), SessionError> {
        let incomplete = self.remaining.is_some_and(|remaining| remaining != 0);
        if (self.remaining.is_some() && !self.receiving) || (incomplete && response.is_ok()) {
            return Err(malformed(
                "install payload has not been completely received",
            ));
        }
        if incomplete {
            let mut discard = Vec::new();
            while self.next_chunk(&mut discard).await? {}
        }
        self.exchange.start(response)?;
        self.exchange.flush().await?;
        self.exchange
            .set_limits(self.options.unary, self.options.unary);
        self.exchange.release();
        Ok(())
    }
}

#[cfg(feature = "server")]
impl super::ServerHandle {
    /// Sends a power request, preserving immediate-send and graceful-response outcomes.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_power(
        &self,
        request: NodePowerRequest,
    ) -> Result<crate::server::node::NodePowerOutcome, SessionError> {
        use crate::server::node::NodePowerOutcome;
        if matches!(
            request,
            NodePowerRequest::Reboot | NodePowerRequest::Shutdown
        ) {
            super::exchange::send_only(
                &self.0.connection,
                &self.0.options,
                u32::from(crate::client::RequestCode::NodePower),
                request,
            )
            .await?;
            Ok(NodePowerOutcome::Sent)
        } else {
            unary(
                &self.0.connection,
                &self.0.options,
                u32::from(crate::client::RequestCode::NodePower),
                request,
            )
            .await
            .map(NodePowerOutcome::Response)
        }
    }

    /// Streams exactly the declared install size after a successful preflight.
    ///
    /// A terminal preflight consumes no source bytes. Extra source bytes remain
    /// unread. A truncated source aborts both protocol stream directions.
    /// # Errors
    /// Returns malformed request, source truncation, transport, limit, remote rejection, or deadline errors.
    pub async fn node_package_install<R: tokio::io::AsyncRead + Unpin + Send>(
        &self,
        request: NodePackageRequest,
        mut source: R,
    ) -> Result<crate::server::node::InstallOutcome, SessionError> {
        use tokio::io::AsyncReadExt;

        use crate::{server::node::InstallOutcome, types::node::InstallPreflight};
        let NodePackageRequest::Install { size, .. } = &request else {
            return Err(malformed(
                "node_package_install requires an install request",
            ));
        };
        let mut remaining = *size;
        let options = &self.0.options;
        let mut certainty = OutcomeCertainty::NotSent;
        let operation = async {
            let (send, recv) = self
                .0
                .connection
                .open_bi()
                .await
                .map_err(|e| SessionError::transport(e, certainty))?;
            let mut exchange = Exchange::new(send, recv, options.unary);
            exchange.start_request(u32::from(crate::client::RequestCode::NodePackage), &request)?;
            certainty = OutcomeCertainty::Unknown;
            exchange.flush().await?;
            let verdict: Result<InstallPreflight, String> = exchange.receive().await?;
            if let Some(terminal) =
                terminal_preflight(verdict.map_err(SessionError::RemoteRejection)?)
            {
                exchange.complete();
                return Ok(InstallOutcome::Preflight(terminal));
            }
            exchange.set_limits(options.unary, options.package_chunks);
            // Sender tuning only; the configured limit is always respected.
            let chunk_size = options.package_chunks.get().min(64 * 1024);
            if chunk_size == 0 && remaining > 0 {
                return Err(SessionError::limit(oinq::frame::FrameError::TooLarge {
                    length: 1,
                    limit: options.package_chunks,
                })
                .within(certainty));
            }
            let mut buffer = vec![0; chunk_size];
            while remaining > 0 {
                let want = usize::try_from(
                    remaining.min(u64::try_from(chunk_size).map_err(SessionError::malformed)?),
                )
                .map_err(SessionError::malformed)?;
                let length = source
                    .read(&mut buffer[..want])
                    .await
                    .map_err(|e| SessionError::transport(e, certainty))?;
                if length == 0 {
                    return Err(SessionError::transport(
                        std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "package source ended before the declared size",
                        ),
                        certainty,
                    ));
                }
                exchange.start_raw(&buffer[..length])?;
                exchange.flush().await?;
                remaining -= u64::try_from(length).map_err(SessionError::malformed)?;
            }
            let response: Result<NodePackageResponse, String> = exchange.receive().await?;
            exchange.complete();
            response
                .map(InstallOutcome::Applied)
                .map_err(SessionError::RemoteRejection)
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
}

#[cfg(feature = "server")]
fn terminal_preflight(
    verdict: crate::types::node::InstallPreflight,
) -> Option<crate::server::node::TerminalPreflight> {
    use crate::{server::node::TerminalPreflight as T, types::node::InstallPreflight as P};
    match verdict {
        P::Proceed => None,
        P::AlreadyApplied => Some(T::AlreadyApplied),
        P::InsufficientDiskSpace {
            filesystem,
            required,
            available,
        } => Some(T::InsufficientDiskSpace {
            filesystem,
            required,
            available,
        }),
        P::BindAddrsOnUpdate => Some(T::BindAddrsOnUpdate),
        P::NamespaceUnconfigured => Some(T::NamespaceUnconfigured),
        P::EnrollmentUnsupported => Some(T::EnrollmentUnsupported),
        P::ConfigTemplateOnUpdate => Some(T::ConfigTemplateOnUpdate),
        P::UnknownConfigTemplate { id } => Some(T::UnknownConfigTemplate { id }),
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use std::collections::BTreeSet;

    use crate::{client::RequestCode, session::ServerHandle};

    /// How the session API covers one manager-to-agent request code.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Coverage {
        /// The `ServerHandle` method that sends the code.
        ServerHandle(&'static str),
        /// The legacy `server::Connection` has no sender for the code either.
        NoLegacySender,
        /// The single documented exception: legacy `send_ping` (code 17).
        PingNotProvided,
    }

    /// Names a `ServerHandle` method, so a renamed or removed method fails to
    /// compile, and records it as the code's sender.
    macro_rules! handle {
        ($method:ident) => {{
            let _ = ServerHandle::$method;
            Coverage::ServerHandle(stringify!($method))
        }};
    }

    /// Classifies every request code the manager can send to an agent.
    ///
    /// The `match` has no wildcard arm, so a new `client::RequestCode` fails to
    /// compile until it is classified here. Each code maps to exactly one of:
    ///
    /// - the `ServerHandle` method that sends it: the ten configuration and list
    ///   pushes, the four engine commands, and the eleven `node_*` families
    ///   (`NodePackage` also covers `node_package_install`);
    /// - no legacy `server::Connection` sender, so nothing to carry over;
    /// - `EchoRequest`, the one documented exception: legacy `send_ping` is
    ///   intentionally not provided on `ServerHandle`, because transport
    ///   keepalive and idle timeout (`ServerTransportOptions`) cover liveness.
    ///
    /// The legacy surface that is not keyed by a request code maps as follows:
    ///
    /// - the `node()` namespace and the `node_*_authorized` and
    ///   `node_*_with_context` variants map to `ServerHandle::node_*`, with the
    ///   application authorizing before the call. `node().reboot()` and
    ///   `node().shutdown()` send code 106, so they map to `node_power`, not to
    ///   codes 4 (`Reboot`) and 21 (`Shutdown`);
    /// - the inbound `accept_detection_event_stream`,
    ///   `handle_detection_event_stream`, `server::handshake` and
    ///   `respond_with_labeldb_patterns` are covered by `ServerIncoming` and
    ///   `ServerListener`;
    /// - `from_quinn`, `as_quinn`, `open_bi`, `accept_uni` and `peer_identity`
    ///   are raw-transport access and intentionally not provided;
    /// - `close` maps to `ServerSessionControl::close` and `abort`;
    /// - the free functions `server::notify_config_update` and the deprecated
    ///   `server::send_trusted_domain_list` map to `send_config_update_cmd` and
    ///   `send_trusted_domain_list`.
    fn coverage(code: RequestCode) -> Coverage {
        match code {
            RequestCode::ExclusionList => handle!(send_exclusion_list),
            RequestCode::Watchlist => handle!(send_watchlist),
            RequestCode::UpdateConfig => handle!(send_config_update_cmd),
            RequestCode::DeleteCustomerData => handle!(send_delete_customer_data_cmd),
            RequestCode::ReloadFilterRule => handle!(send_filtering_rules),
            RequestCode::InternalNetworkList => handle!(send_internal_network_list),
            RequestCode::TimeSeriesGenerationPolicyList => {
                handle!(send_time_series_generation_policies)
            }
            RequestCode::TorExitNodeList => handle!(send_tor_exit_node_list),
            RequestCode::TrustedDomainList => handle!(send_trusted_domain_list),
            RequestCode::TrustedUserAgentList => handle!(send_trusted_user_agent_list),
            RequestCode::TrainModel => handle!(send_train_model),
            RequestCode::CloneModel => handle!(send_clone_model),
            RequestCode::CancelRun => handle!(send_cancel_run),
            RequestCode::RunDetectorOnce => handle!(send_run_detector_once),
            RequestCode::NodeService => handle!(node_service),
            RequestCode::NodeNetworkInterface => handle!(node_network_interface),
            RequestCode::NodeHostname => handle!(node_hostname),
            RequestCode::NodeTimeSync => handle!(node_time_sync),
            RequestCode::NodeLogging => handle!(node_logging),
            RequestCode::NodeRemoteAccess => handle!(node_remote_access),
            RequestCode::NodePower => handle!(node_power),
            RequestCode::NodeObservation => handle!(node_observation),
            RequestCode::NodeVersion => handle!(node_version),
            RequestCode::NodePackage => handle!(node_package),
            RequestCode::NodeEnroll => handle!(node_enroll),
            RequestCode::DnsStart
            | RequestCode::DnsStop
            | RequestCode::Reboot
            | RequestCode::ReloadConfig
            | RequestCode::ReloadTi
            | RequestCode::ResourceUsage
            | RequestCode::DeleteTimeSeriesGenerationPolicy
            | RequestCode::ProcessList
            | RequestCode::SemiSupervisedModels
            | RequestCode::Shutdown
            | RequestCode::Unknown => Coverage::NoLegacySender,
            RequestCode::EchoRequest => Coverage::PingNotProvided,
        }
    }

    #[test]
    fn every_request_code_is_classified_for_server_handle() {
        let mut methods = BTreeSet::new();
        let mut unsent = BTreeSet::new();
        let mut exceptions = Vec::new();
        // Every defined code is below 1024; anything else decodes as `Unknown`.
        for number in (0..1024).chain([u32::MAX]) {
            let code = RequestCode::from(number);
            if code == RequestCode::Unknown && number != u32::MAX {
                continue;
            }
            assert_eq!(u32::from(code), number);
            match coverage(code) {
                Coverage::ServerHandle(method) => {
                    assert!(methods.insert(method), "{method} sends two codes");
                }
                Coverage::NoLegacySender => {
                    unsent.insert(number);
                }
                Coverage::PingNotProvided => exceptions.push(number),
            }
        }
        assert_eq!(methods.len(), 25, "{methods:?}");
        assert_eq!(
            unsent,
            BTreeSet::from([1, 2, 4, 5, 6, 7, 13, 19, 20, 21, u32::MAX])
        );
        assert_eq!(exceptions, [17], "only EchoRequest is an exception");
    }
}
