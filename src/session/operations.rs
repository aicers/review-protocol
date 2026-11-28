//! Typed protocol adapters sharing bounded exchange machinery.
#[cfg(feature = "server")]
use std::collections::HashSet;
use std::{
    future::poll_fn,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::Arc,
    task::Poll,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[cfg(feature = "client")]
use super::exchange::{Decoding, unary_as};
use super::{
    OutcomeCertainty, SessionActivity, SessionError, SessionLifecycle, Shared,
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
    CloneModelRequest, CustomerDataDeletionReport, DetectorStatusReport, EndpointSources,
    EndpointSourcesRequest, EngineExclusionReport, NetworkListItem, ReportedRunState,
    RoundFilterReport, SignatureRules, SignatureStatusReport, TrainModelRequest,
    TrainingFilterReport,
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

impl Shared {
    pub(super) async fn unary<I: Serialize, O: DeserializeOwned>(
        &self,
        code: u32,
        input: I,
    ) -> Result<O, SessionError> {
        unary(
            &self.lifecycle,
            &self.connection,
            &self.options,
            code,
            input,
        )
        .await
    }

    #[cfg(feature = "client")]
    pub(super) async fn unary_as<I: Serialize, O: DeserializeOwned>(
        &self,
        code: u32,
        input: I,
        decoding: Decoding,
    ) -> Result<O, SessionError> {
        unary_as(
            &self.lifecycle,
            &self.connection,
            &self.options,
            code,
            input,
            decoding,
        )
        .await
    }

    #[cfg(feature = "server")]
    pub(super) async fn send_only<I: Serialize>(
        &self,
        code: u32,
        input: I,
    ) -> Result<(), SessionError> {
        super::exchange::send_only(
            &self.lifecycle,
            &self.connection,
            &self.options,
            code,
            input,
        )
        .await
    }
}

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
        self.arguments_as(code, frame, limit, super::exchange::Decoding::Prefix)
            .await
    }

    #[cfg(feature = "client")]
    async fn arguments_exact<T: DeserializeOwned>(
        &mut self,
        code: u32,
        frame: oinq::frame::Frame,
        limit: usize,
    ) -> Result<T, SessionError> {
        self.arguments_as(code, frame, limit, super::exchange::Decoding::Exact)
            .await
    }

    async fn arguments_as<T: DeserializeOwned>(
        &mut self,
        code: u32,
        frame: oinq::frame::Frame,
        limit: usize,
        decoding: super::exchange::Decoding,
    ) -> Result<T, SessionError> {
        let result = arguments(&frame, limit, decoding);
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
        let result = arguments(&frame, limit, super::exchange::Decoding::Prefix);
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
    /// Whether this stream has already read at least one request frame.
    started: bool,
    /// An answer to an unserved request code is prepared but not yet flushed.
    answering: bool,
    lifecycle: SessionLifecycle,
    /// Keeps this accepted stream counted as active work until it drops.
    _activity: SessionActivity,
}
impl RequestOwner {
    fn new(
        send: oinq::SendStream,
        recv: oinq::RecvStream,
        options: super::SessionOptions,
        connection: &oinq::Connection,
        lifecycle: SessionLifecycle,
        activity: SessionActivity,
    ) -> Self {
        Self {
            exchange: Exchange::new(send, recv, options.unary, connection),
            options,
            ended: false,
            started: false,
            answering: false,
            lifecycle,
            _activity: activity,
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
        response_write: &mut bool,
    ) -> Result<Option<(u32, oinq::frame::Frame)>, SessionError> {
        loop {
            *response_write = self.answering;
            self.flush_unserved().await?;
            *response_write = false;
            let Some((code, frame)) = self.read_request().await? else {
                return Ok(None);
            };
            if serves(code) {
                return Ok(Some((code, frame)));
            }
            *response_write = true;
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
        let lifecycle = self.lifecycle.clone();
        // Before this stream's first invocation, a request that is already
        // buffered is the current invocation and may complete even when drain
        // has started. From the second invocation on, drain wins the ordering
        // point so a second buffered request is not executed.
        let prefer_buffered = !self.started;
        if self.lifecycle.is_draining() && !prefer_buffered {
            let partial = self.exchange.buffered_since_boundary();
            self.ended = true;
            self.exchange.finish()?;
            return if partial {
                Err(SessionError::Draining)
            } else {
                Ok(None)
            };
        }
        let outcome = {
            let mut read = Box::pin(self.exchange.next_frame());
            let drain = lifecycle.wait_drained();
            tokio::pin!(drain);
            poll_fn(|context| {
                // Prefer an immediately ready frame or clean EOF over drain so
                // a buffered invocation and a FIN are not lost to the race.
                match read.as_mut().poll(context) {
                    Poll::Ready(result) => return Poll::Ready(Some(result)),
                    Poll::Pending => {}
                }
                if drain.as_mut().poll(context).is_ready() {
                    // One final poll distinguishes an already buffered frame
                    // or EOF from a stalled or partially read request.
                    return Poll::Ready(match read.as_mut().poll(context) {
                        Poll::Ready(result) => Some(result),
                        Poll::Pending => None,
                    });
                }
                Poll::Pending
            })
            .await
        };
        let frame = if let Some(frame) = outcome {
            frame?
        } else {
            // Drain raced a read in progress. If the framing layer consumed
            // no byte since the last frame boundary, the stream was idle and
            // this is a clean stop. A partially read header or payload is
            // not a successful completion, so surface the local drain.
            let partial = self.exchange.buffered_since_boundary();
            self.ended = true;
            self.exchange.finish()?;
            return if partial {
                Err(SessionError::Draining)
            } else {
                Ok(None)
            };
        };
        let Some(frame) = frame else {
            self.ended = true;
            self.exchange.complete();
            return Ok(None);
        };
        if self.lifecycle.is_draining() && !prefer_buffered {
            // Drain won the ordering point after this stream's first
            // invocation. Discard the buffered frame rather than executing it.
            self.ended = true;
            self.exchange.finish()?;
            return Ok(None);
        }
        self.started = true;
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

/// Whether the original [`AgentRequestStream::next`] surface dispatches `code`.
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
            | C::SignatureRules
    )
}

/// Whether the complete command surface dispatches request `code`.
#[cfg(feature = "client")]
fn command_serves(code: u32) -> bool {
    use crate::client::RequestCode as C;
    agent_serves(code)
        || matches!(
            C::from(code),
            C::SemiSupervisedModels
                | C::DnsStart
                | C::DnsStop
                | C::Reboot
                | C::ReloadConfig
                | C::ReloadTi
                | C::ResourceUsage
                | C::TorExitNodeList
                | C::TrustedDomainList
                | C::TrustedUserAgentList
                | C::TimeSeriesGenerationPolicyList
                | C::DeleteTimeSeriesGenerationPolicy
                | C::ReloadFilterRule
                | C::InternalNetworkList
                | C::ExclusionList
                | C::Watchlist
                | C::EchoRequest
                | C::DeleteCustomerData
                | C::ProcessList
                | C::Shutdown
                | C::UpdateConfig
        )
}

/// Whether the node-only runner dispatches request `code`.
#[cfg(feature = "client")]
fn node_serves(code: u32) -> bool {
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
    decoding: super::exchange::Decoding,
) -> Result<T, SessionError> {
    let bytes = frame
        .as_bytes()
        .get(4..)
        .ok_or_else(|| malformed("request code is truncated"))?;
    let (value, consumed) = decode(bytes, &super::decode::Budget::new(limit))?;
    let trailing = bytes.len().saturating_sub(consumed);
    if decoding == super::exchange::Decoding::Exact && trailing != 0 {
        return Err(SessionError::malformed(format!(
            "{trailing} unexpected trailing bytes after the payload"
        )));
    }
    Ok(value)
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

    /// Returns the cloneable drain state shared with this connection's owners.
    #[must_use]
    pub fn lifecycle(&self) -> SessionLifecycle {
        self.shared.lifecycle.clone()
    }

    /// Stops incoming acceptance and refuses new outgoing exchanges.
    ///
    /// Repeated calls are idempotent and wake a blocked accept.
    pub fn drain(&self) {
        self.shared.lifecycle.drain();
    }

    /// Waits until every admitted exchange of this connection completes.
    pub async fn wait_idle(&self) {
        self.shared.lifecycle.wait_idle().await;
    }

    /// Accepts the next stream or returns `None` on clean exhaustion.
    ///
    /// Drain, local closure, or peer closure with application code zero ends
    /// acceptance. An accept that wins the admission race with drain returns a
    /// stream already counted as active; a stream that loses the race is
    /// dropped and never escapes untracked. Cancellation consumes no stream.
    ///
    /// # Errors
    /// Returns a typed transport failure for abnormal connection closure.
    pub async fn accept_next(&mut self) -> Result<Option<ServerStream>, SessionError> {
        tokio::select! {
            biased;
            () = self.control.drained() => Ok(None),
            closed = self.control.closed() => exhausted(closed, &self.shared.connection),
            stream = self.accept_stream() => match stream {
                Ok(stream) => Ok(Some(stream)),
                Err(SessionError::Draining) => Ok(None),
                Err(_) => exhausted(self.control.closed().await, &self.shared.connection),
            },
        }
    }

    async fn accept_until_drained(&mut self) -> Result<Option<ServerStream>, SessionError> {
        tokio::select! {
            biased;
            () = self.control.drained() => Ok(None),
            stream = self.accept_stream() => match stream {
                Ok(stream) => Ok(Some(stream)),
                Err(SessionError::Draining) => Ok(None),
                Err(error) => Err(error),
            },
        }
    }

    async fn accept_stream(&self) -> Result<ServerStream, SessionError> {
        tokio::select! {
            result = self.shared.connection.accept_bi() => {
                let (send, recv) = result.map_err(|e| SessionError::transport(e, OutcomeCertainty::NotSent).on_connection(&self.shared.connection))?;
                let activity = self.shared.lifecycle.try_admit()?;
                Ok(ServerStream::Requests(ServerRequestStream {
                    owner: RequestOwner::new(
                        send,
                        recv,
                        self.shared.options.clone(),
                        &self.shared.connection,
                        self.shared.lifecycle.clone(),
                        activity,
                    ),
                    authorization: self.authorization.clone(),
                    session: self.shared.clone(),
                }))
            }
            result = self.shared.connection.accept_uni() => {
                let recv = result.map_err(|e| SessionError::transport(e, OutcomeCertainty::NotSent).on_connection(&self.shared.connection))?;
                let activity = self.shared.lifecycle.try_admit()?;
                Ok(ServerStream::DetectionEvents(super::DetectionEventReceiver::new(
                    recv,
                    self.shared.options.detection_events,
                    self.shared.clone(),
                    activity,
                )))
            }
        }
    }
}

#[cfg(feature = "server")]
fn exhausted(
    closed: ServerSessionClose,
    connection: &oinq::Connection,
) -> Result<Option<ServerStream>, SessionError> {
    match closed {
        ServerSessionClose::Local | ServerSessionClose::Peer { code: 0, .. } => Ok(None),
        ServerSessionClose::Peer { code, reason } => {
            Err(unsent(PeerClosed { code, reason }).on_connection(connection))
        }
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
            let Some((code, frame)) = self
                .owner
                .next(server_serves, server_unserved, &mut false)
                .await?
            else {
                return Ok(None);
            };
            self.owner.exchange.certainty = OutcomeCertainty::Unknown;
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
            let names = match arguments::<Vec<(&str, &str)>>(
                &frame,
                limit,
                super::exchange::Decoding::Prefix,
            ) {
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
        GetEndpointSources(EndpointSourcesRequest) -> EndpointSources
            => |h, peer, request| h.get_endpoint_sources(peer, &request).await,
        ReportTrainingFilter((u32, TrainingFilterReport)) -> ()
            => |h, peer, (run_id, report)| h.report_training_filter(peer, run_id, &report).await,
        ReportRoundFilter((i32, String, RoundFilterReport)) -> ()
            => |h, peer, (detector_id, model, report)| h.report_round_filter(peer, detector_id, &model, &report).await,
        GetSignatureRules(Option<u64>) -> Option<SignatureRules>
            => |h, peer, known_revision| h.get_signature_rules(peer, known_revision).await,
        ReportSignatureStatus(SignatureStatusReport) -> ()
            => |h, peer, report| h.report_signature_status(peer, &report).await,
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

/// An owned, sent run report awaiting its response.
///
/// Cancelling `response` retains framing progress; dropping this owner aborts
/// the exchange. The configured operation timeout applies to the response phase.
/// A transport failure after sending leaves the outcome unknown.
#[cfg(feature = "client")]
pub struct ReportRunExchange {
    exchange: Exchange,
    operation_timeout: Option<std::time::Duration>,
    /// Keeps the sent exchange counted as active until its response completes.
    _activity: SessionActivity,
}

#[cfg(feature = "client")]
impl ReportRunExchange {
    /// Receives the report response, retaining progress across cancellation.
    ///
    /// # Errors
    /// Returns a classified transport, framing, deadline, or remote rejection error.
    pub async fn response(&mut self) -> Result<(), SessionError> {
        let operation = async {
            let response: Result<(), String> = self.exchange.receive().await?;
            self.exchange.complete();
            response.map_err(SessionError::RemoteRejection)
        };
        if let Some(timeout) = self.operation_timeout {
            tokio::time::timeout(timeout, operation)
                .await
                .map_err(|source| SessionError::Deadline {
                    certainty: self.exchange.certainty,
                    source: Some(source),
                })?
        } else {
            operation.await
        }
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

    /// Returns a cloneable control for draining, closing, or waiting.
    #[must_use]
    pub fn control(&self) -> super::AgentSessionControl {
        super::AgentSessionControl::new(self.0.connection.clone(), self.0.lifecycle.clone())
    }

    /// Returns the cloneable drain state shared with this connection's owners.
    #[must_use]
    pub fn lifecycle(&self) -> SessionLifecycle {
        self.0.lifecycle.clone()
    }

    /// Stops incoming acceptance and refuses new outgoing exchanges.
    ///
    /// Repeated calls are idempotent and wake a blocked accept.
    pub fn drain(&self) {
        self.0.lifecycle.drain();
    }

    /// Waits until every admitted exchange of this connection completes.
    pub async fn wait_idle(&self) {
        self.0.lifecycle.wait_idle().await;
    }

    /// Accepts a command stream without waiting for its first request frame.
    ///
    /// Cancellation consumes no stream. Supervise returned stream owners independently.
    /// # Errors
    /// Returns a classified transport error when the connection closes, or
    /// [`SessionError::Draining`] once acceptance has drained.
    pub async fn accept(&mut self) -> Result<AgentRequestStream, SessionError> {
        self.accept_next().await?.ok_or(SessionError::Draining)
    }

    /// Accepts the next command stream or returns `None` on clean exhaustion.
    ///
    /// Drain, local closure, or peer closure ends acceptance. A stream that wins
    /// the admission race with drain is returned already counted as active; a
    /// stream that loses is dropped and never escapes untracked. Cancellation
    /// consumes no stream.
    ///
    /// # Errors
    /// Returns a classified transport error when the connection closes abnormally.
    pub async fn accept_next(&mut self) -> Result<Option<AgentRequestStream>, SessionError> {
        let lifecycle = self.0.lifecycle.clone();
        tokio::select! {
            biased;
            () = lifecycle.wait_drained() => Ok(None),
            result = self.0.connection.accept_bi() => {
                let (send, recv) = result.map_err(|e| {
                    SessionError::transport(e, OutcomeCertainty::NotSent)
                        .on_connection(&self.0.connection)
                })?;
                let activity = match self.0.lifecycle.try_admit() {
                    Ok(activity) => activity,
                    Err(SessionError::Draining) => return Ok(None),
                    Err(error) => return Err(error),
                };
                Ok(Some(AgentRequestStream(RequestOwner::new(
                    send,
                    recv,
                    self.0.options.clone(),
                    &self.0.connection,
                    lifecycle,
                    activity,
                ))))
            }
        }
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
    pub async fn next(&mut self) -> Result<Option<AgentRequest<'_>>, SessionError> {
        let Some(command) = self.next_with(agent_serves).await? else {
            return Ok(None);
        };
        match command {
            AgentCommand::TrainModel { request, reply } => {
                Ok(Some(AgentRequest::TrainModel { request, reply }))
            }
            AgentCommand::CloneModel { request, reply } => {
                Ok(Some(AgentRequest::CloneModel { request, reply }))
            }
            AgentCommand::CancelRun { request, reply } => {
                Ok(Some(AgentRequest::CancelRun { request, reply }))
            }
            AgentCommand::RunDetectorOnce { request, reply } => {
                Ok(Some(AgentRequest::RunDetectorOnce { request, reply }))
            }
            AgentCommand::SignatureRules { request, reply } => {
                Ok(Some(AgentRequest::SignatureRules { request, reply }))
            }
            AgentCommand::Service { request, reply } => {
                Ok(Some(AgentRequest::Service { request, reply }))
            }
            AgentCommand::NetworkInterface { request, reply } => {
                Ok(Some(AgentRequest::NetworkInterface { request, reply }))
            }
            AgentCommand::Hostname { request, reply } => {
                Ok(Some(AgentRequest::Hostname { request, reply }))
            }
            AgentCommand::TimeSync { request, reply } => {
                Ok(Some(AgentRequest::TimeSync { request, reply }))
            }
            AgentCommand::Logging { request, reply } => {
                Ok(Some(AgentRequest::Logging { request, reply }))
            }
            AgentCommand::RemoteAccess { request, reply } => {
                Ok(Some(AgentRequest::RemoteAccess { request, reply }))
            }
            AgentCommand::Observation { request, reply } => {
                Ok(Some(AgentRequest::Observation { request, reply }))
            }
            AgentCommand::Version { request, reply } => {
                Ok(Some(AgentRequest::Version { request, reply }))
            }
            AgentCommand::Enroll { request, reply } => {
                Ok(Some(AgentRequest::Enroll { request, reply }))
            }
            AgentCommand::Power { request, reply } => {
                Ok(Some(AgentRequest::Power { request, reply }))
            }
            AgentCommand::Package { request, reply } => {
                Ok(Some(AgentRequest::Package { request, reply }))
            }
            _ => unreachable!("the original request filter admits only AgentRequest variants"),
        }
    }

    /// Reads the next supported command, including legacy flat commands.
    ///
    /// Authorize every returned command. Respond before reading another command.
    /// # Errors
    /// Returns classified transport, malformed request, or limit errors and aborts the stream.
    pub async fn next_command(&mut self) -> Result<Option<AgentCommand<'_>>, SessionError> {
        self.next_with(command_serves).await
    }

    async fn next_with(
        &mut self,
        serves: fn(u32) -> bool,
    ) -> Result<Option<AgentCommand<'_>>, SessionError> {
        self.next_with_phase(serves, &mut false).await
    }

    #[allow(clippy::too_many_lines)]
    async fn next_with_phase(
        &mut self,
        serves: fn(u32) -> bool,
        response_write: &mut bool,
    ) -> Result<Option<AgentCommand<'_>>, SessionError> {
        let next = self.0.next(serves, agent_unserved, response_write).await?;
        let Some((code, frame)) = next else {
            return Ok(None);
        };
        self.0.exchange.certainty = OutcomeCertainty::Unknown;
        let limit = self.0.options.unary.get();
        let mut exchange = ExchangeLease(Some(&mut self.0.exchange));
        let request = match code {
            code if code == u32::from(crate::client::RequestCode::NodeService) => {
                let request: NodeServiceRequest = exchange.arguments(code, frame, limit).await?;
                AgentCommand::Service {
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
                AgentCommand::NetworkInterface {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeNetworkInterfaceResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeHostname) => {
                let request: NodeHostnameRequest = exchange.arguments(code, frame, limit).await?;
                AgentCommand::Hostname {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeHostnameResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeTimeSync) => {
                let request: NodeTimeSyncRequest = exchange.arguments(code, frame, limit).await?;
                AgentCommand::TimeSync {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeTimeSyncResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeLogging) => {
                let request: NodeLoggingRequest = exchange.arguments(code, frame, limit).await?;
                AgentCommand::Logging {
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
                AgentCommand::RemoteAccess {
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
                AgentCommand::Observation {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeObservationResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeVersion) => {
                let request: NodeVersionRequest = exchange.arguments(code, frame, limit).await?;
                AgentCommand::Version {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeVersionResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeEnroll) => {
                let request: NodeEnrollRequest = exchange.arguments(code, frame, limit).await?;
                AgentCommand::Enroll {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeEnrollResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodePower) => {
                let request: NodePowerRequest = exchange.arguments(code, frame, limit).await?;
                AgentCommand::Power {
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
                AgentCommand::Package {
                    request,
                    reply: PackageReply {
                        exchange,
                        remaining,
                        size: remaining,
                        options: self.0.options.clone(),
                        receiving: false,
                        failed: false,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::UpdateConfig) => {
                let request: () = exchange.arguments(code, frame, limit).await?;
                AgentCommand::UpdateConfig {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::TrainModel) => {
                let request: TrainModelRequest = exchange.arguments(code, frame, limit).await?;
                AgentCommand::TrainModel {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::CloneModel) => {
                let request: CloneModelRequest = exchange.arguments(code, frame, limit).await?;
                AgentCommand::CloneModel {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::CancelRun) => {
                let request: u32 = exchange.arguments(code, frame, limit).await?;
                AgentCommand::CancelRun {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::RunDetectorOnce) => {
                let request: i32 = exchange.arguments(code, frame, limit).await?;
                AgentCommand::RunDetectorOnce {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::SignatureRules) => {
                let request: SignatureRules = exchange.arguments(code, frame, limit).await?;
                AgentCommand::SignatureRules {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::DnsStart) => {
                let request: () = exchange.arguments(code, frame, limit).await?;
                AgentCommand::DnsStart {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::DnsStop) => {
                let request: () = exchange.arguments(code, frame, limit).await?;
                AgentCommand::DnsStop {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::Reboot) => {
                let request: () = exchange.arguments(code, frame, limit).await?;
                AgentCommand::Reboot {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::ReloadConfig) => {
                let request: () = exchange.arguments(code, frame, limit).await?;
                AgentCommand::ReloadConfig {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::ReloadTi) => {
                let request: String = exchange.arguments(code, frame, limit).await?;
                AgentCommand::ReloadTi {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::ResourceUsage) => {
                let request: () = exchange.arguments(code, frame, limit).await?;
                AgentCommand::ResourceUsage {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<(String, crate::types::ResourceUsage)>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::TorExitNodeList) => {
                let request: Vec<String> = exchange.arguments(code, frame, limit).await?;
                AgentCommand::TorExitNodeList {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::TrustedDomainList) => {
                let request: Vec<String> = exchange.arguments(code, frame, limit).await?;
                AgentCommand::TrustedDomainList {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::TrustedUserAgentList) => {
                let request: Vec<String> = exchange.arguments(code, frame, limit).await?;
                AgentCommand::TrustedUserAgentList {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code
                == u32::from(crate::client::RequestCode::TimeSeriesGenerationPolicyList) =>
            {
                let request: Vec<crate::types::TimeSeriesGenerationPolicy> =
                    exchange.arguments(code, frame, limit).await?;
                AgentCommand::TimeSeriesGenerationPolicyList {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code
                == u32::from(crate::client::RequestCode::DeleteTimeSeriesGenerationPolicy) =>
            {
                let request: Vec<u32> = exchange.arguments(code, frame, limit).await?;
                AgentCommand::DeleteTimeSeriesGenerationPolicy {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::ReloadFilterRule) => {
                let request: Vec<crate::types::TrafficFilterRule> =
                    exchange.arguments(code, frame, limit).await?;
                AgentCommand::ReloadFilterRule {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::InternalNetworkList) => {
                let request: crate::types::HostNetworkGroup =
                    exchange.arguments(code, frame, limit).await?;
                AgentCommand::InternalNetworkList {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::ExclusionList) => {
                let request: Vec<NetworkListItem> =
                    exchange.arguments_exact(code, frame, limit).await?;
                AgentCommand::ExclusionList {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::Watchlist) => {
                let request: Vec<NetworkListItem> =
                    exchange.arguments_exact(code, frame, limit).await?;
                AgentCommand::Watchlist {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::EchoRequest) => {
                let request: () = exchange.arguments(code, frame, limit).await?;
                AgentCommand::EchoRequest {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::DeleteCustomerData) => {
                let request: crate::types::CustomerDataDeletionRequest =
                    exchange.arguments(code, frame, limit).await?;
                AgentCommand::DeleteCustomerData {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::ProcessList) => {
                let request: () = exchange.arguments(code, frame, limit).await?;
                AgentCommand::ProcessList {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<Vec<crate::types::Process>>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::Shutdown) => {
                let request: () = exchange.arguments(code, frame, limit).await?;
                AgentCommand::Shutdown {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::SemiSupervisedModels) => {
                let request = frame
                    .as_bytes()
                    .get(4..)
                    .ok_or_else(|| malformed("request code is truncated"))?
                    .to_vec();
                exchange.recycle(frame)?;
                AgentCommand::SemiSupervisedModels {
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

/// The original typed agent-side invocation surface.
///
/// Use [`AgentRequestStream::next_command`] to receive every supported command,
/// including legacy flat commands.
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
        /// The peer-supplied run identifier.
        request: u32,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, ()>,
    },
    /// The `RunDetectorOnce` engine operation.
    RunDetectorOnce {
        /// The peer-supplied detector identifier.
        request: i32,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, ()>,
    },
    /// The signature-rule push to a Semi-supervised Engine.
    SignatureRules {
        /// The peer-supplied rule sets.
        request: SignatureRules,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, ()>,
    },
    /// The node service family.
    Service {
        /// The peer-supplied request.
        request: NodeServiceRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeServiceResponse>,
    },
    /// The node network-interface family.
    NetworkInterface {
        /// The peer-supplied request.
        request: NodeNetworkInterfaceRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeNetworkInterfaceResponse>,
    },
    /// The node hostname family.
    Hostname {
        /// The peer-supplied request.
        request: NodeHostnameRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeHostnameResponse>,
    },
    /// The node time-synchronization family.
    TimeSync {
        /// The peer-supplied request.
        request: NodeTimeSyncRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeTimeSyncResponse>,
    },
    /// The node logging-configuration family.
    Logging {
        /// The peer-supplied request.
        request: NodeLoggingRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeLoggingResponse>,
    },
    /// The node remote-access family.
    RemoteAccess {
        /// The peer-supplied request.
        request: NodeRemoteAccessRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeRemoteAccessResponse>,
    },
    /// The node host-observation family.
    Observation {
        /// The peer-supplied request.
        request: NodeObservationRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeObservationResponse>,
    },
    /// The node version-management family.
    Version {
        /// The peer-supplied request.
        request: NodeVersionRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeVersionResponse>,
    },
    /// The node service-enrollment family.
    Enroll {
        /// The peer-supplied request.
        request: NodeEnrollRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeEnrollResponse>,
    },
    /// The node power-control family.
    Power {
        /// The peer-supplied request.
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

/// A failure while running an agent command stream.
#[cfg(feature = "client")]
#[derive(Debug, thiserror::Error)]
pub enum AgentRunError {
    /// A session failure while no response was being written (for example, reading a request).
    #[error(transparent)]
    Session(#[from] SessionError),
    /// A failure while preparing or writing a response, including package preflight.
    #[error("writing agent response: {0}")]
    ResponseWrite(#[source] SessionError),
    /// The application policy denied a command before handler execution.
    #[error("authorization denied for {service}")]
    AuthorizationDenied {
        /// The logical service that was denied.
        service: crate::service_id::ServiceId,
        /// The application's authorization failure.
        #[source]
        source: crate::auth::AuthorizationError,
    },
}

/// A typed agent-side command, including the original requests and legacy flat commands.
#[cfg(feature = "client")]
pub enum AgentCommand<'a> {
    /// Legacy `DnsStart` command.
    DnsStart {
        /// Peer-supplied arguments.
        request: (),
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `DnsStop` command.
    DnsStop {
        /// Peer-supplied arguments.
        request: (),
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `Reboot` command.
    Reboot {
        /// Peer-supplied arguments.
        request: (),
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `ReloadConfig` command.
    ReloadConfig {
        /// Peer-supplied arguments.
        request: (),
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `ReloadTi` command.
    ReloadTi {
        /// Peer-supplied arguments.
        request: String,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `ResourceUsage` command.
    ResourceUsage {
        /// Peer-supplied arguments.
        request: (),
        /// Response capability.
        reply: Reply<'a, (String, crate::types::ResourceUsage)>,
    },
    /// Legacy `TorExitNodeList` command.
    TorExitNodeList {
        /// Peer-supplied arguments.
        request: Vec<String>,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `TrustedDomainList` command.
    TrustedDomainList {
        /// Peer-supplied arguments.
        request: Vec<String>,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `TrustedUserAgentList` command.
    TrustedUserAgentList {
        /// Peer-supplied arguments.
        request: Vec<String>,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `TimeSeriesGenerationPolicyList` command.
    TimeSeriesGenerationPolicyList {
        /// Peer-supplied arguments.
        request: Vec<crate::types::TimeSeriesGenerationPolicy>,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `DeleteTimeSeriesGenerationPolicy` command.
    DeleteTimeSeriesGenerationPolicy {
        /// Peer-supplied arguments.
        request: Vec<u32>,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `ReloadFilterRule` command.
    ReloadFilterRule {
        /// Peer-supplied arguments.
        request: Vec<crate::types::TrafficFilterRule>,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `InternalNetworkList` command.
    InternalNetworkList {
        /// Peer-supplied arguments.
        request: crate::types::HostNetworkGroup,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `ExclusionList` command.
    ExclusionList {
        /// Peer-supplied arguments.
        request: Vec<NetworkListItem>,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `Watchlist` command.
    Watchlist {
        /// Peer-supplied arguments.
        request: Vec<NetworkListItem>,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `EchoRequest` command.
    EchoRequest {
        /// Peer-supplied arguments.
        request: (),
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `DeleteCustomerData` command.
    DeleteCustomerData {
        /// Peer-supplied arguments.
        request: crate::types::CustomerDataDeletionRequest,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy `ProcessList` command.
    ProcessList {
        /// Peer-supplied arguments.
        request: (),
        /// Response capability.
        reply: Reply<'a, Vec<crate::types::Process>>,
    },
    /// Legacy `Shutdown` command.
    Shutdown {
        /// Peer-supplied arguments.
        request: (),
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// Legacy raw model update.
    SemiSupervisedModels {
        /// The raw model bytes.
        request: Vec<u8>,
        /// Response capability.
        reply: Reply<'a, ()>,
    },
    /// The configuration update notification.
    UpdateConfig {
        /// The empty request body.
        request: (),
        /// The response capability borrowing this request stream.
        reply: Reply<'a, ()>,
    },

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

    /// The `SignatureRules` push: the signature rule sets a Semi-supervised
    /// Engine replaces its own with.
    SignatureRules {
        /// The peer-supplied arguments.
        request: SignatureRules,
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
    /// The node network-interface family.
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
    /// The node time-synchronization family.
    TimeSync {
        /// The peer-supplied arguments.
        request: NodeTimeSyncRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeTimeSyncResponse>,
    },
    /// The node logging-configuration family.
    Logging {
        /// The peer-supplied arguments.
        request: NodeLoggingRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeLoggingResponse>,
    },
    /// The node remote-access family.
    RemoteAccess {
        /// The peer-supplied arguments.
        request: NodeRemoteAccessRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeRemoteAccessResponse>,
    },
    /// The node host-observation family.
    Observation {
        /// The peer-supplied arguments.
        request: NodeObservationRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeObservationResponse>,
    },
    /// The node version-management family.
    Version {
        /// The peer-supplied arguments.
        request: NodeVersionRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeVersionResponse>,
    },
    /// The node service-enrollment family.
    Enroll {
        /// The peer-supplied arguments.
        request: NodeEnrollRequest,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, NodeEnrollResponse>,
    },
    /// The node power-control family.
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

#[cfg(feature = "client")]
impl AgentCommand<'_> {
    /// Returns the logical service used for authorization, including node subcommands.
    #[must_use]
    pub fn service_id(&self) -> crate::service_id::ServiceId {
        match self {
            Self::DnsStart { .. } => crate::service_id::COMMON_DNS_START,
            Self::DnsStop { .. } => crate::service_id::COMMON_DNS_STOP,
            Self::Reboot { .. } => crate::service_id::NODE_POWER_REBOOT,
            Self::ReloadConfig { .. } => crate::service_id::COMMON_RELOAD_CONFIG,
            Self::ReloadTi { .. } => crate::service_id::COMMON_RELOAD_TI,
            Self::ResourceUsage { .. } => crate::service_id::NODE_OBSERVATION_RESOURCE_USAGE,
            Self::TorExitNodeList { .. } => crate::service_id::COMMON_TOR_EXIT_NODE_LIST,
            Self::TrustedDomainList { .. } => crate::service_id::COMMON_TRUSTED_DOMAIN_LIST,
            Self::TrustedUserAgentList { .. } => crate::service_id::COMMON_TRUSTED_USER_AGENT_LIST,
            Self::TimeSeriesGenerationPolicyList { .. } => {
                crate::service_id::COMMON_TIME_SERIES_GENERATION_POLICY_LIST
            }
            Self::DeleteTimeSeriesGenerationPolicy { .. } => {
                crate::service_id::COMMON_DELETE_TIME_SERIES_GENERATION_POLICY
            }
            Self::ReloadFilterRule { .. } => crate::service_id::COMMON_RELOAD_FILTER_RULE,
            Self::InternalNetworkList { .. } => crate::service_id::COMMON_INTERNAL_NETWORK_LIST,
            Self::ExclusionList { .. } => crate::service_id::COMMON_EXCLUSION_LIST,
            Self::Watchlist { .. } => crate::service_id::COMMON_WATCHLIST,
            Self::EchoRequest { .. } => crate::service_id::COMMON_ECHO,
            Self::DeleteCustomerData { .. } => crate::service_id::COMMON_DELETE_CUSTOMER_DATA,
            Self::ProcessList { .. } => crate::service_id::NODE_OBSERVATION_PROCESS_LIST,
            Self::Shutdown { .. } => crate::service_id::NODE_POWER_SHUTDOWN,
            Self::SemiSupervisedModels { .. } => crate::service_id::COMMON_SEMI_SUPERVISED_MODELS,
            Self::SignatureRules { .. } => crate::service_id::COMMON_SIGNATURE_RULES,
            Self::UpdateConfig { .. } => crate::service_id::COMMON_UPDATE_CONFIG,
            Self::TrainModel { .. } => crate::service_id::ENGINE_TRAIN_MODEL,
            Self::CloneModel { .. } => crate::service_id::ENGINE_CLONE_MODEL,
            Self::CancelRun { .. } => crate::service_id::ENGINE_CANCEL_RUN,
            Self::RunDetectorOnce { .. } => crate::service_id::ENGINE_RUN_DETECTOR_ONCE,
            Self::Service { request, .. } => request.service_id(),
            Self::NetworkInterface { request, .. } => request.service_id(),
            Self::Hostname { request, .. } => request.service_id(),
            Self::TimeSync { request, .. } => request.service_id(),
            Self::Logging { request, .. } => request.service_id(),
            Self::RemoteAccess { request, .. } => request.service_id(),
            Self::Observation { request, .. } => request.service_id(),
            Self::Version { request, .. } => request.service_id(),
            Self::Enroll { request, .. } => request.service_id(),
            Self::Power { request, .. } => request.service_id(),
            Self::Package { request, .. } => request.service_id(),
        }
    }
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

    /// Fetches a data source, returning `None` when it does not exist.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn get_data_source(
        &self,
        key: &crate::types::DataSourceKey<'_>,
    ) -> Result<Option<crate::types::DataSource>, SessionError> {
        self.0
            .unary(u32::from(crate::server::RequestCode::GetDataSource), key)
            .await
    }

    /// Fetches an indicator by name.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn get_indicator(
        &self,
        name: &str,
    ) -> Result<std::collections::HashSet<Vec<String>>, SessionError> {
        self.0
            .unary(u32::from(crate::server::RequestCode::GetIndicator), name)
            .await
    }

    /// Fetches the internal-network list.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn get_internal_network_list(
        &self,
    ) -> Result<crate::types::HostNetworkGroup, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetInternalNetworkList),
                (),
            )
            .await
    }

    /// Fetches label-database patterns for the requested databases.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn get_labeldb_patterns(
        &self,
        labeldbs: &[(&str, &str)],
    ) -> Result<Vec<(String, Option<crate::types::LabelDb>)>, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetLabelDbPatterns),
                labeldbs,
            )
            .await
    }

    /// Fetches the Tor exit-node list.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn get_tor_exit_node_list(&self) -> Result<Vec<String>, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetTorExitNodeList),
                (),
            )
            .await
    }

    /// Fetches the trusted-domain list.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn get_trusted_domain_list(&self) -> Result<Vec<String>, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetTrustedDomainList),
                (),
            )
            .await
    }

    /// Fetches the trusted-user-agent list.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn get_trusted_user_agent_list(&self) -> Result<Vec<String>, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetTrustedUserAgentList),
                (),
            )
            .await
    }

    /// Fetches the time-series generation policies.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn get_time_series_generation_policy_list(
        &self,
    ) -> Result<Vec<crate::types::TimeSeriesGenerationPolicy>, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetTimeSeriesGenerationPolicyList),
                (),
            )
            .await
    }

    /// Requests a renewed certificate and private key.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn renew_certificate(&self) -> Result<(String, String), SessionError> {
        self.0
            .unary(u32::from(crate::server::RequestCode::RenewCertificate), ())
            .await
    }

    /// Inserts column statistics for a model batch.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn insert_column_statistics(
        &self,
        statistics: &[crate::types::ColumnStatisticsUpdate],
        model_id: u32,
        batch_ts: i64,
    ) -> Result<(), SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::InsertColumnStatistics),
                &(statistics, model_id, batch_ts),
            )
            .await
    }

    /// Inserts time-series updates for a model batch.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn insert_time_series(
        &self,
        time_series: &[crate::types::TimeSeriesUpdate],
        model_id: u32,
        batch_ts: i64,
    ) -> Result<(), SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::InsertTimeSeries),
                &(time_series, model_id, batch_ts),
            )
            .await
    }

    /// Updates a model's clusters.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn update_clusters(
        &self,
        input: &[crate::types::UpdateClusterRequest],
        model_id: u32,
    ) -> Result<(), SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::UpdateClusters),
                &(input, model_id),
            )
            .await
    }

    /// Updates a model's outliers at a timestamp.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn update_outliers(
        &self,
        outliers: &[crate::types::OutlierInfo],
        model_id: u32,
        timestamp: i64,
    ) -> Result<(), SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::UpdateOutliers),
                &(outliers, model_id, timestamp),
            )
            .await
    }

    /// Inserts a model round's detection events.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn insert_detection_events(
        &self,
        model_id: u32,
        round: u32,
        events: &[crate::types::DetectionEvent],
    ) -> Result<(), SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::InsertDetectionEvents),
                &(model_id, round, events),
            )
            .await
    }

    /// Inserts a data source and returns its identifier.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn insert_data_source(
        &self,
        data_source: &crate::types::DataSource,
    ) -> Result<u32, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::InsertDataSource),
                data_source,
            )
            .await
    }

    /// Fetches a model's outliers at a timestamp.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn get_outliers(
        &self,
        model_id: u32,
        timestamp: i64,
    ) -> Result<Vec<(String, Vec<i64>)>, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetOutliers),
                &(model_id, timestamp),
            )
            .await
    }

    /// Fetches the DAI extractor configuration for sensors.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn get_dai_extractor_config(
        &self,
        sensors: &[String],
    ) -> Result<crate::types::DaiExtractorConfig, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetDaiExtractorConfig),
                sensors,
            )
            .await
    }

    /// Fetches DAI read cursors for sensors.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn get_dai_cursors(
        &self,
        sensors: &[String],
    ) -> Result<crate::types::DaiCursors, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetDaiCursors),
                sensors,
            )
            .await
    }

    /// Sends a DAI observation batch.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn send_dai_observations(
        &self,
        batch: &crate::types::DaiObservationBatch,
    ) -> Result<crate::types::DaiStoreAck, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::SendDaiObservations),
                batch,
            )
            .await
    }

    /// Starts a DAI range-day round.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn begin_dai_range_day(
        &self,
        unit: &crate::types::DaiRangeUnit,
        restore_generation: u64,
    ) -> Result<crate::types::DaiRangeGrant, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::BeginDaiRangeDay),
                (unit, restore_generation),
            )
            .await
    }

    /// Renews a DAI range-day lease.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn renew_dai_range_day(
        &self,
        unit: &crate::types::DaiRangeUnit,
        lease_token: u64,
    ) -> Result<Option<i64>, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::RenewDaiRangeDay),
                (unit, lease_token),
            )
            .await
    }

    /// Sends DAI range-day counts.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn send_dai_range_day(
        &self,
        day: &crate::types::DaiRangeDay,
    ) -> Result<crate::types::DaiStoreAck, SessionError> {
        self.0
            .unary(u32::from(crate::server::RequestCode::SendDaiRangeDay), day)
            .await
    }

    /// Reports late DAI range days and returns their assigned marks.
    ///
    /// # Errors
    /// Returns a classified transport, framing, limit, or remote rejection error.
    pub async fn report_dai_range_late(
        &self,
        late: &crate::types::DaiRangeLate,
    ) -> Result<Vec<crate::types::DaiRangeMark>, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::ReportDaiRangeLate),
                late,
            )
            .await
    }

    /// Sends the `upload_run_model` engine operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn upload_run_model(&self, run_id: u32, model: &[u8]) -> Result<(), SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::UploadRunModel),
                (run_id, model),
            )
            .await
    }

    /// Sends a run report and returns an owned response exchange.
    ///
    /// # Errors
    /// Returns a classified transport, encoding, limit, or deadline error. Once
    /// sending begins, failure may leave the mutation outcome unknown.
    pub async fn start_report_run(
        &self,
        run_id: u32,
        state: ReportedRunState,
        reason: Option<&str>,
    ) -> Result<ReportRunExchange, SessionError> {
        let activity = self.0.lifecycle.try_admit()?;
        let mut activity = Some(activity);
        let mut certainty = OutcomeCertainty::NotSent;
        let operation = async {
            let (send, recv) = self.0.connection.open_bi().await.map_err(|error| {
                SessionError::transport(error, certainty).on_connection(&self.0.connection)
            })?;
            let mut exchange = Exchange::new(send, recv, self.0.options.unary, &self.0.connection);
            exchange.start_request(
                u32::from(crate::server::RequestCode::ReportRun),
                (run_id, state, reason),
            )?;
            certainty = OutcomeCertainty::Unknown;
            exchange.flush().await?;
            let activity = activity.take().ok_or(SessionError::Draining)?;
            Ok(ReportRunExchange {
                exchange,
                operation_timeout: self.0.options.operation_timeout,
                _activity: activity,
            })
        };
        if let Some(timeout) = self.0.options.operation_timeout {
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

    /// Sends the `report_run` engine operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn report_run(
        &self,
        run_id: u32,
        state: ReportedRunState,
        reason: Option<&str>,
    ) -> Result<(), SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::ReportRun),
                (run_id, state, reason),
            )
            .await
    }

    /// Sends the `report_active_runs` engine operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn report_active_runs(&self, run_ids: &[u32]) -> Result<(), SessionError> {
        self.0
            .unary(
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
        self.0
            .unary(
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
        self.0
            .unary(
                u32::from(crate::server::RequestCode::ReportExclusionCounts),
                report,
            )
            .await
    }

    /// Sends the `get_signature_rules` engine operation, pulling the
    /// signature rule sets.
    ///
    /// `known_revision` is the revision of the rule sets the engine has, if
    /// any. The manager answers `None` when it is the manager's current
    /// revision, and the current rule sets otherwise.
    ///
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn get_signature_rules(
        &self,
        known_revision: Option<u64>,
    ) -> Result<Option<SignatureRules>, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetSignatureRules),
                known_revision,
            )
            .await
    }

    /// Sends the `report_signature_status` engine operation, the status of a
    /// Semi-supervised Engine's signature matching.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn report_signature_status(
        &self,
        report: &SignatureStatusReport,
    ) -> Result<(), SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::ReportSignatureStatus),
                report,
            )
            .await
    }

    /// Resolves endpoint sources at training start or before an analysis round.
    ///
    /// See [`EndpointSourcesRequest`] and the report types for producer obligations.
    /// # Errors
    /// Returns an error on transport failure, malformed response or remote refusal.
    pub async fn get_endpoint_sources(
        &self,
        request: &EndpointSourcesRequest,
    ) -> Result<EndpointSources, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetEndpointSources),
                request,
            )
            .await
    }

    /// Reports training filter counts before model upload.
    ///
    /// See [`EndpointSourcesRequest`] and the report types for producer obligations.
    /// # Errors
    /// Returns an error on transport failure, malformed response or remote refusal.
    pub async fn report_training_filter(
        &self,
        run_id: u32,
        report: &TrainingFilterReport,
    ) -> Result<(), SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::ReportTrainingFilter),
                (run_id, report),
            )
            .await
    }

    /// Reports endpoint-scope round filter counts after its status report.
    ///
    /// See [`EndpointSourcesRequest`] and the report types for producer obligations.
    /// # Errors
    /// Returns an error on transport failure, malformed response or remote refusal.
    pub async fn report_round_filter(
        &self,
        detector_id: i32,
        model: &str,
        report: &RoundFilterReport,
    ) -> Result<(), SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::ReportRoundFilter),
                (detector_id, model, report),
            )
            .await
    }

    /// Sends the `get_config` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn get_config(&self) -> Result<String, SessionError> {
        self.0
            .unary(u32::from(crate::server::RequestCode::GetConfig), ())
            .await
    }
    /// Sends the `get_model` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn get_model(&self, request: &str) -> Result<Vec<u8>, SessionError> {
        self.0
            .unary(u32::from(crate::server::RequestCode::GetModel), request)
            .await
    }
    /// Sends the `get_pretrained_model` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn get_pretrained_model(&self, request: &str) -> Result<Vec<u8>, SessionError> {
        self.0
            .unary(
                u32::from(crate::server::RequestCode::GetPretrainedModel),
                request,
            )
            .await
    }
    /// Sends the `get_model_names` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn get_model_names(&self) -> Result<Vec<String>, SessionError> {
        self.0
            .unary(u32::from(crate::server::RequestCode::GetModelNames), ())
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
        self.0
            .unary_as(
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
        self.0
            .unary_as(
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
        self.0
            .unary(u32::from(crate::server::RequestCode::InsertModel), request)
            .await
    }
    /// Sends the `update_model` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn update_model(&self, request: &[u8]) -> Result<u32, SessionError> {
        self.0
            .unary(u32::from(crate::server::RequestCode::UpdateModel), request)
            .await
    }
    /// Sends the `remove_model` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn remove_model(&self, request: &str) -> Result<(), SessionError> {
        self.0
            .unary(u32::from(crate::server::RequestCode::RemoveModel), request)
            .await
    }
    /// Sends the `report_customer_data_deletion` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn report_customer_data_deletion(
        &self,
        request: &CustomerDataDeletionReport,
    ) -> Result<(), SessionError> {
        self.0
            .unary(
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
        self.0
            .unary(u32::from(crate::client::RequestCode::TrainModel), request)
            .await
    }

    /// Sends the `send_clone_model` engine operation.
    ///
    /// Success acknowledges acceptance; subsequent run state arrives in reports.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_clone_model(&self, request: &CloneModelRequest) -> Result<(), SessionError> {
        self.0
            .unary(u32::from(crate::client::RequestCode::CloneModel), request)
            .await
    }

    /// Requests cancellation of an engine run.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_cancel_run(&self, run_id: u32) -> Result<(), SessionError> {
        self.0
            .unary(u32::from(crate::client::RequestCode::CancelRun), run_id)
            .await
    }

    /// Requests one round of an engine detector.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_run_detector_once(&self, detector_id: i32) -> Result<(), SessionError> {
        self.0
            .unary(
                u32::from(crate::client::RequestCode::RunDetectorOnce),
                detector_id,
            )
            .await
    }

    /// Pushes the signature rule sets to a Semi-supervised Engine.
    ///
    /// `Ok(())` means the engine accepted the rule sets.
    ///
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn send_signature_rules(&self, rules: &SignatureRules) -> Result<(), SessionError> {
        self.push(crate::client::RequestCode::SignatureRules, rules)
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
        self.0.unary(u32::from(code), input).await
    }

    /// Sends a typed node service operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_service(
        &self,
        request: NodeServiceRequest,
    ) -> Result<NodeServiceResponse, SessionError> {
        self.0
            .unary(u32::from(crate::client::RequestCode::NodeService), request)
            .await
    }
    /// Sends a typed node network interface operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_network_interface(
        &self,
        request: NodeNetworkInterfaceRequest,
    ) -> Result<NodeNetworkInterfaceResponse, SessionError> {
        self.0
            .unary(
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
        self.0
            .unary(u32::from(crate::client::RequestCode::NodeHostname), request)
            .await
    }
    /// Sends a typed node time sync operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_time_sync(
        &self,
        request: NodeTimeSyncRequest,
    ) -> Result<NodeTimeSyncResponse, SessionError> {
        self.0
            .unary(u32::from(crate::client::RequestCode::NodeTimeSync), request)
            .await
    }
    /// Sends a typed node logging operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_logging(
        &self,
        request: NodeLoggingRequest,
    ) -> Result<NodeLoggingResponse, SessionError> {
        self.0
            .unary(u32::from(crate::client::RequestCode::NodeLogging), request)
            .await
    }
    /// Sends a typed node remote access operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_remote_access(
        &self,
        request: NodeRemoteAccessRequest,
    ) -> Result<NodeRemoteAccessResponse, SessionError> {
        self.0
            .unary(
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
        self.0
            .unary(
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
        self.0
            .unary(u32::from(crate::client::RequestCode::NodeVersion), request)
            .await
    }
    /// Sends a typed node enroll operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn node_enroll(
        &self,
        request: NodeEnrollRequest,
    ) -> Result<NodeEnrollResponse, SessionError> {
        self.0
            .unary(u32::from(crate::client::RequestCode::NodeEnroll), request)
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
        self.0
            .unary(u32::from(crate::client::RequestCode::NodePackage), request)
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
    size: Option<u64>,
    options: super::SessionOptions,
    receiving: bool,
    failed: bool,
}

#[cfg(feature = "client")]
impl PackageReply<'_> {
    /// Returns the declared install payload size, or `None` for other requests.
    #[must_use]
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Returns the unread install payload bytes, or `None` for other requests.
    #[must_use]
    pub fn remaining(&self) -> Option<u64> {
        self.remaining
    }

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
    /// After a failed read or overrun, only an error response may complete the exchange.
    /// # Errors
    /// Returns malformed-state, oversized, overrun, truncation, or transport errors.
    pub async fn next_chunk(&mut self, buffer: &mut Vec<u8>) -> Result<bool, SessionError> {
        if !self.receiving {
            return Err(malformed("package preflight has not proceeded"));
        }
        if self.failed {
            return Err(malformed("the package transfer already failed"));
        }
        let remaining = self
            .remaining
            .ok_or_else(|| malformed("chunk reads require an install"))?;
        if remaining == 0 {
            buffer.clear();
            return Ok(false);
        }
        let frame = match self.exchange.frame_for_package().await {
            Ok(frame) => frame,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        let length = u64::try_from(frame.as_bytes().len()).map_err(SessionError::malformed)?;
        if length > remaining {
            self.exchange.recycle(frame)?;
            self.failed = true;
            return Err(malformed("package chunk exceeds the declared size"));
        }
        self.remaining = Some(remaining - length);
        let previous = std::mem::replace(buffer, frame.into_bytes());
        if let Err(error) = self.exchange.recycle_bytes(previous) {
            self.failed = true;
            return Err(error);
        }
        Ok(true)
    }

    /// Sends the terminal package response after a unary request or an install.
    ///
    /// An incomplete install cannot send a terminal success: an `Ok` response
    /// before every declared byte was received is refused and aborts the stream.
    /// An `Err` response first reads and discards any unread payload when the
    /// transfer is still aligned. After a failed read or overrun, the failure is
    /// already terminal and the rejection is sent without another drain.
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
        if incomplete && !self.failed {
            let mut discard = Vec::new();
            while self.remaining.is_some_and(|remaining| remaining != 0) {
                if self.next_chunk(&mut discard).await.is_err() {
                    break;
                }
            }
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
            self.0
                .send_only(u32::from(crate::client::RequestCode::NodePower), request)
                .await?;
            Ok(NodePowerOutcome::Sent)
        } else {
            self.0
                .unary(u32::from(crate::client::RequestCode::NodePower), request)
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
        let _activity = self.0.lifecycle.try_admit()?;
        let mut certainty = OutcomeCertainty::NotSent;
        let operation = async {
            let (send, recv) = self.0.connection.open_bi().await.map_err(|e| {
                SessionError::transport(e, certainty).on_connection(&self.0.connection)
            })?;
            let mut exchange = Exchange::new(send, recv, options.unary, &self.0.connection);
            exchange.start_request(u32::from(crate::client::RequestCode::NodePackage), &request)?;
            certainty = OutcomeCertainty::Unknown;
            exchange.flush().await?;
            let verdict: Result<InstallPreflight, String> = exchange.receive().await?;
            let terminal = match verdict {
                Ok(verdict) => terminal_preflight(verdict),
                Err(message) => {
                    exchange.complete();
                    return Err(SessionError::RemoteRejection(message));
                }
            };
            if let Some(terminal) = terminal {
                exchange.complete();
                return Ok(InstallOutcome::Preflight(terminal));
            }
            exchange.set_limits(options.unary, options.package_chunks);
            // Sender tuning only; the configured limit is always respected.
            let chunk_size = options.package_chunks.get().min(64 * 1024);
            if chunk_size == 0 && remaining > 0 {
                return Err(SessionError::limit(super::FrameError::TooLarge {
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
    ///   pushes, the four engine commands, the signature rule push, and the
    ///   eleven `node_*` families
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
            RequestCode::SignatureRules => handle!(send_signature_rules),
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
        assert_eq!(methods.len(), 26, "{methods:?}");
        assert_eq!(
            unsent,
            BTreeSet::from([1, 2, 4, 5, 6, 7, 13, 19, 20, 21, u32::MAX])
        );
        assert_eq!(exceptions, [17], "only EchoRequest is an exception");
    }
}

#[cfg(feature = "client")]
impl crate::request::SessionPackageSource for PackageReply<'_> {
    fn next_chunk<'a>(
        &'a mut self,
        buf: &'a mut Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<bool>> + Send + 'a>>
    {
        Box::pin(async move {
            PackageReply::next_chunk(self, buf)
                .await
                .map_err(|error| match error {
                    SessionError::Transport { source, .. } => {
                        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, source)
                    }
                    SessionError::Malformed { source, .. } => {
                        let kind = if source
                            .as_ref()
                            .downcast_ref::<super::FrameError>()
                            .is_some_and(|error| {
                                matches!(error, super::FrameError::Truncated { .. })
                            }) {
                            std::io::ErrorKind::UnexpectedEof
                        } else {
                            std::io::ErrorKind::InvalidData
                        };
                        std::io::Error::new(kind, source)
                    }
                    SessionError::LimitExceeded { source, .. } => {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, source)
                    }
                    error => std::io::Error::other(error),
                })
        })
    }
}

#[cfg(feature = "client")]
impl AgentRequestStream {
    /// Runs node-family commands with a node-only handler and authenticated policy.
    /// Non-node commands receive the legacy unknown-code response without authorization or dispatch.
    ///
    /// # Errors
    /// Returns an authorization failure before handler execution, [`AgentRunError::ResponseWrite`]
    /// while preparing/writing a response, or [`AgentRunError::Session`] otherwise.
    pub async fn run_node_authorized<H: crate::request::NodeHandler>(
        self,
        handler: &mut H,
        context: &crate::auth::AuthorizationContext,
        policy: &dyn crate::auth::AuthorizerV2,
    ) -> Result<(), AgentRunError> {
        self.run_with(&mut NodeHandlerAdapter(handler), true, |command| {
            policy.authorize_with_context(context, &command.service_id())
        })
        .await
    }

    /// Runs commands with an authenticated context and an application policy.
    /// The policy is consulted for every invocation; handshake claims do not grant access.
    /// A denial sends a constant remote rejection, stops the runner, and returns the
    /// typed policy error locally.
    ///
    /// # Errors
    /// Returns an authorization failure before handler execution, [`AgentRunError::ResponseWrite`]
    /// while preparing/writing a response, or [`AgentRunError::Session`] otherwise.
    pub async fn run_authorized<H: crate::request::Handler>(
        self,
        handler: &mut H,
        context: &crate::auth::AuthorizationContext,
        policy: &dyn crate::auth::AuthorizerV2,
    ) -> Result<(), AgentRunError> {
        self.run(handler, |command| {
            policy.authorize_with_context(context, &command.service_id())
        })
        .await
    }

    /// Runs sequential commands using an application-provided authorization check.
    ///
    /// The check runs for each invocation and must use authenticated context
    /// captured by the caller, rather than handshake capability claims.
    ///
    /// # Errors
    /// Returns an authorization failure before handler execution, [`AgentRunError::ResponseWrite`]
    /// while preparing/writing a response, or [`AgentRunError::Session`] otherwise.
    // The dispatch table mirrors the legacy handler contracts; each arm completes a response.
    #[allow(clippy::too_many_lines, clippy::semicolon_if_nothing_returned)]
    pub async fn run<H, A>(self, handler: &mut H, authorize: A) -> Result<(), AgentRunError>
    where
        H: crate::request::Handler,
        A: FnMut(&AgentCommand<'_>) -> Result<(), crate::auth::AuthorizationError>,
    {
        self.run_with(handler, false, authorize).await
    }

    #[allow(clippy::too_many_lines, clippy::semicolon_if_nothing_returned)]
    async fn run_with<H, A>(
        mut self,
        handler: &mut H,
        node_only: bool,
        mut authorize: A,
    ) -> Result<(), AgentRunError>
    where
        H: crate::request::Handler,
        A: FnMut(&AgentCommand<'_>) -> Result<(), crate::auth::AuthorizationError>,
    {
        let serves = if node_only {
            node_serves
        } else {
            command_serves
        };
        let mut authorization_denied = None;
        let mut response_write = false;
        while let Some(command) = self
            .next_with_phase(serves, &mut response_write)
            .await
            .map_err(|error| {
                if response_write {
                    AgentRunError::ResponseWrite(error)
                } else {
                    AgentRunError::Session(error)
                }
            })?
        {
            let service = command.service_id();
            let authorization = authorize(&command);
            macro_rules! record_denied {
                ($source:expr) => {{
                    authorization_denied = Some(AgentRunError::AuthorizationDenied {
                        service,
                        source: $source,
                    });
                }};
            }
            macro_rules! dispatch {
                ($reply:ident, $call:expr) => {{
                    let result = match authorization {
                        Ok(()) => $call.await,
                        Err(source) => {
                            record_denied!(source);
                            let _ = $reply
                                .respond(Err(crate::server::AUTHORIZATION_DENIED.to_owned()))
                                .await;
                            break;
                        }
                    };
                    $reply
                        .respond(result)
                        .await
                        .map_err(AgentRunError::ResponseWrite)?;
                }};
            }
            match command {
                AgentCommand::DnsStart { request: (), reply } => {
                    dispatch!(reply, handler.dns_start())
                }
                AgentCommand::DnsStop { request: (), reply } => {
                    dispatch!(reply, handler.dns_stop())
                }
                AgentCommand::Reboot { request: (), reply } => dispatch!(reply, async {
                    handler
                        .node_power(NodePowerRequest::Reboot)
                        .await
                        .map(|_| ())
                }),
                #[allow(deprecated)]
                AgentCommand::ReloadConfig { request: (), reply } => {
                    dispatch!(reply, handler.reload_config())
                }
                AgentCommand::ReloadTi { request, reply } => {
                    dispatch!(reply, handler.reload_ti(&request))
                }
                AgentCommand::ResourceUsage { request: (), reply } => dispatch!(reply, async {
                    handler
                        .node_observation(NodeObservationRequest::ResourceUsage)
                        .await
                        .and_then(|response| match response {
                            NodeObservationResponse::ResourceUsage {
                                hostname,
                                resource_usage,
                            } => Ok((hostname, resource_usage)),
                            other => {
                                Err(format!("unexpected node_observation response: {other:?}"))
                            }
                        })
                }),
                AgentCommand::TorExitNodeList { request, reply } => dispatch!(
                    reply,
                    handler.tor_exit_node_list(
                        &request.iter().map(String::as_str).collect::<Vec<_>>()
                    )
                ),
                AgentCommand::TrustedDomainList { request, reply } => dispatch!(
                    reply,
                    handler.trusted_domain_list(
                        &request.iter().map(String::as_str).collect::<Vec<_>>()
                    )
                ),
                AgentCommand::TrustedUserAgentList { request, reply } => dispatch!(
                    reply,
                    handler.trusted_user_agent_list(
                        &request.iter().map(String::as_str).collect::<Vec<_>>()
                    )
                ),
                AgentCommand::TimeSeriesGenerationPolicyList { request, reply } => {
                    dispatch!(reply, handler.time_series_generation_policy_list(&request))
                }
                AgentCommand::DeleteTimeSeriesGenerationPolicy { request, reply } => dispatch!(
                    reply,
                    handler.delete_time_series_generation_policy(&request)
                ),
                AgentCommand::ReloadFilterRule { request, reply } => {
                    dispatch!(reply, handler.update_traffic_filter_rules(&request))
                }
                AgentCommand::InternalNetworkList { request, reply } => {
                    dispatch!(reply, handler.internal_network_list(request))
                }
                AgentCommand::ExclusionList { request, reply } => {
                    dispatch!(reply, handler.exclusion_list(request))
                }
                AgentCommand::Watchlist { request, reply } => {
                    dispatch!(reply, handler.watchlist(request))
                }
                AgentCommand::EchoRequest { request: (), reply } => {
                    dispatch!(reply, async { Ok(()) })
                }
                AgentCommand::DeleteCustomerData { request, reply } => {
                    dispatch!(reply, handler.delete_customer_data(&request))
                }
                AgentCommand::ProcessList { request: (), reply } => dispatch!(reply, async {
                    handler
                        .node_observation(NodeObservationRequest::ProcessList)
                        .await
                        .and_then(|response| match response {
                            NodeObservationResponse::ProcessList { processes } => Ok(processes),
                            other => {
                                Err(format!("unexpected node_observation response: {other:?}"))
                            }
                        })
                }),
                AgentCommand::Shutdown { request: (), reply } => dispatch!(reply, async {
                    handler
                        .node_power(NodePowerRequest::Shutdown)
                        .await
                        .map(|_| ())
                }),
                AgentCommand::SemiSupervisedModels { request, reply } => {
                    dispatch!(reply, handler.update_semi_supervised_models(&request))
                }
                AgentCommand::SignatureRules { request, reply } => {
                    dispatch!(reply, handler.signature_rules(request))
                }
                AgentCommand::UpdateConfig { reply, .. } => {
                    dispatch!(reply, handler.update_config())
                }
                AgentCommand::TrainModel { request, reply } => {
                    dispatch!(reply, handler.train_model(&request))
                }
                AgentCommand::CloneModel { request, reply } => {
                    dispatch!(reply, handler.clone_model(&request))
                }
                AgentCommand::CancelRun { request, reply } => {
                    dispatch!(reply, handler.cancel_run(request))
                }
                AgentCommand::RunDetectorOnce { request, reply } => {
                    dispatch!(reply, handler.run_detector_once(request))
                }
                AgentCommand::Service { request, reply } => {
                    dispatch!(reply, handler.node_service(request))
                }
                AgentCommand::NetworkInterface { request, reply } => {
                    dispatch!(reply, handler.node_network_interface(request))
                }
                AgentCommand::Hostname { request, reply } => {
                    dispatch!(reply, handler.node_hostname(request))
                }
                AgentCommand::TimeSync { request, reply } => {
                    dispatch!(reply, handler.node_time_sync(request))
                }
                AgentCommand::Logging { request, reply } => {
                    dispatch!(reply, handler.node_logging(request))
                }
                AgentCommand::RemoteAccess { request, reply } => {
                    dispatch!(reply, handler.node_remote_access(request))
                }
                AgentCommand::Observation { request, reply } => {
                    dispatch!(reply, handler.node_observation(request))
                }
                AgentCommand::Version { request, reply } => {
                    dispatch!(reply, handler.node_version(request))
                }
                AgentCommand::Enroll { request, reply } => {
                    dispatch!(reply, handler.node_enroll(request))
                }
                AgentCommand::Power { request, reply } => {
                    let immediate = matches!(
                        request,
                        NodePowerRequest::Reboot | NodePowerRequest::Shutdown
                    );
                    let result = match authorization {
                        Ok(()) => handler.node_power(request).await,
                        Err(source) => {
                            record_denied!(source);
                            if immediate {
                                reply.complete_without_response();
                            } else {
                                let _ = reply
                                    .respond(Err(crate::server::AUTHORIZATION_DENIED.to_owned()))
                                    .await;
                            }
                            break;
                        }
                    };
                    if immediate {
                        reply.complete_without_response();
                    } else {
                        reply
                            .respond(result)
                            .await
                            .map_err(AgentRunError::ResponseWrite)?;
                    }
                }
                AgentCommand::Package { request, reply } => {
                    if let Some(size) = reply.size() {
                        let verdict = match authorization {
                            Ok(()) => handler.node_package_install_preflight(&request).await,
                            Err(source) => {
                                record_denied!(source);
                                let _ = reply
                                    .preflight(Err(crate::server::AUTHORIZATION_DENIED.to_owned()))
                                    .await;
                                break;
                            }
                        };
                        if let Some(mut reply) = reply
                            .preflight(verdict)
                            .await
                            .map_err(AgentRunError::ResponseWrite)?
                        {
                            let result = {
                                let mut reader =
                                    crate::request::PackageReader::from_session(&mut reply, size);
                                let result =
                                    handler.node_package_install(request, &mut reader).await;
                                let drained = async {
                                    let mut buffer = Vec::new();
                                    while reader.remaining() > 0 {
                                        reader.next_chunk(&mut buffer).await?;
                                    }
                                    std::io::Result::Ok(())
                                }
                                .await;
                                match (result, drained) {
                                    (result, Ok(())) => result,
                                    (Err(error), Err(_)) => Err(error),
                                    (Ok(_), Err(error)) => Err(format!(
                                        "failed to receive the package payload: {error}"
                                    )),
                                }
                            };
                            reply
                                .respond(result)
                                .await
                                .map_err(AgentRunError::ResponseWrite)?;
                        }
                    } else {
                        let result = match authorization {
                            Ok(()) => handler.node_package(request).await,
                            Err(source) => {
                                record_denied!(source);
                                let _ = reply
                                    .respond(Err(crate::server::AUTHORIZATION_DENIED.to_owned()))
                                    .await;
                                break;
                            }
                        };
                        reply
                            .respond(result)
                            .await
                            .map_err(AgentRunError::ResponseWrite)?;
                    }
                }
            }
        }
        if let Some(error) = authorization_denied {
            let _ = self.finish();
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(feature = "client")]
struct NodeHandlerAdapter<'a, H>(&'a mut H);

#[cfg(feature = "client")]
#[async_trait::async_trait]
impl<H: crate::request::NodeHandler> crate::request::Handler for NodeHandlerAdapter<'_, H> {
    async fn node_service(
        &mut self,
        request: NodeServiceRequest,
    ) -> Result<NodeServiceResponse, String> {
        self.0.node_service(request).await
    }
    async fn node_network_interface(
        &mut self,
        request: NodeNetworkInterfaceRequest,
    ) -> Result<NodeNetworkInterfaceResponse, String> {
        self.0.node_network_interface(request).await
    }
    async fn node_hostname(
        &mut self,
        request: NodeHostnameRequest,
    ) -> Result<NodeHostnameResponse, String> {
        self.0.node_hostname(request).await
    }
    async fn node_time_sync(
        &mut self,
        request: NodeTimeSyncRequest,
    ) -> Result<NodeTimeSyncResponse, String> {
        self.0.node_time_sync(request).await
    }
    async fn node_logging(
        &mut self,
        request: NodeLoggingRequest,
    ) -> Result<NodeLoggingResponse, String> {
        self.0.node_logging(request).await
    }
    async fn node_remote_access(
        &mut self,
        request: NodeRemoteAccessRequest,
    ) -> Result<NodeRemoteAccessResponse, String> {
        self.0.node_remote_access(request).await
    }
    async fn node_observation(
        &mut self,
        request: NodeObservationRequest,
    ) -> Result<NodeObservationResponse, String> {
        self.0.node_observation(request).await
    }
    async fn node_version(
        &mut self,
        request: NodeVersionRequest,
    ) -> Result<NodeVersionResponse, String> {
        self.0.node_version(request).await
    }
    async fn node_enroll(
        &mut self,
        request: NodeEnrollRequest,
    ) -> Result<NodeEnrollResponse, String> {
        self.0.node_enroll(request).await
    }
    async fn node_power(&mut self, request: NodePowerRequest) -> Result<NodePowerResponse, String> {
        self.0.node_power(request).await
    }
    async fn node_package(
        &mut self,
        request: NodePackageRequest,
    ) -> Result<NodePackageResponse, String> {
        self.0.node_package(request).await
    }
    async fn node_package_install_preflight(
        &mut self,
        request: &NodePackageRequest,
    ) -> Result<crate::types::node::InstallPreflight, String> {
        self.0.node_package_install_preflight(request).await
    }
    async fn node_package_install(
        &mut self,
        request: NodePackageRequest,
        reader: &mut crate::request::PackageReader<'_>,
    ) -> Result<NodePackageResponse, String> {
        self.0.node_package_install(request, reader).await
    }
}
