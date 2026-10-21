//! Typed protocol adapters sharing bounded exchange machinery.
use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use serde::{Serialize, de::DeserializeOwned};

use super::{
    OutcomeCertainty, SessionError, Shared,
    decode::decode,
    exchange::{Exchange, unary},
};
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
use crate::types::{CustomerDataDeletionReport, HostNetworkGroup};

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

fn malformed(message: &'static str) -> SessionError {
    SessionError::Malformed(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    )))
}

struct RequestOwner {
    exchange: Exchange,
    options: super::SessionOptions,
    ended: bool,
}
impl RequestOwner {
    fn new(send: oinq::SendStream, recv: oinq::RecvStream, options: super::SessionOptions) -> Self {
        Self {
            exchange: Exchange::new(send, recv, options.unary),
            options,
            ended: false,
        }
    }

    async fn next(&mut self) -> Result<Option<(u32, oinq::frame::Frame)>, SessionError> {
        if self.ended {
            return Ok(None);
        }
        let Some(frame) = self.exchange.next_frame().await? else {
            self.ended = true;
            self.exchange.complete();
            return Ok(None);
        };
        let Some(code) = frame.as_bytes().get(..4) else {
            self.exchange.cancel();
            return Err(malformed("request code is truncated"));
        };
        let code = u32::from_le_bytes(
            code.try_into()
                .expect("the request code slice has four bytes"),
        );
        Ok(Some((code, frame)))
    }
}

fn arguments<T: DeserializeOwned>(
    frame: &oinq::frame::Frame,
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
    /// An ordered event sequence.
    Events(super::EventReceiver),
}

/// The unique server-side owner of incoming stream acceptance.
#[cfg(feature = "server")]
pub struct ServerIncoming(pub(super) Arc<Shared>);
#[cfg(feature = "server")]
impl ServerIncoming {
    pub(super) fn new(shared: Arc<Shared>) -> Self {
        Self(shared)
    }

    /// Accepts the next request or event stream without reading its contents.
    ///
    /// Cancellation consumes no stream. Both directions are polled concurrently;
    /// applications supervise the returned owners independently.
    /// # Errors
    /// Returns a classified transport error when the connection closes.
    pub async fn accept(&mut self) -> Result<ServerStream, SessionError> {
        tokio::select! {
            result = self.0.connection.accept_bi() => {
                let (send, recv) = result.map_err(|e| SessionError::transport(e, OutcomeCertainty::NotSent))?;
                Ok(ServerStream::Requests(ServerRequestStream(RequestOwner::new(send, recv, self.0.options.clone()))))
            }
            result = self.0.connection.accept_uni() => {
                let recv = result.map_err(|e| SessionError::transport(e, OutcomeCertainty::NotSent))?;
                Ok(ServerStream::Events(super::EventReceiver::new(recv, self.0.options.events)))
            }
        }
    }
}

/// A manager-side request stream that preserves multiple invocations.
///
/// Each response borrows this owner until completed. Cancelling `next` retains
/// partial framing; dropping the stream or an unfinished response aborts it.
#[cfg(feature = "server")]
pub struct ServerRequestStream(RequestOwner);
#[cfg(feature = "server")]
impl ServerRequestStream {
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
    pub async fn next(&mut self) -> Result<Option<ServerRequest<'_>>, SessionError> {
        let Some((code, frame)) = self.0.next().await? else {
            return Ok(None);
        };
        let limit = self.0.options.unary.get();
        let mut exchange = ExchangeLease(Some(&mut self.0.exchange));
        let request = match code {
            code if code == u32::from(crate::server::RequestCode::GetConfig) => {
                let request: () = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                ServerRequest::GetConfig {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<String>,
                    },
                }
            }
            code if code == u32::from(crate::server::RequestCode::GetModel) => {
                let request: String = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                ServerRequest::GetModel {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<Vec<u8>>,
                    },
                }
            }
            code if code == u32::from(crate::server::RequestCode::GetPretrainedModel) => {
                let request: String = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                ServerRequest::GetPretrainedModel {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<Vec<u8>>,
                    },
                }
            }
            code if code == u32::from(crate::server::RequestCode::GetModelNames) => {
                let request: () = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                ServerRequest::GetModelNames {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<Vec<String>>,
                    },
                }
            }
            code if code == u32::from(crate::server::RequestCode::GetAllowlist) => {
                let request: () = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                ServerRequest::GetAllowlist {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<HostNetworkGroup>,
                    },
                }
            }
            code if code == u32::from(crate::server::RequestCode::GetBlocklist) => {
                let request: () = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                ServerRequest::GetBlocklist {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<HostNetworkGroup>,
                    },
                }
            }
            code if code == u32::from(crate::server::RequestCode::InsertModel) => {
                let request: Vec<u8> = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                ServerRequest::InsertModel {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<u32>,
                    },
                }
            }
            code if code == u32::from(crate::server::RequestCode::UpdateModel) => {
                let request: Vec<u8> = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                ServerRequest::UpdateModel {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<u32>,
                    },
                }
            }
            code if code == u32::from(crate::server::RequestCode::RemoveModel) => {
                let request: String = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                ServerRequest::RemoveModel {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            code if code == u32::from(crate::server::RequestCode::ReportCustomerDataDeletion) => {
                let request: CustomerDataDeletionReport = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                ServerRequest::ReportCustomerDataDeletion {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<()>,
                    },
                }
            }
            _ => return Err(malformed("unknown request code")),
        };
        Ok(Some(request))
    }
}

/// A typed manager-side invocation borrowing its stream until responded to.
#[cfg(feature = "server")]
pub enum ServerRequest<'a> {
    /// The `get_config` operation.
    GetConfig {
        /// The peer-supplied arguments.
        request: (),
        /// The response capability borrowing this request stream.
        reply: Reply<'a, String>,
    },
    /// The `get_model` operation.
    GetModel {
        /// The peer-supplied arguments.
        request: String,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, Vec<u8>>,
    },
    /// The `get_pretrained_model` operation.
    GetPretrainedModel {
        /// The peer-supplied arguments.
        request: String,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, Vec<u8>>,
    },
    /// The `get_model_names` operation.
    GetModelNames {
        /// The peer-supplied arguments.
        request: (),
        /// The response capability borrowing this request stream.
        reply: Reply<'a, Vec<String>>,
    },
    /// The `get_allowlist` operation.
    GetAllowlist {
        /// The peer-supplied arguments.
        request: (),
        /// The response capability borrowing this request stream.
        reply: Reply<'a, HostNetworkGroup>,
    },
    /// The `get_blocklist` operation.
    GetBlocklist {
        /// The peer-supplied arguments.
        request: (),
        /// The response capability borrowing this request stream.
        reply: Reply<'a, HostNetworkGroup>,
    },
    /// The `insert_model` operation.
    InsertModel {
        /// The peer-supplied arguments.
        request: Vec<u8>,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, u32>,
    },
    /// The `update_model` operation.
    UpdateModel {
        /// The peer-supplied arguments.
        request: Vec<u8>,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, u32>,
    },
    /// The `remove_model` operation.
    RemoveModel {
        /// The peer-supplied arguments.
        request: String,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, ()>,
    },
    /// The `report_customer_data_deletion` operation.
    ReportCustomerDataDeletion {
        /// The peer-supplied arguments.
        request: CustomerDataDeletionReport,
        /// The response capability borrowing this request stream.
        reply: Reply<'a, ()>,
    },
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
        let Some((code, frame)) = self.0.next().await? else {
            return Ok(None);
        };
        let limit = self.0.options.unary.get();
        let mut exchange = ExchangeLease(Some(&mut self.0.exchange));
        let request = match code {
            code if code == u32::from(crate::client::RequestCode::NodeService) => {
                let request: NodeServiceRequest = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                AgentRequest::Service {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeServiceResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeNetworkInterface) => {
                let request: NodeNetworkInterfaceRequest = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                AgentRequest::NetworkInterface {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeNetworkInterfaceResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeHostname) => {
                let request: NodeHostnameRequest = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                AgentRequest::Hostname {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeHostnameResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeTimeSync) => {
                let request: NodeTimeSyncRequest = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                AgentRequest::TimeSync {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeTimeSyncResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeLogging) => {
                let request: NodeLoggingRequest = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                AgentRequest::Logging {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeLoggingResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeRemoteAccess) => {
                let request: NodeRemoteAccessRequest = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                AgentRequest::RemoteAccess {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeRemoteAccessResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeObservation) => {
                let request: NodeObservationRequest = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                AgentRequest::Observation {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeObservationResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeVersion) => {
                let request: NodeVersionRequest = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                AgentRequest::Version {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeVersionResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodeEnroll) => {
                let request: NodeEnrollRequest = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                AgentRequest::Enroll {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodeEnrollResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodePower) => {
                let request: NodePowerRequest = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
                AgentRequest::Power {
                    request,
                    reply: Reply {
                        exchange,
                        response: PhantomData::<NodePowerResponse>,
                    },
                }
            }
            code if code == u32::from(crate::client::RequestCode::NodePackage) => {
                let request: NodePackageRequest = arguments(&frame, limit)?;
                exchange.recycle(frame)?;
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
            _ => return Err(malformed("unknown request code")),
        };
        Ok(Some(request))
    }
}

/// A typed agent-side invocation borrowing its stream until responded to.
#[cfg(feature = "client")]
pub enum AgentRequest<'a> {
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

#[cfg(feature = "client")]
impl super::AgentHandle {
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
    /// Sends the `get_allowlist` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn get_allowlist(&self) -> Result<HostNetworkGroup, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::GetAllowlist),
            (),
        )
        .await
    }
    /// Sends the `get_blocklist` domain operation.
    /// # Errors
    /// Returns classified transport, malformed data, remote rejection, limit, or deadline errors.
    pub async fn get_blocklist(&self) -> Result<HostNetworkGroup, SessionError> {
        unary(
            &self.0.connection,
            &self.0.options,
            u32::from(crate::server::RequestCode::GetBlocklist),
            (),
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
        let length = u64::try_from(frame.as_bytes().len())
            .map_err(|e| SessionError::Malformed(Box::new(e)))?;
        if length > *remaining {
            self.exchange.cancel();
            return Err(malformed("package chunk exceeds the declared size"));
        }
        *remaining -= length;
        let previous = std::mem::replace(buffer, frame.into_bytes());
        self.exchange.recycle_bytes(previous)?;
        Ok(true)
    }

    /// Sends the terminal package response after a unary request or complete install.
    /// # Errors
    /// Returns malformed-state, encoding, limit, or transport errors.
    pub async fn respond(
        mut self,
        response: Result<NodePackageResponse, String>,
    ) -> Result<(), SessionError> {
        if self.remaining.is_some_and(|remaining| remaining != 0)
            || (self.remaining.is_some() && !self.receiving)
        {
            return Err(malformed(
                "install payload has not been completely received",
            ));
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
                return Err(SessionError::LimitExceeded(
                    oinq::frame::FrameError::TooLarge {
                        length: 1,
                        limit: options.package_chunks,
                    },
                ));
            }
            let mut buffer = vec![0; chunk_size];
            while remaining > 0 {
                let want = usize::try_from(remaining.min(
                    u64::try_from(chunk_size).map_err(|e| SessionError::Malformed(Box::new(e)))?,
                ))
                .map_err(|e| SessionError::Malformed(Box::new(e)))?;
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
                remaining -=
                    u64::try_from(length).map_err(|e| SessionError::Malformed(Box::new(e)))?;
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
