//! Request handling for the agent.
//!
//! # `ProtocolErrorKind` integration
//!
//! Selected request paths in [`handle()`] classify internal errors
//! with [`ProtocolErrorKind`](crate::ProtocolErrorKind) via
//! `DispatchError` (a crate-internal error type).  This
//! is an **internal-only** taxonomy — it does not change the
//! on-wire error format.  Callers can inspect the classification
//! through [`HandlerError::kind()`].
//!
//! Currently classified paths:
//!
//! - Argument parse failures (representative handlers) →
//!   [`InvalidArgs`](crate::ProtocolErrorKind::InvalidArgs)
//!
//! Handler-level `Err("not supported")` responses are sent on the
//! wire as-is (preserving backward compatibility) and do **not**
//! appear as `HandlerError`.  When the project surfaces
//! `ProtocolErrorKind` on the wire, prefer additive changes (new
//! optional fields or a parallel error envelope) to avoid breaking
//! existing callers.
//!
//! This module provides two handler traits and two dispatch entry
//! points:
//!
//! - [`Handler`] – the full agent-side handler covering both
//!   shared/common flat methods and grouped node methods. This is
//!   the trait consumed by [`handle()`].
//! - [`NodeHandler`] – a trait that groups node service-family
//!   methods under their own surface. It can be used independently
//!   with [`handle_node()`] for node-focused agents.
//!
//! A blanket `impl<T: Handler> NodeHandler for T` ensures that
//! existing `Handler` implementations satisfy `NodeHandler`
//! automatically.
//!
//! [`handle_node()`] is an **additive** dispatch entry point — it
//! does not replace [`handle()`]. Existing agents using `Handler`
//! + `handle()` continue to work unchanged.

use std::io;

use async_trait::async_trait;
use num_enum::FromPrimitive;
pub use oinq::request::{parse_args, send_response};
use thiserror::Error;

use crate::{
    client::RequestCode,
    types::{
        CustomerDataDeletionRequest, HostNetworkGroup, Process, ResourceUsage, SamplingPolicy,
        TrafficFilterRule,
        node::{
            NodeHostnameRequest, NodeHostnameResponse, NodeLoggingRequest, NodeLoggingResponse,
            NodeNetworkInterfaceRequest, NodeNetworkInterfaceResponse, NodeObservationRequest,
            NodeObservationResponse, NodePowerRequest, NodePowerResponse, NodeRemoteAccessRequest,
            NodeRemoteAccessResponse, NodeServiceRequest, NodeServiceResponse, NodeTimeSyncRequest,
            NodeTimeSyncResponse, NodeVersionRequest, NodeVersionResponse,
        },
    },
};

/// The error type for handling a request.
///
/// Each variant wraps an [`io::Error`] from the transport layer.
/// Use [`kind()`](Self::kind) to obtain the semantic
/// [`ProtocolErrorKind`](crate::ProtocolErrorKind) classification
/// of the error — for example, distinguishing a malformed-argument
/// parse failure ([`InvalidArgs`](crate::ProtocolErrorKind::InvalidArgs))
/// from a generic I/O error.
#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("failed to receive request")]
    RecvError(io::Error),
    #[error("failed to send response")]
    SendError(io::Error),
}

/// Returns whether a [`NodePowerRequest`] expects a wire response.
///
/// Immediate operations ([`NodePowerRequest::Reboot`],
/// [`NodePowerRequest::Shutdown`]) are fire-and-forget because the
/// agent may close the connection while rebooting or shutting down.
/// Graceful operations use the normal request/response path.
fn node_power_expects_response(req: &NodePowerRequest) -> bool {
    matches!(
        req,
        NodePowerRequest::GracefulReboot | NodePowerRequest::GracefulShutdown
    )
}

impl HandlerError {
    /// Returns the semantic [`ProtocolErrorKind`](crate::ProtocolErrorKind) for this error.
    ///
    /// For `RecvError`, the classification is extracted from the
    /// inner `io::Error` (which may embed a
    /// `DispatchError` (a crate-internal error type)
    /// carrying an explicit classification).  `SendError` always
    /// maps to [`Other`](crate::ProtocolErrorKind::Other) because
    /// send failures are transport-level issues, not semantic
    /// protocol errors.
    #[must_use]
    pub fn kind(&self) -> crate::ProtocolErrorKind {
        match self {
            Self::RecvError(e) => crate::ProtocolErrorKind::of_io_error(e),
            Self::SendError(_) => crate::ProtocolErrorKind::Other,
        }
    }
}

/// A trait that groups the nine node feature-family methods under
/// their own handler surface.
///
/// This trait can be used independently with [`handle_node()`] to
/// build a node-focused agent that handles only node-family
/// requests without implementing the full [`Handler`] trait.
///
/// A blanket implementation forwards every `NodeHandler` method to
/// the corresponding method on [`Handler`], so existing `Handler`
/// implementations automatically satisfy `NodeHandler` without
/// changes.
///
/// # Example
///
/// ```ignore
/// struct MyNodeAgent;
///
/// #[async_trait::async_trait]
/// impl review_protocol::request::NodeHandler for MyNodeAgent {
///     async fn node_hostname(
///         &mut self,
///         req: NodeHostnameRequest,
///     ) -> Result<NodeHostnameResponse, String> {
///         Ok(NodeHostnameResponse::Get {
///             hostname: "my-node".into(),
///         })
///     }
/// }
///
/// // Use handle_node() to dispatch only node-family requests:
/// // request::handle_node(&mut agent, &mut send, &mut recv).await
/// ```
#[async_trait]
pub trait NodeHandler: Send {
    /// Handles a node service-control request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_service(
        &mut self,
        _req: NodeServiceRequest,
    ) -> Result<NodeServiceResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node network-interface management request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_network_interface(
        &mut self,
        _req: NodeNetworkInterfaceRequest,
    ) -> Result<NodeNetworkInterfaceResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node hostname management request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_hostname(
        &mut self,
        _req: NodeHostnameRequest,
    ) -> Result<NodeHostnameResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node time-synchronization request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_time_sync(
        &mut self,
        _req: NodeTimeSyncRequest,
    ) -> Result<NodeTimeSyncResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node logging-configuration request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_logging(
        &mut self,
        _req: NodeLoggingRequest,
    ) -> Result<NodeLoggingResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node remote-access configuration request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_remote_access(
        &mut self,
        _req: NodeRemoteAccessRequest,
    ) -> Result<NodeRemoteAccessResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node power-control request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_power(&mut self, _req: NodePowerRequest) -> Result<NodePowerResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node host-observation request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_observation(
        &mut self,
        _req: NodeObservationRequest,
    ) -> Result<NodeObservationResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node version-management request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_version(
        &mut self,
        _req: NodeVersionRequest,
    ) -> Result<NodeVersionResponse, String> {
        Err("not supported".to_string())
    }
}

/// A request handler that can handle a request to an agent.
///
/// This trait covers all agent-side request handling, including both
/// the shared/common flat methods and the node service-family methods.
/// It is the only trait required by the dispatch path today
/// ([`handle()`](super::server::handle)).
///
/// The node methods are also available through the narrower
/// [`NodeHandler`] trait; a blanket implementation ensures that every
/// `Handler` automatically satisfies `NodeHandler`.
#[async_trait]
pub trait Handler: Send {
    async fn dns_start(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn dns_stop(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn forward(&mut self, _target: &str, _msg: &[u8]) -> Result<Vec<u8>, String> {
        return Err("not supported".to_string());
    }

    /// Reboots the system
    async fn reboot(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    #[deprecated(since = "0.4.1", note = "Use `update_config` instead")]
    async fn reload_config(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn update_config(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn delete_customer_data(
        &mut self,
        _request: &CustomerDataDeletionRequest,
    ) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn reload_ti(&mut self, _version: &str) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    /// Returns the hostname and the cpu, memory, and disk usage.
    async fn resource_usage(&mut self) -> Result<(String, ResourceUsage), String> {
        return Err("not supported".to_string());
    }

    async fn tor_exit_node_list(&mut self, _nodes: &[&str]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn trusted_domain_list(&mut self, _domains: &[&str]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    /// Updates the list of sampling policies.
    async fn sampling_policy_list(&mut self, _policies: &[SamplingPolicy]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn update_traffic_filter_rules(
        &mut self,
        _rules: &[TrafficFilterRule],
    ) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn delete_sampling_policy(&mut self, _policies_ids: &[u32]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn internal_network_list(&mut self, _list: HostNetworkGroup) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn allowlist(&mut self, _list: HostNetworkGroup) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn blocklist(&mut self, _list: HostNetworkGroup) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn trusted_user_agent_list(&mut self, _list: &[&str]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn process_list(&mut self) -> Result<Vec<Process>, String> {
        return Err("not supported".to_string());
    }

    async fn update_semi_supervised_models(&mut self, _list: &[u8]) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    async fn shutdown(&mut self) -> Result<(), String> {
        return Err("not supported".to_string());
    }

    // ── grouped node handler methods ───────────────────────────
    //
    // One method per node feature family. Default implementations
    // return `Err("not supported")` so that existing `Handler`
    // implementations remain compatible. Node-agent implementations
    // override the families they support.
    //
    // These will eventually replace the flat methods that overlap
    // with node functionality (e.g. `reboot`, `resource_usage`,
    // `process_list`), but the flat methods are kept for now to
    // avoid breaking non-node agents.

    /// Handles a node service-control request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_service(
        &mut self,
        _req: NodeServiceRequest,
    ) -> Result<NodeServiceResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node network-interface management request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_network_interface(
        &mut self,
        _req: NodeNetworkInterfaceRequest,
    ) -> Result<NodeNetworkInterfaceResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node hostname management request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_hostname(
        &mut self,
        _req: NodeHostnameRequest,
    ) -> Result<NodeHostnameResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node time-synchronization request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_time_sync(
        &mut self,
        _req: NodeTimeSyncRequest,
    ) -> Result<NodeTimeSyncResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node logging-configuration request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_logging(
        &mut self,
        _req: NodeLoggingRequest,
    ) -> Result<NodeLoggingResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node remote-access configuration request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_remote_access(
        &mut self,
        _req: NodeRemoteAccessRequest,
    ) -> Result<NodeRemoteAccessResponse, String> {
        Err("not supported".to_string())
    }

    /// Handles a node power-control request.
    ///
    /// The default implementation delegates to the flat `reboot` and
    /// `shutdown` methods for backward compatibility. Agents that
    /// implement those flat methods will automatically support the
    /// corresponding `node_power` requests without changes.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_power(&mut self, req: NodePowerRequest) -> Result<NodePowerResponse, String> {
        match req {
            NodePowerRequest::Reboot => self.reboot().await.map(|()| NodePowerResponse::Initiated),
            NodePowerRequest::Shutdown => {
                self.shutdown().await.map(|()| NodePowerResponse::Initiated)
            }
            NodePowerRequest::GracefulReboot | NodePowerRequest::GracefulShutdown => {
                Err("not supported".to_string())
            }
        }
    }

    /// Handles a node host-observation request.
    ///
    /// The default implementation delegates to the flat
    /// `process_list` and `resource_usage` methods for backward
    /// compatibility. Agents that implement those flat methods will
    /// automatically support the corresponding `node_observation`
    /// requests without changes.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_observation(
        &mut self,
        req: NodeObservationRequest,
    ) -> Result<NodeObservationResponse, String> {
        match req {
            NodeObservationRequest::ProcessList => self
                .process_list()
                .await
                .map(|processes| NodeObservationResponse::ProcessList { processes }),
            NodeObservationRequest::ResourceUsage => {
                self.resource_usage()
                    .await
                    .map(
                        |(hostname, resource_usage)| NodeObservationResponse::ResourceUsage {
                            hostname,
                            resource_usage,
                        },
                    )
            }
            NodeObservationRequest::Uptime => Err("not supported".to_string()),
        }
    }

    /// Handles a node version-management request.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_version(
        &mut self,
        _req: NodeVersionRequest,
    ) -> Result<NodeVersionResponse, String> {
        Err("not supported".to_string())
    }
}

/// Blanket implementation: every [`Handler`] automatically satisfies
/// [`NodeHandler`] by forwarding to the corresponding `Handler`
/// methods. This preserves compatibility so that existing `Handler`
/// implementations work as `NodeHandler` without changes.
#[async_trait]
impl<T: Handler + ?Sized> NodeHandler for T {
    async fn node_service(
        &mut self,
        req: NodeServiceRequest,
    ) -> Result<NodeServiceResponse, String> {
        Handler::node_service(self, req).await
    }

    async fn node_network_interface(
        &mut self,
        req: NodeNetworkInterfaceRequest,
    ) -> Result<NodeNetworkInterfaceResponse, String> {
        Handler::node_network_interface(self, req).await
    }

    async fn node_hostname(
        &mut self,
        req: NodeHostnameRequest,
    ) -> Result<NodeHostnameResponse, String> {
        Handler::node_hostname(self, req).await
    }

    async fn node_time_sync(
        &mut self,
        req: NodeTimeSyncRequest,
    ) -> Result<NodeTimeSyncResponse, String> {
        Handler::node_time_sync(self, req).await
    }

    async fn node_logging(
        &mut self,
        req: NodeLoggingRequest,
    ) -> Result<NodeLoggingResponse, String> {
        Handler::node_logging(self, req).await
    }

    async fn node_remote_access(
        &mut self,
        req: NodeRemoteAccessRequest,
    ) -> Result<NodeRemoteAccessResponse, String> {
        Handler::node_remote_access(self, req).await
    }

    async fn node_power(&mut self, req: NodePowerRequest) -> Result<NodePowerResponse, String> {
        Handler::node_power(self, req).await
    }

    async fn node_observation(
        &mut self,
        req: NodeObservationRequest,
    ) -> Result<NodeObservationResponse, String> {
        Handler::node_observation(self, req).await
    }

    async fn node_version(
        &mut self,
        req: NodeVersionRequest,
    ) -> Result<NodeVersionResponse, String> {
        Handler::node_version(self, req).await
    }
}

/// Handles only node-family requests to an agent.
///
/// This is a node-only dispatch entry point that accepts
/// [`NodeHandler`] directly, allowing a node-focused agent to serve
/// node-family requests without implementing the full [`Handler`]
/// trait.
///
/// Only `Node*` request codes (100–108) are dispatched. Any
/// non-node request code receives an error response on the wire
/// (same format as unknown codes in [`handle()`]).
///
/// This function is **additive** — it does not replace [`handle()`].
/// Existing agents using `Handler` + `handle()` continue to work
/// unchanged. Use `handle_node` when an agent only needs to serve
/// the node service family.
///
/// # Errors
///
/// * `HandlerError::RecvError` if the request could not be received
/// * `HandlerError::SendError` if the response could not be sent
#[allow(clippy::too_many_lines)]
pub async fn handle_node<H: NodeHandler>(
    handler: &mut H,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<(), HandlerError> {
    let mut buf = Vec::new();
    loop {
        let (code, body) = match oinq::message::recv_request_raw(recv, &mut buf).await {
            Ok(res) => res,
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(HandlerError::RecvError(e));
            }
        };

        let req = RequestCode::from_primitive(code);
        match req {
            RequestCode::NodeService => {
                let req =
                    parse_args::<NodeServiceRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_service(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeNetworkInterface => {
                let req = parse_args::<NodeNetworkInterfaceRequest>(body)
                    .map_err(HandlerError::RecvError)?;
                let result = handler.node_network_interface(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeHostname => {
                let req =
                    parse_args::<NodeHostnameRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_hostname(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeTimeSync => {
                let req =
                    parse_args::<NodeTimeSyncRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_time_sync(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeLogging => {
                let req =
                    parse_args::<NodeLoggingRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_logging(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeRemoteAccess => {
                let req =
                    parse_args::<NodeRemoteAccessRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_remote_access(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodePower => {
                // Classify parse failures as InvalidArgs so that
                // HandlerError::kind() returns the correct
                // category.
                let req = parse_args::<NodePowerRequest>(body).map_err(|e| {
                    HandlerError::RecvError(crate::protocol_error::DispatchError::from_io(
                        crate::ProtocolErrorKind::InvalidArgs,
                        &e,
                    ))
                })?;
                let expects_response = node_power_expects_response(&req);
                let result = handler.node_power(req).await;
                if expects_response {
                    send_response(send, &mut buf, result)
                        .await
                        .map_err(HandlerError::SendError)?;
                }
            }
            RequestCode::NodeObservation => {
                let req =
                    parse_args::<NodeObservationRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_observation(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeVersion => {
                let req =
                    parse_args::<NodeVersionRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_version(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            _ => {
                let err_msg = format!("unknown request code: {code}");
                oinq::message::send_err(send, &mut buf, err_msg)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
        }
    }
    Ok(())
}

/// Handles requests to an agent.
///
/// Both legacy flat request codes and new `node` request codes are
/// dispatched here. For the overlapping host-control operations
/// (`reboot`, `shutdown`, `process_list`, `resource_usage`), both
/// wire formats are supported:
///
/// - Legacy flat codes call the flat handler methods directly.
/// - New `node` codes (`NodePower`, `NodeObservation`) call the
///   grouped handler methods, whose default implementations
///   delegate back to the flat methods.
///
/// This dual support lets updated agents work with both old `REview`
/// (sending flat codes) and future `REview` (sending `node` codes).
/// See issue #142 for the intended migration order:
///
/// 1. Update agents to accept both wire formats (this change).
/// 2. Switch `REview` to send `node` wire requests.
/// 3. Remove legacy flat handling from agents.
///
/// # Errors
///
/// * `HandlerError::RecvError` if the request could not be received
/// * `HandlerError::SendError` if the response could not be sent
#[allow(clippy::too_many_lines)]
pub async fn handle<H: Handler>(
    handler: &mut H,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<(), HandlerError> {
    let mut buf = Vec::new();
    loop {
        let (code, body) = match oinq::message::recv_request_raw(recv, &mut buf).await {
            Ok(res) => res,
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(HandlerError::RecvError(e));
            }
        };

        let req = RequestCode::from_primitive(code);
        match req {
            RequestCode::DnsStart => {
                send_response(send, &mut buf, handler.dns_start().await)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::DnsStop => {
                send_response(send, &mut buf, handler.dns_stop().await)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            // Compatibility: routes through `node_power` so that
            // agents only need to implement the grouped handler.
            RequestCode::Reboot => {
                let result = handler
                    .node_power(NodePowerRequest::Reboot)
                    .await
                    .map(|_| ());
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::ReloadConfig => {
                #[allow(deprecated)]
                send_response(send, &mut buf, handler.reload_config().await)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::ReloadTi => {
                // Classify parse failures as InvalidArgs so that
                // HandlerError::kind() returns the correct category.
                let version = parse_args::<&str>(body).map_err(|e| {
                    HandlerError::RecvError(crate::protocol_error::DispatchError::from_io(
                        crate::ProtocolErrorKind::InvalidArgs,
                        &e,
                    ))
                })?;
                let result = handler.reload_ti(version).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            // Compatibility: routes through `node_observation` and
            // translates back to the flat `(String, ResourceUsage)`
            // response shape.
            RequestCode::ResourceUsage => {
                let result = handler
                    .node_observation(NodeObservationRequest::ResourceUsage)
                    .await
                    .and_then(|resp| match resp {
                        NodeObservationResponse::ResourceUsage {
                            hostname,
                            resource_usage,
                        } => Ok((hostname, resource_usage)),
                        other => Err(format!("unexpected node_observation response: {other:?}")),
                    });
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::TorExitNodeList => {
                let nodes = parse_args::<Vec<&str>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.tor_exit_node_list(&nodes).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::SamplingPolicyList => {
                let list =
                    parse_args::<Vec<SamplingPolicy>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.sampling_policy_list(&list).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::DeleteSamplingPolicy => {
                let policy_ids = parse_args::<Vec<u32>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.delete_sampling_policy(&policy_ids).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::TrustedDomainList => {
                let domains = parse_args::<Vec<&str>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.trusted_domain_list(&domains).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::InternalNetworkList => {
                let network_list =
                    parse_args::<HostNetworkGroup>(body).map_err(HandlerError::RecvError)?;
                let result = handler.internal_network_list(network_list).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::Allowlist => {
                let allowlist =
                    parse_args::<HostNetworkGroup>(body).map_err(HandlerError::RecvError)?;
                let result = handler.allowlist(allowlist).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::Blocklist => {
                let blocklist =
                    parse_args::<HostNetworkGroup>(body).map_err(HandlerError::RecvError)?;
                let result = handler.blocklist(blocklist).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::EchoRequest => {
                send_response(send, &mut buf, Ok::<(), String>(()))
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::TrustedUserAgentList => {
                let user_agent_list =
                    parse_args::<Vec<&str>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.trusted_user_agent_list(&user_agent_list).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::ReloadFilterRule => {
                let rules =
                    parse_args::<Vec<TrafficFilterRule>>(body).map_err(HandlerError::RecvError)?;
                let result = handler.update_traffic_filter_rules(&rules).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::UpdateConfig => {
                let result = handler.update_config().await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::DeleteCustomerData => {
                let request = parse_args::<CustomerDataDeletionRequest>(body)
                    .map_err(HandlerError::RecvError)?;
                let result = handler.delete_customer_data(&request).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            // Compatibility: routes through `node_observation` and
            // extracts the process list from the typed response.
            RequestCode::ProcessList => {
                let result = handler
                    .node_observation(NodeObservationRequest::ProcessList)
                    .await
                    .and_then(|resp| match resp {
                        NodeObservationResponse::ProcessList { processes } => Ok(processes),
                        other => Err(format!("unexpected node_observation response: {other:?}")),
                    });
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::SemiSupervisedModels => {
                let result = handler.update_semi_supervised_models(body).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            // Compatibility: routes through `node_power` so that
            // agents only need to implement the grouped handler.
            RequestCode::Shutdown => {
                let result = handler
                    .node_power(NodePowerRequest::Shutdown)
                    .await
                    .map(|_| ());
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }

            // ── node feature-family dispatch ───────────────────
            //
            // Each arm deserializes the typed request payload and
            // invokes the corresponding grouped handler method.
            RequestCode::NodeService => {
                let req =
                    parse_args::<NodeServiceRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_service(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeNetworkInterface => {
                let req = parse_args::<NodeNetworkInterfaceRequest>(body)
                    .map_err(HandlerError::RecvError)?;
                let result = handler.node_network_interface(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeHostname => {
                let req =
                    parse_args::<NodeHostnameRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_hostname(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeTimeSync => {
                let req =
                    parse_args::<NodeTimeSyncRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_time_sync(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeLogging => {
                let req =
                    parse_args::<NodeLoggingRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_logging(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeRemoteAccess => {
                let req =
                    parse_args::<NodeRemoteAccessRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_remote_access(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodePower => {
                // Classify parse failures as InvalidArgs so that
                // HandlerError::kind() returns the correct category.
                let req = parse_args::<NodePowerRequest>(body).map_err(|e| {
                    HandlerError::RecvError(crate::protocol_error::DispatchError::from_io(
                        crate::ProtocolErrorKind::InvalidArgs,
                        &e,
                    ))
                })?;
                let expects_response = node_power_expects_response(&req);
                let result = handler.node_power(req).await;
                if expects_response {
                    send_response(send, &mut buf, result)
                        .await
                        .map_err(HandlerError::SendError)?;
                }
            }
            RequestCode::NodeObservation => {
                let req =
                    parse_args::<NodeObservationRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_observation(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
            RequestCode::NodeVersion => {
                let req =
                    parse_args::<NodeVersionRequest>(body).map_err(HandlerError::RecvError)?;
                let result = handler.node_version(req).await;
                send_response(send, &mut buf, result)
                    .await
                    .map_err(HandlerError::SendError)?;
            }

            RequestCode::Unknown => {
                let err_msg = format!("unknown request code: {code}");
                oinq::message::send_err(send, &mut buf, err_msg)
                    .await
                    .map_err(HandlerError::SendError)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use num_enum::FromPrimitive;

    use super::RequestCode;

    #[test]
    fn request_code_serde() {
        assert_eq!(7u32, u32::from(RequestCode::ResourceUsage));
        assert_eq!(RequestCode::ResourceUsage, RequestCode::from_primitive(7));
        assert_eq!(22u32, u32::from(RequestCode::DeleteCustomerData));
        assert_eq!(
            RequestCode::DeleteCustomerData,
            RequestCode::from_primitive(22)
        );
    }

    /// Verify that every node feature-family request code maps to a
    /// stable numeric value and round-trips through `FromPrimitive`.
    #[test]
    fn node_request_code_mapping() {
        let cases: &[(RequestCode, u32)] = &[
            (RequestCode::NodeService, 100),
            (RequestCode::NodeNetworkInterface, 101),
            (RequestCode::NodeHostname, 102),
            (RequestCode::NodeTimeSync, 103),
            (RequestCode::NodeLogging, 104),
            (RequestCode::NodeRemoteAccess, 105),
            (RequestCode::NodePower, 106),
            (RequestCode::NodeObservation, 107),
            (RequestCode::NodeVersion, 108),
        ];
        for &(code, num) in cases {
            assert_eq!(u32::from(code), num);
            assert_eq!(RequestCode::from_primitive(num), code);
        }
    }

    /// Verify that node request codes do not collide with existing
    /// (non-node) codes and that unknown values still map to `Unknown`.
    #[test]
    fn node_request_codes_no_collision() {
        // All existing non-node codes live in 0..=22; node codes
        // start at 100. Verify that the gap maps to Unknown.
        assert_eq!(RequestCode::from_primitive(50), RequestCode::Unknown);
        assert_eq!(RequestCode::from_primitive(99), RequestCode::Unknown);
        assert_eq!(RequestCode::from_primitive(109), RequestCode::Unknown);
    }

    #[cfg(feature = "server")]
    struct NoopHandler;

    #[cfg(feature = "server")]
    #[async_trait::async_trait]
    impl super::Handler for NoopHandler {}

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn delete_customer_data_default_not_supported() {
        let request = crate::types::CustomerDataDeletionRequest {
            customer_id: 42,
            host_fqdn: "sensor.example.com".to_string(),
            requested_at: 1_753_174_800,
        };
        let result = super::Handler::delete_customer_data(&mut NoopHandler, &request).await;

        assert_eq!(result.unwrap_err(), "not supported");
    }

    /// Dispatch round-trip test helper: sends a typed node request
    /// through `request::handle` with a `NoopHandler` and verifies
    /// that the default implementation returns `Err("not supported")`.
    #[cfg(feature = "server")]
    async fn node_dispatch_roundtrip<Req, Resp>(code: RequestCode, req: Req)
    where
        Req: serde::Serialize + std::fmt::Debug,
        Resp: serde::de::DeserializeOwned + std::fmt::Debug,
    {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = NoopHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<Resp, String> =
            crate::unary_request(&mut client_send, &mut client_recv, u32::from(code), req)
                .await
                .expect("wire transport should succeed");

        assert_eq!(
            res.unwrap_err(),
            "not supported",
            "node handler should respond with 'not supported'"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// Success-path round-trip test helper: sends a typed node request
    /// through the wire, responds with an `Ok(expected)` payload on
    /// the server side, and verifies that the client decodes the
    /// concrete response correctly.
    #[cfg(feature = "server")]
    async fn node_success_roundtrip<Req, Resp>(code: RequestCode, req: Req, expected: Resp)
    where
        Req: serde::Serialize + std::fmt::Debug,
        Resp: serde::Serialize
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + PartialEq
            + Clone
            + Send
            + 'static,
    {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let resp_to_send = expected.clone();
        let server_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            let (_code, _body) = oinq::message::recv_request_raw(&mut server_recv, &mut buf)
                .await
                .expect("should receive request");
            super::send_response(&mut server_send, &mut buf, Ok::<Resp, String>(resp_to_send))
                .await
                .expect("should send response");
        });

        let res: Result<Resp, String> =
            crate::unary_request(&mut client_send, &mut client_recv, u32::from(code), req)
                .await
                .expect("wire transport should succeed");

        assert_eq!(
            res.expect("response should be Ok"),
            expected,
            "decoded response should match the sent payload"
        );

        drop(client_send);
        drop(client_recv);

        server_task.await.unwrap();
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_service_wire_roundtrip() {
        use crate::types::node::{NodeServiceRequest, NodeServiceResponse};
        node_dispatch_roundtrip::<_, NodeServiceResponse>(
            RequestCode::NodeService,
            NodeServiceRequest::Status {
                service: "nginx".into(),
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_network_interface_wire_roundtrip() {
        use crate::types::node::{NodeNetworkInterfaceRequest, NodeNetworkInterfaceResponse};
        node_dispatch_roundtrip::<_, NodeNetworkInterfaceResponse>(
            RequestCode::NodeNetworkInterface,
            NodeNetworkInterfaceRequest::List {
                prefix: Some("eth".into()),
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_hostname_wire_roundtrip() {
        use crate::types::node::{NodeHostnameRequest, NodeHostnameResponse};
        node_dispatch_roundtrip::<_, NodeHostnameResponse>(
            RequestCode::NodeHostname,
            NodeHostnameRequest::Get,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_time_sync_wire_roundtrip() {
        use crate::types::node::{NodeTimeSyncRequest, NodeTimeSyncResponse};
        node_dispatch_roundtrip::<_, NodeTimeSyncResponse>(
            RequestCode::NodeTimeSync,
            NodeTimeSyncRequest::Set {
                servers: vec!["0.pool.ntp.org".into()],
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_logging_wire_roundtrip() {
        use crate::types::node::{NodeLoggingRequest, NodeLoggingResponse};
        node_dispatch_roundtrip::<_, NodeLoggingResponse>(
            RequestCode::NodeLogging,
            NodeLoggingRequest::Get,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_remote_access_wire_roundtrip() {
        use crate::types::node::{
            NodeRemoteAccessConfig, NodeRemoteAccessRequest, NodeRemoteAccessResponse,
        };
        node_dispatch_roundtrip::<_, NodeRemoteAccessResponse>(
            RequestCode::NodeRemoteAccess,
            NodeRemoteAccessRequest::Set {
                config: NodeRemoteAccessConfig { port: 22 },
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_power_wire_roundtrip() {
        use crate::types::node::{NodePowerRequest, NodePowerResponse};
        node_dispatch_roundtrip::<_, NodePowerResponse>(
            RequestCode::NodePower,
            NodePowerRequest::GracefulReboot,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_observation_wire_roundtrip() {
        use crate::types::node::{NodeObservationRequest, NodeObservationResponse};
        node_dispatch_roundtrip::<_, NodeObservationResponse>(
            RequestCode::NodeObservation,
            NodeObservationRequest::ResourceUsage,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_version_wire_roundtrip() {
        use crate::types::node::{NodeVersionRequest, NodeVersionResponse};
        node_dispatch_roundtrip::<_, NodeVersionResponse>(
            RequestCode::NodeVersion,
            NodeVersionRequest::SetOsVersion {
                version: "22.04".into(),
            },
        )
        .await;
    }

    // ── success-path wire round-trip tests ─────────────────────
    //
    // These tests verify that a concrete `Ok(response)` payload for
    // each node family can be framed, sent, and decoded correctly
    // on the client side.

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_service_success_roundtrip() {
        use crate::types::node::{NodeServiceRequest, NodeServiceResponse};
        node_success_roundtrip(
            RequestCode::NodeService,
            NodeServiceRequest::Status {
                service: "nginx".into(),
            },
            NodeServiceResponse::Status { active: true },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_network_interface_success_roundtrip() {
        use crate::types::node::{NodeNetworkInterfaceRequest, NodeNetworkInterfaceResponse};
        node_success_roundtrip(
            RequestCode::NodeNetworkInterface,
            NodeNetworkInterfaceRequest::List {
                prefix: Some("eth".into()),
            },
            NodeNetworkInterfaceResponse::List {
                devices: vec!["eth0".into(), "eth1".into()],
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_hostname_success_roundtrip() {
        use crate::types::node::{NodeHostnameRequest, NodeHostnameResponse};
        node_success_roundtrip(
            RequestCode::NodeHostname,
            NodeHostnameRequest::Get,
            NodeHostnameResponse::Get {
                hostname: "node-1".into(),
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_time_sync_success_roundtrip() {
        use crate::types::node::{NodeTimeSyncRequest, NodeTimeSyncResponse};
        node_success_roundtrip(
            RequestCode::NodeTimeSync,
            NodeTimeSyncRequest::Set {
                servers: vec!["0.pool.ntp.org".into()],
            },
            NodeTimeSyncResponse::Done,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_logging_success_roundtrip() {
        use crate::types::node::{
            NodeLoggingEndpoint, NodeLoggingProtocol, NodeLoggingRequest, NodeLoggingResponse,
        };
        node_success_roundtrip(
            RequestCode::NodeLogging,
            NodeLoggingRequest::Get,
            NodeLoggingResponse::Get {
                endpoints: Some(vec![NodeLoggingEndpoint {
                    protocol: NodeLoggingProtocol::Tcp,
                    address: "192.168.1.100".into(),
                    port: 514,
                }]),
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_remote_access_success_roundtrip() {
        use crate::types::node::{
            NodeRemoteAccessConfig, NodeRemoteAccessRequest, NodeRemoteAccessResponse,
        };
        node_success_roundtrip(
            RequestCode::NodeRemoteAccess,
            NodeRemoteAccessRequest::Set {
                config: NodeRemoteAccessConfig { port: 22 },
            },
            NodeRemoteAccessResponse::Done,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_power_success_roundtrip() {
        use crate::types::node::{NodePowerRequest, NodePowerResponse};
        node_success_roundtrip(
            RequestCode::NodePower,
            NodePowerRequest::GracefulReboot,
            NodePowerResponse::Initiated,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_observation_success_roundtrip() {
        use crate::types::node::{NodeObservationRequest, NodeObservationResponse};
        node_success_roundtrip(
            RequestCode::NodeObservation,
            NodeObservationRequest::ResourceUsage,
            NodeObservationResponse::ResourceUsage {
                hostname: "node-1".into(),
                resource_usage: crate::types::ResourceUsage {
                    cpu_usage: 45.2,
                    total_memory: 16_000_000_000,
                    used_memory: 8_000_000_000,
                    disk_used_bytes: 100_000_000_000,
                    disk_available_bytes: 400_000_000_000,
                },
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_version_success_roundtrip() {
        use crate::types::node::{NodeVersionRequest, NodeVersionResponse};
        node_success_roundtrip(
            RequestCode::NodeVersion,
            NodeVersionRequest::SetOsVersion {
                version: "22.04".into(),
            },
            NodeVersionResponse::Done,
        )
        .await;
    }

    // ── handler-dispatch round-trip tests ────────────────────────
    //
    // These tests verify that `request::handle` dispatches each
    // node feature-family request to the corresponding grouped
    // handler method and returns its response through the wire.

    /// A handler that implements the grouped node methods with
    /// concrete responses, used to verify full dispatch through
    /// `request::handle`.
    #[cfg(feature = "server")]
    struct NodeHandler;

    #[cfg(feature = "server")]
    #[async_trait::async_trait]
    impl super::Handler for NodeHandler {
        async fn node_service(
            &mut self,
            _req: crate::types::node::NodeServiceRequest,
        ) -> Result<crate::types::node::NodeServiceResponse, String> {
            Ok(crate::types::node::NodeServiceResponse::Status { active: true })
        }

        async fn node_network_interface(
            &mut self,
            _req: crate::types::node::NodeNetworkInterfaceRequest,
        ) -> Result<crate::types::node::NodeNetworkInterfaceResponse, String> {
            Ok(crate::types::node::NodeNetworkInterfaceResponse::List {
                devices: vec!["eth0".into()],
            })
        }

        async fn node_hostname(
            &mut self,
            _req: crate::types::node::NodeHostnameRequest,
        ) -> Result<crate::types::node::NodeHostnameResponse, String> {
            Ok(crate::types::node::NodeHostnameResponse::Get {
                hostname: "node-1".into(),
            })
        }

        async fn node_time_sync(
            &mut self,
            _req: crate::types::node::NodeTimeSyncRequest,
        ) -> Result<crate::types::node::NodeTimeSyncResponse, String> {
            Ok(crate::types::node::NodeTimeSyncResponse::Done)
        }

        async fn node_logging(
            &mut self,
            _req: crate::types::node::NodeLoggingRequest,
        ) -> Result<crate::types::node::NodeLoggingResponse, String> {
            Ok(crate::types::node::NodeLoggingResponse::Done)
        }

        async fn node_remote_access(
            &mut self,
            _req: crate::types::node::NodeRemoteAccessRequest,
        ) -> Result<crate::types::node::NodeRemoteAccessResponse, String> {
            Ok(crate::types::node::NodeRemoteAccessResponse::Done)
        }

        async fn node_power(
            &mut self,
            _req: crate::types::node::NodePowerRequest,
        ) -> Result<crate::types::node::NodePowerResponse, String> {
            Ok(crate::types::node::NodePowerResponse::Initiated)
        }

        async fn node_observation(
            &mut self,
            _req: crate::types::node::NodeObservationRequest,
        ) -> Result<crate::types::node::NodeObservationResponse, String> {
            Ok(crate::types::node::NodeObservationResponse::ResourceUsage {
                hostname: "node-1".into(),
                resource_usage: crate::types::ResourceUsage {
                    cpu_usage: 10.0,
                    total_memory: 8_000_000_000,
                    used_memory: 4_000_000_000,
                    disk_used_bytes: 50_000_000_000,
                    disk_available_bytes: 200_000_000_000,
                },
            })
        }

        async fn node_version(
            &mut self,
            _req: crate::types::node::NodeVersionRequest,
        ) -> Result<crate::types::node::NodeVersionResponse, String> {
            Ok(crate::types::node::NodeVersionResponse::Get {
                os_version: "22.04".into(),
                product_version: "1.0.0".into(),
            })
        }
    }

    /// Handler-dispatch round-trip helper: sends a typed node request
    /// through `request::handle` backed by `NodeHandler` and verifies
    /// that the expected `Ok` response is returned.
    #[cfg(feature = "server")]
    async fn node_handler_roundtrip<Req, Resp>(code: RequestCode, req: Req, expected: Resp)
    where
        Req: serde::Serialize + std::fmt::Debug,
        Resp: serde::de::DeserializeOwned + std::fmt::Debug + PartialEq,
    {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = NodeHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<Resp, String> =
            crate::unary_request(&mut client_send, &mut client_recv, u32::from(code), req)
                .await
                .expect("wire transport should succeed");

        assert_eq!(
            res.expect("response should be Ok"),
            expected,
            "handler response should match expected value"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_service_handler_dispatch() {
        use crate::types::node::{NodeServiceRequest, NodeServiceResponse};
        node_handler_roundtrip(
            RequestCode::NodeService,
            NodeServiceRequest::Status {
                service: "nginx".into(),
            },
            NodeServiceResponse::Status { active: true },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_network_interface_handler_dispatch() {
        use crate::types::node::{NodeNetworkInterfaceRequest, NodeNetworkInterfaceResponse};
        node_handler_roundtrip(
            RequestCode::NodeNetworkInterface,
            NodeNetworkInterfaceRequest::List {
                prefix: Some("eth".into()),
            },
            NodeNetworkInterfaceResponse::List {
                devices: vec!["eth0".into()],
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_hostname_handler_dispatch() {
        use crate::types::node::{NodeHostnameRequest, NodeHostnameResponse};
        node_handler_roundtrip(
            RequestCode::NodeHostname,
            NodeHostnameRequest::Get,
            NodeHostnameResponse::Get {
                hostname: "node-1".into(),
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_time_sync_handler_dispatch() {
        use crate::types::node::{NodeTimeSyncRequest, NodeTimeSyncResponse};
        node_handler_roundtrip(
            RequestCode::NodeTimeSync,
            NodeTimeSyncRequest::Set {
                servers: vec!["0.pool.ntp.org".into()],
            },
            NodeTimeSyncResponse::Done,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_logging_handler_dispatch() {
        use crate::types::node::{NodeLoggingRequest, NodeLoggingResponse};
        node_handler_roundtrip(
            RequestCode::NodeLogging,
            NodeLoggingRequest::Get,
            NodeLoggingResponse::Done,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_remote_access_handler_dispatch() {
        use crate::types::node::{
            NodeRemoteAccessConfig, NodeRemoteAccessRequest, NodeRemoteAccessResponse,
        };
        node_handler_roundtrip(
            RequestCode::NodeRemoteAccess,
            NodeRemoteAccessRequest::Set {
                config: NodeRemoteAccessConfig { port: 22 },
            },
            NodeRemoteAccessResponse::Done,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_power_handler_dispatch() {
        use crate::types::node::{NodePowerRequest, NodePowerResponse};
        node_handler_roundtrip(
            RequestCode::NodePower,
            NodePowerRequest::GracefulReboot,
            NodePowerResponse::Initiated,
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_observation_handler_dispatch() {
        use crate::types::node::{NodeObservationRequest, NodeObservationResponse};
        node_handler_roundtrip(
            RequestCode::NodeObservation,
            NodeObservationRequest::ResourceUsage,
            NodeObservationResponse::ResourceUsage {
                hostname: "node-1".into(),
                resource_usage: crate::types::ResourceUsage {
                    cpu_usage: 10.0,
                    total_memory: 8_000_000_000,
                    used_memory: 4_000_000_000,
                    disk_used_bytes: 50_000_000_000,
                    disk_available_bytes: 200_000_000_000,
                },
            },
        )
        .await;
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_version_handler_dispatch() {
        use crate::types::node::{NodeVersionRequest, NodeVersionResponse};
        node_handler_roundtrip(
            RequestCode::NodeVersion,
            NodeVersionRequest::SetOsVersion {
                version: "22.04".into(),
            },
            NodeVersionResponse::Get {
                os_version: "22.04".into(),
                product_version: "1.0.0".into(),
            },
        )
        .await;
    }

    // ── flat-to-node compatibility tests ──────────────────────────
    //
    // These tests verify that flat request codes (Reboot, Shutdown,
    // ProcessList, ResourceUsage) are correctly routed through the
    // grouped `node_power` / `node_observation` handler methods.

    /// A handler that only implements `node_power` and
    /// `node_observation`, leaving flat methods at their defaults.
    /// This verifies that the flat dispatch path routes through the
    /// node handler methods.
    #[cfg(feature = "server")]
    struct NodeOnlyHandler;

    #[cfg(feature = "server")]
    #[async_trait::async_trait]
    impl super::Handler for NodeOnlyHandler {
        async fn node_power(
            &mut self,
            _req: crate::types::node::NodePowerRequest,
        ) -> Result<crate::types::node::NodePowerResponse, String> {
            Ok(crate::types::node::NodePowerResponse::Initiated)
        }

        async fn node_observation(
            &mut self,
            req: crate::types::node::NodeObservationRequest,
        ) -> Result<crate::types::node::NodeObservationResponse, String> {
            match req {
                crate::types::node::NodeObservationRequest::ProcessList => {
                    Ok(crate::types::node::NodeObservationResponse::ProcessList {
                        processes: vec![crate::types::Process {
                            user: "root".into(),
                            cpu_usage: 1.0,
                            mem_usage: 2.0,
                            start_time: 100,
                            command: "init".into(),
                        }],
                    })
                }
                crate::types::node::NodeObservationRequest::ResourceUsage => {
                    Ok(crate::types::node::NodeObservationResponse::ResourceUsage {
                        hostname: "node-1".into(),
                        resource_usage: crate::types::ResourceUsage {
                            cpu_usage: 50.0,
                            total_memory: 16_000,
                            used_memory: 8_000,
                            disk_used_bytes: 100_000,
                            disk_available_bytes: 400_000,
                        },
                    })
                }
                crate::types::node::NodeObservationRequest::Uptime => {
                    Err("not supported".to_string())
                }
            }
        }
    }

    /// Helper for flat-to-node compatibility tests: sends a flat
    /// request code through `request::handle` backed by
    /// `NodeOnlyHandler` and verifies the response.
    #[cfg(feature = "server")]
    async fn flat_compat_roundtrip<Req, Resp>(code: RequestCode, req: Req, expected: Resp)
    where
        Req: serde::Serialize + std::fmt::Debug,
        Resp: serde::de::DeserializeOwned + std::fmt::Debug + PartialEq,
    {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = NodeOnlyHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<Resp, String> =
            crate::unary_request(&mut client_send, &mut client_recv, u32::from(code), req)
                .await
                .expect("wire transport should succeed");

        assert_eq!(
            res.expect("response should be Ok"),
            expected,
            "flat request should produce expected response \
             via node handler"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// Flat `Reboot` request code dispatches through `node_power`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn flat_reboot_routes_through_node_power() {
        flat_compat_roundtrip(RequestCode::Reboot, (), ()).await;
    }

    /// Flat `Shutdown` request code dispatches through `node_power`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn flat_shutdown_routes_through_node_power() {
        flat_compat_roundtrip(RequestCode::Shutdown, (), ()).await;
    }

    /// Flat `ProcessList` request code dispatches through
    /// `node_observation`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn flat_process_list_routes_through_node_observation() {
        flat_compat_roundtrip(
            RequestCode::ProcessList,
            (),
            vec![crate::types::Process {
                user: "root".into(),
                cpu_usage: 1.0,
                mem_usage: 2.0,
                start_time: 100,
                command: "init".into(),
            }],
        )
        .await;
    }

    /// Flat `ResourceUsage` request code dispatches through
    /// `node_observation`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn flat_resource_usage_routes_through_node_observation() {
        flat_compat_roundtrip(
            RequestCode::ResourceUsage,
            (),
            (
                "node-1".to_string(),
                crate::types::ResourceUsage {
                    cpu_usage: 50.0,
                    total_memory: 16_000,
                    used_memory: 8_000,
                    disk_used_bytes: 100_000,
                    disk_available_bytes: 400_000,
                },
            ),
        )
        .await;
    }

    // ── node default-delegation tests ─────────────────────────────
    //
    // Verify that the default `node_power` and `node_observation`
    // implementations delegate to the flat handler methods, so
    // agents that only implement the flat methods still work.

    /// A handler that implements only the flat `reboot`, `shutdown`,
    /// `process_list`, and `resource_usage` methods. The default
    /// `node_power` / `node_observation` implementations should
    /// delegate to these.
    #[cfg(feature = "server")]
    struct FlatOnlyHandler;

    #[cfg(feature = "server")]
    #[async_trait::async_trait]
    impl super::Handler for FlatOnlyHandler {
        async fn reboot(&mut self) -> Result<(), String> {
            Ok(())
        }
        async fn shutdown(&mut self) -> Result<(), String> {
            Ok(())
        }
        async fn process_list(&mut self) -> Result<Vec<crate::types::Process>, String> {
            Ok(vec![crate::types::Process {
                user: "flat-user".into(),
                cpu_usage: 5.0,
                mem_usage: 10.0,
                start_time: 200,
                command: "flat-cmd".into(),
            }])
        }
        async fn resource_usage(
            &mut self,
        ) -> Result<(String, crate::types::ResourceUsage), String> {
            Ok((
                "flat-host".into(),
                crate::types::ResourceUsage {
                    cpu_usage: 25.0,
                    total_memory: 1_000,
                    used_memory: 500,
                    disk_used_bytes: 10_000,
                    disk_available_bytes: 90_000,
                },
            ))
        }
    }

    /// Helper for node-default-delegation tests.
    #[cfg(feature = "server")]
    async fn flat_delegation_roundtrip<Req, Resp>(code: RequestCode, req: Req, expected: Resp)
    where
        Req: serde::Serialize + std::fmt::Debug,
        Resp: serde::de::DeserializeOwned + std::fmt::Debug + PartialEq,
    {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = FlatOnlyHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<Resp, String> =
            crate::unary_request(&mut client_send, &mut client_recv, u32::from(code), req)
                .await
                .expect("wire transport should succeed");

        assert_eq!(
            res.expect("response should be Ok"),
            expected,
            "node request should delegate to flat handler"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// Helper: immediate `NodePower` ops run the handler but send no
    /// response frame (fire-and-forget).
    #[cfg(feature = "server")]
    async fn node_power_immediate_no_response_handle(req: crate::types::node::NodePowerRequest) {
        use std::time::Duration;

        use crate::test::{TOKEN, channel};
        use crate::types::node::NodePowerResponse;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = FlatOnlyHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let mut buf = Vec::new();
        oinq::message::send_request(
            &mut client_send,
            &mut buf,
            u32::from(RequestCode::NodePower),
            req,
        )
        .await
        .expect("should send request");

        let recv_result = tokio::time::timeout(
            Duration::from_millis(200),
            oinq::frame::recv::<Result<NodePowerResponse, String>>(&mut client_recv, &mut buf),
        )
        .await;
        assert!(
            recv_result.is_err(),
            "immediate NodePower should not produce a response frame"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// `NodePower::Reboot` delegates to flat `reboot()` without a
    /// wire response.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_power_reboot_delegates_to_flat() {
        use crate::types::node::NodePowerRequest;
        node_power_immediate_no_response_handle(NodePowerRequest::Reboot).await;
    }

    /// `NodePower::Shutdown` delegates to flat `shutdown()` without a
    /// wire response.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_power_shutdown_delegates_to_flat() {
        use crate::types::node::NodePowerRequest;
        node_power_immediate_no_response_handle(NodePowerRequest::Shutdown).await;
    }

    /// `NodeObservation::ProcessList` delegates to flat
    /// `process_list()` handler.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_observation_process_list_delegates_to_flat() {
        use crate::types::node::{NodeObservationRequest, NodeObservationResponse};
        flat_delegation_roundtrip(
            RequestCode::NodeObservation,
            NodeObservationRequest::ProcessList,
            NodeObservationResponse::ProcessList {
                processes: vec![crate::types::Process {
                    user: "flat-user".into(),
                    cpu_usage: 5.0,
                    mem_usage: 10.0,
                    start_time: 200,
                    command: "flat-cmd".into(),
                }],
            },
        )
        .await;
    }

    /// `NodeObservation::ResourceUsage` delegates to flat
    /// `resource_usage()` handler.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_observation_resource_usage_delegates_to_flat() {
        use crate::types::node::{NodeObservationRequest, NodeObservationResponse};
        flat_delegation_roundtrip(
            RequestCode::NodeObservation,
            NodeObservationRequest::ResourceUsage,
            NodeObservationResponse::ResourceUsage {
                hostname: "flat-host".into(),
                resource_usage: crate::types::ResourceUsage {
                    cpu_usage: 25.0,
                    total_memory: 1_000,
                    used_memory: 500,
                    disk_used_bytes: 10_000,
                    disk_available_bytes: 90_000,
                },
            },
        )
        .await;
    }

    // ── NodeHandler trait tests ──────────────────────────────────
    //
    // Verify that the `NodeHandler` trait is independently usable
    // and that the blanket `impl<T: Handler> NodeHandler for T`
    // correctly forwards calls.

    /// A `Handler` implementor used to verify that the blanket
    /// `NodeHandler` impl forwards to its `Handler` node methods.
    #[cfg(feature = "server")]
    struct BlanketTestHandler;

    #[cfg(feature = "server")]
    #[async_trait::async_trait]
    impl super::Handler for BlanketTestHandler {
        async fn node_service(
            &mut self,
            _req: crate::types::node::NodeServiceRequest,
        ) -> Result<crate::types::node::NodeServiceResponse, String> {
            Ok(crate::types::node::NodeServiceResponse::Status { active: true })
        }

        async fn node_power(
            &mut self,
            _req: crate::types::node::NodePowerRequest,
        ) -> Result<crate::types::node::NodePowerResponse, String> {
            Ok(crate::types::node::NodePowerResponse::Initiated)
        }
    }

    /// Calling a `NodeHandler` method on a `Handler` implementor
    /// should forward through the blanket impl.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn blanket_node_handler_forwards_to_handler() {
        use crate::types::node::{
            NodePowerRequest, NodePowerResponse, NodeServiceRequest, NodeServiceResponse,
        };

        let mut h = BlanketTestHandler;

        // Call through `NodeHandler` trait explicitly.
        let service_resp = super::NodeHandler::node_service(
            &mut h,
            NodeServiceRequest::Status {
                service: "test".into(),
            },
        )
        .await;
        assert_eq!(
            service_resp.unwrap(),
            NodeServiceResponse::Status { active: true },
        );

        let power_resp = super::NodeHandler::node_power(&mut h, NodePowerRequest::Reboot).await;
        assert_eq!(power_resp.unwrap(), NodePowerResponse::Initiated);
    }

    /// Default `NodeHandler` methods return `"not supported"` when
    /// the underlying `Handler` does not override them.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn blanket_node_handler_defaults_not_supported() {
        use crate::types::node::{NodeHostnameRequest, NodeVersionRequest};

        let mut h = BlanketTestHandler;

        // `BlanketTestHandler` does not override `node_hostname` or
        // `node_version`, so the defaults should return an error.
        let hostname_resp =
            super::NodeHandler::node_hostname(&mut h, NodeHostnameRequest::Get).await;
        assert_eq!(hostname_resp.unwrap_err(), "not supported");

        let version_resp = super::NodeHandler::node_version(
            &mut h,
            NodeVersionRequest::SetOsVersion {
                version: "1.0".into(),
            },
        )
        .await;
        assert_eq!(version_resp.unwrap_err(), "not supported");
    }

    // ── ProtocolErrorKind classification tests ───────────────────
    //
    // These tests verify that HandlerError::kind() returns the
    // correct ProtocolErrorKind for representative error paths.

    /// Malformed payload for `ReloadTi` classifies as `InvalidArgs`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn reload_ti_parse_failure_is_invalid_args() {
        use crate::ProtocolErrorKind;
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = NoopHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        // Send ReloadTi with wrong payload type (u32 instead of &str).
        let mut buf = Vec::new();
        oinq::message::send_request(
            &mut client_send,
            &mut buf,
            u32::from(RequestCode::ReloadTi),
            42u32,
        )
        .await
        .unwrap();

        drop(client_send);
        drop(client_recv);

        let server_err = server_task.await.unwrap().unwrap_err();
        assert_eq!(
            server_err.kind(),
            ProtocolErrorKind::InvalidArgs,
            "parse failure should classify as InvalidArgs"
        );
    }

    /// Malformed payload for `NodePower` classifies as `InvalidArgs`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_power_parse_failure_is_invalid_args() {
        use crate::ProtocolErrorKind;
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = NoopHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        // Send NodePower with wrong payload type (String instead of
        // NodePowerRequest enum).
        let mut buf = Vec::new();
        oinq::message::send_request(
            &mut client_send,
            &mut buf,
            u32::from(RequestCode::NodePower),
            "not-a-power-request".to_string(),
        )
        .await
        .unwrap();

        drop(client_send);
        drop(client_recv);

        let server_err = server_task.await.unwrap().unwrap_err();
        assert_eq!(
            server_err.kind(),
            ProtocolErrorKind::InvalidArgs,
            "parse failure should classify as InvalidArgs"
        );
    }

    /// Default "not supported" handler responses still produce the
    /// expected wire error string — wire behavior is unchanged.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn unsupported_handler_preserves_wire_error() {
        use crate::test::{TOKEN, channel};
        use crate::types::node::{NodePowerRequest, NodePowerResponse};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = NoopHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        // NoopHandler does not implement node_power, so the default
        // returns Err("not supported").
        let res: Result<NodePowerResponse, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::NodePower),
            NodePowerRequest::GracefulReboot,
        )
        .await
        .unwrap();

        assert_eq!(
            res.unwrap_err(),
            "not supported",
            "wire error message must be preserved"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    // ── handle_node dispatch tests ──────────────────────────────
    //
    // These tests verify that `handle_node` dispatches node-family
    // requests to a `NodeHandler`-only type (not implementing
    // `Handler`) and that non-node codes receive an error response.

    /// A type implementing only `NodeHandler`, not `Handler`.
    #[cfg(feature = "server")]
    struct StandaloneNodeHandler;

    #[cfg(feature = "server")]
    #[async_trait::async_trait]
    impl super::NodeHandler for StandaloneNodeHandler {
        async fn node_hostname(
            &mut self,
            req: crate::types::node::NodeHostnameRequest,
        ) -> Result<crate::types::node::NodeHostnameResponse, String> {
            match req {
                crate::types::node::NodeHostnameRequest::Get => {
                    Ok(crate::types::node::NodeHostnameResponse::Get {
                        hostname: "standalone-node".into(),
                    })
                }
                crate::types::node::NodeHostnameRequest::Set { hostname } => {
                    let _ = hostname;
                    Ok(crate::types::node::NodeHostnameResponse::Done)
                }
            }
        }

        async fn node_power(
            &mut self,
            _req: crate::types::node::NodePowerRequest,
        ) -> Result<crate::types::node::NodePowerResponse, String> {
            Ok(crate::types::node::NodePowerResponse::Initiated)
        }
    }

    /// Helper for `handle_node` dispatch tests.
    #[cfg(feature = "server")]
    async fn handle_node_roundtrip<Req, Resp>(code: RequestCode, req: Req, expected: Resp)
    where
        Req: serde::Serialize + std::fmt::Debug,
        Resp: serde::de::DeserializeOwned + std::fmt::Debug + PartialEq,
    {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = StandaloneNodeHandler;
            super::handle_node(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<Resp, String> =
            crate::unary_request(&mut client_send, &mut client_recv, u32::from(code), req)
                .await
                .expect("wire transport should succeed");

        assert_eq!(
            res.expect("response should be Ok"),
            expected,
            "handle_node should dispatch node request correctly"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// `handle_node` dispatches `NodeHostname` to a
    /// `NodeHandler`-only type.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_hostname_dispatch() {
        use crate::types::node::{NodeHostnameRequest, NodeHostnameResponse};
        handle_node_roundtrip(
            RequestCode::NodeHostname,
            NodeHostnameRequest::Get,
            NodeHostnameResponse::Get {
                hostname: "standalone-node".into(),
            },
        )
        .await;
    }

    /// `handle_node` dispatches `NodePower` to a
    /// `NodeHandler`-only type.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_power_dispatch() {
        use crate::types::node::{NodePowerRequest, NodePowerResponse};
        handle_node_roundtrip(
            RequestCode::NodePower,
            NodePowerRequest::GracefulReboot,
            NodePowerResponse::Initiated,
        )
        .await;
    }

    /// Helper: `handle_node` immediate `NodePower` ops send no
    /// response frame.
    #[cfg(feature = "server")]
    async fn node_power_immediate_no_response_handle_node(
        req: crate::types::node::NodePowerRequest,
    ) {
        use std::time::Duration;

        use crate::test::{TOKEN, channel};
        use crate::types::node::NodePowerResponse;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = StandaloneNodeHandler;
            super::handle_node(&mut handler, &mut server_send, &mut server_recv).await
        });

        let mut buf = Vec::new();
        oinq::message::send_request(
            &mut client_send,
            &mut buf,
            u32::from(RequestCode::NodePower),
            req,
        )
        .await
        .expect("should send request");

        let recv_result = tokio::time::timeout(
            Duration::from_millis(200),
            oinq::frame::recv::<Result<NodePowerResponse, String>>(&mut client_recv, &mut buf),
        )
        .await;
        assert!(
            recv_result.is_err(),
            "handle_node immediate NodePower should not produce a response frame"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// `handle_node` runs `NodePower::Reboot` without a wire response.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_power_reboot_no_response() {
        use crate::types::node::NodePowerRequest;
        node_power_immediate_no_response_handle_node(NodePowerRequest::Reboot).await;
    }

    /// `handle_node` runs `NodePower::Shutdown` without a wire response.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_power_shutdown_no_response() {
        use crate::types::node::NodePowerRequest;
        node_power_immediate_no_response_handle_node(NodePowerRequest::Shutdown).await;
    }

    /// Unimplemented node methods return `"not supported"` through
    /// `handle_node`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_default_not_supported() {
        use crate::test::{TOKEN, channel};
        use crate::types::node::{NodeServiceRequest, NodeServiceResponse};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = StandaloneNodeHandler;
            super::handle_node(&mut handler, &mut server_send, &mut server_recv).await
        });

        // StandaloneNodeHandler does not implement node_service.
        let res: Result<NodeServiceResponse, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::NodeService),
            NodeServiceRequest::Status {
                service: "test".into(),
            },
        )
        .await
        .expect("wire transport should succeed");

        assert_eq!(res.unwrap_err(), "not supported");

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// Non-node request codes receive an error through
    /// `handle_node`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_rejects_non_node_codes() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = StandaloneNodeHandler;
            super::handle_node(&mut handler, &mut server_send, &mut server_recv).await
        });

        // Send a flat DnsStart code — not a node family code.
        let res: Result<(), String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::DnsStart),
            (),
        )
        .await
        .expect("wire transport should succeed");

        assert!(
            res.unwrap_err().contains("unknown request code"),
            "non-node code should be rejected"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }
}
