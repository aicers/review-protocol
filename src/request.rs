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
            InstallPreflight, NodeHostnameRequest, NodeHostnameResponse, NodeLoggingRequest,
            NodeLoggingResponse, NodeNetworkInterfaceRequest, NodeNetworkInterfaceResponse,
            NodeObservationRequest, NodeObservationResponse, NodePackageRequest,
            NodePackageResponse, NodePowerRequest, NodePowerResponse, NodeRemoteAccessRequest,
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

/// A bounded reader over the package payload that follows a
/// [`NodePackageRequest::Install`] request on the same bi-stream.
///
/// The reader is created by the dispatch loop and handed to
/// [`NodeHandler::node_package_install`] only after the handler
/// answered the preflight with [`InstallPreflight::Proceed`].  It
/// borrows the request's own [`quinn::RecvStream`] and is bounded to
/// the request's `size`, so it cannot over-read into the next request
/// frame — which is what keeps the dispatch loop aligned.
///
/// The payload arrives as length-prefixed chunks.  How the sender
/// chunked is not part of the contract: a reader must not depend on
/// chunk sizes, only on having received exactly `size` bytes in total.
#[derive(Debug)]
pub struct PackageReader<'a> {
    recv: &'a mut quinn::RecvStream,
    size: u64,
    remaining: u64,
    failed: bool,
}

impl<'a> PackageReader<'a> {
    fn new(recv: &'a mut quinn::RecvStream, size: u64) -> Self {
        Self {
            recv,
            size,
            remaining: size,
            failed: false,
        }
    }
}

impl PackageReader<'_> {
    /// Returns the total payload length, taken from the request's
    /// `size`.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the number of bytes not yet handed to the caller.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Reads the next length-prefixed chunk into `buf`, replacing its
    /// contents.
    ///
    /// Returns `Ok(false)` once exactly [`size`](Self::size) bytes
    /// have been read.
    ///
    /// A failed read ends the transfer: the reader keeps no way to
    /// tell how much of the declared payload is still coming, so
    /// every later call fails without touching the stream rather
    /// than waiting for a chunk that may never be sent.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::UnexpectedEof`] if the stream ends or
    /// resets before the whole payload arrives, and
    /// [`io::ErrorKind::InvalidData`] if a chunk would carry the
    /// transfer past the declared `size` or if an earlier read
    /// already failed.
    pub async fn next_chunk(&mut self, buf: &mut Vec<u8>) -> io::Result<bool> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the package transfer already failed",
            ));
        }
        if self.remaining == 0 {
            buf.clear();
            return Ok(false);
        }
        match self.read_chunk(buf).await {
            Ok(()) => Ok(true),
            Err(e) => {
                self.failed = true;
                Err(e)
            }
        }
    }

    /// Reads one chunk and accounts for it against `remaining`.
    async fn read_chunk(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
        oinq::frame::recv_raw(self.recv, buf)
            .await
            .map_err(truncated_payload)?;
        let len =
            u64::try_from(buf.len()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if len > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "package chunk of {len} bytes overruns the {} bytes still expected",
                    self.remaining
                ),
            ));
        }
        self.remaining -= len;
        Ok(())
    }

    /// Reads whatever the handler left behind, so that the dispatch
    /// loop resumes on the next request frame.
    ///
    /// A transfer that already failed is not drained: there is no
    /// determinate end to read up to, so waiting for one would park
    /// the dispatch loop on chunks the peer has no reason to send.
    async fn drain(&mut self) -> io::Result<()> {
        let mut buf = Vec::new();
        while self.next_chunk(&mut buf).await? {}
        Ok(())
    }
}

/// Reports a payload that stopped short as an end of file.
///
/// A bounded read that fails before the declared `size` is a truncated
/// transfer whatever the transport called it, so a peer reset is
/// reported the same way a clean early end is, with the original cause
/// kept as the message.
fn truncated_payload(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        e
    } else {
        io::Error::new(io::ErrorKind::UnexpectedEof, e)
    }
}

/// A trait that groups the node feature-family methods under
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

    /// Handles a unary node package-management request:
    /// [`Remove`](NodePackageRequest::Remove),
    /// [`ListInstalled`](NodePackageRequest::ListInstalled) or
    /// [`Status`](NodePackageRequest::Status).
    ///
    /// [`Install`](NodePackageRequest::Install) never reaches this
    /// method — it carries a payload and is served by
    /// [`node_package_install_preflight`](Self::node_package_install_preflight)
    /// and [`node_package_install`](Self::node_package_install).
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_package(
        &mut self,
        _req: NodePackageRequest,
    ) -> Result<NodePackageResponse, String> {
        Err("not supported".to_string())
    }

    /// Decides whether the agent will accept the package bytes of an
    /// [`Install`](NodePackageRequest::Install) request.
    ///
    /// This is step 2 of the install exchange and is decided from the
    /// framed request **alone** — from `idempotency_key` and
    /// `(target, version, commit)` — before any bytes move.  An `Err`
    /// returned here is the terminal frame of the exchange: no
    /// package bytes are requested and
    /// [`node_package_install`](Self::node_package_install) is not
    /// called.
    ///
    /// [`AlreadyApplied`](InstallPreflight::AlreadyApplied) is also
    /// terminal, and must **never** be returned for a build whose
    /// unit is in a failed state.  Keyed on build identity alone, a
    /// package that installed cleanly but failed to start could never
    /// be re-applied: an operator would fix the cause, re-run the
    /// same build, and get a recorded success over a still-failed
    /// service.  The contract is therefore `AlreadyApplied` only when
    /// the build is installed **and** its unit is not failed;
    /// otherwise [`Proceed`](InstallPreflight::Proceed).
    ///
    /// [`InsufficientDiskSpace`](InstallPreflight::InsufficientDiskSpace)
    /// is decided from `size` alone, so nothing on the host is
    /// touched before it is returned.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the preflight checks could not be run.
    async fn node_package_install_preflight(
        &mut self,
        _req: &NodePackageRequest,
    ) -> Result<InstallPreflight, String> {
        Err("not supported".to_string())
    }

    /// Applies an [`Install`](NodePackageRequest::Install) request
    /// whose payload is arriving on `pkg`.
    ///
    /// This is step 4 of the install exchange and is called **only**
    /// after this handler answered
    /// [`Proceed`](InstallPreflight::Proceed).  `pkg` is bounded to
    /// the request's `size`; whatever the handler leaves unread is
    /// consumed by the dispatch loop, which then resumes on the next
    /// request frame, unless a read failed and the payload has no
    /// determinate end left.  The value returned here is the single terminal
    /// frame of the exchange: there are no progress frames, and
    /// sub-steps are reported only through it.
    ///
    /// Return [`Done`](NodePackageResponse::Done) for an apply both
    /// endpoints survive, and [`Accepted`](NodePackageResponse::Accepted)
    /// for a self-disrupting apply — one whose target is the agent's
    /// own binary or the manager itself, so that the swap tears down
    /// this response channel.  `Accepted` is the terminal frame; no
    /// `Done` follows it.  A typed apply failure travels as
    /// [`Failed`](NodePackageResponse::Failed), not through the error
    /// channel.
    ///
    /// # Contract
    ///
    /// The agent trusts **only** the manifest and signature inside
    /// the received package, never the request.  The order is fixed:
    ///
    /// 1. Stream the payload to a temporary path.
    /// 2. Verify: the signature over the in-package manifest, then
    ///    each artifact's hash against that manifest, then that the
    ///    manifest's identity equals the request's
    ///    `target`/`version`/`commit`, failing with
    ///    [`TargetMismatch`](crate::types::node::NodePackageError::TargetMismatch)
    ///    otherwise.
    /// 3. If `bootstrap_material` is `Some`, run enrollment — never
    ///    before verification.
    /// 4. Apply.
    ///
    /// A first install of a package with no existing identity
    /// **requires** `bootstrap_material` and is rejected with
    /// [`MissingBootstrapMaterial`](crate::types::node::NodePackageError::MissingBootstrapMaterial)
    /// if it is absent, before any apply.  On an update, or on a
    /// package whose identity already exists, `None` is expected and
    /// a stray `Some` is ignored.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the payload could not be received.  A failure of the apply
    /// itself is reported as
    /// [`Failed`](NodePackageResponse::Failed) instead.
    async fn node_package_install(
        &mut self,
        _req: NodePackageRequest,
        _pkg: &mut PackageReader<'_>,
    ) -> Result<NodePackageResponse, String> {
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

    /// Handles a unary node package-management request:
    /// [`Remove`](NodePackageRequest::Remove),
    /// [`ListInstalled`](NodePackageRequest::ListInstalled) or
    /// [`Status`](NodePackageRequest::Status).
    ///
    /// See [`NodeHandler::node_package`] for the full contract.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the underlying operation fails.
    async fn node_package(
        &mut self,
        _req: NodePackageRequest,
    ) -> Result<NodePackageResponse, String> {
        Err("not supported".to_string())
    }

    /// Decides whether the agent will accept the package bytes of an
    /// [`Install`](NodePackageRequest::Install) request.
    ///
    /// See [`NodeHandler::node_package_install_preflight`] for the
    /// full contract, including why
    /// [`AlreadyApplied`](InstallPreflight::AlreadyApplied) must
    /// never be returned for a build whose unit is in a failed state.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the preflight checks could not be run.
    async fn node_package_install_preflight(
        &mut self,
        _req: &NodePackageRequest,
    ) -> Result<InstallPreflight, String> {
        Err("not supported".to_string())
    }

    /// Applies an [`Install`](NodePackageRequest::Install) request
    /// whose payload is arriving on `pkg`.
    ///
    /// See [`NodeHandler::node_package_install`] for the full
    /// contract, including the fixed verify-then-enrol-then-apply
    /// order and the `bootstrap_material` presence rule.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or
    /// the payload could not be received.  A failure of the apply
    /// itself is reported as
    /// [`Failed`](NodePackageResponse::Failed) instead.
    async fn node_package_install(
        &mut self,
        _req: NodePackageRequest,
        _pkg: &mut PackageReader<'_>,
    ) -> Result<NodePackageResponse, String> {
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

    async fn node_package(
        &mut self,
        req: NodePackageRequest,
    ) -> Result<NodePackageResponse, String> {
        Handler::node_package(self, req).await
    }

    async fn node_package_install_preflight(
        &mut self,
        req: &NodePackageRequest,
    ) -> Result<InstallPreflight, String> {
        Handler::node_package_install_preflight(self, req).await
    }

    async fn node_package_install(
        &mut self,
        req: NodePackageRequest,
        pkg: &mut PackageReader<'_>,
    ) -> Result<NodePackageResponse, String> {
        Handler::node_package_install(self, req, pkg).await
    }
}

/// Serves one `node.package` request, streaming the payload when the
/// request is an [`Install`](NodePackageRequest::Install).
///
/// The parsed request's variant decides the path.  `Remove`,
/// `ListInstalled` and `Status` are answered with a single frame like
/// every other family.  `Install` runs the three-step exchange: ask
/// the handler for a preflight verdict, write it, and — only on
/// [`Proceed`](InstallPreflight::Proceed) — read exactly `size` bytes
/// of payload before writing the single terminal response.
///
/// Whatever the handler leaves unread is consumed here, so the caller's
/// dispatch loop resumes on the next request frame either way.  A
/// transfer that failed mid-payload is the exception: the stream is no
/// longer determinate, so it is reported rather than drained.
async fn dispatch_node_package<H: NodeHandler>(
    handler: &mut H,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    buf: &mut Vec<u8>,
    req: NodePackageRequest,
) -> Result<(), HandlerError> {
    let size = match &req {
        NodePackageRequest::Install { size, .. } => *size,
        NodePackageRequest::Remove { .. }
        | NodePackageRequest::ListInstalled
        | NodePackageRequest::Status { .. } => {
            let result = handler.node_package(req).await;
            return send_response(send, buf, result)
                .await
                .map_err(HandlerError::SendError);
        }
    };

    let verdict = handler.node_package_install_preflight(&req).await;
    let proceed = matches!(verdict, Ok(InstallPreflight::Proceed));
    send_response(send, buf, verdict)
        .await
        .map_err(HandlerError::SendError)?;
    if !proceed {
        // `AlreadyApplied`, `InsufficientDiskSpace` and an `Err`
        // verdict are each the terminal frame: no bytes move and no
        // response follows.
        return Ok(());
    }

    let mut pkg = PackageReader::new(recv, size);
    let result = handler.node_package_install(req, &mut pkg).await;
    // Whatever the handler did not read is consumed here. A handler
    // that already failed keeps its own, more specific message.
    let result = match (result, pkg.drain().await) {
        (result, Ok(())) => result,
        (Err(e), Err(_)) => Err(e),
        (Ok(_), Err(e)) => Err(format!("failed to receive the package payload: {e}")),
    };
    send_response(send, buf, result)
        .await
        .map_err(HandlerError::SendError)
}

/// Handles only node-family requests to an agent.
///
/// This is a node-only dispatch entry point that accepts
/// [`NodeHandler`] directly, allowing a node-focused agent to serve
/// node-family requests without implementing the full [`Handler`]
/// trait.
///
/// Only `Node*` request codes (100–109) are dispatched. Any
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
            RequestCode::NodePackage => {
                let req =
                    parse_args::<NodePackageRequest>(body).map_err(HandlerError::RecvError)?;
                dispatch_node_package(handler, send, recv, &mut buf, req).await?;
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

            // `Install` streams its payload on this same stream, so
            // this arm reads past the request frame; the other three
            // variants are answered with one frame like every other
            // family.
            RequestCode::NodePackage => {
                let req =
                    parse_args::<NodePackageRequest>(body).map_err(HandlerError::RecvError)?;
                dispatch_node_package(handler, send, recv, &mut buf, req).await?;
            }

            // The fail-closed backstop for a code this build has not
            // assigned. An older binary, whose `RequestCode` has no
            // `NodePackage` variant, answers 109 through here.
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
            (RequestCode::NodePackage, 109),
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
        assert_eq!(
            RequestCode::from_primitive(109),
            RequestCode::NodePackage,
            "109 is now assigned to the node.package family"
        );
        // The first value past the assigned node codes.
        assert_eq!(RequestCode::from_primitive(110), RequestCode::Unknown);
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
            id: 42,
            host_fqdn: "sensor.example.com".to_string(),
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

    // ── node.package dispatch tests ──────────────────────────────
    //
    // These cover both entry points: the unary variants answered
    // with one frame, and the `Install` streaming exchange whose
    // frame order the crate — not the handler — enforces.

    /// Builds an `Install` request for `target` whose payload is
    /// `size` bytes long.
    #[cfg(feature = "server")]
    fn install_request(target: &str, size: u64) -> crate::types::node::NodePackageRequest {
        use crate::types::node::{FailurePolicy, NodePackageRequest};

        NodePackageRequest::Install {
            target: target.into(),
            instance: Some(1),
            version: "1.2.3".into(),
            commit: "0123456789abcdef".into(),
            size,
            idempotency_key: "idem-1".into(),
            bootstrap_material: None,
            on_failure: FailurePolicy::Rollback,
        }
    }

    /// The two installed entries a `ListInstalled` answer carries.
    /// They differ only in `instance`, which is what makes the
    /// instance dimension observable on the wire.
    #[cfg(feature = "server")]
    fn installed_pair() -> Vec<crate::types::node::InstalledPackage> {
        use crate::types::node::{InstalledPackage, Lifecycle, PackageState};

        let state = || PackageState {
            version: "1.2.3".into(),
            commit: "0123456789abcdef".into(),
            lifecycle: Lifecycle::Running,
            bound_addrs: vec![],
        };
        vec![
            InstalledPackage {
                target: "sensor".into(),
                instance: Some(1),
                state: state(),
            },
            InstalledPackage {
                target: "sensor".into(),
                instance: Some(2),
                state: state(),
            },
        ]
    }

    /// A handler that serves the whole `node.package` family.
    ///
    /// The preflight verdict is chosen by the install target, so a
    /// test picks the branch it wants to drive by naming it; the
    /// received payload is recorded so a test can compare it against
    /// what it sent.
    #[cfg(feature = "server")]
    #[derive(Clone, Default)]
    struct PackageHandler {
        received: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    #[cfg(feature = "server")]
    #[async_trait::async_trait]
    impl super::Handler for PackageHandler {
        async fn node_package(
            &mut self,
            req: crate::types::node::NodePackageRequest,
        ) -> Result<crate::types::node::NodePackageResponse, String> {
            use crate::types::node::{
                Lifecycle, NodePackageRequest, NodePackageResponse, PackageState,
            };

            match req {
                NodePackageRequest::Remove { .. } => Ok(NodePackageResponse::Done),
                NodePackageRequest::ListInstalled => {
                    Ok(NodePackageResponse::Installed(installed_pair()))
                }
                NodePackageRequest::Status { .. } => Ok(NodePackageResponse::State(PackageState {
                    version: "1.2.3".into(),
                    commit: "0123456789abcdef".into(),
                    lifecycle: Lifecycle::Stopped,
                    bound_addrs: vec![],
                })),
                NodePackageRequest::Install { .. } => {
                    Err("an install must never reach the unary method".to_string())
                }
            }
        }

        async fn node_package_install_preflight(
            &mut self,
            req: &crate::types::node::NodePackageRequest,
        ) -> Result<crate::types::node::InstallPreflight, String> {
            use crate::types::node::{InstallPreflight, NodePackageRequest};

            let NodePackageRequest::Install { target, .. } = req else {
                return Err("the preflight must only see an install".to_string());
            };
            match target.as_str() {
                "already" => Ok(InstallPreflight::AlreadyApplied),
                "nospace" => Ok(InstallPreflight::InsufficientDiskSpace {
                    filesystem: "/opt".to_string(),
                    required: 4_194_304,
                    available: 1_024,
                }),
                _ => Ok(InstallPreflight::Proceed),
            }
        }

        async fn node_package_install(
            &mut self,
            req: crate::types::node::NodePackageRequest,
            pkg: &mut super::PackageReader<'_>,
        ) -> Result<crate::types::node::NodePackageResponse, String> {
            use crate::types::node::{NodePackageRequest, NodePackageResponse};

            let NodePackageRequest::Install { target, .. } = req else {
                return Err("the install path must only see an install".to_string());
            };

            let mut payload = Vec::new();
            let mut chunk = Vec::new();
            while pkg
                .next_chunk(&mut chunk)
                .await
                .map_err(|e| format!("failed to read the payload: {e}"))?
            {
                payload.extend_from_slice(&chunk);
            }
            assert_eq!(pkg.remaining(), 0);
            assert_eq!(payload.len() as u64, pkg.size());
            *self.received.lock().unwrap() = payload;

            if target == "selfdisrupting" {
                Ok(NodePackageResponse::Accepted)
            } else {
                Ok(NodePackageResponse::Done)
            }
        }
    }

    /// Round-trip helper for the unary `node.package` variants
    /// through `handle`.
    #[cfg(feature = "server")]
    async fn package_unary_roundtrip(
        req: crate::types::node::NodePackageRequest,
        expected: crate::types::node::NodePackageResponse,
    ) {
        use crate::test::{TOKEN, channel};
        use crate::types::node::NodePackageResponse;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = PackageHandler::default();
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<NodePackageResponse, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::NodePackage),
            req,
        )
        .await
        .expect("wire transport should succeed");

        assert_eq!(res.expect("response should be Ok"), expected);

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// Round-trip helper for the unary `node.package` variants
    /// through `handle_node`.
    #[cfg(feature = "server")]
    async fn package_unary_roundtrip_handle_node(
        req: crate::types::node::NodePackageRequest,
        expected: crate::types::node::NodePackageResponse,
    ) {
        use crate::test::{TOKEN, channel};
        use crate::types::node::NodePackageResponse;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = PackageHandler::default();
            super::handle_node(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<NodePackageResponse, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::NodePackage),
            req,
        )
        .await
        .expect("wire transport should succeed");

        assert_eq!(res.expect("response should be Ok"), expected);

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// `Remove` is unary through `handle`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_remove_roundtrip() {
        use crate::types::node::{NodePackageRequest, NodePackageResponse};
        package_unary_roundtrip(
            NodePackageRequest::Remove {
                target: "sensor".into(),
                instance: Some(1),
                idempotency_key: "idem-1".into(),
            },
            NodePackageResponse::Done,
        )
        .await;
    }

    /// `ListInstalled` carries entries that differ only in
    /// `instance`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_list_installed_roundtrip() {
        use crate::types::node::{NodePackageRequest, NodePackageResponse};
        package_unary_roundtrip(
            NodePackageRequest::ListInstalled,
            NodePackageResponse::Installed(installed_pair()),
        )
        .await;
    }

    /// `Status` is unary through `handle`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_status_roundtrip() {
        use crate::types::node::{
            Lifecycle, NodePackageRequest, NodePackageResponse, PackageState,
        };
        package_unary_roundtrip(
            NodePackageRequest::Status {
                target: "sensor".into(),
                instance: Some(1),
            },
            NodePackageResponse::State(PackageState {
                version: "1.2.3".into(),
                commit: "0123456789abcdef".into(),
                lifecycle: Lifecycle::Stopped,
                bound_addrs: vec![],
            }),
        )
        .await;
    }

    /// `Remove` is unary through `handle_node` too.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_package_remove_roundtrip() {
        use crate::types::node::{NodePackageRequest, NodePackageResponse};
        package_unary_roundtrip_handle_node(
            NodePackageRequest::Remove {
                target: "sensor".into(),
                instance: None,
                idempotency_key: "idem-2".into(),
            },
            NodePackageResponse::Done,
        )
        .await;
    }

    /// `ListInstalled` is unary through `handle_node` too.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_package_list_installed_roundtrip() {
        use crate::types::node::{NodePackageRequest, NodePackageResponse};
        package_unary_roundtrip_handle_node(
            NodePackageRequest::ListInstalled,
            NodePackageResponse::Installed(installed_pair()),
        )
        .await;
    }

    /// `Status` is unary through `handle_node` too.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_package_status_roundtrip() {
        use crate::types::node::{
            Lifecycle, NodePackageRequest, NodePackageResponse, PackageState,
        };
        package_unary_roundtrip_handle_node(
            NodePackageRequest::Status {
                target: "sensor".into(),
                instance: Some(7),
            },
            NodePackageResponse::State(PackageState {
                version: "1.2.3".into(),
                commit: "0123456789abcdef".into(),
                lifecycle: Lifecycle::Stopped,
                bound_addrs: vec![],
            }),
        )
        .await;
    }

    /// Sends the framed install request and returns the agent's
    /// preflight verdict frame.
    #[cfg(feature = "server")]
    async fn send_install_request(
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        req: crate::types::node::NodePackageRequest,
    ) -> Result<crate::types::node::InstallPreflight, String> {
        use crate::types::node::InstallPreflight;

        let mut buf = Vec::new();
        oinq::message::send_request(send, &mut buf, u32::from(RequestCode::NodePackage), req)
            .await
            .expect("should send the install request");
        oinq::frame::recv::<Result<InstallPreflight, String>>(recv, &mut buf)
            .await
            .expect("should receive the preflight verdict")
    }

    /// A payload whose length is deliberately not a multiple of the
    /// chunk sizes the tests send it in.
    #[cfg(feature = "server")]
    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    /// A `Proceed` install transfers the payload byte-for-byte and
    /// is answered with exactly one terminal response.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_install_proceed() {
        use std::time::Duration;

        use crate::test::{TOKEN, channel};
        use crate::types::node::{InstallPreflight, NodePackageResponse};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let handler = PackageHandler::default();
        let received = handler.received.clone();
        let server_task = tokio::spawn(async move {
            let mut handler = handler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        // 2431 bytes in chunks of 1000, 1000 and 431: the length is
        // not a multiple of the chunk size, so the last chunk is a
        // partial one.
        let sent = payload(2431);
        let verdict = send_install_request(
            &mut client_send,
            &mut client_recv,
            install_request("sensor", sent.len() as u64),
        )
        .await
        .expect("the verdict should be Ok");
        assert_eq!(verdict, InstallPreflight::Proceed);

        for chunk in sent.chunks(1000) {
            oinq::frame::send_raw(&mut client_send, chunk)
                .await
                .expect("should send a payload chunk");
        }

        let mut buf = Vec::new();
        let resp =
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf)
                .await
                .expect("should receive the terminal response");
        assert_eq!(
            resp.expect("response should be Ok"),
            NodePackageResponse::Done
        );
        assert_eq!(*received.lock().unwrap(), sent);

        // Exactly one terminal frame: nothing else follows it.
        let extra = tokio::time::timeout(
            Duration::from_millis(200),
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf),
        )
        .await;
        assert!(extra.is_err(), "a completed install sends one frame only");

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// A self-disrupting apply answers `Accepted`, and that frame is
    /// terminal.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_install_accepted_is_terminal() {
        use std::time::Duration;

        use crate::test::{TOKEN, channel};
        use crate::types::node::{InstallPreflight, NodePackageResponse};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = PackageHandler::default();
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let sent = payload(600);
        let verdict = send_install_request(
            &mut client_send,
            &mut client_recv,
            install_request("selfdisrupting", sent.len() as u64),
        )
        .await
        .expect("the verdict should be Ok");
        assert_eq!(verdict, InstallPreflight::Proceed);

        oinq::frame::send_raw(&mut client_send, &sent)
            .await
            .expect("should send the payload");

        let mut buf = Vec::new();
        let resp =
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf)
                .await
                .expect("should receive the terminal response");
        assert_eq!(
            resp.expect("response should be Ok"),
            NodePackageResponse::Accepted
        );

        let extra = tokio::time::timeout(
            Duration::from_millis(200),
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf),
        )
        .await;
        assert!(extra.is_err(), "no frame follows `Accepted`");

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// An `AlreadyApplied` verdict ends the exchange: no bytes are
    /// sent and no response frame follows.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_install_already_applied_is_terminal() {
        use std::time::Duration;

        use crate::test::{TOKEN, channel};
        use crate::types::node::{InstallPreflight, NodePackageResponse};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let handler = PackageHandler::default();
        let received = handler.received.clone();
        let server_task = tokio::spawn(async move {
            let mut handler = handler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let verdict = send_install_request(
            &mut client_send,
            &mut client_recv,
            install_request("already", 4_194_304),
        )
        .await
        .expect("the verdict should be Ok");
        assert_eq!(verdict, InstallPreflight::AlreadyApplied);

        let mut buf = Vec::new();
        let extra = tokio::time::timeout(
            Duration::from_millis(200),
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf),
        )
        .await;
        assert!(
            extra.is_err(),
            "`AlreadyApplied` is the terminal frame; nothing follows it"
        );
        assert!(
            received.lock().unwrap().is_empty(),
            "no payload should have been requested"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// An `InsufficientDiskSpace` verdict ends the exchange and
    /// carries its measurements through.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_install_insufficient_disk_space_is_terminal() {
        use std::time::Duration;

        use crate::test::{TOKEN, channel};
        use crate::types::node::{InstallPreflight, NodePackageResponse};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = PackageHandler::default();
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let verdict = send_install_request(
            &mut client_send,
            &mut client_recv,
            install_request("nospace", 4_194_304),
        )
        .await
        .expect("the verdict should be Ok");
        assert_eq!(
            verdict,
            InstallPreflight::InsufficientDiskSpace {
                filesystem: "/opt".to_string(),
                required: 4_194_304,
                available: 1_024,
            }
        );

        let mut buf = Vec::new();
        let extra = tokio::time::timeout(
            Duration::from_millis(200),
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf),
        )
        .await;
        assert!(
            extra.is_err(),
            "`InsufficientDiskSpace` is the terminal frame; nothing follows it"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// A payload that stops short leaves the agent with an error
    /// terminal response rather than a hang.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_install_truncated_payload() {
        use std::time::Duration;

        use crate::test::{TOKEN, channel};
        use crate::types::node::{InstallPreflight, NodePackageResponse};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = PackageHandler::default();
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let verdict = send_install_request(
            &mut client_send,
            &mut client_recv,
            install_request("sensor", 4_096),
        )
        .await
        .expect("the verdict should be Ok");
        assert_eq!(verdict, InstallPreflight::Proceed);

        // Half the declared payload, then a clean end of stream.
        oinq::frame::send_raw(&mut client_send, &payload(2_048))
            .await
            .expect("should send a payload chunk");
        client_send.finish().ok();

        let mut buf = Vec::new();
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf),
        )
        .await
        .expect("the agent must answer rather than hang")
        .expect("should receive the terminal response");
        assert!(
            resp.unwrap_err().contains("failed to read the payload"),
            "a truncated transfer is an error terminal response"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// A payload cut off by a peer reset is an error terminal
    /// response too, not a hang.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_install_reset_payload() {
        use std::time::Duration;

        use crate::test::{TOKEN, channel};
        use crate::types::node::{InstallPreflight, NodePackageResponse};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = PackageHandler::default();
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let verdict = send_install_request(
            &mut client_send,
            &mut client_recv,
            install_request("sensor", 4_096),
        )
        .await
        .expect("the verdict should be Ok");
        assert_eq!(verdict, InstallPreflight::Proceed);

        oinq::frame::send_raw(&mut client_send, &payload(1_024))
            .await
            .expect("should send a payload chunk");
        client_send.reset(quinn::VarInt::from_u32(1)).ok();

        let mut buf = Vec::new();
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf),
        )
        .await
        .expect("the agent must answer rather than hang")
        .expect("should receive the terminal response");
        assert!(
            resp.is_err(),
            "a reset transfer is an error terminal response"
        );

        drop(client_send);
        drop(client_recv);

        // The reset also breaks the dispatch loop's own next read, so
        // its result is not asserted here.
        let _ = server_task.await.unwrap();
    }

    /// A chunk that overruns the declared `size` is an error terminal
    /// response, and the agent does not park waiting for the rest of
    /// a payload the sender has already overshot.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_install_chunk_overruns_size() {
        use std::time::Duration;

        use crate::test::{TOKEN, channel};
        use crate::types::node::{InstallPreflight, NodePackageResponse};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = PackageHandler::default();
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let verdict = send_install_request(
            &mut client_send,
            &mut client_recv,
            install_request("sensor", 1_000),
        )
        .await
        .expect("the verdict should be Ok");
        assert_eq!(verdict, InstallPreflight::Proceed);

        // Twice the declared size in one chunk, then nothing: a
        // sender that overshoots has no reason to send more, so an
        // agent that tried to drain the difference would hang.
        oinq::frame::send_raw(&mut client_send, &payload(2_000))
            .await
            .expect("should send a payload chunk");

        let mut buf = Vec::new();
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf),
        )
        .await
        .expect("the agent must answer rather than hang")
        .expect("should receive the terminal response");
        assert!(
            resp.unwrap_err().contains("overruns"),
            "an overrunning chunk is an error terminal response"
        );

        drop(client_send);
        drop(client_recv);

        let _ = server_task.await.unwrap();
    }

    /// A handler that leaves part of the payload unread still leaves
    /// the dispatch loop aligned: the rest is drained for it.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_install_unread_payload_is_drained() {
        use crate::test::{TOKEN, channel};
        use crate::types::node::{
            InstallPreflight, NodePackageRequest, NodePackageResponse, NodeServiceRequest,
            NodeServiceResponse,
        };

        /// A handler that reads a single chunk and answers, leaving
        /// the rest of the payload on the stream.
        struct LazyPackageHandler;

        #[async_trait::async_trait]
        impl super::Handler for LazyPackageHandler {
            async fn node_package_install_preflight(
                &mut self,
                _req: &NodePackageRequest,
            ) -> Result<InstallPreflight, String> {
                Ok(InstallPreflight::Proceed)
            }

            async fn node_package_install(
                &mut self,
                _req: NodePackageRequest,
                pkg: &mut super::PackageReader<'_>,
            ) -> Result<NodePackageResponse, String> {
                let mut chunk = Vec::new();
                pkg.next_chunk(&mut chunk)
                    .await
                    .map_err(|e| format!("failed to read the payload: {e}"))?;
                assert!(pkg.remaining() > 0, "the handler must leave bytes behind");
                Ok(NodePackageResponse::Done)
            }
        }

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = LazyPackageHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let sent = payload(1_500);
        let verdict = send_install_request(
            &mut client_send,
            &mut client_recv,
            install_request("sensor", sent.len() as u64),
        )
        .await
        .expect("the verdict should be Ok");
        assert_eq!(verdict, InstallPreflight::Proceed);

        for chunk in sent.chunks(500) {
            oinq::frame::send_raw(&mut client_send, chunk)
                .await
                .expect("should send a payload chunk");
        }

        let mut buf = Vec::new();
        let resp =
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf)
                .await
                .expect("should receive the terminal response");
        assert_eq!(
            resp.expect("response should be Ok"),
            NodePackageResponse::Done
        );

        // The two chunks the handler never read were drained, so the
        // next request frame is where the loop resumes.
        let res: Result<NodeServiceResponse, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::NodeService),
            NodeServiceRequest::Status {
                service: "nginx".into(),
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

    /// The streaming exchange runs through `handle_node` too, on a
    /// type that implements only `NodeHandler`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_package_install_proceed() {
        use crate::test::{TOKEN, channel};
        use crate::types::node::{InstallPreflight, NodePackageRequest, NodePackageResponse};

        /// A `NodeHandler`-only type serving the install exchange.
        #[derive(Clone, Default)]
        struct StandalonePackageHandler {
            received: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        }

        #[async_trait::async_trait]
        impl super::NodeHandler for StandalonePackageHandler {
            async fn node_package_install_preflight(
                &mut self,
                _req: &NodePackageRequest,
            ) -> Result<InstallPreflight, String> {
                Ok(InstallPreflight::Proceed)
            }

            async fn node_package_install(
                &mut self,
                _req: NodePackageRequest,
                pkg: &mut super::PackageReader<'_>,
            ) -> Result<NodePackageResponse, String> {
                let mut received = Vec::new();
                let mut chunk = Vec::new();
                while pkg
                    .next_chunk(&mut chunk)
                    .await
                    .map_err(|e| format!("failed to read the payload: {e}"))?
                {
                    received.extend_from_slice(&chunk);
                }
                *self.received.lock().unwrap() = received;
                Ok(NodePackageResponse::Done)
            }
        }

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let handler = StandalonePackageHandler::default();
        let received = handler.received.clone();
        let server_task = tokio::spawn(async move {
            let mut handler = handler;
            super::handle_node(&mut handler, &mut server_send, &mut server_recv).await
        });

        let sent = payload(2_431);
        let verdict = send_install_request(
            &mut client_send,
            &mut client_recv,
            install_request("sensor", sent.len() as u64),
        )
        .await
        .expect("the verdict should be Ok");
        assert_eq!(verdict, InstallPreflight::Proceed);

        for chunk in sent.chunks(1_000) {
            oinq::frame::send_raw(&mut client_send, chunk)
                .await
                .expect("should send a payload chunk");
        }

        let mut buf = Vec::new();
        let resp =
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf)
                .await
                .expect("should receive the terminal response");
        assert_eq!(
            resp.expect("response should be Ok"),
            NodePackageResponse::Done
        );
        assert_eq!(*received.lock().unwrap(), sent);

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// The install exchange consumes exactly its own bytes, so the
    /// next request on the same stream still round-trips.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_install_leaves_the_loop_aligned() {
        use crate::test::{TOKEN, channel};
        use crate::types::node::{
            InstallPreflight, NodePackageResponse, NodeServiceRequest, NodeServiceResponse,
        };

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = PackageHandler::default();
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let sent = payload(1_500);
        let verdict = send_install_request(
            &mut client_send,
            &mut client_recv,
            install_request("sensor", sent.len() as u64),
        )
        .await
        .expect("the verdict should be Ok");
        assert_eq!(verdict, InstallPreflight::Proceed);

        for chunk in sent.chunks(512) {
            oinq::frame::send_raw(&mut client_send, chunk)
                .await
                .expect("should send a payload chunk");
        }

        let mut buf = Vec::new();
        let resp =
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf)
                .await
                .expect("should receive the terminal response");
        assert_eq!(
            resp.expect("response should be Ok"),
            NodePackageResponse::Done
        );

        // A normal node request on the same stream, after the
        // install: the dispatch loop resumed on the request frame.
        let res: Result<NodeServiceResponse, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::NodeService),
            NodeServiceRequest::Status {
                service: "nginx".into(),
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

    /// An agent that overrides none of the new handler methods
    /// answers `"not supported"` to a unary `node.package` request.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_default_not_supported() {
        use crate::test::{TOKEN, channel};
        use crate::types::node::{NodePackageRequest, NodePackageResponse};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = NoopHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<NodePackageResponse, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::NodePackage),
            NodePackageRequest::Status {
                target: "sensor".into(),
                instance: Some(1),
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

    /// The same through `handle_node`, on a `NodeHandler`-only type.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_package_default_not_supported() {
        use crate::test::{TOKEN, channel};
        use crate::types::node::{NodePackageRequest, NodePackageResponse};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = StandaloneNodeHandler;
            super::handle_node(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<NodePackageResponse, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::NodePackage),
            NodePackageRequest::ListInstalled,
        )
        .await
        .expect("wire transport should succeed");

        assert_eq!(res.unwrap_err(), "not supported");

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// An agent that overrides none of the new handler methods
    /// answers an `Install` with `"not supported"` as the terminal
    /// preflight frame, and asks for no bytes.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn node_package_install_default_not_supported() {
        use std::time::Duration;

        use crate::test::{TOKEN, channel};
        use crate::types::node::NodePackageResponse;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = NoopHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let verdict = send_install_request(
            &mut client_send,
            &mut client_recv,
            install_request("sensor", 4_194_304),
        )
        .await;
        assert_eq!(verdict.unwrap_err(), "not supported");

        let mut buf = Vec::new();
        let extra = tokio::time::timeout(
            Duration::from_millis(200),
            oinq::frame::recv::<Result<NodePackageResponse, String>>(&mut client_recv, &mut buf),
        )
        .await;
        assert!(
            extra.is_err(),
            "an error verdict is itself the terminal frame"
        );

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// A code this crate has not assigned still takes the
    /// fail-closed path through `handle`.  This is what an older
    /// binary, whose `RequestCode` has no `NodePackage` variant,
    /// does with 109.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_unassigned_code_is_unknown() {
        use crate::test::{TOKEN, channel};

        const UNASSIGNED: u32 = 111;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        assert_eq!(
            RequestCode::from_primitive(UNASSIGNED),
            RequestCode::Unknown,
            "the test needs a code this crate has not assigned"
        );

        let server_task = tokio::spawn(async move {
            let mut handler = NoopHandler;
            super::handle(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<(), String> =
            crate::unary_request(&mut client_send, &mut client_recv, UNASSIGNED, ())
                .await
                .expect("wire transport should succeed");
        assert_eq!(res.unwrap_err(), "unknown request code: 111");

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }

    /// The same fail-closed path through `handle_node`.
    #[tokio::test]
    #[cfg(feature = "server")]
    async fn handle_node_unassigned_code_is_unknown() {
        use crate::test::{TOKEN, channel};

        const UNASSIGNED: u32 = 111;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            let mut handler = StandaloneNodeHandler;
            super::handle_node(&mut handler, &mut server_send, &mut server_recv).await
        });

        let res: Result<(), String> =
            crate::unary_request(&mut client_send, &mut client_recv, UNASSIGNED, ())
                .await
                .expect("wire transport should succeed");
        assert_eq!(res.unwrap_err(), "unknown request code: 111");

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_ok());
    }
}
