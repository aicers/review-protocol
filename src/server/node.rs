//! Service-family entry point for node operations.
//!
//! This module provides a [`Node`] handle that groups all
//! REview-to-agent node API calls under a single,
//! discoverable namespace.  It is the recommended way to
//! interact with the node API family for new code.
//!
//! # Obtaining a handle
//!
//! A [`Node`] handle is obtained from a
//! [`Connection`](super::Connection) via
//! [`Connection::node()`](super::Connection::node):
//!
//! ```rust,no_run
//! # use review_protocol::server::Connection;
//! # async fn example(conn: Connection) -> anyhow::Result<()> {
//! use review_protocol::types::node::NodePowerRequest;
//!
//! let node = conn.node();
//! let resp = node.power(NodePowerRequest::GracefulReboot).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Immediate power operations
//!
//! [`Node::reboot`] and [`Node::shutdown`] send the request and
//! return immediately without waiting for a response.  The agent
//! may close the connection while processing the command:
//!
//! ```rust,no_run
//! # use review_protocol::server::Connection;
//! # async fn example(conn: Connection) -> anyhow::Result<()> {
//! let node = conn.node();
//! node.reboot().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Authorization
//!
//! Every method has an `_authorized` variant that checks an
//! [`Authorizer`](crate::auth::Authorizer) before sending the
//! request.  The method-level
//! [`ServiceId`](crate::service_id::ServiceId) is extracted
//! from the typed request automatically:
//!
//! ```rust,no_run
//! # use review_protocol::server::Connection;
//! # async fn example(
//! #     conn: Connection,
//! #     peer: review_protocol::auth::PeerContext,
//! #     authorizer: review_protocol::auth::NoopAuthorizer,
//! # ) -> anyhow::Result<()> {
//! use review_protocol::types::node::NodePowerRequest;
//!
//! let node = conn.node();
//! let resp = node.power_authorized(
//!     NodePowerRequest::GracefulReboot,
//!     &peer,
//!     &authorizer,
//! ).await?;
//! # Ok(())
//! # }
//! ```

use crate::types::node::{
    NodeEnrollRequest, NodeEnrollResponse, NodeHostnameRequest, NodeHostnameResponse,
    NodeLoggingRequest, NodeLoggingResponse, NodeNetworkInterfaceRequest,
    NodeNetworkInterfaceResponse, NodeObservationRequest, NodeObservationResponse,
    NodePackageRequest, NodePackageResponse, NodePowerRequest, NodePowerResponse,
    NodeRemoteAccessRequest, NodeRemoteAccessResponse, NodeServiceRequest, NodeServiceResponse,
    NodeTimeSyncRequest, NodeTimeSyncResponse, NodeVersionRequest, NodeVersionResponse,
};

/// Result of a node power-control operation.
///
/// Immediate operations ([`NodePowerRequest::Reboot`],
/// [`NodePowerRequest::Shutdown`]) return [`Sent`](Self::Sent) after
/// the request frame has been written and the send stream finished.
/// The agent may close the connection while processing the command,
/// so no response is awaited.
///
/// Graceful operations ([`NodePowerRequest::GracefulReboot`],
/// [`NodePowerRequest::GracefulShutdown`]) return
/// [`Response`](Self::Response) after receiving the agent's
/// acknowledgment.
#[derive(Debug)]
pub enum NodePowerOutcome {
    /// The request was sent successfully; no response is expected.
    Sent,
    /// The agent responded with a [`NodePowerResponse`].
    Response(NodePowerResponse),
}

/// The two *terminal* preflight verdicts of a package install.
///
/// [`Proceed`](crate::types::node::InstallPreflight::Proceed) is
/// deliberately absent — it is a continuation, not a terminal frame —
/// so it cannot be placed inside an
/// [`InstallOutcome::Preflight`].  This mirrors the terminal arms of
/// the wire [`InstallPreflight`](crate::types::node::InstallPreflight);
/// the manager builds it from the step-2 frame and never surfaces
/// `Proceed` here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalPreflight {
    /// The build is already installed and its unit is not failed.
    AlreadyApplied,
    /// The target filesystem cannot hold the package, decided from
    /// the request's `size` alone before any bytes move.
    InsufficientDiskSpace {
        /// The filesystem that is short of space.
        filesystem: String,
        /// The space in bytes the install needs.
        required: u64,
        /// The space in bytes currently available.
        available: u64,
    },
}

/// Which branch of the package-install exchange terminated, so that a
/// caller cannot mistake a preflight refusal for an applied install.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallOutcome {
    /// The exchange ended at the preflight verdict.  No package bytes
    /// were sent.  The carried [`TerminalPreflight`] is by
    /// construction `AlreadyApplied` or `InsufficientDiskSpace`, never
    /// `Proceed`.
    Preflight(TerminalPreflight),
    /// The package bytes were streamed and the agent answered once
    /// with its terminal response.
    Applied(NodePackageResponse),
}

/// A handle for issuing node-family requests over an existing
/// [`Connection`](super::Connection).
///
/// `Node` borrows the underlying connection and exposes one
/// method per node feature family (service, network-interface,
/// hostname, time-sync, logging, remote-access, power,
/// observation, version).  Each method accepts the
/// corresponding typed `Node*Request` and returns the matching
/// `Node*Response`.
///
/// See the [module-level documentation](self) for usage
/// examples.
#[derive(Clone, Copy, Debug)]
pub struct Node<'a> {
    conn: &'a super::Connection,
}

impl<'a> Node<'a> {
    pub(crate) fn new(conn: &'a super::Connection) -> Self {
        Self { conn }
    }

    /// Sends a node service-control request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn service(&self, req: NodeServiceRequest) -> anyhow::Result<NodeServiceResponse> {
        self.conn.node_service(req).await
    }

    /// Sends a node service-control request with authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn service_authorized(
        &self,
        req: NodeServiceRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeServiceResponse> {
        self.conn
            .node_service_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node network-interface management request to the
    /// agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn network_interface(
        &self,
        req: NodeNetworkInterfaceRequest,
    ) -> anyhow::Result<NodeNetworkInterfaceResponse> {
        self.conn.node_network_interface(req).await
    }

    /// Sends a node network-interface management request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn network_interface_authorized(
        &self,
        req: NodeNetworkInterfaceRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeNetworkInterfaceResponse> {
        self.conn
            .node_network_interface_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node hostname management request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn hostname(&self, req: NodeHostnameRequest) -> anyhow::Result<NodeHostnameResponse> {
        self.conn.node_hostname(req).await
    }

    /// Sends a node hostname management request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn hostname_authorized(
        &self,
        req: NodeHostnameRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeHostnameResponse> {
        self.conn
            .node_hostname_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node time-synchronization request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn time_sync(
        &self,
        req: NodeTimeSyncRequest,
    ) -> anyhow::Result<NodeTimeSyncResponse> {
        self.conn.node_time_sync(req).await
    }

    /// Sends a node time-synchronization request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn time_sync_authorized(
        &self,
        req: NodeTimeSyncRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeTimeSyncResponse> {
        self.conn
            .node_time_sync_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node logging-configuration request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn logging(&self, req: NodeLoggingRequest) -> anyhow::Result<NodeLoggingResponse> {
        self.conn.node_logging(req).await
    }

    /// Sends a node logging-configuration request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn logging_authorized(
        &self,
        req: NodeLoggingRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeLoggingResponse> {
        self.conn
            .node_logging_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node remote-access configuration request to the
    /// agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn remote_access(
        &self,
        req: NodeRemoteAccessRequest,
    ) -> anyhow::Result<NodeRemoteAccessResponse> {
        self.conn.node_remote_access(req).await
    }

    /// Sends a node remote-access configuration request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn remote_access_authorized(
        &self,
        req: NodeRemoteAccessRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeRemoteAccessResponse> {
        self.conn
            .node_remote_access_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node power-control request to the agent.
    ///
    /// Immediate operations (`Reboot`, `Shutdown`) return
    /// [`NodePowerOutcome::Sent`] after the request frame has been
    /// queued and the send stream finished.  The agent may close the
    /// connection while processing the command, so no response is
    /// awaited.
    ///
    /// Graceful operations (`GracefulReboot`, `GracefulShutdown`)
    /// return [`NodePowerOutcome::Response`] after receiving the
    /// agent's acknowledgment.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication
    /// with the client failed.
    pub async fn power(&self, req: NodePowerRequest) -> anyhow::Result<NodePowerOutcome> {
        self.conn.node_power(req).await
    }

    /// Sends a node power-control request with authorization.
    ///
    /// See [`power`](Self::power) for the semantics of immediate
    /// vs graceful operations.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn power_authorized(
        &self,
        req: NodePowerRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodePowerOutcome> {
        self.conn.node_power_authorized(req, peer, authorizer).await
    }

    /// Reboots the node immediately.
    ///
    /// The request is sent and the send stream is finished without
    /// waiting for a response.  The agent may close the connection
    /// while processing the reboot command.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication
    /// with the client failed.
    pub async fn reboot(&self) -> anyhow::Result<()> {
        match self.power(NodePowerRequest::Reboot).await? {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Reboots the node immediately with authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization failed, or communication with the client
    /// failed.
    pub async fn reboot_authorized(
        &self,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<()> {
        match self
            .power_authorized(NodePowerRequest::Reboot, peer, authorizer)
            .await?
        {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Shuts down the node immediately.
    ///
    /// The request is sent and the send stream is finished without
    /// waiting for a response.  The agent may close the connection
    /// while processing the shutdown command.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication
    /// with the client failed.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        match self.power(NodePowerRequest::Shutdown).await? {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Shuts down the node immediately with authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization failed, or communication with the client
    /// failed.
    pub async fn shutdown_authorized(
        &self,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<()> {
        match self
            .power_authorized(NodePowerRequest::Shutdown, peer, authorizer)
            .await?
        {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Sends a node host-observation request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn observation(
        &self,
        req: NodeObservationRequest,
    ) -> anyhow::Result<NodeObservationResponse> {
        self.conn.node_observation(req).await
    }

    /// Sends a node host-observation request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn observation_authorized(
        &self,
        req: NodeObservationRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeObservationResponse> {
        self.conn
            .node_observation_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a node version-management request to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn version(&self, req: NodeVersionRequest) -> anyhow::Result<NodeVersionResponse> {
        self.conn.node_version(req).await
    }

    /// Sends a node version-management request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn version_authorized(
        &self,
        req: NodeVersionRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeVersionResponse> {
        self.conn
            .node_version_authorized(req, peer, authorizer)
            .await
    }

    /// Sends a unary node package-management request to the agent.
    ///
    /// Accepts [`Remove`](NodePackageRequest::Remove),
    /// [`ListInstalled`](NodePackageRequest::ListInstalled) and
    /// [`Status`](NodePackageRequest::Status).  An
    /// [`Install`](NodePackageRequest::Install) is rejected — use
    /// [`package_install`](Self::package_install), which carries the
    /// payload the agent waits for.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is an `Install`,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn package(&self, req: NodePackageRequest) -> anyhow::Result<NodePackageResponse> {
        self.conn.node_package(req).await
    }

    /// Sends a unary node package-management request with
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied, the request is
    /// an [`Install`](NodePackageRequest::Install),
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn package_authorized(
        &self,
        req: NodePackageRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodePackageResponse> {
        self.conn
            .node_package_authorized(req, peer, authorizer)
            .await
    }

    /// Installs a package on the agent, streaming `pkg` on the
    /// request's own stream.
    ///
    /// See
    /// [`Connection::node_package_install`](super::Connection::node_package_install)
    /// for the exchange this drives.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is not an
    /// [`Install`](NodePackageRequest::Install), if `pkg` ends before
    /// the request's `size` bytes, or if communication with the
    /// client failed.
    pub async fn package_install<R>(
        &self,
        req: NodePackageRequest,
        pkg: R,
    ) -> anyhow::Result<InstallOutcome>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
    {
        self.conn.node_package_install(req, pkg).await
    }

    /// Installs a package on the agent with authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied, if the request
    /// is not an [`Install`](NodePackageRequest::Install), if `pkg`
    /// ends before the request's `size` bytes, or if communication
    /// with the client failed.
    pub async fn package_install_authorized<R>(
        &self,
        req: NodePackageRequest,
        pkg: R,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<InstallOutcome>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
    {
        self.conn
            .node_package_install_authorized(req, pkg, peer, authorizer)
            .await
    }

    /// Sends a node service-enrollment request to the agent.
    ///
    /// This family is directed at the **registrar** agent.  A
    /// registrar refusal is not an error: it arrives as
    /// [`NodeEnrollResponse::Failed`], which the caller classifies by
    /// matching or through the response's own
    /// [`retry_after`](NodeEnrollResponse::retry_after) and
    /// [`leaves_teardown_owed`](NodeEnrollResponse::leaves_teardown_owed).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed
    /// or communication with the client failed.
    pub async fn enroll(&self, req: NodeEnrollRequest) -> anyhow::Result<NodeEnrollResponse> {
        self.conn.node_enroll(req).await
    }

    /// Sends a node service-enrollment request with authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn enroll_authorized(
        &self,
        req: NodeEnrollRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeEnrollResponse> {
        self.conn
            .node_enroll_authorized(req, peer, authorizer)
            .await
    }

    // -- _with_context variants (AuthorizerV2) -----------------

    /// Sends a node service-control request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn service_with_context(
        &self,
        req: NodeServiceRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeServiceResponse> {
        self.conn
            .node_service_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node network-interface request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn network_interface_with_context(
        &self,
        req: NodeNetworkInterfaceRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeNetworkInterfaceResponse> {
        self.conn
            .node_network_interface_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node hostname request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn hostname_with_context(
        &self,
        req: NodeHostnameRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeHostnameResponse> {
        self.conn
            .node_hostname_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node time-synchronization request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn time_sync_with_context(
        &self,
        req: NodeTimeSyncRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeTimeSyncResponse> {
        self.conn
            .node_time_sync_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node logging-configuration request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn logging_with_context(
        &self,
        req: NodeLoggingRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeLoggingResponse> {
        self.conn
            .node_logging_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node remote-access request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn remote_access_with_context(
        &self,
        req: NodeRemoteAccessRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeRemoteAccessResponse> {
        self.conn
            .node_remote_access_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node power-control request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// See [`power`](Self::power) for the semantics of immediate
    /// vs graceful operations.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn power_with_context(
        &self,
        req: NodePowerRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodePowerOutcome> {
        self.conn
            .node_power_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Reboots the node immediately with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization failed, or communication with the client
    /// failed.
    pub async fn reboot_with_context(
        &self,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<()> {
        match self
            .power_with_context(NodePowerRequest::Reboot, auth_ctx, authorizer)
            .await?
        {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Shuts down the node immediately with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization failed, or communication with the client
    /// failed.
    pub async fn shutdown_with_context(
        &self,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<()> {
        match self
            .power_with_context(NodePowerRequest::Shutdown, auth_ctx, authorizer)
            .await?
        {
            NodePowerOutcome::Sent | NodePowerOutcome::Response(_) => Ok(()),
        }
    }

    /// Sends a node host-observation request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn observation_with_context(
        &self,
        req: NodeObservationRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeObservationResponse> {
        self.conn
            .node_observation_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a node version-management request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn version_with_context(
        &self,
        req: NodeVersionRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeVersionResponse> {
        self.conn
            .node_version_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Sends a unary node package-management request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied, the request is
    /// an [`Install`](NodePackageRequest::Install),
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn package_with_context(
        &self,
        req: NodePackageRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodePackageResponse> {
        self.conn
            .node_package_with_context(req, auth_ctx, authorizer)
            .await
    }

    /// Installs a package on the agent with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied, if the request
    /// is not an [`Install`](NodePackageRequest::Install), if `pkg`
    /// ends before the request's `size` bytes, or if communication
    /// with the client failed.
    pub async fn package_install_with_context<R>(
        &self,
        req: NodePackageRequest,
        pkg: R,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<InstallOutcome>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
    {
        self.conn
            .node_package_install_with_context(req, pkg, auth_ctx, authorizer)
            .await
    }

    /// Sends a node service-enrollment request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication
    /// with the client failed.
    pub async fn enroll_with_context(
        &self,
        req: NodeEnrollRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeEnrollResponse> {
        self.conn
            .node_enroll_with_context(req, auth_ctx, authorizer)
            .await
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "client", feature = "server"))]
    use super::NodePowerOutcome;
    #[cfg(all(feature = "client", feature = "server"))]
    use crate::test::TEST_ENV;
    #[cfg(all(feature = "client", feature = "server"))]
    use crate::types::node::*;

    #[cfg(all(feature = "client", feature = "server"))]
    struct TestHandler;

    #[cfg(all(feature = "client", feature = "server"))]
    #[async_trait::async_trait]
    impl crate::request::Handler for TestHandler {
        async fn node_power(
            &mut self,
            _req: NodePowerRequest,
        ) -> Result<NodePowerResponse, String> {
            Ok(NodePowerResponse::Initiated)
        }

        async fn node_observation(
            &mut self,
            req: NodeObservationRequest,
        ) -> Result<NodeObservationResponse, String> {
            match req {
                NodeObservationRequest::ProcessList => Ok(NodeObservationResponse::ProcessList {
                    processes: vec![crate::types::Process {
                        user: "test-user".to_string(),
                        cpu_usage: 10.0,
                        mem_usage: 20.0,
                        start_time: 1_234_567_890,
                        command: "test-command".to_string(),
                    }],
                }),
                NodeObservationRequest::ResourceUsage => {
                    Ok(NodeObservationResponse::ResourceUsage {
                        hostname: "test-host".into(),
                        resource_usage: crate::types::ResourceUsage {
                            cpu_usage: 0.5,
                            total_memory: 100,
                            used_memory: 50,
                            disk_used_bytes: 500,
                            disk_available_bytes: 500,
                        },
                    })
                }
                NodeObservationRequest::Uptime => Err("not supported".to_string()),
            }
        }

        async fn node_service(
            &mut self,
            _req: NodeServiceRequest,
        ) -> Result<NodeServiceResponse, String> {
            Ok(NodeServiceResponse::Status { active: true })
        }
    }

    /// Verifies that `Node::power` produces the same result as
    /// `Connection::node_power`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_via_node_handle() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let node = server_conn.node();
        let resp = node.power(NodePowerRequest::GracefulReboot).await.unwrap();
        assert!(matches!(
            resp,
            NodePowerOutcome::Response(NodePowerResponse::Initiated)
        ));

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::power_authorized` checks
    /// authorization and produces the same result as
    /// `Connection::node_power_authorized`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_authorized_via_node_handle() {
        use crate::auth::{NoopAuthorizer, PeerContext};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let peer = PeerContext::new("test-agent");
        let authorizer = NoopAuthorizer;
        let node = server_conn.node();
        let resp = node
            .power_authorized(NodePowerRequest::GracefulReboot, &peer, &authorizer)
            .await
            .unwrap();
        assert!(matches!(
            resp,
            NodePowerOutcome::Response(NodePowerResponse::Initiated)
        ));

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::power_authorized` returns an error
    /// when the authorizer denies the request.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_authorized_denied_via_node_handle() {
        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::service_id::ServiceId;

        struct DenyAll;
        impl Authorizer for DenyAll {
            fn authorize(
                &self,
                _peer: &PeerContext,
                _service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                Err(AuthorizationError::new("denied"))
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let peer = PeerContext::new("test-agent");
        let authorizer = DenyAll;
        let node = server_conn.node();
        let result = node
            .power_authorized(NodePowerRequest::Reboot, &peer, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied")
        );

        drop(client_conn);
        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::observation` produces the same
    /// result as `Connection::node_observation`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn observation_via_node_handle() {
        use crate::types::ResourceUsage;

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let node = server_conn.node();
        let resp = node
            .observation(NodeObservationRequest::ResourceUsage)
            .await
            .unwrap();
        assert_eq!(
            resp,
            NodeObservationResponse::ResourceUsage {
                hostname: "test-host".into(),
                resource_usage: ResourceUsage {
                    cpu_usage: 0.5,
                    total_memory: 100,
                    used_memory: 50,
                    disk_used_bytes: 500,
                    disk_available_bytes: 500,
                },
            }
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::power_with_context` allows a request
    /// when the `AuthorizerV2` permits it.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_with_context_via_node_handle() {
        use crate::auth::{AuthorizationContext, AuthorizerV2Adapter, NoopAuthorizer, PeerContext};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let peer = PeerContext::new("test-agent");
        let auth_ctx = AuthorizationContext::from_peer_context(&peer);
        let authorizer = AuthorizerV2Adapter::new(NoopAuthorizer);
        let node = server_conn.node();
        let resp = node
            .power_with_context(NodePowerRequest::GracefulReboot, &auth_ctx, &authorizer)
            .await
            .unwrap();
        assert!(matches!(
            resp,
            NodePowerOutcome::Response(NodePowerResponse::Initiated)
        ));

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::power_with_context` denies a request
    /// when an `AuthorizerV2` checks roles.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_with_context_denied_by_role() {
        use crate::auth::{AuthorizationContext, AuthorizationError, AuthorizerV2, PeerContext};
        use crate::service_id::ServiceId;

        struct RequireAdmin;
        impl AuthorizerV2 for RequireAdmin {
            fn authorize_with_context(
                &self,
                ctx: &AuthorizationContext,
                _service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                if ctx.roles().is_some_and(|r| r.iter().any(|s| s == "admin")) {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("admin required"))
                }
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let peer = PeerContext::new("test-agent");
        let auth_ctx = AuthorizationContext::from_peer_context(&peer);
        let authorizer = RequireAdmin;
        let node = server_conn.node();
        let result = node
            .power_with_context(NodePowerRequest::Reboot, &auth_ctx, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied")
        );

        drop(client_conn);
        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::service` works via the node handle.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn service_via_node_handle() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let node = server_conn.node();
        let resp = node
            .service(NodeServiceRequest::Status {
                service: "nginx".into(),
            })
            .await
            .unwrap();
        assert_eq!(resp, NodeServiceResponse::Status { active: true });

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::power` with `Reboot` returns `Sent`
    /// and does not wait for a response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_reboot_returns_sent() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        // Client accepts the stream but closes it immediately without
        // sending a response, simulating an agent that reboots.
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            // Read the request frame
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            // Close the send side without sending a response
            send.finish().ok();
        });

        let node = server_conn.node();
        let result = node.power(NodePowerRequest::Reboot).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), NodePowerOutcome::Sent));

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::power` with `Shutdown` returns `Sent`
    /// and does not wait for a response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn power_shutdown_returns_sent() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            send.finish().ok();
        });

        let node = server_conn.node();
        let result = node.power(NodePowerRequest::Shutdown).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), NodePowerOutcome::Sent));

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::reboot` succeeds without waiting for a
    /// response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn reboot_no_response() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            send.finish().ok();
        });

        let node = server_conn.node();
        let result = node.reboot().await;
        assert!(result.is_ok());

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::shutdown` succeeds without waiting for a
    /// response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn shutdown_no_response() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            send.finish().ok();
        });

        let node = server_conn.node();
        let result = node.shutdown().await;
        assert!(result.is_ok());

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::reboot_authorized` succeeds when
    /// authorized and does not wait for a response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn reboot_authorized_no_response() {
        use crate::auth::{NoopAuthorizer, PeerContext};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            send.finish().ok();
        });

        let peer = PeerContext::new("test-agent");
        let authorizer = NoopAuthorizer;
        let node = server_conn.node();
        let result = node.reboot_authorized(&peer, &authorizer).await;
        assert!(result.is_ok());

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::shutdown_authorized` succeeds when
    /// authorized and does not wait for a response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn shutdown_authorized_no_response() {
        use crate::auth::{NoopAuthorizer, PeerContext};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            send.finish().ok();
        });

        let peer = PeerContext::new("test-agent");
        let authorizer = NoopAuthorizer;
        let node = server_conn.node();
        let result = node.shutdown_authorized(&peer, &authorizer).await;
        assert!(result.is_ok());

        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    // ── node.package handle tests ────────────────────────────────

    /// The payload the package test handler last received.  The
    /// install tests hold the `TEST_ENV` lock, so they observe it one
    /// at a time.
    #[cfg(all(feature = "client", feature = "server"))]
    static RECEIVED_PACKAGE: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

    /// A handler that serves the `node.package` family.
    #[cfg(all(feature = "client", feature = "server"))]
    struct PackageHandler;

    #[cfg(all(feature = "client", feature = "server"))]
    #[async_trait::async_trait]
    impl crate::request::Handler for PackageHandler {
        async fn node_package(
            &mut self,
            req: NodePackageRequest,
        ) -> Result<NodePackageResponse, String> {
            match req {
                NodePackageRequest::Remove { .. } => Ok(NodePackageResponse::Done),
                NodePackageRequest::ListInstalled => Ok(NodePackageResponse::Installed(vec![])),
                NodePackageRequest::Status { .. } => Ok(NodePackageResponse::State(PackageState {
                    version: "1.2.3".into(),
                    commit: "0123456789abcdef".into(),
                    lifecycle: Lifecycle::Running,
                    bound_addrs: vec![],
                })),
                NodePackageRequest::Install { .. } => {
                    Err("an install must never reach the unary method".to_string())
                }
            }
        }

        async fn node_package_install_preflight(
            &mut self,
            _req: &NodePackageRequest,
        ) -> Result<InstallPreflight, String> {
            Ok(InstallPreflight::Proceed)
        }

        async fn node_package_install(
            &mut self,
            _req: NodePackageRequest,
            pkg: &mut crate::request::PackageReader<'_>,
        ) -> Result<NodePackageResponse, String> {
            let mut payload = Vec::new();
            let mut chunk = Vec::new();
            while pkg
                .next_chunk(&mut chunk)
                .await
                .map_err(|e| format!("failed to read the payload: {e}"))?
            {
                payload.extend_from_slice(&chunk);
            }
            *RECEIVED_PACKAGE.lock().unwrap() = payload;
            Ok(NodePackageResponse::Done)
        }
    }

    /// Builds an `Install` request whose payload is `size` bytes.
    #[cfg(all(feature = "client", feature = "server"))]
    fn install_request(size: u64) -> NodePackageRequest {
        NodePackageRequest::Install {
            target: "sensor".into(),
            instance: Some(1),
            version: "1.2.3".into(),
            commit: "0123456789abcdef".into(),
            size,
            idempotency_key: "idem-1".into(),
            bootstrap_material: None,
            on_failure: FailurePolicy::Rollback,
        }
    }

    /// Spawns the agent side: one accepted bi-stream served by
    /// `crate::request::handle`.
    #[cfg(all(feature = "client", feature = "server"))]
    fn spawn_package_agent(
        conn: crate::client::Connection,
    ) -> tokio::task::JoinHandle<Result<(), crate::request::HandlerError>> {
        tokio::spawn(async move {
            let mut handler = PackageHandler;
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        })
    }

    /// Verifies that `Node::package` produces the same result as
    /// `Connection::node_package`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn package_via_node_handle() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let client_handle = spawn_package_agent(client_conn.clone());

        let node = server_conn.node();
        let resp = node
            .package(NodePackageRequest::Remove {
                target: "sensor".into(),
                instance: Some(1),
                idempotency_key: "idem-1".into(),
            })
            .await
            .unwrap();
        assert_eq!(resp, NodePackageResponse::Done);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::package_install` drives the whole
    /// exchange.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn package_install_via_node_handle() {
        use super::InstallOutcome;

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        RECEIVED_PACKAGE.lock().unwrap().clear();
        let client_handle = spawn_package_agent(client_conn.clone());

        let pkg: Vec<u8> = (0..3_333_u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let node = server_conn.node();
        let outcome = node
            .package_install(install_request(pkg.len() as u64), pkg.as_slice())
            .await
            .unwrap();
        assert_eq!(outcome, InstallOutcome::Applied(NodePackageResponse::Done));
        assert_eq!(*RECEIVED_PACKAGE.lock().unwrap(), pkg);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::package_authorized` denies before
    /// sending when the authorizer refuses.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn package_authorized_denied_via_node_handle() {
        use std::time::Duration;

        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::service_id::ServiceId;

        struct DenyAll;
        impl Authorizer for DenyAll {
            fn authorize(
                &self,
                _peer: &PeerContext,
                _service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                Err(AuthorizationError::new("denied"))
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move { handler_conn.accept_bi().await });

        let peer = PeerContext::new("test-agent");
        let authorizer = DenyAll;
        let node = server_conn.node();
        let result = node
            .package_authorized(NodePackageRequest::ListInstalled, &peer, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied")
        );

        let accepted = tokio::time::timeout(Duration::from_millis(200), client_handle).await;
        assert!(accepted.is_err(), "a denied request is never sent");

        drop(client_conn);
        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::package_install_authorized` denies
    /// before sending and without reading `pkg`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn package_install_authorized_denied_via_node_handle() {
        use std::time::Duration;

        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::service_id::ServiceId;

        struct DenyAll;
        impl Authorizer for DenyAll {
            fn authorize(
                &self,
                _peer: &PeerContext,
                _service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                Err(AuthorizationError::new("denied"))
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move { handler_conn.accept_bi().await });

        let peer = PeerContext::new("test-agent");
        let authorizer = DenyAll;
        let node = server_conn.node();
        let pkg = vec![7_u8; 512];
        let mut source = pkg.as_slice();
        let result = node
            .package_install_authorized(install_request(512), &mut source, &peer, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied")
        );
        assert_eq!(source.len(), pkg.len(), "`pkg` must not be read");

        let accepted = tokio::time::timeout(Duration::from_millis(200), client_handle).await;
        assert!(accepted.is_err(), "a denied request is never sent");

        drop(client_conn);
        test_env.teardown(&server_conn);
    }

    // ── node.enroll handle tests ─────────────────────────────────

    /// The material the enroll test handler mints.
    #[cfg(all(feature = "client", feature = "server"))]
    fn enroll_material() -> BootstrapMaterial {
        BootstrapMaterial {
            role_id: "sensor-installer".into(),
            wrapped_secret_id: "s.9f3c1b".into(),
            ca_anchor: vec![0x30, 0x82, 0x01, 0x0a],
            expires_at: "2026-01-02T03:04:05.123456789Z"
                .parse()
                .expect("literal is a valid timestamp"),
        }
    }

    /// A `Register` request for the identity the handler serves.
    #[cfg(all(feature = "client", feature = "server"))]
    fn enroll_register() -> NodeEnrollRequest {
        NodeEnrollRequest::Register {
            service_name: "sensor".into(),
            delivery_mode: DeliveryMode::RemoteBootstrap,
            host: "host01".into(),
            instance: Some(1),
            spec: ServiceSpec {
                component: "sensor".into(),
                service_name: "sensor".into(),
                reload: ReloadHook("reload-sensor".into()),
                cert_group: Some(CertGroup("internal".into())),
            },
            wrap_ttl: std::time::Duration::from_mins(10),
            idempotency_key: "idem-1".into(),
        }
    }

    /// A handler that serves the `node.enroll` family: it mints for a
    /// `Register`, tears down for a `Deregister` on the bound host,
    /// and refuses a wrong-host teardown with a typed failure.
    #[cfg(all(feature = "client", feature = "server"))]
    struct EnrollHandler;

    #[cfg(all(feature = "client", feature = "server"))]
    #[async_trait::async_trait]
    impl crate::request::Handler for EnrollHandler {
        async fn node_enroll(
            &mut self,
            req: NodeEnrollRequest,
        ) -> Result<NodeEnrollResponse, String> {
            match req {
                NodeEnrollRequest::Register { .. } => {
                    Ok(NodeEnrollResponse::Material(enroll_material()))
                }
                NodeEnrollRequest::Deregister { host, .. } if host == "host01" => {
                    Ok(NodeEnrollResponse::Done)
                }
                NodeEnrollRequest::Deregister { .. } => Ok(NodeEnrollResponse::Failed(
                    NodeEnrollError::ServiceHostMismatch,
                )),
            }
        }
    }

    /// Spawns the registrar side: one accepted bi-stream served by
    /// `crate::request::handle`.
    #[cfg(all(feature = "client", feature = "server"))]
    fn spawn_enroll_agent(
        conn: crate::client::Connection,
    ) -> tokio::task::JoinHandle<Result<(), crate::request::HandlerError>> {
        tokio::spawn(async move {
            let mut handler = EnrollHandler;
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        })
    }

    /// Verifies that `Node::enroll` round-trips a `Register` and
    /// returns the minted material.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn enroll_register_via_node_handle() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let client_handle = spawn_enroll_agent(client_conn.clone());

        let node = server_conn.node();
        let resp = node.enroll(enroll_register()).await.unwrap();
        assert_eq!(resp, NodeEnrollResponse::Material(enroll_material()));
        assert_eq!(resp.retry_after(), None);
        assert!(!resp.leaves_teardown_owed());

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::enroll` round-trips a `Deregister`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn enroll_deregister_via_node_handle() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let client_handle = spawn_enroll_agent(client_conn.clone());

        let node = server_conn.node();
        let resp = node
            .enroll(NodeEnrollRequest::Deregister {
                service_name: "sensor".into(),
                host: "host01".into(),
                instance: Some(1),
                idempotency_key: "idem-1".into(),
            })
            .await
            .unwrap();
        assert_eq!(resp, NodeEnrollResponse::Done);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// A typed registrar refusal arrives as a successful response the
    /// caller matches on, not as a transport error.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn enroll_typed_failure_via_node_handle() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let client_handle = spawn_enroll_agent(client_conn.clone());

        let node = server_conn.node();
        let resp = node
            .enroll(NodeEnrollRequest::Deregister {
                service_name: "sensor".into(),
                host: "other-host".into(),
                instance: Some(1),
                idempotency_key: "idem-1".into(),
            })
            .await
            .expect("a typed refusal is success-shaped on the wire");
        assert_eq!(
            resp,
            NodeEnrollResponse::Failed(NodeEnrollError::ServiceHostMismatch)
        );
        assert_eq!(resp.retry_after(), None);
        assert!(!resp.leaves_teardown_owed());

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::enroll_authorized` denies before sending
    /// when the authorizer refuses.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn enroll_authorized_denied_via_node_handle() {
        use std::time::Duration;

        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::service_id::ServiceId;

        struct DenyAll;
        impl Authorizer for DenyAll {
            fn authorize(
                &self,
                _peer: &PeerContext,
                _service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                Err(AuthorizationError::new("denied"))
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move { handler_conn.accept_bi().await });

        let peer = PeerContext::new("test-agent");
        let authorizer = DenyAll;
        let node = server_conn.node();
        let result = node
            .enroll_authorized(enroll_register(), &peer, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied")
        );

        let accepted = tokio::time::timeout(Duration::from_millis(200), client_handle).await;
        assert!(accepted.is_err(), "a denied request is never sent");

        drop(client_conn);
        test_env.teardown(&server_conn);
    }

    /// Authorization is checked against the request's **method-level**
    /// identifier, so `register` and `deregister` are separately
    /// grantable: an authorizer holding only `node.enroll.register`
    /// passes a `Register` and refuses a `Deregister`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn enroll_authorized_uses_the_method_level_service_id() {
        use std::time::Duration;

        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::service_id::{NODE_ENROLL_REGISTER, ServiceId};

        struct RegisterOnly;
        impl Authorizer for RegisterOnly {
            fn authorize(
                &self,
                _peer: &PeerContext,
                service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                if *service == NODE_ENROLL_REGISTER {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("denied"))
                }
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let client_handle = spawn_enroll_agent(client_conn.clone());

        let peer = PeerContext::new("test-agent");
        let authorizer = RegisterOnly;
        let node = server_conn.node();
        let resp = node
            .enroll_authorized(enroll_register(), &peer, &authorizer)
            .await
            .unwrap();
        assert_eq!(resp, NodeEnrollResponse::Material(enroll_material()));

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        // The sibling method identifier is a separate grant, and the
        // family identifier is not what is checked: the same authorizer
        // refuses the teardown, which is therefore never sent.
        let handler_conn = client_conn.clone();
        let deny_handle = tokio::spawn(async move { handler_conn.accept_bi().await });

        let result = node
            .enroll_authorized(
                NodeEnrollRequest::Deregister {
                    service_name: "sensor".into(),
                    host: "host01".into(),
                    instance: Some(1),
                    idempotency_key: "idem-1".into(),
                },
                &peer,
                &authorizer,
            )
            .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied")
        );

        let accepted = tokio::time::timeout(Duration::from_millis(200), deny_handle).await;
        assert!(accepted.is_err(), "a denied request is never sent");

        drop(client_conn);
        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::enroll_with_context` allows a request the
    /// `AuthorizerV2` permits.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn enroll_with_context_via_node_handle() {
        use crate::auth::{AuthorizationContext, AuthorizerV2Adapter, NoopAuthorizer, PeerContext};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let client_handle = spawn_enroll_agent(client_conn.clone());

        let peer = PeerContext::new("test-agent");
        let auth_ctx = AuthorizationContext::from_peer_context(&peer);
        let authorizer = AuthorizerV2Adapter::new(NoopAuthorizer);
        let node = server_conn.node();
        let resp = node
            .enroll_with_context(enroll_register(), &auth_ctx, &authorizer)
            .await
            .unwrap();
        assert_eq!(resp, NodeEnrollResponse::Material(enroll_material()));

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::package_with_context` allows a request
    /// the `AuthorizerV2` permits.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn package_with_context_via_node_handle() {
        use crate::auth::{AuthorizationContext, AuthorizerV2Adapter, NoopAuthorizer, PeerContext};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let client_handle = spawn_package_agent(client_conn.clone());

        let peer = PeerContext::new("test-agent");
        let auth_ctx = AuthorizationContext::from_peer_context(&peer);
        let authorizer = AuthorizerV2Adapter::new(NoopAuthorizer);
        let node = server_conn.node();
        let resp = node
            .package_with_context(NodePackageRequest::ListInstalled, &auth_ctx, &authorizer)
            .await
            .unwrap();
        assert_eq!(resp, NodePackageResponse::Installed(vec![]));

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// Verifies that `Node::package_install_with_context` denies
    /// before sending when the `AuthorizerV2` refuses.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn package_install_with_context_denied() {
        use std::time::Duration;

        use crate::auth::{AuthorizationContext, AuthorizationError, AuthorizerV2, PeerContext};
        use crate::service_id::ServiceId;

        struct RequireAdmin;
        impl AuthorizerV2 for RequireAdmin {
            fn authorize_with_context(
                &self,
                ctx: &AuthorizationContext,
                _service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                if ctx.roles().is_some_and(|r| r.iter().any(|s| s == "admin")) {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("admin required"))
                }
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move { handler_conn.accept_bi().await });

        let peer = PeerContext::new("test-agent");
        let auth_ctx = AuthorizationContext::from_peer_context(&peer);
        let authorizer = RequireAdmin;
        let node = server_conn.node();
        let pkg = vec![7_u8; 256];
        let mut source = pkg.as_slice();
        let result = node
            .package_install_with_context(install_request(256), &mut source, &auth_ctx, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied")
        );
        assert_eq!(source.len(), pkg.len(), "`pkg` must not be read");

        let accepted = tokio::time::timeout(Duration::from_millis(200), client_handle).await;
        assert!(accepted.is_err(), "a denied request is never sent");

        drop(client_conn);
        test_env.teardown(&server_conn);
    }
}
