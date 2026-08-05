use anyhow::{Context, anyhow, bail};
use oinq::frame;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::Connection;
use super::node::{InstallOutcome, NodePowerOutcome, TerminalPreflight};
use crate::{
    client,
    types::{
        CustomerDataDeletionRequest, HostNetworkGroup, SamplingPolicy, TrafficFilterRule,
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

/// The size of the chunks the package payload is sent in.
///
/// This is sender-side tuning, not wire contract: the receiver reads
/// exactly the request's `size` bytes and must not observe how the
/// payload was split.
const PACKAGE_CHUNK_LEN: u64 = 64 * 1024;

/// The stream error code the manager resets with when its own byte
/// source ends before the declared `size`.
const PACKAGE_TRANSFER_ABORTED: u32 = 1;

/// The server API.
///
/// # Node API vs legacy flat API
///
/// `Connection` exposes three styles of methods for managing the
/// connected agent (node).  **For new code, prefer the
/// [`node()`](Self::node) handle** (see the
/// [`server::node`](super::node) module):
///
/// ```rust,no_run
/// # use review_protocol::server::Connection;
/// # use review_protocol::types::node::NodePowerRequest;
/// # async fn example(conn: Connection) -> anyhow::Result<()> {
/// let resp = conn.node().power(NodePowerRequest::GracefulReboot).await?;
/// # Ok(())
/// # }
/// ```
///
/// - **[`node()`](Self::node) handle** — service-family entry
///   point that groups all node methods under a single
///   [`Node`](super::node::Node) namespace.  **Prefer this for
///   all new code.**
///
/// - **`node_*` methods** (e.g. [`node_power`](Self::node_power),
///   [`node_observation`](Self::node_observation)) accept a typed
///   `Node*Request` enum and return the corresponding
///   `Node*Response`.  These remain available as compatibility
///   wrappers.
///
/// - **Legacy flat methods** provide a simpler,
///   backward-compatible surface.  They do not expose `ServiceId`
///   and cannot participate in `Authorizer`-based access control.
///   Some (e.g. [`send_allowlist`](Self::send_allowlist)) still use
///   their own request path.
///
/// ## Migrating from flat to `node_*`
///
/// When migrating, note the following differences:
///
/// - `node_*` methods return the full `Node*Response` enum; you
///   must match the expected variant.
/// - `node_*_authorized` methods require a
///   [`PeerContext`](crate::auth::PeerContext) and an
///   [`Authorizer`](crate::auth::Authorizer).  Legacy methods
///   perform no authorization check.
/// - Some legacy methods have no `node_*` equivalent (e.g.
///   [`send_allowlist`](Self::send_allowlist),
///   [`send_ping`](Self::send_ping)); continue using them as-is.
impl Connection {
    /// Sends the allowlist for network addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_allowlist(&self, allowlist: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::Allowlist, allowlist)
            .await
    }

    /// Sends the blocklist for network addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_blocklist(&self, blocklist: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::Blocklist, blocklist)
            .await
    }

    /// Sends the config-update command.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_config_update_cmd(&self) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::UpdateConfig, &())
            .await
    }

    /// Sends a customer-data deletion command.
    ///
    /// The request's opaque ID must be returned unchanged in the corresponding
    /// deletion report.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_delete_customer_data_cmd(
        &self,
        request: &CustomerDataDeletionRequest,
    ) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::DeleteCustomerData, request)
            .await
    }

    /// Sends the traffic filtering rules.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_filtering_rules(&self, list: &[TrafficFilterRule]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::ReloadFilterRule, list)
            .await
    }

    /// Sends the internal network list.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_internal_network_list(&self, list: &HostNetworkGroup) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::InternalNetworkList, list)
            .await
    }

    /// Sends the ping message.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_ping(&self) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::EchoRequest, &())
            .await
    }

    /// Sends the sampling policies.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_sampling_policies(&self, list: &[SamplingPolicy]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::SamplingPolicyList, list)
            .await
    }

    /// Sends a list of Tor exit nodes to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_tor_exit_node_list(&self, list: &[String]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::TorExitNodeList, list)
            .await
    }

    /// Sends a list of trusted domains to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_trusted_domain_list(&self, list: &[String]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::TrustedDomainList, list)
            .await
    }

    /// Sends a list of trusted user-agents to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization failed or communication with the client failed.
    pub async fn send_trusted_user_agent_list(&self, list: &[String]) -> anyhow::Result<()> {
        self.send_request(client::RequestCode::TrustedUserAgentList, list)
            .await
    }

    // ── node feature-family methods ──────────────────────────────
    //
    // One method per node feature family. Each accepts the
    // corresponding typed `Node*Request` and returns the matching
    // `Node*Response`, routing through the internal `RequestCode`
    // mapping.
    //
    // ## Targeting
    //
    // Each `Connection` represents a single QUIC connection to one
    // agent (node).  Calling a `node_*` method sends the request to
    // the agent on the other end of *this* connection — there is no
    // additional node-selection parameter.  If you need to reach a
    // different node, use the `Connection` that corresponds to that
    // node.
    //
    // ## ServiceId and authorization
    //
    // Every `Node*Request` variant carries a method-level
    // `ServiceId` (e.g. `"node.power.reboot"`).  The `_authorized`
    // variants of these methods extract the `ServiceId` from the
    // request and pass it, together with the `PeerContext`, to the
    // caller-supplied `Authorizer` **before** the request is sent.
    // See the `_authorized` methods below and the `auth` module for
    // details.
    //
    // ## Legacy flat API compatibility
    //
    // Older "flat" methods on `Connection` provide a simpler,
    // backward-compatible interface for common operations.
    // They do not expose `ServiceId` and cannot be used with
    // `Authorizer`-based access control.
    //
    // **Prefer `node_*` methods for new code** — they offer typed
    // request/response enums, explicit `ServiceId` scoping, and
    // authorization support.

    /// Sends a node service-control request to the agent.
    ///
    /// The request targets the agent on this connection.  The
    /// specific operation is determined by the
    /// [`NodeServiceRequest`] variant (e.g. `Start`, `Stop`,
    /// `Status`, `Restart`).
    ///
    /// Each variant carries a distinct
    /// [`ServiceId`](crate::service_id::ServiceId) (e.g.
    /// `"node.service.start"`).  To enforce authorization based on
    /// this identifier, use
    /// [`node_service_authorized`](Self::node_service_authorized)
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_service(
        &self,
        req: NodeServiceRequest,
    ) -> anyhow::Result<NodeServiceResponse> {
        self.send_request(client::RequestCode::NodeService, &req)
            .await
    }

    /// Sends a node network-interface management request to the
    /// agent.
    ///
    /// The request targets the agent on this connection.  The
    /// specific operation is determined by the
    /// [`NodeNetworkInterfaceRequest`] variant (e.g. `List`, `Get`,
    /// `Set`).
    ///
    /// Each variant carries a distinct
    /// [`ServiceId`](crate::service_id::ServiceId).  To enforce
    /// authorization, use
    /// [`node_network_interface_authorized`](Self::node_network_interface_authorized)
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_network_interface(
        &self,
        req: NodeNetworkInterfaceRequest,
    ) -> anyhow::Result<NodeNetworkInterfaceResponse> {
        self.send_request(client::RequestCode::NodeNetworkInterface, &req)
            .await
    }

    /// Sends a node hostname management request to the agent.
    ///
    /// The request targets the agent on this connection.  The
    /// specific operation is determined by the
    /// [`NodeHostnameRequest`] variant (e.g. `Get`, `Set`).
    ///
    /// Each variant carries a distinct
    /// [`ServiceId`](crate::service_id::ServiceId).  To enforce
    /// authorization, use
    /// [`node_hostname_authorized`](Self::node_hostname_authorized)
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_hostname(
        &self,
        req: NodeHostnameRequest,
    ) -> anyhow::Result<NodeHostnameResponse> {
        self.send_request(client::RequestCode::NodeHostname, &req)
            .await
    }

    /// Sends a node time-synchronization request to the agent.
    ///
    /// The request targets the agent on this connection.  The
    /// specific operation is determined by the
    /// [`NodeTimeSyncRequest`] variant (e.g. `Get`, `Set`,
    /// `Enable`, `Disable`, `Status`).
    ///
    /// Each variant carries a distinct
    /// [`ServiceId`](crate::service_id::ServiceId).  To enforce
    /// authorization, use
    /// [`node_time_sync_authorized`](Self::node_time_sync_authorized)
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_time_sync(
        &self,
        req: NodeTimeSyncRequest,
    ) -> anyhow::Result<NodeTimeSyncResponse> {
        self.send_request(client::RequestCode::NodeTimeSync, &req)
            .await
    }

    /// Sends a node logging-configuration request to the agent.
    ///
    /// The request targets the agent on this connection.  The
    /// specific operation is determined by the
    /// [`NodeLoggingRequest`] variant (e.g. `Get`, `Set`, `Clear`,
    /// `Restart`).
    ///
    /// Each variant carries a distinct
    /// [`ServiceId`](crate::service_id::ServiceId).  To enforce
    /// authorization, use
    /// [`node_logging_authorized`](Self::node_logging_authorized)
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_logging(
        &self,
        req: NodeLoggingRequest,
    ) -> anyhow::Result<NodeLoggingResponse> {
        self.send_request(client::RequestCode::NodeLogging, &req)
            .await
    }

    /// Sends a node remote-access configuration request to the
    /// agent.
    ///
    /// The request targets the agent on this connection.  The
    /// specific operation is determined by the
    /// [`NodeRemoteAccessRequest`] variant (e.g. `Get`, `Set`,
    /// `Restart`).
    ///
    /// Each variant carries a distinct
    /// [`ServiceId`](crate::service_id::ServiceId).  To enforce
    /// authorization, use
    /// [`node_remote_access_authorized`](Self::node_remote_access_authorized)
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_remote_access(
        &self,
        req: NodeRemoteAccessRequest,
    ) -> anyhow::Result<NodeRemoteAccessResponse> {
        self.send_request(client::RequestCode::NodeRemoteAccess, &req)
            .await
    }

    /// Sends a node power-control request to the agent.
    ///
    /// The request targets the agent on this connection.  The
    /// specific operation is determined by the
    /// [`NodePowerRequest`] variant (e.g. `Reboot`, `Shutdown`,
    /// `GracefulReboot`, `GracefulShutdown`).
    ///
    /// Each variant carries a distinct
    /// [`ServiceId`](crate::service_id::ServiceId) (e.g.
    /// `"node.power.reboot"`).  To enforce authorization, use
    /// [`node_power_authorized`](Self::node_power_authorized)
    /// instead.
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
    pub async fn node_power(&self, req: NodePowerRequest) -> anyhow::Result<NodePowerOutcome> {
        match req {
            NodePowerRequest::Reboot | NodePowerRequest::Shutdown => {
                self.send_request_no_response(client::RequestCode::NodePower, &req)
                    .await?;
                Ok(NodePowerOutcome::Sent)
            }
            NodePowerRequest::GracefulReboot | NodePowerRequest::GracefulShutdown => {
                let resp: NodePowerResponse = self
                    .send_request(client::RequestCode::NodePower, &req)
                    .await?;
                Ok(NodePowerOutcome::Response(resp))
            }
        }
    }

    /// Sends a node host-observation request to the agent.
    ///
    /// The request targets the agent on this connection.  The
    /// specific operation is determined by the
    /// [`NodeObservationRequest`] variant (e.g. `ProcessList`,
    /// `ResourceUsage`, `Uptime`).
    ///
    /// Each variant carries a distinct
    /// [`ServiceId`](crate::service_id::ServiceId) (e.g.
    /// `"node.observation.process_list"`).  To enforce
    /// authorization, use
    /// [`node_observation_authorized`](Self::node_observation_authorized)
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_observation(
        &self,
        req: NodeObservationRequest,
    ) -> anyhow::Result<NodeObservationResponse> {
        self.send_request(client::RequestCode::NodeObservation, &req)
            .await
    }

    /// Sends a node version-management request to the agent.
    ///
    /// The request targets the agent on this connection.  The
    /// specific operation is determined by the
    /// [`NodeVersionRequest`] variant (e.g. `Get`,
    /// `SetOsVersion`, `SetProductVersion`).
    ///
    /// Each variant carries a distinct
    /// [`ServiceId`](crate::service_id::ServiceId).  To enforce
    /// authorization, use
    /// [`node_version_authorized`](Self::node_version_authorized)
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization/deserialization failed or
    /// communication with the client failed.
    pub async fn node_version(
        &self,
        req: NodeVersionRequest,
    ) -> anyhow::Result<NodeVersionResponse> {
        self.send_request(client::RequestCode::NodeVersion, &req)
            .await
    }

    /// Sends a unary node package-management request to the agent.
    ///
    /// The request targets the agent on this connection.  The
    /// specific operation is determined by the
    /// [`NodePackageRequest`] variant: `Remove`, `ListInstalled` or
    /// `Status`.
    ///
    /// [`Install`](NodePackageRequest::Install) is **rejected** here
    /// rather than sent, because an install is not unary: the agent
    /// answers it with a preflight verdict and then waits for the
    /// package bytes that this method never sends.  Use
    /// [`node_package_install`](Self::node_package_install) for it.
    ///
    /// Each variant carries a distinct
    /// [`ServiceId`](crate::service_id::ServiceId) (e.g.
    /// `"node.package.remove"`).  To enforce authorization, use
    /// [`node_package_authorized`](Self::node_package_authorized)
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is an `Install`,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_package(
        &self,
        req: NodePackageRequest,
    ) -> anyhow::Result<NodePackageResponse> {
        reject_install(&req)?;
        self.send_request(client::RequestCode::NodePackage, &req)
            .await
    }

    /// Installs a package on the agent, streaming `pkg` on the
    /// request's own stream.
    ///
    /// The exchange runs on a single bi-stream:
    ///
    /// 1. The framed [`Install`](NodePackageRequest::Install) request
    ///    goes out.  No bytes yet.
    /// 2. The agent answers with exactly one preflight verdict.
    ///    [`AlreadyApplied`](InstallPreflight::AlreadyApplied) and
    ///    [`InsufficientDiskSpace`](InstallPreflight::InsufficientDiskSpace)
    ///    are terminal: this method returns
    ///    [`InstallOutcome::Preflight`] without reading a byte of
    ///    `pkg`.
    /// 3. On [`Proceed`](InstallPreflight::Proceed), exactly the
    ///    request's `size` bytes are read from `pkg` and streamed as
    ///    length-prefixed chunks.
    /// 4. The agent answers once, and that response is returned as
    ///    [`InstallOutcome::Applied`].
    ///
    /// A source holding **more** than `size` bytes is not an error:
    /// this method stops at `size` and performs no read beyond it, so
    /// nothing is consumed that the caller may still need.  Pass
    /// `&mut reader` to keep the remainder.  A source that ends
    /// **before** `size` is an error, and the send stream is reset so
    /// that the agent's bounded read fails instead of parking
    /// forever; the agent's response is not awaited in that case.
    ///
    /// # Errors
    ///
    /// Returns an error if `req` is not an `Install`, if `pkg` ends
    /// before `size` bytes, if the agent reports a transport-level
    /// failure, or if communication with the client failed.
    pub async fn node_package_install<R>(
        &self,
        req: NodePackageRequest,
        pkg: R,
    ) -> anyhow::Result<InstallOutcome>
    where
        R: AsyncRead + Unpin + Send,
    {
        let size = install_size(&req)?;
        self.install_exchange(&req, size, pkg).await
    }

    // ── authorized node feature-family methods ───────────────────
    //
    // Like the un-authorized node methods above, but each checks
    // the provided `Authorizer` before sending the request.
    //
    // The method-level `ServiceId` is extracted from the request
    // (via `req.service_id()`) and passed together with the
    // `PeerContext` to `authorizer.authorize(...)`.  If
    // authorization is denied, the request is never sent and an
    // error is returned immediately.

    /// Sends a node service-control request to the agent with
    /// authorization.
    ///
    /// Behaves like [`node_service`](Self::node_service), but
    /// first checks authorization.  The method-level
    /// [`ServiceId`](crate::service_id::ServiceId) is extracted
    /// from `req` (e.g. `"node.service.start"`) and passed to
    /// `authorizer` together with `peer`.  If the authorizer
    /// denies the request, an error is returned and the request is
    /// not sent.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_service_authorized(
        &self,
        req: NodeServiceRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeServiceResponse> {
        let sid = req.service_id();
        self.send_request_authorized(
            client::RequestCode::NodeService,
            &req,
            &sid,
            peer,
            authorizer,
        )
        .await
    }

    /// Sends a node network-interface management request to the
    /// agent with authorization.
    ///
    /// Behaves like
    /// [`node_network_interface`](Self::node_network_interface),
    /// but first checks authorization using the method-level
    /// [`ServiceId`](crate::service_id::ServiceId) from `req`.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_network_interface_authorized(
        &self,
        req: NodeNetworkInterfaceRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeNetworkInterfaceResponse> {
        let sid = req.service_id();
        self.send_request_authorized(
            client::RequestCode::NodeNetworkInterface,
            &req,
            &sid,
            peer,
            authorizer,
        )
        .await
    }

    /// Sends a node hostname management request to the agent with
    /// authorization.
    ///
    /// Behaves like [`node_hostname`](Self::node_hostname), but
    /// first checks authorization using the method-level
    /// [`ServiceId`](crate::service_id::ServiceId) from `req`.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_hostname_authorized(
        &self,
        req: NodeHostnameRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeHostnameResponse> {
        let sid = req.service_id();
        self.send_request_authorized(
            client::RequestCode::NodeHostname,
            &req,
            &sid,
            peer,
            authorizer,
        )
        .await
    }

    /// Sends a node time-synchronization request to the agent with
    /// authorization.
    ///
    /// Behaves like [`node_time_sync`](Self::node_time_sync), but
    /// first checks authorization using the method-level
    /// [`ServiceId`](crate::service_id::ServiceId) from `req`.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_time_sync_authorized(
        &self,
        req: NodeTimeSyncRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeTimeSyncResponse> {
        let sid = req.service_id();
        self.send_request_authorized(
            client::RequestCode::NodeTimeSync,
            &req,
            &sid,
            peer,
            authorizer,
        )
        .await
    }

    /// Sends a node logging-configuration request to the agent with
    /// authorization.
    ///
    /// Behaves like [`node_logging`](Self::node_logging), but
    /// first checks authorization using the method-level
    /// [`ServiceId`](crate::service_id::ServiceId) from `req`.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_logging_authorized(
        &self,
        req: NodeLoggingRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeLoggingResponse> {
        let sid = req.service_id();
        self.send_request_authorized(
            client::RequestCode::NodeLogging,
            &req,
            &sid,
            peer,
            authorizer,
        )
        .await
    }

    /// Sends a node remote-access configuration request to the
    /// agent with authorization.
    ///
    /// Behaves like
    /// [`node_remote_access`](Self::node_remote_access), but first
    /// checks authorization using the method-level
    /// [`ServiceId`](crate::service_id::ServiceId) from `req`.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_remote_access_authorized(
        &self,
        req: NodeRemoteAccessRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeRemoteAccessResponse> {
        let sid = req.service_id();
        self.send_request_authorized(
            client::RequestCode::NodeRemoteAccess,
            &req,
            &sid,
            peer,
            authorizer,
        )
        .await
    }

    /// Sends a node power-control request to the agent with
    /// authorization.
    ///
    /// Behaves like [`node_power`](Self::node_power), but first
    /// checks authorization using the method-level
    /// [`ServiceId`](crate::service_id::ServiceId) from `req`
    /// (e.g. `"node.power.reboot"`).
    ///
    /// Immediate operations (`Reboot`, `Shutdown`) return
    /// [`NodePowerOutcome::Sent`]; graceful operations return
    /// [`NodePowerOutcome::Response`].
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization failed, or communication with the client
    /// failed.
    pub async fn node_power_authorized(
        &self,
        req: NodePowerRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodePowerOutcome> {
        let sid = req.service_id();
        authorizer.authorize(peer, &sid).map_err(|e| anyhow!(e))?;
        match req {
            NodePowerRequest::Reboot | NodePowerRequest::Shutdown => {
                self.send_request_no_response(client::RequestCode::NodePower, &req)
                    .await?;
                Ok(NodePowerOutcome::Sent)
            }
            NodePowerRequest::GracefulReboot | NodePowerRequest::GracefulShutdown => {
                let resp: NodePowerResponse = self
                    .send_request(client::RequestCode::NodePower, &req)
                    .await?;
                Ok(NodePowerOutcome::Response(resp))
            }
        }
    }

    /// Sends a node host-observation request to the agent with
    /// authorization.
    ///
    /// Behaves like
    /// [`node_observation`](Self::node_observation), but first
    /// checks authorization using the method-level
    /// [`ServiceId`](crate::service_id::ServiceId) from `req`.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_observation_authorized(
        &self,
        req: NodeObservationRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeObservationResponse> {
        let sid = req.service_id();
        self.send_request_authorized(
            client::RequestCode::NodeObservation,
            &req,
            &sid,
            peer,
            authorizer,
        )
        .await
    }

    /// Sends a node version-management request to the agent with
    /// authorization.
    ///
    /// Behaves like [`node_version`](Self::node_version), but
    /// first checks authorization using the method-level
    /// [`ServiceId`](crate::service_id::ServiceId) from `req`.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_version_authorized(
        &self,
        req: NodeVersionRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodeVersionResponse> {
        let sid = req.service_id();
        self.send_request_authorized(
            client::RequestCode::NodeVersion,
            &req,
            &sid,
            peer,
            authorizer,
        )
        .await
    }

    /// Sends a unary node package-management request to the agent
    /// with authorization.
    ///
    /// Behaves like [`node_package`](Self::node_package), but first
    /// checks authorization using the method-level
    /// [`ServiceId`](crate::service_id::ServiceId) from `req`.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied, the request is
    /// an [`Install`](NodePackageRequest::Install),
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_package_authorized(
        &self,
        req: NodePackageRequest,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<NodePackageResponse> {
        reject_install(&req)?;
        let sid = req.service_id();
        self.send_request_authorized(
            client::RequestCode::NodePackage,
            &req,
            &sid,
            peer,
            authorizer,
        )
        .await
    }

    /// Installs a package on the agent with authorization.
    ///
    /// Behaves like
    /// [`node_package_install`](Self::node_package_install), but
    /// first checks authorization using the method-level
    /// [`ServiceId`](crate::service_id::ServiceId) from `req`
    /// (`"node.package.install"`).  Nothing is sent and `pkg` is not
    /// read if the authorizer denies the request.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied, if `req` is not
    /// an [`Install`](NodePackageRequest::Install), if `pkg` ends
    /// before `size` bytes, or if communication with the client
    /// failed.
    pub async fn node_package_install_authorized<R>(
        &self,
        req: NodePackageRequest,
        pkg: R,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<InstallOutcome>
    where
        R: AsyncRead + Unpin + Send,
    {
        let size = install_size(&req)?;
        let sid = req.service_id();
        authorizer.authorize(peer, &sid).map_err(|e| anyhow!(e))?;
        self.install_exchange(&req, size, pkg).await
    }

    // -- _with_context variants (AuthorizerV2) -----------------

    /// Sends a node service-control request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// Like [`node_service_authorized`](Self::node_service_authorized)
    /// but accepts an
    /// [`AuthorizationContext`](crate::auth::AuthorizationContext)
    /// and an [`AuthorizerV2`](crate::auth::AuthorizerV2).
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_service_with_context(
        &self,
        req: NodeServiceRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeServiceResponse> {
        let sid = req.service_id();
        self.send_request_authorized_with_context(
            client::RequestCode::NodeService,
            &req,
            &sid,
            auth_ctx,
            authorizer,
        )
        .await
    }

    /// Sends a node network-interface request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_network_interface_with_context(
        &self,
        req: NodeNetworkInterfaceRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeNetworkInterfaceResponse> {
        let sid = req.service_id();
        self.send_request_authorized_with_context(
            client::RequestCode::NodeNetworkInterface,
            &req,
            &sid,
            auth_ctx,
            authorizer,
        )
        .await
    }

    /// Sends a node hostname request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_hostname_with_context(
        &self,
        req: NodeHostnameRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeHostnameResponse> {
        let sid = req.service_id();
        self.send_request_authorized_with_context(
            client::RequestCode::NodeHostname,
            &req,
            &sid,
            auth_ctx,
            authorizer,
        )
        .await
    }

    /// Sends a node time-synchronization request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_time_sync_with_context(
        &self,
        req: NodeTimeSyncRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeTimeSyncResponse> {
        let sid = req.service_id();
        self.send_request_authorized_with_context(
            client::RequestCode::NodeTimeSync,
            &req,
            &sid,
            auth_ctx,
            authorizer,
        )
        .await
    }

    /// Sends a node logging-configuration request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_logging_with_context(
        &self,
        req: NodeLoggingRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeLoggingResponse> {
        let sid = req.service_id();
        self.send_request_authorized_with_context(
            client::RequestCode::NodeLogging,
            &req,
            &sid,
            auth_ctx,
            authorizer,
        )
        .await
    }

    /// Sends a node remote-access request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_remote_access_with_context(
        &self,
        req: NodeRemoteAccessRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeRemoteAccessResponse> {
        let sid = req.service_id();
        self.send_request_authorized_with_context(
            client::RequestCode::NodeRemoteAccess,
            &req,
            &sid,
            auth_ctx,
            authorizer,
        )
        .await
    }

    /// Sends a node power-control request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// See [`node_power`](Self::node_power) for the semantics of
    /// immediate vs graceful operations.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization failed, or communication with the client
    /// failed.
    pub async fn node_power_with_context(
        &self,
        req: NodePowerRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodePowerOutcome> {
        let sid = req.service_id();
        authorizer
            .authorize_with_context(auth_ctx, &sid)
            .map_err(|e| anyhow!(e))?;
        match req {
            NodePowerRequest::Reboot | NodePowerRequest::Shutdown => {
                self.send_request_no_response(client::RequestCode::NodePower, &req)
                    .await?;
                Ok(NodePowerOutcome::Sent)
            }
            NodePowerRequest::GracefulReboot | NodePowerRequest::GracefulShutdown => {
                let resp: NodePowerResponse = self
                    .send_request(client::RequestCode::NodePower, &req)
                    .await?;
                Ok(NodePowerOutcome::Response(resp))
            }
        }
    }

    /// Sends a node host-observation request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_observation_with_context(
        &self,
        req: NodeObservationRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeObservationResponse> {
        let sid = req.service_id();
        self.send_request_authorized_with_context(
            client::RequestCode::NodeObservation,
            &req,
            &sid,
            auth_ctx,
            authorizer,
        )
        .await
    }

    /// Sends a node version-management request with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied,
    /// serialization/deserialization failed, or communication with
    /// the client failed.
    pub async fn node_version_with_context(
        &self,
        req: NodeVersionRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodeVersionResponse> {
        let sid = req.service_id();
        self.send_request_authorized_with_context(
            client::RequestCode::NodeVersion,
            &req,
            &sid,
            auth_ctx,
            authorizer,
        )
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
    pub async fn node_package_with_context(
        &self,
        req: NodePackageRequest,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<NodePackageResponse> {
        reject_install(&req)?;
        let sid = req.service_id();
        self.send_request_authorized_with_context(
            client::RequestCode::NodePackage,
            &req,
            &sid,
            auth_ctx,
            authorizer,
        )
        .await
    }

    /// Installs a package on the agent with
    /// [`AuthorizerV2`](crate::auth::AuthorizerV2) authorization.
    ///
    /// See [`node_package_install`](Self::node_package_install) for
    /// the exchange this drives.  Nothing is sent and `pkg` is not
    /// read if the authorizer denies the request.
    ///
    /// # Errors
    ///
    /// Returns an error if authorization was denied, if `req` is not
    /// an [`Install`](NodePackageRequest::Install), if `pkg` ends
    /// before `size` bytes, or if communication with the client
    /// failed.
    pub async fn node_package_install_with_context<R>(
        &self,
        req: NodePackageRequest,
        pkg: R,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<InstallOutcome>
    where
        R: AsyncRead + Unpin + Send,
    {
        let size = install_size(&req)?;
        let sid = req.service_id();
        authorizer
            .authorize_with_context(auth_ctx, &sid)
            .map_err(|e| anyhow!(e))?;
        self.install_exchange(&req, size, pkg).await
    }

    /// Drives the whole install exchange on one bi-stream.
    ///
    /// `size` is the payload length taken from `req`, which the
    /// callers have already checked is an
    /// [`Install`](NodePackageRequest::Install).
    async fn install_exchange<R>(
        &self,
        req: &NodePackageRequest,
        size: u64,
        mut pkg: R,
    ) -> anyhow::Result<InstallOutcome>
    where
        R: AsyncRead + Unpin + Send,
    {
        let mut buf = encode_request(client::RequestCode::NodePackage, req)?;
        let (mut send, mut recv) = self.conn.open_bi().await?;
        frame::send_raw(&mut send, &buf).await?;

        let preflight = frame::recv::<Result<InstallPreflight, String>>(&mut recv, &mut buf)
            .await
            .context("receiving the install preflight verdict")?
            .map_err(|e| anyhow!(e))?;
        match preflight {
            InstallPreflight::AlreadyApplied => {
                return Ok(InstallOutcome::Preflight(TerminalPreflight::AlreadyApplied));
            }
            InstallPreflight::InsufficientDiskSpace {
                filesystem,
                required,
                available,
            } => {
                return Ok(InstallOutcome::Preflight(
                    TerminalPreflight::InsufficientDiskSpace {
                        filesystem,
                        required,
                        available,
                    },
                ));
            }
            InstallPreflight::Proceed => {}
        }

        if let Err(e) = send_package(&mut send, &mut pkg, size).await {
            // The agent is parked on a bounded read that will never
            // complete, so the transfer has to be ended actively.  A
            // reset says "aborted", where dropping the stream would
            // say "cleanly finished"; either way the agent's read
            // fails rather than hanging, and its response is not
            // awaited here.
            send.reset(quinn::VarInt::from_u32(PACKAGE_TRANSFER_ABORTED))
                .ok();
            return Err(e);
        }

        let resp = frame::recv::<Result<NodePackageResponse, String>>(&mut recv, &mut buf)
            .await
            .context("receiving the install response")?
            .map_err(|e| anyhow!(e))?;
        Ok(InstallOutcome::Applied(resp))
    }

    /// Sends the given payload to the client.
    async fn send_request<T: serde::Serialize + ?Sized, S: serde::de::DeserializeOwned>(
        &self,
        request_code: client::RequestCode,
        payload: &T,
    ) -> anyhow::Result<S> {
        let mut buf = encode_request(request_code, payload)?;

        let (mut send, mut recv) = self.conn.open_bi().await?;
        frame::send_raw(&mut send, &buf).await?;

        frame::recv::<Result<S, String>>(&mut recv, &mut buf)
            .await?
            .map_err(|e| anyhow!(e))
    }

    /// Sends the given payload to the client without waiting for a
    /// response.
    ///
    /// After writing the request frame, the send stream is finished
    /// to ensure the frame is flushed.  This is used for
    /// fire-and-forget operations where the agent may close the
    /// connection while processing the command.
    async fn send_request_no_response<T: serde::Serialize + ?Sized>(
        &self,
        request_code: client::RequestCode,
        payload: &T,
    ) -> anyhow::Result<()> {
        let buf = encode_request(request_code, payload)?;

        let (mut send, _recv) = self.conn.open_bi().await?;
        frame::send_raw(&mut send, &buf).await?;
        send.finish().ok();

        Ok(())
    }

    /// Checks authorization then sends the given payload to the
    /// client.
    async fn send_request_authorized<
        T: serde::Serialize + ?Sized,
        S: serde::de::DeserializeOwned,
    >(
        &self,
        request_code: client::RequestCode,
        payload: &T,
        service_id: &crate::service_id::ServiceId,
        peer: &crate::auth::PeerContext,
        authorizer: &dyn crate::auth::Authorizer,
    ) -> anyhow::Result<S> {
        authorizer
            .authorize(peer, service_id)
            .map_err(|e| anyhow!(e))?;
        self.send_request(request_code, payload).await
    }

    /// Checks authorization via [`AuthorizerV2`] then sends the
    /// given payload to the client.
    ///
    /// [`AuthorizerV2`]: crate::auth::AuthorizerV2
    async fn send_request_authorized_with_context<
        T: serde::Serialize + ?Sized,
        S: serde::de::DeserializeOwned,
    >(
        &self,
        request_code: client::RequestCode,
        payload: &T,
        service_id: &crate::service_id::ServiceId,
        auth_ctx: &crate::auth::AuthorizationContext,
        authorizer: &dyn crate::auth::AuthorizerV2,
    ) -> anyhow::Result<S> {
        authorizer
            .authorize_with_context(auth_ctx, service_id)
            .map_err(|e| anyhow!(e))?;
        self.send_request(request_code, payload).await
    }
}

/// Encodes a request frame: the fixed-int `u32` code followed by the
/// bincode payload.
fn encode_request<T: serde::Serialize + ?Sized>(
    request_code: client::RequestCode,
    payload: &T,
) -> anyhow::Result<Vec<u8>> {
    let code: u32 = request_code.into();
    let Ok(mut buf) =
        bincode::serde::encode_to_vec(code, bincode::config::standard().with_fixed_int_encoding())
    else {
        unreachable!("serialization of u32 into memory buffer should not fail")
    };
    bincode::serde::encode_into_std_write(payload, &mut buf, bincode::config::standard())?;
    Ok(buf)
}

/// Rejects an [`Install`](NodePackageRequest::Install) handed to a
/// unary entry point, before anything goes on the wire.
///
/// # Errors
///
/// Returns an error if `req` is an `Install`.
fn reject_install(req: &NodePackageRequest) -> anyhow::Result<()> {
    if matches!(req, NodePackageRequest::Install { .. }) {
        bail!("an install request carries a payload; use `node_package_install`");
    }
    Ok(())
}

/// Returns the payload length of an
/// [`Install`](NodePackageRequest::Install) request, rejecting a
/// unary variant handed to the install entry point before anything
/// goes on the wire.
///
/// # Errors
///
/// Returns an error if `req` is not an `Install`.
fn install_size(req: &NodePackageRequest) -> anyhow::Result<u64> {
    match req {
        NodePackageRequest::Install { size, .. } => Ok(*size),
        NodePackageRequest::Remove { .. }
        | NodePackageRequest::ListInstalled
        | NodePackageRequest::Status { .. } => {
            bail!("`node_package_install` accepts only an install request; use `node_package`")
        }
    }
}

/// Streams exactly `size` bytes of `pkg` as length-prefixed chunks.
///
/// Stops at `size` and performs no read beyond it, so a source that
/// holds more keeps its remainder.
///
/// # Errors
///
/// Returns an error if `pkg` ends before `size` bytes or the stream
/// could not be written.
async fn send_package<R>(send: &mut quinn::SendStream, pkg: &mut R, size: u64) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send,
{
    let chunk_len = usize::try_from(PACKAGE_CHUNK_LEN)?;
    let mut chunk = vec![0_u8; chunk_len];
    let mut remaining = size;
    while remaining > 0 {
        // `want` is capped at the chunk length and a read never
        // fills more than the slice it was given, so both bounds
        // hold by construction.
        let want = usize::try_from(remaining.min(PACKAGE_CHUNK_LEN))?;
        let read = pkg
            .read(&mut chunk[..want])
            .await
            .context("reading the package payload")?;
        if read == 0 {
            bail!(
                "the package source ended after {} of {size} bytes",
                size - remaining
            );
        }
        frame::send_raw(send, &chunk[..read]).await?;
        remaining -= u64::try_from(read)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "client", feature = "server"))]
    use {
        crate::{
            test::TEST_ENV,
            types::{
                CustomerDataDeletionRequest, HostNetworkGroup, Process, ResourceUsage,
                SamplingKind, SamplingPolicy,
            },
        },
        ipnet::IpNet,
        std::{
            net::{IpAddr, Ipv4Addr},
            time::Duration,
        },
    };

    #[cfg(all(feature = "client", feature = "server"))]
    // Define a constant IP address for tests
    const IP_ADDR_1: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[cfg(all(feature = "client", feature = "server"))]
    const HOST_FQDN: &str = "sensor.example.com";

    #[cfg(all(feature = "client", feature = "server"))]
    const DELETION_REQUEST_ID: u32 = 42;

    #[cfg(all(feature = "client", feature = "server"))]
    // Shared handler for all tests
    struct TestHandler;

    #[cfg(all(feature = "client", feature = "server"))]
    #[async_trait::async_trait]
    impl crate::request::Handler for TestHandler {
        async fn node_service(
            &mut self,
            _req: super::NodeServiceRequest,
        ) -> Result<super::NodeServiceResponse, String> {
            Ok(super::NodeServiceResponse::Status { active: true })
        }

        async fn node_network_interface(
            &mut self,
            _req: super::NodeNetworkInterfaceRequest,
        ) -> Result<super::NodeNetworkInterfaceResponse, String> {
            Ok(super::NodeNetworkInterfaceResponse::List {
                devices: vec!["eth0".into(), "eth1".into()],
            })
        }

        async fn node_hostname(
            &mut self,
            _req: super::NodeHostnameRequest,
        ) -> Result<super::NodeHostnameResponse, String> {
            Ok(super::NodeHostnameResponse::Get {
                hostname: "test-node".into(),
            })
        }

        async fn node_time_sync(
            &mut self,
            _req: super::NodeTimeSyncRequest,
        ) -> Result<super::NodeTimeSyncResponse, String> {
            Ok(super::NodeTimeSyncResponse::Done)
        }

        async fn node_logging(
            &mut self,
            _req: super::NodeLoggingRequest,
        ) -> Result<super::NodeLoggingResponse, String> {
            Ok(super::NodeLoggingResponse::Done)
        }

        async fn node_remote_access(
            &mut self,
            _req: super::NodeRemoteAccessRequest,
        ) -> Result<super::NodeRemoteAccessResponse, String> {
            Ok(super::NodeRemoteAccessResponse::Done)
        }

        async fn node_power(
            &mut self,
            _req: super::NodePowerRequest,
        ) -> Result<super::NodePowerResponse, String> {
            Ok(super::NodePowerResponse::Initiated)
        }

        async fn node_observation(
            &mut self,
            req: super::NodeObservationRequest,
        ) -> Result<super::NodeObservationResponse, String> {
            match req {
                super::NodeObservationRequest::ProcessList => {
                    Ok(super::NodeObservationResponse::ProcessList {
                        processes: vec![Process {
                            user: "test-user".to_string(),
                            cpu_usage: 10.0,
                            mem_usage: 20.0,
                            start_time: 1_234_567_890,
                            command: "test-command".to_string(),
                        }],
                    })
                }
                super::NodeObservationRequest::ResourceUsage => {
                    Ok(super::NodeObservationResponse::ResourceUsage {
                        hostname: "test-host".into(),
                        resource_usage: ResourceUsage {
                            cpu_usage: 0.5,
                            total_memory: 100,
                            used_memory: 50,
                            disk_used_bytes: 500,
                            disk_available_bytes: 500,
                        },
                    })
                }
                super::NodeObservationRequest::Uptime => Err("not supported".to_string()),
            }
        }

        async fn node_version(
            &mut self,
            _req: super::NodeVersionRequest,
        ) -> Result<super::NodeVersionResponse, String> {
            Ok(super::NodeVersionResponse::Get {
                os_version: "22.04".into(),
                product_version: "1.0.0".into(),
            })
        }

        async fn node_package(
            &mut self,
            req: super::NodePackageRequest,
        ) -> Result<super::NodePackageResponse, String> {
            use crate::types::node::{Lifecycle, NodePackageRequest, NodePackageResponse};

            match req {
                NodePackageRequest::Remove { .. } => Ok(NodePackageResponse::Done),
                NodePackageRequest::ListInstalled => {
                    Ok(NodePackageResponse::Installed(installed_pair()))
                }
                NodePackageRequest::Status { .. } => Ok(NodePackageResponse::State(package_state(
                    Lifecycle::Running,
                ))),
                NodePackageRequest::Install { .. } => {
                    Err("an install must never reach the unary method".to_string())
                }
            }
        }

        async fn node_package_install_preflight(
            &mut self,
            req: &super::NodePackageRequest,
        ) -> Result<super::InstallPreflight, String> {
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
            req: super::NodePackageRequest,
            pkg: &mut crate::request::PackageReader<'_>,
        ) -> Result<super::NodePackageResponse, String> {
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
            *RECEIVED_PACKAGE.lock().unwrap() = payload;

            if target == "selfdisrupting" {
                Ok(NodePackageResponse::Accepted)
            } else {
                Ok(NodePackageResponse::Done)
            }
        }

        async fn allowlist(&mut self, list: HostNetworkGroup) -> Result<(), String> {
            if list.hosts == [IP_ADDR_1] {
                Ok(())
            } else {
                Err("unexpected domain list".to_string())
            }
        }

        async fn blocklist(&mut self, list: HostNetworkGroup) -> Result<(), String> {
            if list.hosts == [IP_ADDR_1] {
                Ok(())
            } else {
                Err("unexpected blocklist".to_string())
            }
        }

        async fn update_config(&mut self) -> Result<(), String> {
            Ok(())
        }

        async fn delete_customer_data(
            &mut self,
            request: &CustomerDataDeletionRequest,
        ) -> Result<(), String> {
            let expected = CustomerDataDeletionRequest {
                id: DELETION_REQUEST_ID,
                host_fqdn: HOST_FQDN.to_string(),
            };
            if request == &expected {
                Ok(())
            } else {
                Err("unexpected customer-data deletion request".to_string())
            }
        }

        async fn update_traffic_filter_rules(
            &mut self,
            rules: &[super::TrafficFilterRule],
        ) -> Result<(), String> {
            if rules.len() == 1 {
                Ok(())
            } else {
                Err("unexpected filtering rules".to_string())
            }
        }

        async fn internal_network_list(&mut self, list: HostNetworkGroup) -> Result<(), String> {
            if list.hosts == [IP_ADDR_1] {
                Ok(())
            } else {
                Err("unexpected internal network list".to_string())
            }
        }

        async fn sampling_policy_list(
            &mut self,
            policies: &[super::SamplingPolicy],
        ) -> Result<(), String> {
            if policies.len() == 1 && policies[0].id == 42 {
                Ok(())
            } else {
                Err("unexpected sampling policies".to_string())
            }
        }

        async fn tor_exit_node_list(&mut self, nodes: &[&str]) -> Result<(), String> {
            if nodes == ["192.168.1.1", "10.0.0.1"] {
                Ok(())
            } else {
                Err("unexpected tor exit node list".to_string())
            }
        }

        async fn trusted_domain_list(&mut self, domains: &[&str]) -> Result<(), String> {
            if domains == ["example.com", "test.org"] {
                Ok(())
            } else {
                Err("unexpected trusted domain list".to_string())
            }
        }

        async fn trusted_user_agent_list(&mut self, agents: &[&str]) -> Result<(), String> {
            if agents == ["Mozilla/5.0", "Chrome/91.0"] {
                Ok(())
            } else {
                Err("unexpected trusted user agent list".to_string())
            }
        }
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_allowlist() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let allowlist_to_send = HostNetworkGroup {
            hosts: vec![IP_ADDR_1],
            networks: vec![],
            ip_ranges: vec![],
        };

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_allowlist(&allowlist_to_send).await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_blocklist() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let blocklist_to_send = HostNetworkGroup {
            hosts: vec![IP_ADDR_1],
            networks: vec![],
            ip_ranges: vec![],
        };

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_blocklist(&blocklist_to_send).await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_config_update_cmd() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_config_update_cmd().await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_delete_customer_data_cmd() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let request = CustomerDataDeletionRequest {
            id: DELETION_REQUEST_ID,
            host_fqdn: HOST_FQDN.to_string(),
        };
        let server_res = server_conn.send_delete_customer_data_cmd(&request).await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_filtering_rules() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let filtering_rules_to_send = vec![(
            "0.0.0.0/0".parse::<IpNet>().unwrap(),
            Some(vec![80]),
            Some(vec![6]),
        )];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_filtering_rules(&filtering_rules_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_internal_network_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let internal_network_list_to_send = HostNetworkGroup {
            hosts: vec![IP_ADDR_1],
            networks: vec![],
            ip_ranges: vec![],
        };

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_internal_network_list(&internal_network_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_sampling_policies() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let sampling_policies_to_send = vec![SamplingPolicy {
            id: 42,
            kind: SamplingKind::Conn,
            interval: Duration::from_mins(1),
            period: Duration::from_hours(1),
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: None,
            column: None,
        }];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_sampling_policies(&sampling_policies_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_tor_exit_node_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let tor_exit_node_list_to_send = vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_tor_exit_node_list(&tor_exit_node_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_trusted_domain_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let trusted_domain_list_to_send = vec!["example.com".to_string(), "test.org".to_string()];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_trusted_domain_list(&trusted_domain_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_trusted_user_agent_list() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let trusted_user_agent_list_to_send =
            vec!["Mozilla/5.0".to_string(), "Chrome/91.0".to_string()];

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn
            .send_trusted_user_agent_list(&trusted_user_agent_list_to_send)
            .await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn send_ping() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();

            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });
        let server_res = server_conn.send_ping().await;
        assert!(server_res.is_ok());
        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    // ── node feature-family round-trip tests ──────────────────────

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_service() {
        use crate::types::node::{NodeServiceRequest, NodeServiceResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeServiceRequest::Status {
            service: "nginx".into(),
        };
        let resp = server_conn.node_service(req).await.unwrap();
        assert_eq!(resp, NodeServiceResponse::Status { active: true });

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_network_interface() {
        use crate::types::node::{NodeNetworkInterfaceRequest, NodeNetworkInterfaceResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeNetworkInterfaceRequest::List {
            prefix: Some("eth".into()),
        };
        let resp = server_conn.node_network_interface(req).await.unwrap();
        assert_eq!(
            resp,
            NodeNetworkInterfaceResponse::List {
                devices: vec!["eth0".into(), "eth1".into()],
            }
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_hostname() {
        use crate::types::node::{NodeHostnameRequest, NodeHostnameResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeHostnameRequest::Get;
        let resp = server_conn.node_hostname(req).await.unwrap();
        assert_eq!(
            resp,
            NodeHostnameResponse::Get {
                hostname: "test-node".into(),
            }
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_time_sync() {
        use crate::types::node::{NodeTimeSyncRequest, NodeTimeSyncResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeTimeSyncRequest::Set {
            servers: vec!["0.pool.ntp.org".into()],
        };
        let resp = server_conn.node_time_sync(req).await.unwrap();
        assert_eq!(resp, NodeTimeSyncResponse::Done);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_logging() {
        use crate::types::node::{NodeLoggingRequest, NodeLoggingResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeLoggingRequest::Get;
        let resp = server_conn.node_logging(req).await.unwrap();
        assert_eq!(resp, NodeLoggingResponse::Done);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_remote_access() {
        use crate::types::node::{
            NodeRemoteAccessConfig, NodeRemoteAccessRequest, NodeRemoteAccessResponse,
        };

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeRemoteAccessRequest::Set {
            config: NodeRemoteAccessConfig { port: 22 },
        };
        let resp = server_conn.node_remote_access(req).await.unwrap();
        assert_eq!(resp, NodeRemoteAccessResponse::Done);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_power() {
        use crate::server::node::NodePowerOutcome;
        use crate::types::node::{NodePowerRequest, NodePowerResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodePowerRequest::GracefulReboot;
        let resp = server_conn.node_power(req).await.unwrap();
        assert!(matches!(
            resp,
            NodePowerOutcome::Response(NodePowerResponse::Initiated)
        ));

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_observation() {
        use crate::types::node::{NodeObservationRequest, NodeObservationResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeObservationRequest::ResourceUsage;
        let resp = server_conn.node_observation(req).await.unwrap();
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

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_power_authorization_allowed() {
        use crate::auth::{NoopAuthorizer, PeerContext};
        use crate::server::node::NodePowerOutcome;
        use crate::types::node::{NodePowerRequest, NodePowerResponse};

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
        let req = NodePowerRequest::GracefulReboot;
        let resp = server_conn
            .node_power_authorized(req, &peer, &authorizer)
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

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_power_authorization_denied() {
        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::service_id::ServiceId;
        use crate::types::node::NodePowerRequest;

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
        let req = NodePowerRequest::Reboot;
        let result = server_conn
            .node_power_authorized(req, &peer, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied")
        );

        // No client handler needed — request should not be sent.
        drop(client_conn);
        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_observation_authorization_selective() {
        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::service_id::ServiceId;
        use crate::types::node::{
            NodeObservationRequest, NodeObservationResponse, NodePowerRequest,
        };

        /// Allows observation but denies power operations.
        struct ObservationOnly;
        impl Authorizer for ObservationOnly {
            fn authorize(
                &self,
                _peer: &PeerContext,
                service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                if service.family == "node.observation" {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("only observation allowed"))
                }
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let peer = PeerContext::new("test-agent");
        let authorizer = ObservationOnly;

        // Observation should be allowed.
        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let resp = server_conn
            .node_observation_authorized(NodeObservationRequest::ResourceUsage, &peer, &authorizer)
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

        // Power should be denied.
        let result = server_conn
            .node_power_authorized(NodePowerRequest::Reboot, &peer, &authorizer)
            .await;
        assert!(result.is_err());

        test_env.teardown(&server_conn);
    }

    /// Verifies that authorized node methods discriminate at the
    /// method level within a single family.  For example, an
    /// authorizer can allow `node.power.reboot` while denying
    /// `node.power.shutdown`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_power_authorization_method_level() {
        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::server::node::NodePowerOutcome;
        use crate::service_id::{self, ServiceId};
        use crate::types::node::NodePowerRequest;

        /// Allows only `node.power.reboot`, denies everything else.
        struct RebootOnly;
        impl Authorizer for RebootOnly {
            fn authorize(
                &self,
                _peer: &PeerContext,
                service: &ServiceId,
            ) -> Result<(), AuthorizationError> {
                if *service == service_id::NODE_POWER_REBOOT {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("only reboot allowed"))
                }
            }
        }

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let peer = PeerContext::new("test-agent");
        let authorizer = RebootOnly;

        // Reboot should be allowed and return Sent (no-response).
        // The client reads the request and closes without responding.
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let _ = crate::frame::recv_msg::<NodePowerRequest>(&mut recv).await;
            send.finish().ok();
        });

        let resp = server_conn
            .node_power_authorized(NodePowerRequest::Reboot, &peer, &authorizer)
            .await
            .unwrap();
        assert!(matches!(resp, NodePowerOutcome::Sent));
        let client_res = client_handle.await;
        assert!(client_res.is_ok());

        // Shutdown (same family, different method) should be denied.
        let result = server_conn
            .node_power_authorized(NodePowerRequest::Shutdown, &peer, &authorizer)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("only reboot allowed")
        );

        // GracefulReboot should also be denied.
        let result = server_conn
            .node_power_authorized(NodePowerRequest::GracefulReboot, &peer, &authorizer)
            .await;
        assert!(result.is_err());

        test_env.teardown(&server_conn);
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_version() {
        use crate::types::node::{NodeVersionRequest, NodeVersionResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let mut handler = TestHandler;
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        });

        let req = NodeVersionRequest::Get;
        let resp = server_conn.node_version(req).await.unwrap();
        assert_eq!(
            resp,
            NodeVersionResponse::Get {
                os_version: "22.04".into(),
                product_version: "1.0.0".into(),
            }
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    // ── node.package manager tests ───────────────────────────────

    /// The payload the agent-side test handler last received.  The
    /// install tests hold the `TEST_ENV` lock, so they observe it one
    /// at a time.
    #[cfg(all(feature = "client", feature = "server"))]
    static RECEIVED_PACKAGE: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

    /// A `PackageState` in the given lifecycle.
    #[cfg(all(feature = "client", feature = "server"))]
    fn package_state(lifecycle: crate::types::node::Lifecycle) -> crate::types::node::PackageState {
        crate::types::node::PackageState {
            version: "1.2.3".into(),
            commit: "0123456789abcdef".into(),
            lifecycle,
            bound_addrs: vec![],
        }
    }

    /// Two installed entries that differ only in `instance`.
    #[cfg(all(feature = "client", feature = "server"))]
    fn installed_pair() -> Vec<crate::types::node::InstalledPackage> {
        use crate::types::node::{InstalledPackage, Lifecycle};

        vec![
            InstalledPackage {
                target: "sensor".into(),
                instance: Some(1),
                state: package_state(Lifecycle::Running),
            },
            InstalledPackage {
                target: "sensor".into(),
                instance: Some(2),
                state: package_state(Lifecycle::Stopped),
            },
        ]
    }

    /// Builds an `Install` request for `target` whose payload is
    /// `size` bytes long.
    #[cfg(all(feature = "client", feature = "server"))]
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

    /// A payload of `len` bytes with a recognizable pattern.
    #[cfg(all(feature = "client", feature = "server"))]
    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    /// Spawns the agent side: one accepted bi-stream served by
    /// `crate::request::handle`.
    #[cfg(all(feature = "client", feature = "server"))]
    fn spawn_agent(
        conn: crate::client::Connection,
    ) -> tokio::task::JoinHandle<Result<(), crate::request::HandlerError>> {
        tokio::spawn(async move {
            let mut handler = TestHandler;
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            crate::request::handle(&mut handler, &mut send, &mut recv).await
        })
    }

    /// `Remove` round-trips through `Connection::node_package`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_package_remove() {
        use crate::types::node::{NodePackageRequest, NodePackageResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let client_handle = spawn_agent(client_conn.clone());

        let resp = server_conn
            .node_package(NodePackageRequest::Remove {
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

    /// `ListInstalled` round-trips through `Connection::node_package`,
    /// carrying two entries that differ only in `instance`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_package_list_installed() {
        use crate::types::node::{NodePackageRequest, NodePackageResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let client_handle = spawn_agent(client_conn.clone());

        let resp = server_conn
            .node_package(NodePackageRequest::ListInstalled)
            .await
            .unwrap();
        assert_eq!(resp, NodePackageResponse::Installed(installed_pair()));

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// `Status` round-trips through `Connection::node_package`.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_package_status() {
        use crate::types::node::{Lifecycle, NodePackageRequest, NodePackageResponse};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let client_handle = spawn_agent(client_conn.clone());

        let resp = server_conn
            .node_package(NodePackageRequest::Status {
                target: "sensor".into(),
                instance: Some(1),
            })
            .await
            .unwrap();
        assert_eq!(
            resp,
            NodePackageResponse::State(package_state(Lifecycle::Running))
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// A `Proceed` install streams the payload and returns the
    /// agent's terminal response.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_package_install_proceed() {
        use crate::server::node::InstallOutcome;
        use crate::types::node::NodePackageResponse;

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        RECEIVED_PACKAGE.lock().unwrap().clear();
        let client_handle = spawn_agent(client_conn.clone());

        // Not a multiple of the sender's chunk size.
        let pkg = payload(150_000);
        let outcome = server_conn
            .node_package_install(install_request("sensor", pkg.len() as u64), pkg.as_slice())
            .await
            .unwrap();
        assert_eq!(
            outcome,
            InstallOutcome::Applied(NodePackageResponse::Done),
            "a completed install returns the agent's terminal response"
        );
        assert_eq!(*RECEIVED_PACKAGE.lock().unwrap(), pkg);

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// A self-disrupting apply answers `Accepted`, which the manager
    /// treats as terminal.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_package_install_accepted_is_terminal() {
        use crate::server::node::InstallOutcome;
        use crate::types::node::NodePackageResponse;

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        RECEIVED_PACKAGE.lock().unwrap().clear();
        let client_handle = spawn_agent(client_conn.clone());

        let pkg = payload(4_096);
        let outcome = server_conn
            .node_package_install(
                install_request("selfdisrupting", pkg.len() as u64),
                pkg.as_slice(),
            )
            .await
            .unwrap();
        assert_eq!(
            outcome,
            InstallOutcome::Applied(NodePackageResponse::Accepted)
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// An `AlreadyApplied` verdict ends the exchange with no bytes
    /// sent.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_package_install_already_applied() {
        use crate::server::node::{InstallOutcome, TerminalPreflight};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        RECEIVED_PACKAGE.lock().unwrap().clear();
        let client_handle = spawn_agent(client_conn.clone());

        let pkg = payload(4_096);
        let outcome = server_conn
            .node_package_install(install_request("already", pkg.len() as u64), pkg.as_slice())
            .await
            .unwrap();
        assert_eq!(
            outcome,
            InstallOutcome::Preflight(TerminalPreflight::AlreadyApplied)
        );
        assert!(
            RECEIVED_PACKAGE.lock().unwrap().is_empty(),
            "no package bytes are sent after a terminal verdict"
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// An `InsufficientDiskSpace` verdict ends the exchange and
    /// carries its measurements through.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_package_install_insufficient_disk_space() {
        use crate::server::node::{InstallOutcome, TerminalPreflight};

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        RECEIVED_PACKAGE.lock().unwrap().clear();
        let client_handle = spawn_agent(client_conn.clone());

        let pkg = payload(4_096);
        let outcome = server_conn
            .node_package_install(install_request("nospace", pkg.len() as u64), pkg.as_slice())
            .await
            .unwrap();
        assert_eq!(
            outcome,
            InstallOutcome::Preflight(TerminalPreflight::InsufficientDiskSpace {
                filesystem: "/opt".to_string(),
                required: 4_194_304,
                available: 1_024,
            })
        );
        assert!(RECEIVED_PACKAGE.lock().unwrap().is_empty());

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// A source holding more than `size` succeeds, and the surplus
    /// is left unread.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_package_install_over_long_source() {
        use crate::server::node::InstallOutcome;
        use crate::types::node::NodePackageResponse;

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        RECEIVED_PACKAGE.lock().unwrap().clear();
        let client_handle = spawn_agent(client_conn.clone());

        let pkg = payload(5_000);
        let declared = 3_000;
        let mut source = pkg.as_slice();
        let outcome = server_conn
            .node_package_install(install_request("sensor", declared), &mut source)
            .await
            .unwrap();
        assert_eq!(outcome, InstallOutcome::Applied(NodePackageResponse::Done));
        assert_eq!(
            *RECEIVED_PACKAGE.lock().unwrap(),
            pkg[..usize::try_from(declared).unwrap()],
            "the agent receives exactly the declared size"
        );
        assert_eq!(
            source,
            &pkg[usize::try_from(declared).unwrap()..],
            "the surplus is still unread"
        );

        let client_res = client_handle.await.unwrap();
        assert!(client_res.is_ok());

        test_env.teardown(&server_conn);
    }

    /// A source that ends before `size` is an error, and the manager
    /// does not wait for a step-4 response that will never come.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_package_install_short_source() {
        use std::time::Duration;

        use crate::types::node::InstallPreflight;

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        // An agent that answers `Proceed` and then answers nothing
        // more, so a manager that waited for step 4 would hang.
        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.accept_bi().await.unwrap();
            let mut buf = Vec::new();
            oinq::message::recv_request_raw(&mut recv, &mut buf)
                .await
                .unwrap();
            crate::request::send_response(
                &mut send,
                &mut buf,
                Ok::<InstallPreflight, String>(InstallPreflight::Proceed),
            )
            .await
            .unwrap();
            // Park until the test drops the connection.
            std::future::pending::<()>().await;
        });

        let pkg = payload(1_000);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            server_conn.node_package_install(install_request("sensor", 8_000), pkg.as_slice()),
        )
        .await
        .expect("the manager must not wait for the agent's response");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("ended after 1000 of 8000 bytes"),
            "unexpected error: {err}"
        );

        client_handle.abort();
        test_env.teardown(&server_conn);
    }

    /// `node_package` refuses an `Install` before anything goes on
    /// the wire.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_package_rejects_install() {
        use std::time::Duration;

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move { handler_conn.accept_bi().await });

        let err = server_conn
            .node_package(install_request("sensor", 4_096))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("node_package_install"), "unexpected: {err}");

        let accepted = tokio::time::timeout(Duration::from_millis(200), client_handle).await;
        assert!(
            accepted.is_err(),
            "the agent must not see a request frame at all"
        );

        test_env.teardown(&server_conn);
    }

    /// `node_package_install` refuses each unary variant before
    /// anything goes on the wire or a byte of `pkg` is read.
    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test]
    async fn node_package_install_rejects_unary_variants() {
        use std::time::Duration;

        use crate::types::node::NodePackageRequest;

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = client_conn.clone();
        let client_handle = tokio::spawn(async move { handler_conn.accept_bi().await });

        let unary = [
            NodePackageRequest::Remove {
                target: "sensor".into(),
                instance: Some(1),
                idempotency_key: "idem-1".into(),
            },
            NodePackageRequest::ListInstalled,
            NodePackageRequest::Status {
                target: "sensor".into(),
                instance: Some(1),
            },
        ];
        let pkg = payload(64);
        for req in unary {
            let mut source = pkg.as_slice();
            let err = server_conn
                .node_package_install(req, &mut source)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("node_package"), "unexpected: {err}");
            assert_eq!(source.len(), pkg.len(), "`pkg` must not be read");
        }

        let accepted = tokio::time::timeout(Duration::from_millis(200), client_handle).await;
        assert!(
            accepted.is_err(),
            "the agent must not see a request frame at all"
        );

        test_env.teardown(&server_conn);
    }
}
