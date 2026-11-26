//! An external consumer fixture; the session surface imports no Quinn types.
use review_protocol::{AgentInfo, types::node::NodePowerRequest};

pub fn schema(info: AgentInfo) -> (AgentInfo, NodePowerRequest) {
    (info, NodePowerRequest::GracefulReboot)
}

#[cfg(any(feature = "client", feature = "server"))]
pub fn options() -> review_protocol::session::SessionOptions {
    use review_protocol::session::{FrameLimit, SessionOptions};
    let mut options = SessionOptions::legacy_compatible();
    options.unary = FrameLimit::new(16 * 1024 * 1024).expect("valid example limit");
    options
}

#[cfg(feature = "client")]
pub async fn agent(
    connection: review_protocol::session::Connection,
    info: &AgentInfo,
) -> Result<(), review_protocol::session::SessionError> {
    use review_protocol::session::{AgentHandle, AgentRequest};
    let (handle, mut incoming) = AgentHandle::from_transport(connection, options(), info).await?;
    let _clone: AgentHandle = handle.clone();
    let _identity = handle.id();
    let _chain = handle.peer_certificates();
    let _config: String = handle.get_config().await?;
    let mut stream = incoming.accept().await?;
    if let Some(AgentRequest::Hostname { reply, .. }) = stream.next().await? {
        reply.respond(Err("application rejection".into())).await?;
    }
    stream.finish()?;
    Ok(())
}

#[cfg(feature = "client")]
pub async fn dial_agent(
    tls: std::sync::Arc<rustls::ClientConfig>,
    bind: std::net::SocketAddr,
    remote: std::net::SocketAddr,
    info: &AgentInfo,
) -> Result<(), review_protocol::session::SessionError> {
    use review_protocol::session::{AgentConnector, AgentTransportOptions, ApplicationCode};
    let connector = AgentConnector::bind(bind, tls, AgentTransportOptions::default(), options())?;
    let (handle, _incoming) = connector.connect(remote, "manager.example", info).await?;
    let _: String = handle.get_config().await?;
    handle.close(ApplicationCode::new(0).expect("zero fits"), b"done");
    connector.wait_idle().await;
    Ok(())
}

#[cfg(feature = "server")]
pub async fn server(
    connection: review_protocol::session::Connection,
) -> Result<(), review_protocol::session::SessionError> {
    use review_protocol::session::{ServerHandle, ServerRequest, ServerStream};
    let (handle, mut incoming) =
        ServerHandle::from_transport(connection, options(), ">=0.48.0", "0.49.0").await?;
    let _clone: ServerHandle = handle.clone();
    let _metadata = handle.metadata();
    let _outcome = handle.node_power(NodePowerRequest::GracefulReboot).await?;
    let ServerStream::Requests(mut stream) = incoming.accept().await? else {
        return Ok(());
    };
    if let Some(request) = stream.next().await? {
        match request {
            ServerRequest::GetConfig { reply, .. } => {
                reply.respond(Ok("configuration".into())).await?;
            }
            ServerRequest::GetModel { .. }
            | ServerRequest::GetPretrainedModel { .. }
            | ServerRequest::GetModelNames { .. }
            | ServerRequest::GetExclusionList { .. }
            | ServerRequest::GetWatchlist { .. }
            | ServerRequest::InsertModel { .. }
            | ServerRequest::UpdateModel { .. }
            | ServerRequest::RemoveModel { .. }
            | ServerRequest::ReportCustomerDataDeletion { .. }
            | ServerRequest::UploadRunModel { .. }
            | ServerRequest::ReportRun { .. }
            | ServerRequest::ReportActiveRuns { .. }
            | ServerRequest::ReportDetectorStatus { .. }
            | ServerRequest::ReportExclusionCounts { .. }
            | ServerRequest::GetSignatureRules { .. }
            | ServerRequest::ReportSignatureStatus { .. } => {}
        }
    }
    stream.finish()?;
    Ok(())
}

#[cfg(feature = "test-support")]
pub fn test_support(
    environment: &review_protocol::test::TestEnvironment,
    connection: &review_protocol::server::Connection,
) {
    environment.teardown(connection);
}

#[cfg(feature = "legacy")]
pub mod legacy;

#[cfg(feature = "client")]
pub async fn engine_reports(
    handle: &review_protocol::session::AgentHandle,
    report: &review_protocol::types::DetectorStatusReport,
) -> Result<(), review_protocol::session::SessionError> {
    use review_protocol::types::ReportedRunState;
    handle.upload_run_model(1, &[1, 2]).await?;
    handle.report_run(1, ReportedRunState::Started, None).await?;
    handle.report_active_runs(&[1]).await?;
    handle.report_detector_status(report).await
}

#[cfg(feature = "client")]
pub async fn semi_supervised_engine(
    handle: &review_protocol::session::AgentHandle,
    report: &review_protocol::types::EngineExclusionReport,
) -> Result<(), review_protocol::session::SessionError> {
    let _exclusion_list: Vec<review_protocol::types::NetworkListItem> =
        handle.get_exclusion_list().await?;
    let _watchlist: Vec<review_protocol::types::NetworkListItem> = handle.get_watchlist().await?;
    handle.report_exclusion_counts(report).await
}

#[cfg(feature = "client")]
pub async fn signature_engine(
    handle: &review_protocol::session::AgentHandle,
    report: &review_protocol::types::SignatureStatusReport,
) -> Result<Option<review_protocol::types::SignatureRules>, review_protocol::session::SessionError>
{
    handle.report_signature_status(report).await?;
    handle.get_signature_rules(None).await
}

#[cfg(feature = "client")]
pub async fn signature_rules_push(
    stream: &mut review_protocol::session::AgentRequestStream,
) -> Result<(), review_protocol::session::SessionError> {
    use review_protocol::session::AgentRequest;
    if let Some(AgentRequest::SignatureRules { request, reply }) = stream.next().await? {
        let _revision: u64 = request.revision;
        reply.respond(Ok(())).await?;
    }
    Ok(())
}

#[cfg(feature = "server")]
pub async fn signature_rules_command(
    handle: &review_protocol::session::ServerHandle,
    rules: &review_protocol::types::SignatureRules,
) -> Result<(), review_protocol::session::SessionError> {
    handle.send_signature_rules(rules).await
}

/// The signature schema types and the MITRE tactic mapping need no transport.
pub fn signature_schema(
    detail: &review_protocol::types::SignatureMatchDetail,
) -> (
    Option<review_protocol::types::EventCategory>,
    u32,
    review_protocol::types::DetectionModel,
) {
    use review_protocol::types::{DetectionModel, EventCategory, LoadedSignatureSet, TruncatedCount};
    let _: fn(&LoadedSignatureSet) -> &Option<String> = |set| &set.load_error;
    let _: fn(&TruncatedCount) -> i64 = |count| count.window_start;
    let category = EventCategory::from_mitre_tactic_id(EventCategory::Impact.mitre_tactic_id());
    (category, u32::from(detail.source), DetectionModel::SigmaSignature)
}

/// The exclusion-count report is a schema type, usable without any transport.
pub fn exclusion_counts(
    report: &review_protocol::types::EngineExclusionReport,
) -> &[review_protocol::types::ExcludedCount] {
    &report.counts
}

#[cfg(feature = "server")]
pub async fn engine_commands(
    handle: &review_protocol::session::ServerHandle,
    train: &review_protocol::types::TrainModelRequest,
    clone: &review_protocol::types::CloneModelRequest,
) -> Result<(), review_protocol::session::SessionError> {
    handle.send_train_model(train).await?;
    handle.send_clone_model(clone).await?;
    handle.send_cancel_run(1).await?;
    handle.send_run_detector_once(-3).await
}

#[cfg(feature = "server")]
pub async fn process_server_stream<H, E>(
    incoming: review_protocol::session::ServerIncoming,
    context: review_protocol::auth::AuthorizationContext,
    policy: std::sync::Arc<dyn review_protocol::auth::AuthorizerV2>,
    requests: std::sync::Arc<H>,
    events: E,
) -> Result<(), Box<dyn std::error::Error>>
where
    H: review_protocol::server::Handler + Sync,
    E: review_protocol::server::DetectionEventStreamHandler + Send,
{
    use review_protocol::session::{ServerRequestOutcome, ServerStream};

    let mut incoming = incoming.with_authorization(context, policy);
    match incoming.accept().await? {
        ServerStream::Requests(stream) => {
            if let ServerRequestOutcome::Unhandled(request) = stream.run(requests).await? {
                let (_code, _body) = (request.code(), request.body());
                request
                    .respond(Err::<(), _>("application rejection".into()))
                    .await?
                    .finish()?;
            }
        }
        ServerStream::DetectionEvents(stream) => stream.run(events).await?,
    }
    Ok(())
}

#[cfg(feature = "server")]
pub fn exhaustive_session_error(error: review_protocol::session::SessionError) {
    use review_protocol::session::SessionError;
    match error {
        SessionError::Transport { .. } | SessionError::Malformed { .. }
        | SessionError::IncompatibleProtocol { .. } | SessionError::RemoteRejection(_)
        | SessionError::LimitExceeded { .. } | SessionError::Deadline { .. } => {}
    }
}

#[cfg(feature = "server")]
pub mod listener;

/// Agent tasks can be supervised independently of outgoing requests.
#[cfg(feature = "client")]
pub async fn serve_agent_commands<H: review_protocol::request::Handler>(
    incoming: &mut review_protocol::session::AgentIncoming,
    handler: &mut H,
    context: &review_protocol::auth::AuthorizationContext,
    policy: &dyn review_protocol::auth::AuthorizerV2,
) -> Result<(), review_protocol::session::SessionError> {
    incoming.accept().await?.run_authorized(handler, context, policy).await
}

/// A caller can receive a package directly, using the same bounded exchange.
#[cfg(feature = "client")]
pub async fn receive_package(
    reply: review_protocol::session::PackageReply<'_>,
) -> Result<Vec<u8>, review_protocol::session::SessionError> {
    use review_protocol::types::node::{InstallPreflight, NodePackageResponse};
    let mut payload = Vec::new();
    if let Some(mut transfer) = reply.preflight(Ok(InstallPreflight::Proceed)).await? {
        let mut chunk = Vec::new();
        while transfer.next_chunk(&mut chunk).await? {
            payload.extend_from_slice(&chunk);
        }
        transfer.respond(Ok(NodePackageResponse::Done)).await?;
    }
    Ok(payload)
}

/// Send an event using the schema expected by the peer.
#[cfg(feature = "client")]
pub async fn send_event(
    handle: &review_protocol::session::AgentHandle,
    event: &review_protocol::types::DetectionEvent,
) -> Result<(), review_protocol::session::SessionError> {
    let mut sender = handle.open_detection_event_stream().await?;
    sender.start(event)?;
    sender.flush().await?;
    sender.finish().await
}
