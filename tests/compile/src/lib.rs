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
    if let Some(ServerRequest::GetConfig { reply, .. }) = stream.next().await? {
        reply.respond(Ok("configuration".into())).await?;
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
