//! The listener, admission, and control surface requires only protocol and TLS types.
use std::{
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use review_protocol::{
    auth::{AuthorizationContext, AuthorizerV2},
    session::{
        PendingSession, ProtocolWindow, ServerHandle, ServerIncoming, ServerListener,
        ServerListenerOptions, ServerSessionClose, ServerSessionControl, ServerStream,
        ServerTransportOptions, SessionError, UnadmittedSession,
    },
};

fn options() -> Result<ServerListenerOptions, SessionError> {
    Ok(ServerListenerOptions {
        protocol: ProtocolWindow::new(">=0.48.0", "0.49.0")?,
        transport: ServerTransportOptions {
            max_concurrent_bidi_streams: 8,
            ..ServerTransportOptions::default()
        },
        session: super::options(),
        handshake_timeout: Duration::from_secs(5),
    })
}

pub fn bind(
    address: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
) -> Result<ServerListener, SessionError> {
    ServerListener::bind(address, tls, options()?)
}

pub fn adopt(
    socket: UdpSocket,
    tls: Arc<rustls::ServerConfig>,
) -> Result<ServerListener, SessionError> {
    ServerListener::from_socket(socket, tls, options()?)
}

pub async fn accept(listener: &ServerListener) -> Result<Option<UnadmittedSession>, SessionError> {
    let _: SocketAddr = listener.local_addr()?;
    let pending: Option<PendingSession> = listener.accept().await?;
    match pending {
        Some(pending) => pending.handshake().await.map(Some),
        None => Ok(None),
    }
}

pub async fn admit(
    owner: UnadmittedSession,
    context: AuthorizationContext,
    policy: Arc<dyn AuthorizerV2>,
) -> Result<(), SessionError> {
    let _: Option<&review_protocol::session::PeerCertificates> = owner.peer_certificates();
    let _: &review_protocol::AgentInfo = owner.agent_claims();
    let control: ServerSessionControl = owner.control().clone();
    let (_handle, mut incoming): (ServerHandle, ServerIncoming) = owner.admit(context, policy);
    control.drain();
    let _: Option<ServerStream> = incoming.accept_next().await?;
    control.close(b"drained");
    let _: ServerSessionClose = control.closed().await;
    Ok(())
}

pub async fn shutdown(
    listener: &ServerListener,
    tls: Arc<rustls::ServerConfig>,
) -> Result<(), SessionError> {
    listener.reload_tls(tls)?;
    listener.shutdown();
    listener.abort(b"shutdown");
    listener.wait_idle().await;
    Ok(())
}
