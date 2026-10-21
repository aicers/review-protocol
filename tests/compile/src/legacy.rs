//! The retained Quinn-facing surface is compiled separately from session use.
use std::{io, net::SocketAddr};

use review_protocol::{client, frame, request, server, types::node::{NodePowerRequest, NodeVersionRequest, NodeVersionResponse}};

pub async fn client_surface(connection: &client::Connection) -> io::Result<String> {
    let _: quinn::OpenBi<'_> = connection.open_bi();
    let _: quinn::OpenUni<'_> = connection.open_uni();
    let _: quinn::AcceptBi<'_> = connection.accept_bi();
    let _: Option<io::Error> = connection.close_reason();
    connection.get_config().await
}

pub fn builder(address: SocketAddr, certificate: &[u8], key: &[u8]) -> io::Result<client::ConnectionBuilder> {
    client::ConnectionBuilder::new("localhost", address, "agent", "1.0.0", "0.48.0", review_protocol::types::Status::Ready, certificate, key)
}

pub async fn server_surface(connection: quinn::Connection, address: SocketAddr) -> anyhow::Result<()> {
    let raw = connection;
    let connection = server::Connection::from_quinn(raw.clone());
    #[cfg(feature = "test-support")]
    let _: &quinn::Connection = connection.as_quinn();
    let _: quinn::OpenBi<'_> = connection.open_bi();
    let _: quinn::AcceptUni<'_> = connection.accept_uni();
    let _: review_protocol::AgentInfo = server::handshake(&raw, address, ">=0.48.0", "0.49.0").await?;
    let _: server::node::NodePowerOutcome = connection.node_power(NodePowerRequest::GracefulReboot).await?;
    let _: NodeVersionResponse = connection.node().version(NodeVersionRequest::Get).await?;
    Ok(())
}

pub async fn framing(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream) -> io::Result<String> {
    frame::send_msg(send, "message").await?;
    frame::recv_msg(recv).await
}

pub async fn dispatch<H: request::NodeHandler>(handler: &mut H, send: &mut quinn::SendStream, recv: &mut quinn::RecvStream) -> Result<(), request::HandlerError> {
    request::handle_node(handler, send, recv).await
}
