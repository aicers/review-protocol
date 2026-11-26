//! Handshake wire definitions remain in review-protocol.
use oinq::Connection;
#[cfg(feature = "server")]
use serde::de::DeserializeOwned;

#[cfg(feature = "server")]
use super::decode::decode;
use super::{
    HandshakeMetadata, OutcomeCertainty, SessionError, SessionOptions, Shared, exchange::Exchange,
};

#[cfg(feature = "server")]
impl super::ServerHandle {
    /// Accepts an application handshake with a caller-selected version window and limits.
    ///
    /// Dropping this future aborts an accepted exchange. The returned incoming
    /// owner is unique; handle clones do not create additional acceptors.
    /// # Errors
    /// Returns classified transport, framing, limit, version, or deadline errors.
    pub async fn from_transport(
        connection: Connection,
        options: SessionOptions,
        version_req: &str,
        highest_protocol_version: &str,
    ) -> Result<(Self, super::ServerIncoming), SessionError> {
        let window = super::ProtocolWindow::new(version_req, highest_protocol_version)?;
        let operation = async {
            let (agent, mut exchange) = server_handshake(&connection, &options, &window).await?;
            exchange.finish()?;
            Ok::<_, SessionError>(agent)
        };
        let agent = if let Some(timeout) = options.operation_timeout {
            tokio::time::timeout(timeout, operation)
                .await
                .map_err(|source| SessionError::Deadline {
                    certainty: OutcomeCertainty::Unknown,
                    source: Some(source),
                })??
        } else {
            operation.await?
        };
        let shared = server_shared(connection, options, agent, None);
        Ok((Self(shared.clone()), super::ServerIncoming::new(shared)))
    }
}

#[cfg(feature = "server")]
pub(super) async fn server_handshake(
    connection: &Connection,
    options: &SessionOptions,
    window: &super::ProtocolWindow,
) -> Result<(crate::AgentInfo, Exchange), SessionError> {
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(|e| SessionError::transport(e, OutcomeCertainty::NotSent))?;
    let mut exchange = Exchange::new(send, recv, options.handshake);
    let frame = exchange.frame().await?;
    let mut agent = decode_agent(frame.as_bytes(), options.handshake.get())?;
    exchange.recycle(frame)?;
    agent.addr = connection.remote_addr();
    if window.accepts(&agent.protocol_version) {
        exchange.start(Ok::<_, &str>(window.advertised_version()))?;
        exchange.flush().await?;
        Ok((agent, exchange))
    } else {
        let required = window.accepted_range();
        exchange.start(Err::<&str, _>(&required))?;
        exchange.flush().await?;
        // Retain endpoint resources until the rejection bytes/FIN are
        // acknowledged; this constructor returns no handle on failure.
        // A rejected agent may close the connection as soon as it reads
        // the rejection, so a failure here must not replace the version
        // error, as the legacy handshake ignores it too.
        let _ = exchange.finish_and_wait().await;
        Err(SessionError::IncompatibleProtocol {
            version: agent.protocol_version,
            required,
        })
    }
}

#[cfg(feature = "server")]
pub(super) fn server_shared(
    connection: Connection,
    options: SessionOptions,
    agent: crate::AgentInfo,
    listener: Option<super::listener::ListenerClose>,
) -> std::sync::Arc<Shared> {
    let network_list_blocker =
        crate::network_list_blocker([agent.protocol_version.as_str()]).map(str::to_owned);
    let mut shared = Shared::new(
        connection,
        options,
        HandshakeMetadata::Agent(agent),
        network_list_blocker,
    );
    shared.listener = listener;
    std::sync::Arc::new(shared)
}

#[cfg(feature = "client")]
impl super::AgentHandle {
    /// Sends the complete caller-supplied agent claims using explicitly selected limits.
    ///
    /// The supplied protocol version is preserved. TLS policy belongs to the
    /// endpoint configuration, and peer claims never authorize operations.
    /// # Errors
    /// Returns classified transport, framing, limit, version, or deadline errors.
    pub async fn from_transport(
        connection: Connection,
        options: SessionOptions,
        agent: &crate::AgentInfo,
    ) -> Result<(Self, super::AgentIncoming), SessionError> {
        let timeout = options.operation_timeout;
        let mut certainty = OutcomeCertainty::NotSent;
        let operation = Self::from_transport_inner(connection, options, agent, &mut certainty);
        if let Some(timeout) = timeout {
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

    pub(super) async fn from_transport_inner(
        connection: Connection,
        options: SessionOptions,
        agent: &crate::AgentInfo,
        certainty: &mut OutcomeCertainty,
    ) -> Result<(Self, super::AgentIncoming), SessionError> {
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| SessionError::transport(e, *certainty))?;
        let mut exchange = Exchange::new(send, recv, options.handshake);
        exchange.start(agent)?;
        *certainty = OutcomeCertainty::Unknown;
        exchange.flush().await?;
        let response: Result<String, String> = exchange.receive().await?;
        exchange.complete();
        let protocol_version = response.map_err(|required| SessionError::IncompatibleProtocol {
            version: agent.protocol_version.clone(),
            required,
        })?;
        // The agent's own advertised version counts as well as the manager's
        // reply, which is only the manager's ceiling: a `0.50.0` manager
        // refuses the list pulls of an agent that advertised `0.49.0`.
        let network_list_blocker = crate::network_list_blocker([
            agent.protocol_version.as_str(),
            protocol_version.as_str(),
        ])
        .map(str::to_owned);
        let shared = std::sync::Arc::new(Shared::new(
            connection,
            options,
            HandshakeMetadata::Server { protocol_version },
            network_list_blocker,
        ));
        Ok((Self(shared.clone()), super::AgentIncoming::new(shared)))
    }
}

#[cfg(feature = "server")]
fn decode_agent(bytes: &[u8], limit: usize) -> Result<crate::AgentInfo, SessionError> {
    let budget = super::decode::Budget::new(limit);
    let (base, mut offset): (crate::AgentInfoBase, _) = decode(bytes, &budget)?;
    let capabilities = tail(bytes, &mut offset, &budget)?.unwrap_or_default();
    let active_trust_epoch = tail(bytes, &mut offset, &budget)?.flatten();
    let manifest_formats = tail(bytes, &mut offset, &budget)?.flatten();
    let provisioning_fingerprint = tail(bytes, &mut offset, &budget)?.flatten();
    let audit_health = tail(bytes, &mut offset, &budget)?.flatten();
    Ok(crate::AgentInfo {
        agent_name: base.agent_name,
        agent_version: base.agent_version,
        protocol_version: base.protocol_version,
        addr: base.addr,
        status: base.status,
        capabilities,
        active_trust_epoch,
        manifest_formats,
        provisioning_fingerprint,
        audit_health,
    })
}

#[cfg(feature = "server")]
fn tail<T: DeserializeOwned>(
    bytes: &[u8],
    offset: &mut usize,
    budget: &super::decode::Budget,
) -> Result<Option<T>, SessionError> {
    let Some(rest) = bytes.get(*offset..).filter(|rest| !rest.is_empty()) else {
        return Ok(None);
    };
    let (value, consumed) = decode(rest, budget)?;
    *offset += consumed;
    Ok(Some(value))
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    #[test]
    fn independent_handshake_snapshots() {
        for (base, full) in [
            (
                include_bytes!("../../tests/fixtures/0.21.0/handshake-base.bin").as_slice(),
                include_bytes!("../../tests/fixtures/0.21.0/handshake-tail.bin").as_slice(),
            ),
            (
                include_bytes!("../../tests/fixtures/current/handshake-base.bin").as_slice(),
                include_bytes!("../../tests/fixtures/current/handshake-tail.bin").as_slice(),
            ),
        ] {
            let legacy = crate::decode_agent_info(full).unwrap();
            let current = decode_agent(full, 4096).unwrap();
            assert_eq!(legacy, current);
            assert_eq!(
                bincode::serde::encode_to_vec(&current, bincode::config::standard()).unwrap(),
                full
            );
            assert_eq!(current.protocol_version, "0.49.0");
            assert_eq!(current.capabilities.len(), 2);
            let old = decode_agent(base, 4096).unwrap();
            assert!(old.capabilities.is_empty());
            assert_eq!(old, crate::decode_agent_info(base).unwrap());
            let mut bad = base.to_vec();
            bad.extend_from_slice(&[2, 1, b'a']);
            assert!(matches!(
                decode_agent(&bad, 4096),
                Err(SessionError::Malformed { .. })
            ));
            // Omitting a whole final None field is a valid tail boundary.
            assert!(decode_agent(&full[..full.len() - 1], 4096).is_ok());
            let mut malformed = full.to_vec();
            *malformed.last_mut().unwrap() = 1; // Present audit health, missing value.
            assert!(decode_agent(&malformed, 4096).is_err());
        }
    }

    #[test]
    fn independent_domain_response_snapshots() {
        use crate::types::node::{InstallPreflight, NodePowerResponse};
        let config = bincode::config::standard();
        for (power, preflight, remote) in [
            (
                include_bytes!("../../tests/fixtures/0.21.0/power-response.bin").as_slice(),
                include_bytes!("../../tests/fixtures/0.21.0/install-preflight.bin").as_slice(),
                include_bytes!("../../tests/fixtures/0.21.0/remote-rejection.bin").as_slice(),
            ),
            (
                include_bytes!("../../tests/fixtures/current/power-response.bin").as_slice(),
                include_bytes!("../../tests/fixtures/current/install-preflight.bin").as_slice(),
                include_bytes!("../../tests/fixtures/current/remote-rejection.bin").as_slice(),
            ),
        ] {
            assert_eq!(
                bincode::serde::encode_to_vec(
                    Ok::<_, String>(NodePowerResponse::Initiated),
                    config
                )
                .unwrap(),
                power
            );
            assert_eq!(
                bincode::serde::encode_to_vec(
                    Ok::<_, String>(InstallPreflight::UnknownConfigTemplate {
                        id: "custom".into()
                    }),
                    config
                )
                .unwrap(),
                preflight
            );
            assert_eq!(
                bincode::serde::encode_to_vec(Err::<(), _>("not supported"), config).unwrap(),
                remote
            );
        }
    }
}
