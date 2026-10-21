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
        let requirement = semver::VersionReq::parse(version_req)
            .map_err(|e| SessionError::Malformed(Box::new(e)))?;
        let highest = semver::Version::parse(highest_protocol_version)
            .map_err(|e| SessionError::Malformed(Box::new(e)))?;
        let operation = async {
            let (send, recv) = connection
                .accept_bi()
                .await
                .map_err(|e| SessionError::transport(e, OutcomeCertainty::NotSent))?;
            let mut exchange = Exchange::new(send, recv, options.handshake);
            let frame = exchange.frame().await?;
            let mut agent = decode_agent(frame.as_bytes(), options.handshake.get())?;
            exchange.recycle(frame)?;
            agent.addr = connection.remote_addr();
            if semver::Version::parse(&agent.protocol_version)
                .is_ok_and(|v| requirement.matches(&v) && v <= highest)
            {
                exchange.start(Ok::<_, &str>(highest_protocol_version))?;
                exchange.flush().await?;
                exchange.finish()?;
                Ok(agent)
            } else {
                let required = format!("{requirement}, <={highest}");
                exchange.start(Err::<&str, _>(&required))?;
                exchange.flush().await?;
                // Retain endpoint resources until the rejection bytes/FIN are
                // acknowledged; this constructor returns no handle on failure.
                exchange.finish_and_wait().await?;
                Err(SessionError::IncompatibleProtocol {
                    version: agent.protocol_version,
                    required,
                })
            }
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
        let shared = Shared::new(connection, options, HandshakeMetadata::Agent(agent));
        Ok((Self(shared.clone()), super::ServerIncoming::new(shared)))
    }
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
        let mut certainty = OutcomeCertainty::NotSent;
        let operation = async {
            let (send, recv) = connection
                .open_bi()
                .await
                .map_err(|e| SessionError::transport(e, certainty))?;
            let mut exchange = Exchange::new(send, recv, options.handshake);
            exchange.start(agent)?;
            certainty = OutcomeCertainty::Unknown;
            exchange.flush().await?;
            let response: Result<String, String> = exchange.receive().await?;
            exchange.complete();
            response.map_err(|required| SessionError::IncompatibleProtocol {
                version: agent.protocol_version.clone(),
                required,
            })
        };
        let protocol_version = if let Some(timeout) = options.operation_timeout {
            match tokio::time::timeout(timeout, operation).await {
                Ok(result) => result?,
                Err(source) => {
                    return Err(SessionError::Deadline {
                        certainty,
                        source: Some(source),
                    });
                }
            }
        } else {
            operation.await?
        };
        let shared = Shared::new(
            connection,
            options,
            HandshakeMetadata::Server { protocol_version },
        );
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
                Err(SessionError::Malformed(_))
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
