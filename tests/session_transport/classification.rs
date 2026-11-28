//! Real connection and stream failures through the public session entry points.
use std::{net::UdpSocket, time::Duration};

use review_protocol::session::{
    ApplicationCode, CloseReason, FrameError, FrameLimit, OutcomeCertainty, ServerSessionClose,
    ServerSessionControl, SessionError, TransportCloseKind, TransportFailure,
};
use tokio::time::timeout;

use super::{
    AgentConnector, AgentHandle, AgentTransportOptions, ServerHandle, ServerListener,
    ServerListenerOptions, ServerTransportOptions, SessionOptions, accept_session, claims,
    tls_with_client,
};

const DEADLINE: Duration = Duration::from_secs(10);
const REASON: &[u8] = b"chosen reason\x00\xff";

async fn established(idle: Option<Duration>) -> (AgentHandle, ServerHandle, ServerSessionControl) {
    let (server_tls, client_tls) = super::tls();
    let listener = ServerListener::bind(
        "[::1]:0".parse().unwrap(),
        server_tls,
        ServerListenerOptions {
            transport: ServerTransportOptions {
                idle_timeout: idle,
                keep_alive_interval: None,
                ..ServerTransportOptions::default()
            },
            session: SessionOptions::legacy_compatible(),
            protocol: super::ProtocolWindow::new(">=0.48.0", "0.49.0").unwrap(),
            handshake_timeout: DEADLINE,
        },
    )
    .unwrap();
    let connector = AgentConnector::bind(
        "[::1]:0".parse().unwrap(),
        client_tls,
        AgentTransportOptions {
            idle_timeout: idle,
            keep_alive_interval: None,
            ..AgentTransportOptions::default()
        },
        SessionOptions::legacy_compatible(),
    )
    .unwrap();
    let info = claims();
    let (server, agent) = tokio::join!(
        accept_session(&listener),
        connector.connect(listener.local_addr().unwrap(), "localhost", &info)
    );
    let (server, incoming) = server.unwrap();
    (agent.unwrap().0, server, incoming.control())
}

fn closed_error(error: SessionError, expected: &CloseReason, certainty: OutcomeCertainty) {
    assert_eq!(error.certainty(), Some(certainty));
    assert!(
        std::error::Error::source(&error)
            .and_then(std::error::Error::source)
            .is_some()
    );
    assert!(
        matches!(error, SessionError::Transport { source: TransportFailure::Closed { reason, .. }, .. } if &reason == expected)
    );
}

async fn check_close_query(agent_closes: bool) {
    let (agent, server, _control) = established(None).await;
    assert_eq!(agent.close_reason(), None);
    assert_eq!(server.close_reason(), None);
    let code = ApplicationCode::new(987).unwrap();
    let peer = CloseReason::Application {
        code,
        reason: REASON.to_vec(),
    };
    let (expected_agent, expected_server) = if agent_closes {
        agent.close(code, REASON);
        assert_eq!(agent.close_reason(), Some(CloseReason::Local));
        (CloseReason::Local, peer)
    } else {
        server.close(code, REASON);
        assert_eq!(server.close_reason(), Some(CloseReason::Local));
        (peer, CloseReason::Local)
    };
    let (agent_reason, server_reason) = timeout(DEADLINE, async {
        tokio::join!(agent.closed(), server.closed())
    })
    .await
    .unwrap();
    assert_eq!(agent_reason, expected_agent);
    assert_eq!(server_reason, expected_server);
    assert_eq!(agent.close_reason(), Some(expected_agent.clone()));
    assert_eq!(server.close_reason(), Some(expected_server.clone()));
    closed_error(
        agent.get_config().await.unwrap_err(),
        &expected_agent,
        OutcomeCertainty::NotSent,
    );
    closed_error(
        server.send_config_update_cmd().await.unwrap_err(),
        &expected_server,
        OutcomeCertainty::NotSent,
    );
}

#[tokio::test]
async fn peer_application_close_classifies_agent_and_local_server() {
    check_close_query(false).await;
}

#[tokio::test]
async fn local_agent_close_classifies_peer_server() {
    check_close_query(true).await;
}

#[tokio::test]
async fn abnormal_peer_close_is_classified_by_accept_next() {
    let (server, mut incoming, agent, _) =
        super::sessions(SessionOptions::legacy_compatible()).await;
    let code = ApplicationCode::new(987).unwrap();
    let expected = CloseReason::Application {
        code,
        reason: REASON.to_vec(),
    };
    agent.close(code, REASON);
    assert_eq!(timeout(DEADLINE, server.closed()).await.unwrap(), expected);
    let error = timeout(DEADLINE, incoming.accept_next())
        .await
        .unwrap()
        .err()
        .expect("a nonzero peer close is abnormal exhaustion");
    closed_error(error, &expected, OutcomeCertainty::NotSent);
}

#[tokio::test]
async fn connection_close_overrides_in_flight_stream_failure() {
    for local in [false, true] {
        let (server, mut incoming, agent, _) =
            super::sessions(SessionOptions::legacy_compatible()).await;
        let code = ApplicationCode::new(987).unwrap();
        let (result, ()) = timeout(DEADLINE, async {
            tokio::join!(agent.get_config(), async {
                let mut stream = super::request_stream(&mut incoming).await;
                let _request = stream.next().await.unwrap().unwrap();
                if local {
                    agent.close(code, REASON);
                } else {
                    server.close(code, REASON);
                }
            })
        })
        .await
        .unwrap();
        let expected = if local {
            CloseReason::Local
        } else {
            CloseReason::Application {
                code,
                reason: REASON.to_vec(),
            }
        };
        closed_error(result.unwrap_err(), &expected, OutcomeCertainty::Unknown);
    }
}

#[tokio::test]
async fn idle_timeout_classifies_and_queries_both_roles() {
    let (agent, server, control) = established(Some(Duration::from_millis(150))).await;
    assert_eq!(agent.close_reason(), None);
    assert_eq!(server.close_reason(), None);
    let expected = CloseReason::Transport(TransportCloseKind::IdleTimeout);
    let (agent_reason, server_reason) = timeout(DEADLINE, async {
        tokio::join!(agent.closed(), server.closed())
    })
    .await
    .unwrap();
    assert_eq!(agent_reason, expected);
    assert_eq!(server_reason, expected);
    assert_eq!(agent.close_reason(), Some(expected.clone()));
    assert_eq!(server.close_reason(), Some(expected.clone()));
    closed_error(
        agent.get_config().await.unwrap_err(),
        &expected,
        OutcomeCertainty::NotSent,
    );
    closed_error(
        server.send_config_update_cmd().await.unwrap_err(),
        &expected,
        OutcomeCertainty::NotSent,
    );
    let ServerSessionClose::Transport(error) = timeout(DEADLINE, control.closed()).await.unwrap()
    else {
        panic!("idle timeout must be a transport close");
    };
    closed_error(error, &expected, OutcomeCertainty::NotSent);
}

#[tokio::test]
async fn untrusted_agent_certificate_is_crypto_connect_failure() {
    let (server_tls, client_tls) = tls_with_client(false);
    let listener = super::listener(
        server_tls,
        SessionOptions::legacy_compatible(),
        ">=0.48.0",
        "0.49.0",
    );
    let connector = AgentConnector::bind(
        "127.0.0.1:0".parse().unwrap(),
        client_tls,
        AgentTransportOptions::default(),
        SessionOptions::legacy_compatible(),
    )
    .unwrap();
    let info = claims();
    let (server, agent) = timeout(DEADLINE, async {
        tokio::join!(
            accept_session(&listener),
            connector.connect(listener.local_addr().unwrap(), "localhost", &info)
        )
    })
    .await
    .unwrap();
    assert!(server.is_err());
    let error = agent
        .err()
        .expect("an untrusted agent cannot establish a session");
    assert!(
        matches!(
            error,
            SessionError::Transport {
                source: TransportFailure::Closed {
                    reason: CloseReason::Transport(TransportCloseKind::Crypto { alert: Some(_) }),
                    ..
                },
                ..
            }
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn stream_reset_on_open_connection_is_stream_failed() {
    let (agent, manager) = super::agent_with_raw_manager(SessionOptions::legacy_compatible()).await;
    let (result, ()) = timeout(DEADLINE, async {
        tokio::join!(agent.get_config(), async {
            let (mut send, recv) = manager.accept_bi().await.unwrap();
            let mut reader =
                oinq::frame::FramedReader::new(recv, oinq::frame::FrameLimit::new(4096).unwrap());
            reader.read().await.unwrap().unwrap();
            send.reset(oinq::ApplicationCode::new(31).unwrap()).unwrap();
        })
    })
    .await
    .unwrap();
    let error = result.unwrap_err();
    assert!(
        matches!(
            error,
            SessionError::Transport {
                certainty: OutcomeCertainty::Unknown,
                source: TransportFailure::StreamFailed(_),
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(agent.close_reason(), None);
    assert!(
        tokio_test::task::spawn(manager.closed())
            .poll()
            .is_pending()
    );
}

#[tokio::test]
async fn socket_bind_failure_is_other() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (_, client_tls) = super::tls();
    let error = AgentConnector::bind(
        socket.local_addr().unwrap(),
        client_tls,
        AgentTransportOptions::default(),
        SessionOptions::legacy_compatible(),
    )
    .err()
    .expect("the socket is already bound");
    assert!(matches!(
        error,
        SessionError::Transport {
            certainty: OutcomeCertainty::NotSent,
            source: TransportFailure::Other(_),
            ..
        }
    ));
}

#[test]
fn owned_code_and_frame_limits_check_boundaries() {
    assert_eq!(
        ApplicationCode::new(ApplicationCode::MAX).unwrap().get(),
        ApplicationCode::MAX
    );
    assert!(ApplicationCode::new(ApplicationCode::MAX + 1).is_err());
    assert_eq!(FrameLimit::new(0).unwrap().get(), 0);
    assert_eq!(
        FrameLimit::new(u32::MAX as usize).unwrap().get(),
        u32::MAX as usize
    );
    assert!(matches!(
        FrameLimit::new(usize::MAX),
        Err(FrameError::InvalidLimit)
    ));
}
