//! Agent migration defaults, PEM setup, receipt, and runner phase regressions.
use std::{process::Command, sync::Arc, time::Duration};

use oinq::{TransportOptions, frame::FramedReader};
use review_protocol::{
    auth::{AuthorizationContext, AuthorizerV2Adapter, NoopAuthorizer, PeerContext},
    session::{
        AgentConnector, AgentRunError, AgentTransportOptions, ApplicationCode, ClientPemError,
        CloseReason, ProtocolWindow, ServerListener, ServerListenerOptions, ServerTransportOptions,
        SessionError, SessionOptions, TransportFailure, client_config_from_pem,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use super::{accept_session, claims, detection_event, raw_manager_with_transport, raw_sessions};

const DEADLINE: Duration = Duration::from_secs(10);
const LOOPBACK: &str = "[::1]:0";

fn pem_material() -> (rcgen::CertifiedKey<rcgen::KeyPair>, String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let chain = cert.cert.pem();
    let key = cert.signing_key.serialize_pem();
    (cert, chain, key)
}

#[test]
fn pem_errors_are_matchable() {
    let (_, chain, key) = pem_material();
    let roots = [chain.as_bytes()];
    for empty in [b"".as_slice(), b"not a certificate", key.as_bytes()] {
        assert!(matches!(
            client_config_from_pem(empty, key.as_bytes(), &roots),
            Err(ClientPemError::NoCertificate)
        ));
    }
    for empty in [b"".as_slice(), chain.as_bytes()] {
        assert!(matches!(
            client_config_from_pem(chain.as_bytes(), empty, &roots),
            Err(ClientPemError::NoPrivateKey)
        ));
    }
    for roots in [vec![], vec![b"text".as_slice(), key.as_bytes()]] {
        assert!(matches!(
            client_config_from_pem(chain.as_bytes(), key.as_bytes(), &roots),
            Err(ClientPemError::NoRootCertificate)
        ));
    }
    let (_, _, other_key) = pem_material();
    assert!(matches!(
        client_config_from_pem(chain.as_bytes(), other_key.as_bytes(), &roots),
        Err(ClientPemError::Rustls(_))
    ));
    let bad_root = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    assert!(matches!(
        client_config_from_pem(chain.as_bytes(), key.as_bytes(), &[bad_root]),
        Err(ClientPemError::Rustls(_))
    ));
    let malformed = b"-----BEGIN CERTIFICATE-----\n???\n-----END CERTIFICATE-----\n";
    assert!(matches!(
        client_config_from_pem(malformed, key.as_bytes(), &roots),
        Err(ClientPemError::Pem(_))
    ));
}

async fn pem_connect_and_keepalive() {
    let (cert, chain, key) = pem_material();
    let (_, extra_root, _) = pem_material();
    let bundle = format!("{extra_root}{chain}");
    let tls = client_config_from_pem(
        chain.as_bytes(),
        key.as_bytes(),
        &[b"", bundle.as_bytes(), chain.as_bytes()],
    )
    .unwrap();
    let aws = rustls::crypto::aws_lc_rs::default_provider();
    assert!(std::ptr::eq(
        tls.crypto_provider().key_provider,
        aws.key_provider
    ));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let provider = Arc::new(aws);
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .unwrap();
    let server_tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let idle = Some(Duration::from_millis(300));
    let keepalive = Some(Duration::from_millis(40));
    let listener = ServerListener::bind(
        LOOPBACK.parse().unwrap(),
        Arc::new(server_tls),
        ServerListenerOptions {
            transport: ServerTransportOptions {
                idle_timeout: idle,
                keep_alive_interval: keepalive,
                ..ServerTransportOptions::default()
            },
            session: SessionOptions::legacy_compatible(),
            protocol: ProtocolWindow::new(">=0.48.0", "0.49.0").unwrap(),
            handshake_timeout: DEADLINE,
        },
    )
    .unwrap();
    let connector = AgentConnector::bind(
        LOOPBACK.parse().unwrap(),
        tls,
        AgentTransportOptions {
            idle_timeout: idle,
            keep_alive_interval: keepalive,
            ..AgentTransportOptions::default()
        },
        SessionOptions::legacy_compatible(),
    )
    .unwrap();
    let info = claims();
    let (agent, server) = timeout(DEADLINE, async {
        tokio::join!(
            connector.connect(listener.local_addr().unwrap(), "localhost", &info),
            accept_session(&listener)
        )
    })
    .await
    .unwrap();
    let (agent, _incoming) = agent.unwrap();
    let (server, mut incoming) = server.unwrap();
    // Exercise transport timers for four idle periods without application traffic.
    let observation = Duration::from_millis(1200);
    let (agent_closed, server_closed) = tokio::join!(
        timeout(observation, agent.closed()),
        timeout(observation, server.closed())
    );
    assert!(agent_closed.is_err());
    assert!(server_closed.is_err());
    assert_eq!(agent.close_reason(), None);
    assert_eq!(server.close_reason(), None);
    let (response, ()) = timeout(DEADLINE, async {
        tokio::join!(agent.get_config(), async {
            let mut stream = super::request_stream(&mut incoming).await;
            let Some(super::ServerRequest::GetConfig { reply, .. }) = stream.next().await.unwrap()
            else {
                panic!("expected config");
            };
            reply.respond(Ok("still connected".into())).await.unwrap();
            stream.finish().unwrap();
        })
    })
    .await
    .unwrap();
    assert_eq!(response.unwrap(), "still connected");
    agent.close(ApplicationCode::new(0).unwrap(), b"done");
    connector.wait_idle().await;
}

#[tokio::test]
async fn pem_connects_with_explicit_aws_provider_and_keepalive() {
    pem_connect_and_keepalive().await;
}

#[test]
fn pem_ignores_installed_ring_provider() {
    const CHILD: &str = "REVIEW_PROTOCOL_PEM_PROVIDER_CHILD";
    const NAME: &str = "agent_helpers::pem_ignores_installed_ring_provider";
    if std::env::var_os(CHILD).is_some() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(pem_connect_and_keepalive());
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("running 1 test"), "{stdout}");
    assert!(stdout.contains("1 passed"), "{stdout}");
}

#[test]
fn server_defaults_are_unchanged() {
    let options = ServerTransportOptions::default();
    assert_eq!(options.keep_alive_interval, None);
    assert_eq!(options.idle_timeout, Some(Duration::from_secs(30)));
    assert_eq!(options.max_concurrent_bidi_streams, 100);
    assert_eq!(options.max_concurrent_uni_streams, 100);
    assert_eq!(options.stream_receive_window, 1_250_000);
    assert_eq!(options.receive_window, 10_000_000);
    assert_eq!(options.send_window, 10_000_000);
}

#[tokio::test]
async fn event_receipt_confirms_whole_stream() {
    let (_, mut incoming, agent, _) = super::sessions(SessionOptions::legacy_compatible()).await;
    let mut sender = agent.open_detection_event_stream().await.unwrap();
    sender.start(&detection_event(0.75)).unwrap();
    let (receipt, ()) = timeout(DEADLINE, async {
        tokio::join!(sender.finish_and_wait(), async {
            let mut receiver = super::event_stream(&mut incoming).await;
            assert_eq!(receiver.next().await.unwrap().unwrap().score, 0.75);
            assert!(receiver.next().await.unwrap().is_none());
        })
    })
    .await
    .unwrap();
    receipt.unwrap();
}

async fn stopped_receipt(during_flush: bool, close_connection: bool) {
    let mut options = SessionOptions::legacy_compatible();
    options.detection_events = super::SessionFrameLimit::new(32 * 1024 * 1024).unwrap();
    let (manager, (agent, _incoming)) = raw_manager_with_transport(
        options,
        "0.49.0",
        &claims(),
        TransportOptions {
            stream_receive_window: 64,
            ..TransportOptions::default()
        },
    )
    .await;
    let mut sender = agent.open_detection_event_stream().await.unwrap();
    let mut recv = timeout(DEADLINE, manager.accept_uni())
        .await
        .unwrap()
        .unwrap();
    // A frame larger than the peer's credit blocks flushing. A smaller frame
    // fits, so the future below reaches the receipt wait on its first poll.
    let payload = vec![7_u8; if during_flush { 4096 } else { 32 }];
    sender.start_serialized(&payload).unwrap();
    if during_flush {
        let mut flush = tokio_test::task::spawn(sender.flush());
        assert!(flush.poll().is_pending());
    } else {
        timeout(DEADLINE, sender.flush()).await.unwrap().unwrap();
    }
    let mut receipt = tokio_test::task::spawn(sender.finish_and_wait());
    assert!(receipt.poll().is_pending());
    // No await between queuing FIN and stopping/closing: on this current-thread
    // runtime the peer cannot acknowledge FIN before the stop is queued.
    let code = 79;
    if close_connection {
        manager.close(
            oinq::ApplicationCode::new(code).unwrap(),
            b"lost during receipt",
        );
    } else {
        recv.stop(oinq::ApplicationCode::new(code).unwrap())
            .unwrap();
    }
    let error = timeout(DEADLINE, receipt).await.unwrap().unwrap_err();
    if close_connection {
        assert!(
            matches!(error, SessionError::Transport { source: TransportFailure::Closed { reason: CloseReason::Application { code: actual, .. }, .. }, .. } if actual.get() == code),
            "{error:?}"
        );
    } else {
        assert!(
            matches!(error, SessionError::StreamStopped { code: actual } if actual.get() == code),
            "{error:?}"
        );
        assert_eq!(agent.close_reason(), None);
    }
}

#[tokio::test]
async fn event_stop_during_flush_preserves_code() {
    stopped_receipt(true, false).await;
}

#[tokio::test]
async fn event_stop_while_waiting_preserves_code() {
    stopped_receipt(false, false).await;
}

#[tokio::test]
async fn event_connection_loss_while_waiting_is_classified() {
    stopped_receipt(false, true).await;
}

#[tokio::test]
async fn event_stop_after_flush_before_fin_preserves_code() {
    let (manager, (agent, _incoming)) =
        super::raw_manager(SessionOptions::legacy_compatible(), "0.49.0", &claims()).await;
    let mut sender = agent.open_detection_event_stream().await.unwrap();
    sender.start(&detection_event(0.75)).unwrap();
    sender.flush().await.unwrap();
    let mut recv = timeout(DEADLINE, manager.accept_uni())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        timeout(DEADLINE, recv.read_u16()).await.unwrap().unwrap(),
        0
    );
    let mut reader = FramedReader::new(recv, super::FrameLimit::new(4096).unwrap());
    assert!(
        timeout(DEADLINE, reader.read())
            .await
            .unwrap()
            .unwrap()
            .is_some()
    );
    let code = ApplicationCode::MAX;
    reader
        .into_inner()
        .stop(oinq::ApplicationCode::new(code).unwrap())
        .unwrap();
    // Wait for a round trip so STOP is processed before finish_and_wait queues FIN.
    let mut barrier = manager.open_uni().await.unwrap();
    barrier.write_all(&[0]).await.unwrap();
    barrier.finish().unwrap();
    timeout(DEADLINE, barrier.stopped()).await.unwrap().unwrap();
    let error = timeout(DEADLINE, sender.finish_and_wait())
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error, SessionError::StreamStopped { code: actual } if actual.get() == code),
        "{error:?}"
    );
    assert_eq!(agent.close_reason(), None);
}

#[tokio::test]
async fn cancelling_event_receipt_resets_stream_during_flush_and_wait() {
    for payload_size in [4096, 32] {
        let (manager, (agent, _incoming)) = raw_manager_with_transport(
            SessionOptions::legacy_compatible(),
            "0.49.0",
            &claims(),
            TransportOptions {
                stream_receive_window: 64,
                ..TransportOptions::default()
            },
        )
        .await;
        let mut sender = agent.open_detection_event_stream().await.unwrap();
        let mut recv = timeout(DEADLINE, manager.accept_uni())
            .await
            .unwrap()
            .unwrap();
        sender.start_serialized(&vec![7_u8; payload_size]).unwrap();
        let mut receipt = tokio_test::task::spawn(sender.finish_and_wait());
        assert!(receipt.poll().is_pending());
        // The larger frame blocks flushing; the smaller one reaches the FIN wait.
        // Cancel before yielding, so neither can finish through peer acknowledgment.
        drop(receipt);
        let error = timeout(DEADLINE, recv.read_to_end(&mut Vec::new()))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        assert_eq!(agent.close_reason(), None);
    }
}

struct Handler;
#[async_trait::async_trait]
impl review_protocol::request::Handler for Handler {
    async fn node_hostname(
        &mut self,
        _: review_protocol::types::node::NodeHostnameRequest,
    ) -> Result<review_protocol::types::node::NodeHostnameResponse, String> {
        Ok(review_protocol::types::node::NodeHostnameResponse::Get {
            hostname: "agent".into(),
        })
    }
}

#[tokio::test]
async fn all_agent_runners_report_response_write_and_later_read_failures() {
    for runner in 0..3 {
        for (writing, unserved) in [(true, false), (false, false), (true, true), (false, true)] {
            let (_, mut incoming, manager, _) =
                raw_sessions(SessionOptions::legacy_compatible()).await;
            let (mut send, mut recv) = manager.open_bi().await.unwrap();
            // Queue the stop before the command and await a transport round trip
            // below before dispatching the runner.
            if writing {
                recv.stop(oinq::ApplicationCode::new(83).unwrap()).unwrap();
            }
            let code = if unserved { u32::MAX } else { 102_u32 };
            let body = if code == 102 {
                bincode::serde::encode_to_vec(
                    (
                        code.to_le_bytes(),
                        review_protocol::types::node::NodeHostnameRequest::Get,
                    ),
                    bincode::config::standard(),
                )
                .unwrap()
            } else {
                bincode::serde::encode_to_vec((code.to_le_bytes(), ()), bincode::config::standard())
                    .unwrap()
            };
            send.write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
                .await
                .unwrap();
            send.write_all(&body).await.unwrap();
            // Use a separate stream as a transport barrier: its FIN acknowledgment
            // establishes peer processing of the stop before runner dispatch.
            let mut barrier = manager.open_uni().await.unwrap();
            barrier.write_all(&[0]).await.unwrap();
            barrier.finish().unwrap();
            timeout(DEADLINE, barrier.stopped()).await.unwrap().unwrap();
            let stream = timeout(DEADLINE, incoming.accept()).await.unwrap().unwrap();
            let context = AuthorizationContext::from_peer_context(&PeerContext::new("manager"));
            let policy = AuthorizerV2Adapter::new(NoopAuthorizer);
            let (result, ()) = timeout(DEADLINE, async {
                tokio::join!(
                    async {
                        let mut handler = Handler;
                        match runner {
                            0 => stream.run(&mut handler, |_| Ok(())).await,
                            1 => stream.run_authorized(&mut handler, &context, &policy).await,
                            _ => {
                                stream
                                    .run_node_authorized(&mut handler, &context, &policy)
                                    .await
                            }
                        }
                    },
                    async {
                        if !writing {
                            let mut reader =
                                FramedReader::new(recv, super::FrameLimit::new(4096).unwrap());
                            let frame = reader.read().await.unwrap().unwrap();
                            if unserved {
                                assert!(
                                    frame
                                        .decode::<Result<(), String>>()
                                        .unwrap()
                                        .unwrap_err()
                                        .starts_with("unknown request code")
                                );
                            } else {
                                assert!(
                                    frame
                                        .decode::<Result<
                                            review_protocol::types::node::NodeHostnameResponse,
                                            String,
                                        >>()
                                        .unwrap()
                                        .is_ok()
                                );
                            }
                            // The response was completely received; break the next read.
                            send.reset(oinq::ApplicationCode::new(84).unwrap()).unwrap();
                        }
                    }
                )
            })
            .await
            .unwrap();
            if writing {
                assert!(
                    matches!(result, Err(AgentRunError::ResponseWrite(_))),
                    "{result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(AgentRunError::Session(_))),
                    "{result:?}"
                );
            }
        }
    }
}
