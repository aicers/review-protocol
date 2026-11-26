//! External session API fixtures deliberately import no Quinn types.
#![cfg(all(feature = "client", feature = "server"))]
// Test assertions and local transport setup deliberately panic on failure.
#![allow(clippy::unwrap_used)]

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use review_protocol::{
    AgentInfo, PROTOCOL_VERSION,
    session::{
        AgentCommand, AgentHandle, AgentIncoming, AgentRequest, AgentRunError, ApplicationCode,
        CloseReason, Connection, DetectionEventReceiver, Endpoint, FrameLimit, OutcomeCertainty,
        ServerHandle, ServerIncoming, ServerRequest, ServerRequestStream, ServerStream,
        SessionError, SessionOptions, TransportOptions,
    },
    types::{
        ManifestFormatRange, Status,
        node::{InstallPreflight, NodePackageRequest, NodePowerRequest, NodePowerResponse},
    },
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Returns a minimal synthetic detection event, told apart by `score`.
fn detection_event(score: f64) -> review_protocol::types::DetectionEvent {
    use review_protocol::types::{
        Detail, DetectionEvent, DetectionModel, PortScanDetail, PrimarySubject, RawEventKind,
        Target, TimeWindow,
    };
    DetectionEvent {
        time: jiff::Timestamp::UNIX_EPOCH,
        sensor: None,
        detection_model: DetectionModel::PortScan,
        raw_event_kind: RawEventKind::Conn,
        category: None,
        target: Target::Subject {
            primary: PrimarySubject::Cluster {
                clustering_model: 0,
                cluster_id: 1,
            },
            related_ips: Vec::new(),
            window: TimeWindow {
                start: jiff::Timestamp::UNIX_EPOCH,
                end: jiff::Timestamp::UNIX_EPOCH,
            },
        },
        score,
        detail: Detail::PortScan(PortScanDetail {
            resp_ports: vec![22],
            proto: 6,
        }),
    }
}

fn claims() -> AgentInfo {
    AgentInfo {
        agent_name: "agent".into(),
        agent_version: "1.2.3".into(),
        protocol_version: "0.49.0".into(),
        addr: "127.0.0.1:8080".parse().unwrap(),
        status: Status::Ready,
        capabilities: BTreeSet::from(["node.package".into(), "registrar".into()]),
        active_trust_epoch: Some(42),
        manifest_formats: Some(ManifestFormatRange { min: 1, max: 2 }),
        provisioning_fingerprint: None,
        audit_health: None,
    }
}

async fn connections() -> (Connection, Connection) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert);
    let key = cert.signing_key.serialize_der();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots.clone()),
        provider.clone(),
    )
    .build()
    .unwrap();
    let server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![der.clone()],
            PrivatePkcs8KeyDer::from(key.clone()).into(),
        )
        .unwrap();
    let client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![der], PrivatePkcs8KeyDer::from(key).into())
        .unwrap();
    let options = TransportOptions {
        max_concurrent_bidi_streams: 7,
        ..TransportOptions::default()
    };
    let server = Endpoint::server(
        Arc::new(server_tls),
        "127.0.0.1:0".parse().unwrap(),
        options.clone(),
    )
    .unwrap();
    let client = Endpoint::client(
        Arc::new(client_tls),
        "127.0.0.1:0".parse().unwrap(),
        options,
    )
    .unwrap();
    let (accepted, connected) = tokio::join!(
        async { server.accept().await.unwrap().await.unwrap() },
        client.connect(server.local_addr().unwrap(), "localhost")
    );
    // Connections retain their endpoint resources after these endpoint handles drop.
    (accepted, connected.unwrap())
}

async fn sessions(
    options: SessionOptions,
) -> (ServerHandle, ServerIncoming, AgentHandle, AgentIncoming) {
    sessions_at(options, "0.49.0").await
}

/// Connects like [`sessions`], with the agent advertising `version` and the
/// manager replying with `version` as its ceiling.
async fn sessions_at(
    options: SessionOptions,
    version: &str,
) -> (ServerHandle, ServerIncoming, AgentHandle, AgentIncoming) {
    let (server, agent) = connections().await;
    let mut claims = claims();
    claims.protocol_version = version.into();
    let (server, agent) = tokio::join!(
        ServerHandle::from_transport(server, options.clone(), ">=0.48.0", version),
        AgentHandle::from_transport(agent, options, &claims)
    );
    let (server, server_incoming) = server.unwrap();
    let (agent, agent_incoming) = agent.unwrap();
    (server, server_incoming, agent, agent_incoming)
}

/// Connects a manager session to an agent transport whose streams the test
/// answers by hand, with the agent advertising `version` and the manager
/// replying with `version` as its ceiling.
async fn raw_agent(options: SessionOptions, version: &str) -> (ServerHandle, Connection) {
    let (server, agent) = connections().await;
    let mut claims = claims();
    claims.protocol_version = version.into();
    let (server, _) = tokio::join!(
        ServerHandle::from_transport(server, options.clone(), ">=0.48.0", version),
        AgentHandle::from_transport(agent.clone(), options, &claims)
    );
    (server.unwrap().0, agent)
}

async fn agent_with_raw_manager(options: SessionOptions) -> (AgentHandle, Connection) {
    let (manager, node) = connections().await;
    let claims = claims();
    let (server, agent) = tokio::join!(
        ServerHandle::from_transport(manager.clone(), options.clone(), ">=0.48.0", "0.49.0"),
        AgentHandle::from_transport(node, options, &claims)
    );
    let _server = server.unwrap().0;
    (agent.unwrap().0, manager)
}

async fn request_stream(incoming: &mut ServerIncoming) -> ServerRequestStream {
    let ServerStream::Requests(stream) = incoming.accept().await.unwrap() else {
        panic!("expected a request stream");
    };
    stream
}

async fn event_stream(incoming: &mut ServerIncoming) -> DetectionEventReceiver {
    let ServerStream::DetectionEvents(stream) = incoming.accept().await.unwrap() else {
        panic!("expected an event stream");
    };
    stream
}

#[tokio::test]
async fn identity_claims_close_and_domain_errors() {
    let (server, mut incoming, agent, _) = sessions(SessionOptions::legacy_compatible()).await;
    assert_eq!(server.id(), server.clone().id());
    assert_ne!(server.id(), agent.id());
    assert_eq!(server.peer_certificates().unwrap().chain().len(), 1);
    assert_eq!(agent.peer_certificates().unwrap().chain().len(), 1);
    assert!(
        matches!(server.metadata(), review_protocol::session::HandshakeMetadata::Agent(claims) if claims.capabilities.contains("registrar"))
    );
    let (response, ()) = tokio::join!(agent.get_config(), async {
        let mut stream = request_stream(&mut incoming).await;
        let ServerRequest::GetConfig { reply, .. } = stream.next().await.unwrap().unwrap() else {
            panic!("wrong request");
        };
        reply
            .respond(Err("unknown request code: literal remote diagnostic".into()))
            .await
            .unwrap();
        stream.finish().unwrap();
    });
    let error = response.unwrap_err();
    assert_eq!(error.certainty(), Some(OutcomeCertainty::Rejected));
    assert!(matches!(error, SessionError::RemoteRejection(text)
        if text == "unknown request code: literal remote diagnostic"));
    let code = ApplicationCode::new(77).unwrap();
    server.close(code, b"application shutdown");
    assert!(
        matches!(agent.closed().await, CloseReason::Application { code: actual, reason } if actual == code && reason == b"application shutdown")
    );
}

#[tokio::test]
async fn large_configuration_and_model_transfers() {
    let mut options = SessionOptions::legacy_compatible();
    options.unary = FrameLimit::new(32 * 1024 * 1024).unwrap();
    let (_, mut incoming, agent, _) = sessions(options).await;
    let model = vec![42_u8; 8 * 1024 * 1024];
    let config = "x".repeat(4 * 1024 * 1024);
    let (responses, ()) = tokio::join!(
        async {
            (
                agent.get_config().await.unwrap(),
                agent.get_model("large").await.unwrap(),
            )
        },
        async {
            let mut stream = request_stream(&mut incoming).await;
            let ServerRequest::GetConfig { reply, .. } = stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request");
            };
            reply.respond(Ok(config.clone())).await.unwrap();
            stream.finish().unwrap();
            let mut stream = request_stream(&mut incoming).await;
            let ServerRequest::GetModel { request, reply } = stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request");
            };
            assert_eq!(request, "large");
            reply.respond(Ok(model.clone())).await.unwrap();
            stream.finish().unwrap();
        }
    );
    assert_eq!(responses, (config, model));
}

#[tokio::test]
async fn oversized_header_rejected_without_waiting_for_payload() {
    let mut options = SessionOptions::legacy_compatible();
    options.unary = FrameLimit::new(32).unwrap();
    let (server, agent) = connections().await;
    let ((), (agent, _)) = tokio::join!(
        async {
            let (_, mut incoming) =
                ServerHandle::from_transport(server, options.clone(), ">=0.48.0", "0.49.0")
                    .await
                    .unwrap();
            let mut stream = request_stream(&mut incoming).await;
            let error = stream.next().await.err().unwrap();
            assert!(matches!(error, SessionError::LimitExceeded { .. }));
        },
        async {
            let (handle, incoming) =
                AgentHandle::from_transport(agent.clone(), options.clone(), &claims())
                    .await
                    .unwrap();
            let (mut send, _recv) = agent.open_bi().await.unwrap();
            send.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
            // There is no payload; a reader waiting for it would hang.
            (handle, incoming)
        }
    );
    drop(agent);
}

#[tokio::test]
async fn sent_mutation_transport_failure_is_unknown() {
    let (_, mut incoming, agent, _) = sessions(SessionOptions::legacy_compatible()).await;
    let (result, ()) = tokio::join!(agent.insert_model(&[1, 2, 3]), async {
        let mut stream = request_stream(&mut incoming).await;
        let request = stream.next().await.unwrap().unwrap();
        assert!(matches!(request, ServerRequest::InsertModel { .. }));
        drop(request);
    });
    let error = result.unwrap_err();
    assert!(matches!(error, SessionError::Transport { .. }));
    assert_eq!(error.certainty(), Some(OutcomeCertainty::Unknown));
    assert!(std::error::Error::source(&error).is_some());
}

#[tokio::test]
async fn abandoning_outbound_exchange_resets_and_stops_both_directions() {
    let (server, agent) = raw_agent(SessionOptions::legacy_compatible(), "0.49.0").await;
    let caller = server.clone();
    let operation =
        tokio::spawn(async move { caller.node_power(NodePowerRequest::GracefulReboot).await });
    let (send, recv) = agent.accept_bi().await.unwrap();
    let mut reader = oinq::frame::FramedReader::new(recv, FrameLimit::new(1024).unwrap());
    reader.read().await.unwrap().unwrap();
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    assert_eq!(send.stopped().await.unwrap().unwrap().get(), 1);
    let mut recv = reader.into_inner();
    let error = recv.read_u8().await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn retained_request_stream_resumes_partial_frame() {
    let (server, agent) = connections().await;
    let ((_, mut incoming), _) = tokio::join!(
        async {
            ServerHandle::from_transport(
                server,
                SessionOptions::legacy_compatible(),
                ">=0.48.0",
                "0.49.0",
            )
            .await
            .unwrap()
        },
        async {
            AgentHandle::from_transport(
                agent.clone(),
                SessionOptions::legacy_compatible(),
                &claims(),
            )
            .await
            .unwrap()
        }
    );
    let (mut send, recv) = agent.open_bi().await.unwrap();
    send.write_all(&[0, 0]).await.unwrap();
    let mut stream = request_stream(&mut incoming).await;
    {
        let future = stream.next();
        tokio::pin!(future);
        assert!(tokio_test::task::spawn(future.as_mut()).poll().is_pending());
    }
    // Remaining BE header and LE request code 36; unit body has zero bytes.
    send.write_all(&[0, 4, 36, 0, 0, 0]).await.unwrap();
    let ServerRequest::GetConfig { reply, .. } = stream.next().await.unwrap().unwrap() else {
        panic!("wrong request");
    };
    let mut reader = oinq::frame::FramedReader::new(recv, FrameLimit::new(1024).unwrap());
    let ((), frame) = tokio::join!(
        async {
            reply.respond(Ok("resumed".into())).await.unwrap();
        },
        reader.read()
    );
    stream.finish().unwrap();
    assert_eq!(
        frame
            .unwrap()
            .unwrap()
            .decode::<Result<String, String>>()
            .unwrap(),
        Ok("resumed".into())
    );
    assert!(reader.read().await.unwrap().is_none());
    assert_eq!(send.stopped().await.unwrap().unwrap().get(), 1);
}

#[tokio::test]
async fn timeout_reports_certainty_and_aborts_exchange() {
    let mut options = SessionOptions::legacy_compatible();
    options.operation_timeout = Some(Duration::from_secs(1));
    let (server, agent) = raw_agent(options, "0.49.0").await;
    let (result, ()) = tokio::join!(server.node_power(NodePowerRequest::GracefulReboot), async {
        let (send, recv) = agent.accept_bi().await.unwrap();
        let mut reader = oinq::frame::FramedReader::new(recv, FrameLimit::new(1024).unwrap());
        reader.read().await.unwrap().unwrap();
        assert_eq!(send.stopped().await.unwrap().unwrap().get(), 1);
    });
    assert!(matches!(
        result,
        Err(SessionError::Deadline {
            certainty: OutcomeCertainty::Unknown,
            ..
        })
    ));
}

#[tokio::test]
async fn preserves_typed_power_and_terminal_install_outcomes() {
    let (server, _, _, mut incoming) = sessions(SessionOptions::legacy_compatible()).await;
    let (result, ()) = tokio::join!(server.node_power(NodePowerRequest::GracefulReboot), async {
        let mut stream = incoming.accept().await.unwrap();
        let AgentRequest::Power { reply, .. } = stream.next().await.unwrap().unwrap() else {
            panic!("wrong request");
        };
        reply
            .respond(Ok(NodePowerResponse::Initiated))
            .await
            .unwrap();
        stream.finish().unwrap();
    });
    assert!(matches!(
        result.unwrap(),
        review_protocol::server::node::NodePowerOutcome::Response(NodePowerResponse::Initiated)
    ));
    let request = install_request(3);
    let mut source = std::io::Cursor::new(vec![1, 2, 3]);
    let (result, ()) = tokio::join!(server.node_package_install(request, &mut source), async {
        let mut stream = incoming.accept().await.unwrap();
        let AgentRequest::Package { request, reply } = stream.next().await.unwrap().unwrap() else {
            panic!("wrong request");
        };
        assert_eq!(request, install_request(3));
        assert!(
            reply
                .preflight(Ok(InstallPreflight::AlreadyApplied))
                .await
                .unwrap()
                .is_none()
        );
        stream.finish().unwrap();
    });
    assert!(matches!(
        result.unwrap(),
        review_protocol::server::node::InstallOutcome::Preflight(
            review_protocol::server::node::TerminalPreflight::AlreadyApplied
        )
    ));
    assert_eq!(source.position(), 0);
}

#[tokio::test]
async fn terminal_install_preflight_rejection_finishes_cleanly() {
    use oinq::frame::{FramedReader, FramedWriter};

    let (manager, agent) = raw_agent(SessionOptions::legacy_compatible(), "0.49.0").await;
    let mut source = std::io::Cursor::new(vec![1, 2, 3]);
    let (result, ()) = tokio::join!(
        manager.node_package_install(install_request(3), &mut source),
        async {
            let (send, recv) = agent.accept_bi().await.unwrap();
            let limit = FrameLimit::new(1024).unwrap();
            let mut reader = FramedReader::new(recv, limit);
            let mut writer = FramedWriter::new(send, limit);
            reader.read().await.unwrap().unwrap();
            writer
                .start(Err::<InstallPreflight, String>("disk full".into()))
                .unwrap();
            writer.flush().await.unwrap();
            writer.into_inner().finish().unwrap();
            assert!(reader.read().await.unwrap().is_none());
        }
    );
    assert!(matches!(
        result,
        Err(SessionError::RemoteRejection(message)) if message == "disk full"
    ));
    assert_eq!(source.position(), 0);
}

fn install_request(size: u64) -> NodePackageRequest {
    NodePackageRequest::Install {
        target: "test".into(),
        instance: None,
        version: "1.0".into(),
        commit: "abc".into(),
        size,
        idempotency_key: "key".into(),
        bootstrap_material: None,
        on_failure: review_protocol::types::node::FailurePolicy::Rollback,
        bind_addrs: None,
        config_template: None,
        privilege_profile: Some("restricted".into()),
    }
}

#[tokio::test]
async fn install_transfer_stops_at_size_and_truncation_aborts() {
    use review_protocol::{server::node::InstallOutcome, types::node::NodePackageResponse};
    let mut options = SessionOptions::legacy_compatible();
    options.package_chunks = FrameLimit::new(1024).unwrap();
    let (server, _, _, mut incoming) = sessions(options).await;
    let bytes = vec![7; 4096];
    let mut source = std::io::Cursor::new(bytes.clone());
    let (result, received) = tokio::join!(
        server.node_package_install(install_request(3000), &mut source),
        async {
            let mut stream = incoming.accept().await.unwrap();
            let AgentRequest::Package { reply, .. } = stream.next().await.unwrap().unwrap() else {
                panic!("wrong request");
            };
            assert_eq!(reply.size(), Some(3000));
            assert_eq!(reply.remaining(), Some(3000));
            let mut transfer = reply
                .preflight(Ok(InstallPreflight::Proceed))
                .await
                .unwrap()
                .unwrap();
            let mut buffer = Vec::new();
            let mut received = Vec::new();
            while transfer.next_chunk(&mut buffer).await.unwrap() {
                assert!(buffer.len() <= 1024);
                received.extend_from_slice(&buffer);
                assert_eq!(
                    transfer.remaining(),
                    Some(3000 - u64::try_from(received.len()).unwrap())
                );
                assert_eq!(transfer.size(), Some(3000));
            }
            transfer
                .respond(Ok(NodePackageResponse::Done))
                .await
                .unwrap();
            stream.finish().unwrap();
            received
        }
    );
    assert!(matches!(
        result.unwrap(),
        InstallOutcome::Applied(NodePackageResponse::Done)
    ));
    assert_eq!(received, bytes[..3000]);
    assert_eq!(source.position(), 3000);
    let (result, ()) = tokio::join!(
        server.node_package_install(install_request(5), std::io::Cursor::new(vec![1, 2, 3])),
        async {
            let mut stream = incoming.accept().await.unwrap();
            let AgentRequest::Package { reply, .. } = stream.next().await.unwrap().unwrap() else {
                panic!("wrong request");
            };
            let mut transfer = reply
                .preflight(Ok(InstallPreflight::Proceed))
                .await
                .unwrap()
                .unwrap();
            let mut buffer = Vec::new();
            while transfer.next_chunk(&mut buffer).await.is_ok() {}
            assert!(transfer.next_chunk(&mut buffer).await.is_err());
        }
    );
    assert!(matches!(
        result,
        Err(SessionError::Transport {
            certainty: OutcomeCertainty::Unknown,
            ..
        })
    ));
}

#[tokio::test]
async fn caller_selected_handshake_window_accepts_previous_protocol() {
    let (server, agent) = connections().await;
    let mut info = claims();
    info.protocol_version = "0.48.0".into();
    let (manager, node) = tokio::join!(
        ServerHandle::from_transport(
            server,
            SessionOptions::legacy_compatible(),
            ">=0.48.0",
            "0.49.0"
        ),
        AgentHandle::from_transport(agent, SessionOptions::legacy_compatible(), &info)
    );
    let (manager, _) = manager.unwrap();
    node.unwrap();
    assert!(
        matches!(manager.metadata(), review_protocol::session::HandshakeMetadata::Agent(info) if info.protocol_version == "0.48.0")
    );
}

#[tokio::test]
async fn handshake_version_rejection_is_structured_on_both_sides() {
    let (server, agent) = connections().await;
    let mut info = claims();
    info.protocol_version = "0.48.0".into();
    let (manager, node) = tokio::join!(
        ServerHandle::from_transport(
            server,
            SessionOptions::legacy_compatible(),
            ">=0.49.0",
            "0.49.0"
        ),
        AgentHandle::from_transport(agent, SessionOptions::legacy_compatible(), &info)
    );
    assert!(
        matches!(manager, Err(SessionError::IncompatibleProtocol { version, required }) if version == "0.48.0" && required == ">=0.49.0, <=0.49.0")
    );
    assert!(
        matches!(node, Err(SessionError::IncompatibleProtocol { version, required }) if version == "0.48.0" && required == ">=0.49.0, <=0.49.0")
    );
}

#[tokio::test]
async fn nested_response_allocations_are_classified_as_limits() {
    let mut options = SessionOptions::legacy_compatible();
    options.unary = FrameLimit::new(1024).unwrap();
    let (manager, node) = connections().await;
    let info = claims();
    let (_manager_session, node_session) = tokio::join!(
        ServerHandle::from_transport(manager.clone(), options.clone(), ">=0.48.0", "0.49.0"),
        AgentHandle::from_transport(node, options, &info)
    );
    let (node, _) = node_session.unwrap();
    let (result, ()) = tokio::join!(node.get_model_names(), async {
        let (send, recv) = manager.accept_bi().await.unwrap();
        let mut reader = oinq::frame::FramedReader::new(recv, FrameLimit::new(4096).unwrap());
        reader.read().await.unwrap().unwrap();
        let mut writer = oinq::frame::FramedWriter::new(send, FrameLimit::new(4096).unwrap());
        // The encoded reply fits, but the String elements exceed the decode budget.
        writer
            .start(Ok::<_, String>(vec![String::new(); 200]))
            .unwrap();
        writer.flush().await.unwrap();
        writer.into_inner().finish().unwrap();
    });
    assert!(matches!(
        result,
        Err(SessionError::LimitExceeded {
            source: oinq::frame::FrameError::Decode(_),
            ..
        })
    ));
}

#[tokio::test]
async fn transport_failure_before_open_is_not_sent() {
    let (server, _, agent, _) = sessions(SessionOptions::legacy_compatible()).await;
    server.close(ApplicationCode::new(1).unwrap(), b"closed before request");
    agent.closed().await;
    let error = agent.insert_model(&[1]).await.unwrap_err();
    assert_eq!(error.certainty(), Some(OutcomeCertainty::NotSent));
}

#[tokio::test]
async fn event_stream_round_trip_and_resumption() {
    let (server, mut incoming, agent, _) = sessions(SessionOptions::legacy_compatible()).await;
    let event = detection_event(1.0);
    let ((), received) = tokio::join!(
        async {
            let mut sender = agent.open_detection_event_stream().await.unwrap();
            let value = serde_json::to_value(&event).unwrap();
            sender
                .start(&serde_json::from_value(value).unwrap())
                .unwrap();
            sender.flush().await.unwrap();
            sender.finish().await.unwrap();
        },
        async {
            let mut sequence = event_stream(&mut incoming).await;
            let event = sequence.next().await.unwrap().unwrap();
            assert!(sequence.next().await.unwrap().is_none());
            event
        }
    );
    assert_eq!(received, event);
    // Handles retain the connection after the event owners finish.
    assert_eq!(server.id(), server.clone().id());
}

#[tokio::test]
async fn retained_event_header_and_payload_resume_after_cancellation() {
    let (manager, node) = connections().await;
    let info = claims();
    let (manager_session, _node_session) = tokio::join!(
        ServerHandle::from_transport(
            manager,
            SessionOptions::legacy_compatible(),
            ">=0.48.0",
            "0.49.0"
        ),
        AgentHandle::from_transport(node.clone(), SessionOptions::legacy_compatible(), &info)
    );
    let (_, mut incoming) = manager_session.unwrap();
    let mut send = node.open_uni().await.unwrap();
    send.write_all(&[0]).await.unwrap();
    let mut sequence = event_stream(&mut incoming).await;
    {
        let future = sequence.next();
        tokio::pin!(future);
        assert!(tokio_test::task::spawn(future.as_mut()).poll().is_pending());
    }
    let event = detection_event(2.0);
    let payload = bincode::serde::encode_to_vec(&event, bincode::config::standard()).unwrap();
    send.write_all(&[0]).await.unwrap();
    send.write_all(&u32::try_from(payload.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    send.write_all(&payload[..1]).await.unwrap();
    {
        let future = sequence.next();
        tokio::pin!(future);
        assert!(tokio_test::task::spawn(future.as_mut()).poll().is_pending());
    }
    send.write_all(&payload[1..]).await.unwrap();
    send.finish().unwrap();
    assert_eq!(sequence.next().await.unwrap().unwrap(), event);
    assert!(sequence.next().await.unwrap().is_none());
}

#[tokio::test]
async fn timeout_while_waiting_for_stream_credit_is_not_sent() {
    let (manager, node) = connections().await;
    let mut options = SessionOptions::legacy_compatible();
    options.operation_timeout = Some(Duration::from_secs(1));
    let info = claims();
    let (manager_session, _node_session) = tokio::join!(
        ServerHandle::from_transport(manager.clone(), options, ">=0.48.0", "0.49.0"),
        AgentHandle::from_transport(node, SessionOptions::legacy_compatible(), &info)
    );
    let (server, _) = manager_session.unwrap();
    let mut held = Vec::new();
    // The endpoint helper deliberately selects seven incoming bidi streams.
    for _ in 0..7 {
        held.push(manager.open_bi().await.unwrap());
    }
    let error = server
        .node_power(NodePowerRequest::GracefulReboot)
        .await
        .unwrap_err();
    assert_eq!(error.certainty(), Some(OutcomeCertainty::NotSent));
    assert!(matches!(
        error,
        SessionError::Deadline {
            source: Some(_),
            ..
        }
    ));
}

#[tokio::test]
async fn handshake_limit_and_base_only_wire_compatibility() {
    let (manager, node) = connections().await;
    let (accepted, ()) = tokio::join!(
        ServerHandle::from_transport(
            manager,
            SessionOptions::legacy_compatible(),
            ">=0.48.0",
            "0.49.0"
        ),
        async {
            let (send, recv) = node.open_bi().await.unwrap();
            let mut writer = oinq::frame::FramedWriter::new(send, FrameLimit::new(4096).unwrap());
            writer
                .start_raw(include_bytes!("fixtures/0.21.0/handshake-base.bin"))
                .unwrap();
            writer.flush().await.unwrap();
            let mut reader = oinq::frame::FramedReader::new(recv, FrameLimit::new(4096).unwrap());
            assert_eq!(
                reader
                    .read()
                    .await
                    .unwrap()
                    .unwrap()
                    .decode::<Result<String, String>>()
                    .unwrap(),
                Ok("0.49.0".into())
            );
        }
    );
    let (handle, _) = accepted.unwrap();
    assert!(
        matches!(handle.metadata(), review_protocol::session::HandshakeMetadata::Agent(info) if info.capabilities.is_empty())
    );

    let (manager, node) = connections().await;
    let mut options = SessionOptions::legacy_compatible();
    options.handshake = FrameLimit::new(8).unwrap();
    let info = claims();
    let (manager_result, node_result) = tokio::join!(
        ServerHandle::from_transport(manager, options, ">=0.48.0", "0.49.0"),
        AgentHandle::from_transport(node, SessionOptions::legacy_compatible(), &info)
    );
    assert!(matches!(
        manager_result,
        Err(SessionError::LimitExceeded { .. })
    ));
    assert!(node_result.is_err());
}

// Keep raw transport clones to exercise sequential requests on one legacy wire stream.
async fn raw_sessions(
    options: SessionOptions,
) -> (ServerIncoming, AgentIncoming, Connection, Connection) {
    raw_sessions_at(options, "0.49.0").await
}

/// Connects like [`raw_sessions`], with the agent advertising `version` and
/// the manager replying with `version` as its ceiling.
async fn raw_sessions_at(
    options: SessionOptions,
    version: &str,
) -> (ServerIncoming, AgentIncoming, Connection, Connection) {
    let (manager, node) = connections().await;
    let mut info = claims();
    info.protocol_version = version.into();
    let (server, agent) = tokio::join!(
        ServerHandle::from_transport(manager.clone(), options.clone(), ">=0.48.0", version),
        AgentHandle::from_transport(node.clone(), options, &info),
    );
    (server.unwrap().1, agent.unwrap().1, manager, node)
}

#[tokio::test]
async fn server_request_stream_continues_after_success_and_rejection() {
    use oinq::frame::{FramedReader, FramedWriter};
    let (mut incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let (send, recv) = node.open_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut writer = FramedWriter::new(send, limit);
    let mut reader = FramedReader::new(recv, limit);
    let ((), ()) = tokio::join!(
        async {
            for expected in [
                Ok("first".to_string()),
                Err("literal rejection".to_string()),
                Ok("third".to_string()),
            ] {
                // Independent legacy request layout: fixed LE code, standard unit body.
                writer.start((36_u32.to_le_bytes(), ())).unwrap();
                writer.flush().await.unwrap();
                let actual = reader
                    .read()
                    .await
                    .unwrap()
                    .unwrap()
                    .decode::<Result<String, String>>()
                    .unwrap();
                assert_eq!(actual, expected);
            }
            writer.into_inner().finish().unwrap();
            assert!(reader.read().await.unwrap().is_none());
        },
        async {
            let mut stream = request_stream(&mut incoming).await;
            for response in [
                Ok("first".to_string()),
                Err("literal rejection".to_string()),
                Ok("third".to_string()),
            ] {
                let ServerRequest::GetConfig { reply, .. } = stream.next().await.unwrap().unwrap()
                else {
                    panic!("wrong request");
                };
                reply.respond(response).await.unwrap();
            }
            assert!(stream.next().await.unwrap().is_none());
            assert!(stream.next().await.unwrap().is_none());
        }
    );
}

#[tokio::test]
// Keep the complete peer/runner sequence together to verify one stream survives all phases.
#[allow(clippy::too_many_lines)]
async fn agent_request_stream_continues_after_install_and_immediate_power() {
    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::types::node::{
        NodeHostnameRequest, NodeHostnameResponse, NodePackageResponse,
    };
    let mut options = SessionOptions::legacy_compatible();
    options.unary = FrameLimit::new(4096).unwrap();
    options.package_chunks = FrameLimit::new(1).unwrap();
    let (_, mut incoming, manager, _) = raw_sessions(options).await;
    let (send, recv) = manager.open_bi().await.unwrap();
    let limit = FrameLimit::new(4096).unwrap();
    let mut writer = FramedWriter::new(send, limit);
    let mut reader = FramedReader::new(recv, limit);
    let ((), ()) = tokio::join!(
        async {
            // An immediate power operation carries no response.
            writer
                .start((106_u32.to_le_bytes(), NodePowerRequest::Reboot))
                .unwrap();
            writer.flush().await.unwrap();
            // A terminal preflight must also preserve the stream.
            writer
                .start((109_u32.to_le_bytes(), install_request(1)))
                .unwrap();
            writer.flush().await.unwrap();
            assert_eq!(
                reader
                    .read()
                    .await
                    .unwrap()
                    .unwrap()
                    .decode::<Result<InstallPreflight, String>>()
                    .unwrap(),
                Ok(InstallPreflight::AlreadyApplied)
            );
            writer
                .start((109_u32.to_le_bytes(), install_request(1)))
                .unwrap();
            writer.flush().await.unwrap();
            assert_eq!(
                reader
                    .read()
                    .await
                    .unwrap()
                    .unwrap()
                    .decode::<Result<InstallPreflight, String>>()
                    .unwrap(),
                Ok(InstallPreflight::Proceed)
            );
            writer.start_raw(&[42]).unwrap();
            writer.flush().await.unwrap();
            assert_eq!(
                reader
                    .read()
                    .await
                    .unwrap()
                    .unwrap()
                    .decode::<Result<NodePackageResponse, String>>()
                    .unwrap(),
                Ok(NodePackageResponse::Done)
            );
            // This request exceeds the package-chunk budget: unary limits must be restored.
            writer
                .start((
                    102_u32.to_le_bytes(),
                    NodeHostnameRequest::Set {
                        hostname: "after-install".into(),
                    },
                ))
                .unwrap();
            writer.flush().await.unwrap();
            assert_eq!(
                reader
                    .read()
                    .await
                    .unwrap()
                    .unwrap()
                    .decode::<Result<NodeHostnameResponse, String>>()
                    .unwrap(),
                Ok(NodeHostnameResponse::Done)
            );
            writer.into_inner().finish().unwrap();
            assert!(reader.read().await.unwrap().is_none());
        },
        async {
            let mut stream = incoming.accept().await.unwrap();
            let AgentRequest::Power { reply, .. } = stream.next().await.unwrap().unwrap() else {
                panic!("wrong request");
            };
            reply.complete_without_response();
            let AgentRequest::Package { reply, .. } = stream.next().await.unwrap().unwrap() else {
                panic!("wrong request");
            };
            assert!(
                reply
                    .preflight(Ok(InstallPreflight::AlreadyApplied))
                    .await
                    .unwrap()
                    .is_none()
            );
            let AgentRequest::Package { reply, .. } = stream.next().await.unwrap().unwrap() else {
                panic!("wrong request");
            };
            let mut transfer = reply
                .preflight(Ok(InstallPreflight::Proceed))
                .await
                .unwrap()
                .unwrap();
            let mut buffer = Vec::new();
            assert!(transfer.next_chunk(&mut buffer).await.unwrap());
            assert_eq!(buffer, [42]);
            assert!(!transfer.next_chunk(&mut buffer).await.unwrap());
            transfer
                .respond(Ok(NodePackageResponse::Done))
                .await
                .unwrap();
            let AgentRequest::Hostname { request, reply } = stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request");
            };
            assert_eq!(
                request,
                NodeHostnameRequest::Set {
                    hostname: "after-install".into()
                }
            );
            reply.respond(Ok(NodeHostnameResponse::Done)).await.unwrap();
            assert!(stream.next().await.unwrap().is_none());
        }
    );
}

#[tokio::test]
async fn stalled_request_and_event_headers_do_not_block_other_streams() {
    use oinq::frame::FramedReader;
    let (mut incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    {
        let mut future = tokio_test::task::spawn(incoming.accept());
        assert!(future.poll().is_pending());
    }
    let (mut stalled_send, mut stalled_recv) = node.open_bi().await.unwrap();
    stalled_send.write_all(&[0, 0]).await.unwrap();
    let mut stalled = request_stream(&mut incoming).await;
    {
        let mut future = tokio_test::task::spawn(stalled.next());
        assert!(future.poll().is_pending());
    }
    let (mut send, recv) = node.open_bi().await.unwrap();
    send.write_all(&[0, 0, 0, 4, 36, 0, 0, 0]).await.unwrap();
    send.finish().unwrap();
    let mut event_send = node.open_uni().await.unwrap();
    event_send.write_all(&[0]).await.unwrap();
    // Accept both kinds while neither the stalled request nor event header is complete.
    let (mut requests, mut events) = tokio::time::timeout(Duration::from_secs(5), async {
        let mut requests = None;
        let mut events = None;
        for _ in 0..2 {
            match incoming.accept().await.unwrap() {
                ServerStream::Requests(stream) => requests = Some(stream),
                ServerStream::DetectionEvents(stream) => events = Some(stream),
            }
        }
        (requests.unwrap(), events.unwrap())
    })
    .await
    .unwrap();
    {
        let mut future = tokio_test::task::spawn(events.next());
        assert!(future.poll().is_pending());
    }
    let ServerRequest::GetConfig { reply, .. } = requests.next().await.unwrap().unwrap() else {
        panic!("wrong request");
    };
    reply.respond(Ok("independent".into())).await.unwrap();
    assert!(requests.next().await.unwrap().is_none());
    let mut reader = FramedReader::new(recv, FrameLimit::new(1024).unwrap());
    assert_eq!(
        reader
            .read()
            .await
            .unwrap()
            .unwrap()
            .decode::<Result<String, String>>()
            .unwrap(),
        Ok("independent".into())
    );
    event_send.write_all(&[0]).await.unwrap();
    event_send.finish().unwrap();
    assert!(events.next().await.unwrap().is_none());
    // Dropping the abandoned request owner still explicitly aborts both directions.
    drop(stalled);
    assert_eq!(stalled_send.stopped().await.unwrap().unwrap().get(), 1);
    assert!(stalled_recv.read(&mut [0]).await.is_err());
}

#[tokio::test]
async fn cancelling_agent_accept_consumes_no_command_stream() {
    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::types::node::{NodeHostnameRequest, NodeHostnameResponse};

    let (_server_incoming, mut incoming, manager, _node) =
        raw_sessions(SessionOptions::legacy_compatible()).await;
    {
        let mut accept = tokio_test::task::spawn(incoming.accept());
        assert!(accept.poll().is_pending());
    }
    let (send, recv) = manager.open_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut writer = FramedWriter::new(send, limit);
    let mut reader = FramedReader::new(recv, limit);
    writer
        .start((
            102_u32.to_le_bytes(),
            NodeHostnameRequest::Set {
                hostname: "accepted".into(),
            },
        ))
        .unwrap();
    writer.flush().await.unwrap();
    let mut stream = tokio::time::timeout(Duration::from_secs(5), incoming.accept())
        .await
        .unwrap()
        .unwrap();
    let AgentRequest::Hostname { request, reply } = stream.next().await.unwrap().unwrap() else {
        panic!("wrong request");
    };
    assert_eq!(
        request,
        NodeHostnameRequest::Set {
            hostname: "accepted".into()
        }
    );
    reply.respond(Ok(NodeHostnameResponse::Done)).await.unwrap();
    writer.into_inner().finish().unwrap();
    assert!(stream.next().await.unwrap().is_none());
    assert_eq!(
        reader
            .read()
            .await
            .unwrap()
            .unwrap()
            .decode::<Result<NodeHostnameResponse, String>>()
            .unwrap(),
        Ok(NodeHostnameResponse::Done)
    );
}

#[tokio::test]
async fn request_stream_distinguishes_clean_eof_from_truncation() {
    let (mut incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let (mut send, _recv) = node.open_bi().await.unwrap();
    send.finish().unwrap();
    let mut stream = request_stream(&mut incoming).await;
    assert!(stream.next().await.unwrap().is_none());
    for bytes in [&[0, 0][..], &[0, 0, 0, 4, 36][..], &[0, 0, 0, 1, 36][..]] {
        let (mut send, mut recv) = node.open_bi().await.unwrap();
        send.write_all(bytes).await.unwrap();
        send.finish().unwrap();
        let mut stream = request_stream(&mut incoming).await;
        assert!(matches!(
            stream.next().await,
            Err(SessionError::Malformed { .. })
        ));
        assert!(stream.next().await.is_err());
        assert!(recv.read(&mut [0]).await.is_err());
    }
}

#[tokio::test]
async fn engine_commands_preserve_arguments_and_remote_rejection() {
    use review_protocol::types::{CloneModelRequest, TrainModelRequest};
    let (manager, _, _, mut incoming) = sessions(SessionOptions::legacy_compatible()).await;
    let train = TrainModelRequest {
        run_id: 300,
        model: "model".into(),
        definition: "raw_event_kind = \"http\"".into(),
    };
    let clone = CloneModelRequest {
        run_id: 301,
        source: "model".into(),
        target_name: "copy".into(),
        strip_events: true,
    };
    let ((), ()) = tokio::join!(
        async {
            manager.send_train_model(&train).await.unwrap();
            manager.send_clone_model(&clone).await.unwrap();
            manager.send_cancel_run(300).await.unwrap();
            let error = manager.send_run_detector_once(-3).await.unwrap_err();
            assert!(
                matches!(error, SessionError::RemoteRejection(message) if message == "detector disabled")
            );
        },
        async {
            let mut stream = incoming.accept().await.unwrap();
            let AgentRequest::TrainModel { request, reply } = stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request")
            };
            assert_eq!(request, train);
            reply.respond(Ok(())).await.unwrap();
            stream.finish().unwrap();
            let mut stream = incoming.accept().await.unwrap();
            let AgentRequest::CloneModel { request, reply } = stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request")
            };
            assert_eq!(request, clone);
            reply.respond(Ok(())).await.unwrap();
            stream.finish().unwrap();
            let mut stream = incoming.accept().await.unwrap();
            let AgentRequest::CancelRun { request, reply } = stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request")
            };
            assert_eq!(request, 300);
            reply.respond(Ok(())).await.unwrap();
            stream.finish().unwrap();
            let mut stream = incoming.accept().await.unwrap();
            let AgentRequest::RunDetectorOnce { request, reply } =
                stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request")
            };
            assert_eq!(request, -3);
            reply
                .respond(Err("detector disabled".into()))
                .await
                .unwrap();
            stream.finish().unwrap();
        }
    );
}

#[tokio::test]
async fn engine_reports_preserve_arguments_and_remote_rejection() {
    use review_protocol::types::{
        DetectionModel, DetectionModelStatus, DetectorState, DetectorStatusReport, ExcludedCount,
        ReportedRunState,
    };
    let (_, mut incoming, engine, _) = sessions(SessionOptions::legacy_compatible()).await;
    let report = DetectorStatusReport {
        detector_id: -3,
        state: DetectorState::Disabled,
        finished_at: None,
        outcome: None,
        reason: Some("disabled".into()),
        events: 0,
        sources: Vec::new(),
        detection_models: vec![
            DetectionModelStatus {
                detection_model: DetectionModel::TorExitNode,
                skipped: Some("no Tor exit node list".into()),
                truncated: 0,
            },
            DetectionModelStatus {
                detection_model: DetectionModel::PortScan,
                skipped: None,
                truncated: 12,
            },
        ],
        excluded: vec![ExcludedCount {
            entry: (1 << 53) + 1,
            day: jiff::civil::date(2026, 3, 15),
            count: 4,
        }],
    };
    let ((), ()) = tokio::join!(
        async {
            engine.upload_run_model(300, &[1, 2, 3]).await.unwrap();
            engine
                .report_run(300, ReportedRunState::Failed, Some("failed"))
                .await
                .unwrap();
            engine.report_active_runs(&[300, 301]).await.unwrap();
            let error = engine.report_detector_status(&report).await.unwrap_err();
            assert!(
                matches!(error, SessionError::RemoteRejection(message) if message == "unknown detector")
            );
        },
        async {
            let mut stream = request_stream(&mut incoming).await;
            let ServerRequest::UploadRunModel { request, reply } =
                stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request")
            };
            assert_eq!(request, (300, vec![1, 2, 3]));
            reply.respond(Ok(())).await.unwrap();
            stream.finish().unwrap();
            let mut stream = request_stream(&mut incoming).await;
            let ServerRequest::ReportRun { request, reply } = stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request")
            };
            assert_eq!(
                request,
                (300, ReportedRunState::Failed, Some("failed".into()))
            );
            reply.respond(Ok(())).await.unwrap();
            stream.finish().unwrap();
            let mut stream = request_stream(&mut incoming).await;
            let ServerRequest::ReportActiveRuns { request, reply } =
                stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request")
            };
            assert_eq!(request, [300, 301]);
            reply.respond(Ok(())).await.unwrap();
            stream.finish().unwrap();
            let mut stream = request_stream(&mut incoming).await;
            let ServerRequest::ReportDetectorStatus { request, reply } =
                stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request")
            };
            assert_eq!(request, report);
            reply.respond(Err("unknown detector".into())).await.unwrap();
            stream.finish().unwrap();
        }
    );
}

/// Every exclusion-count report, one with no counts among them, reaches the
/// manager as request 52 with its counts intact and in order, and the
/// manager's reply, a success or a rejection, reaches the engine.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn exclusion_count_reports_round_trip() {
    use review_protocol::test::engine_exclusion_reports;

    let reports = engine_exclusion_reports();
    assert!(reports.iter().any(|report| report.counts.is_empty()));
    let (_, mut incoming, engine, _) = sessions(SessionOptions::legacy_compatible()).await;
    let ((), ()) = tokio::join!(
        async {
            for report in &reports {
                let result = engine.report_exclusion_counts(report).await;
                if report.counts.is_empty() {
                    assert!(
                        matches!(result, Err(SessionError::RemoteRejection(message)) if message == "nothing to record")
                    );
                } else {
                    result.unwrap();
                }
            }
        },
        async {
            for report in &reports {
                let mut stream = request_stream(&mut incoming).await;
                let ServerRequest::ReportExclusionCounts { request, reply } =
                    stream.next().await.unwrap().unwrap()
                else {
                    panic!("wrong request")
                };
                assert_eq!(&request, report);
                let answer = if request.counts.is_empty() {
                    Err("nothing to record".into())
                } else {
                    Ok(())
                };
                reply.respond(answer).await.unwrap();
                stream.finish().unwrap();
            }
        }
    );
}

/// Every signature rule push, one with two rule sets and disabled rules and
/// one with neither, reaches the agent as request 27 intact, and the agent's
/// reply, a success or a rejection, reaches the manager.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn signature_rule_pushes_round_trip() {
    use review_protocol::test::signature_rules;

    let pushes = signature_rules();
    assert!(
        pushes
            .iter()
            .any(|rules| rules.sets.len() == 2 && !rules.disabled_rules.is_empty())
    );
    let (manager, _, _, mut incoming) = sessions(SessionOptions::legacy_compatible()).await;
    let ((), ()) = tokio::join!(
        async {
            for rules in &pushes {
                let result = manager.send_signature_rules(rules).await;
                if rules.sets.is_empty() {
                    assert!(
                        matches!(result, Err(SessionError::RemoteRejection(message)) if message == "no rule sets")
                    );
                } else {
                    result.unwrap();
                }
            }
        },
        async {
            for rules in &pushes {
                let mut stream = incoming.accept().await.unwrap();
                let AgentRequest::SignatureRules { request, reply } =
                    stream.next().await.unwrap().unwrap()
                else {
                    panic!("wrong request")
                };
                assert_eq!(&request, rules);
                let answer = if request.sets.is_empty() {
                    Err("no rule sets".into())
                } else {
                    Ok(())
                };
                reply.respond(answer).await.unwrap();
                stream.finish().unwrap();
            }
        }
    );
}

/// A Semi-supervised Engine's rule pull, request 56, reaches the manager's
/// request stream with its known revision, `None` or `Some`, and the
/// manager's `Some` and `None` answers and rejection reach the engine intact;
/// every status report, request 57, reaches the manager as sent.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn signature_rule_pulls_and_status_reports_round_trip() {
    use review_protocol::test::{signature_rules, signature_status_reports};

    let rules = signature_rules();
    let current = rules[0].clone();
    let pulls = [
        (None, Ok(Some(current.clone()))),
        (Some(current.revision), Ok(None)),
        (Some(3), Err("revision unknown".to_string())),
    ];
    let reports = signature_status_reports();
    let (_, mut incoming, engine, _) = sessions(SessionOptions::legacy_compatible()).await;
    let ((), ()) = tokio::join!(
        async {
            for (known_revision, answer) in &pulls {
                let result = engine.get_signature_rules(*known_revision).await;
                match answer {
                    Ok(expected) => assert_eq!(&result.unwrap(), expected),
                    Err(reason) => assert!(
                        matches!(result, Err(SessionError::RemoteRejection(message)) if &message == reason)
                    ),
                }
            }
            for report in &reports {
                let result = engine.report_signature_status(report).await;
                if report.loaded.is_empty() {
                    assert!(
                        matches!(result, Err(SessionError::RemoteRejection(message)) if message == "nothing loaded")
                    );
                } else {
                    result.unwrap();
                }
            }
        },
        async {
            for (known_revision, answer) in &pulls {
                let mut stream = request_stream(&mut incoming).await;
                let ServerRequest::GetSignatureRules { request, reply } =
                    stream.next().await.unwrap().unwrap()
                else {
                    panic!("wrong request")
                };
                assert_eq!(&request, known_revision);
                reply.respond(answer.clone()).await.unwrap();
                stream.finish().unwrap();
            }
            for report in &reports {
                let mut stream = request_stream(&mut incoming).await;
                let ServerRequest::ReportSignatureStatus { request, reply } =
                    stream.next().await.unwrap().unwrap()
                else {
                    panic!("wrong request")
                };
                assert_eq!(&request, report);
                let answer = if request.loaded.is_empty() {
                    Err("nothing loaded".into())
                } else {
                    Ok(())
                };
                reply.respond(answer).await.unwrap();
                stream.finish().unwrap();
            }
        }
    );
}

/// Every detection event of the batch, with one that fails `validate` among
/// valid ones, crosses the session-layer stream as sent and in order, both
/// through `next` and through the owned runner.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn detection_event_stream_delivers_every_event_unvalidated() {
    use std::sync::Mutex;

    use review_protocol::{
        server::DetectionEventStreamHandler,
        test::{INVALID_DETECTION_EVENT, detection_events},
        types::DetectionEvent,
    };

    #[derive(Clone, Default)]
    struct Collect(Arc<Mutex<Vec<DetectionEvent>>>);

    #[async_trait::async_trait]
    impl DetectionEventStreamHandler for Collect {
        async fn handle_detection_event(&mut self, event: DetectionEvent) -> std::io::Result<()> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }

        async fn on_error(&mut self, error: &str) -> std::io::Result<()> {
            panic!("unexpected stream error: {error}");
        }
    }

    let events = detection_events();
    assert!(events[INVALID_DETECTION_EVENT].validate().is_err());
    let (_, mut incoming, agent, _) = sessions(SessionOptions::legacy_compatible()).await;

    let send = || async {
        let mut sender = agent.open_detection_event_stream().await.unwrap();
        for event in &events {
            sender.start(event).unwrap();
            sender.flush().await.unwrap();
        }
        sender.finish().await.unwrap();
    };

    let ((), received) = tokio::join!(send(), async {
        let mut sequence = event_stream(&mut incoming).await;
        let mut received = Vec::new();
        while let Some(event) = sequence.next().await.unwrap() {
            received.push(event);
        }
        received
    });
    assert_eq!(received, events);

    let collect = Collect::default();
    let ((), result) = tokio::join!(send(), async {
        event_stream(&mut incoming).await.run(collect.clone()).await
    });
    result.unwrap();
    assert_eq!(*collect.0.lock().unwrap(), events);
}

/// The exclusion-list and watchlist pulls carry every item, in the order the
/// manager supplied, with ids above 2^53 and overlapping groups intact.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn list_pulls_preserve_every_item_in_order() {
    use review_protocol::test::network_list_items;

    let items = network_list_items();
    let mut reversed = items.clone();
    reversed.reverse();
    let (_, mut incoming, agent, _) =
        sessions_at(SessionOptions::legacy_compatible(), PROTOCOL_VERSION).await;
    let ((), ()) = tokio::join!(
        async {
            assert_eq!(agent.get_exclusion_list().await.unwrap(), items);
            assert_eq!(agent.get_watchlist().await.unwrap(), reversed);
        },
        async {
            let mut stream = request_stream(&mut incoming).await;
            let ServerRequest::GetExclusionList { reply, .. } =
                stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request")
            };
            reply.respond(Ok(items.clone())).await.unwrap();
            stream.finish().unwrap();
            let mut stream = request_stream(&mut incoming).await;
            let ServerRequest::GetWatchlist { reply, .. } = stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request")
            };
            reply.respond(Ok(reversed.clone())).await.unwrap();
            stream.finish().unwrap();
        }
    );
}

/// An exclusion-list or watchlist reply in the `0.49.0` shape, a
/// `HostNetworkGroup` with no explicit hosts but other entries, from a manager
/// whose handshake claimed `0.50.0`, is refused as malformed rather than read
/// as an empty item list, which a prefix decode would do.
#[tokio::test]
async fn list_pulls_reject_legacy_host_network_group_reply() {
    use std::net::{IpAddr, Ipv4Addr};

    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::types::{HostNetworkGroup, NetworkListItem};

    let group = HostNetworkGroup {
        hosts: Vec::new(),
        networks: vec!["192.0.2.0/24".parse().unwrap()],
        ip_ranges: vec![
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))..=IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        ],
    };
    let reply =
        bincode::serde::encode_to_vec(Ok::<_, String>(group), bincode::config::standard()).unwrap();
    let (prefix, _) = bincode::serde::decode_from_slice::<Result<Vec<NetworkListItem>, String>, _>(
        &reply,
        bincode::config::standard(),
    )
    .unwrap();
    assert_eq!(
        prefix,
        Ok(Vec::new()),
        "a prefix decode reads an empty list"
    );

    let options = SessionOptions::legacy_compatible();
    let (manager, node) = connections().await;
    let mut info = claims();
    info.protocol_version = PROTOCOL_VERSION.into();
    let (server, agent) = tokio::join!(
        ServerHandle::from_transport(
            manager.clone(),
            options.clone(),
            ">=0.48.0",
            PROTOCOL_VERSION
        ),
        AgentHandle::from_transport(node, options, &info),
    );
    // Keep the manager session alive without accepting its streams.
    let _server = server.unwrap();
    let (agent, _) = agent.unwrap();
    for pull_watchlist in [false, true] {
        let ((), result) = tokio::join!(
            async {
                let (send, recv) = manager.accept_bi().await.unwrap();
                let limit = FrameLimit::new(1024).unwrap();
                let mut reader = FramedReader::new(recv, limit);
                let mut writer = FramedWriter::new(send, limit);
                reader.read().await.unwrap().unwrap();
                writer.start_raw(&reply).unwrap();
                writer.flush().await.unwrap();
                let _ = writer.into_inner().finish();
            },
            async {
                if pull_watchlist {
                    agent.get_watchlist().await
                } else {
                    agent.get_exclusion_list().await
                }
            }
        );
        let error = result.unwrap_err();
        assert!(matches!(error, SessionError::Malformed { .. }), "{error:?}");
        assert_eq!(error.certainty(), Some(OutcomeCertainty::Unknown));
    }
}

/// Checks that a `0.49.0` exclusion-list or watchlist reply can get past
/// full-frame decoding: a `HostNetworkGroup` holding one IPv4 host is also a
/// complete one-item `Vec<NetworkListItem>` with an invented id and name and an
/// empty group. Only the handshake version keeps it out.
fn assert_legacy_list_reply_decodes_in_full() {
    use std::net::{IpAddr, Ipv4Addr};

    use review_protocol::types::{HostNetworkGroup, NetworkListItem};

    let group = HostNetworkGroup {
        hosts: vec![IpAddr::V4(Ipv4Addr::new(2, b'x', b'y', 0))],
        networks: Vec::new(),
        ip_ranges: Vec::new(),
    };
    let reply =
        bincode::serde::encode_to_vec(Ok::<_, String>(group), bincode::config::standard()).unwrap();
    let (misread, consumed) = bincode::serde::decode_from_slice::<
        Result<Vec<NetworkListItem>, String>,
        _,
    >(&reply, bincode::config::standard())
    .unwrap();
    assert_eq!(consumed, reply.len(), "the reply decodes in full");
    assert_eq!(
        misread,
        Ok(vec![NetworkListItem {
            id: 0,
            name: "xy".into(),
            group: HostNetworkGroup::default(),
        }]),
        "the host is lost without an error"
    );
}

/// Answers the next request stream `manager` accepts with `reply` and returns
/// the request's code.
async fn answer_raw(manager: &Connection, reply: &[u8]) -> u32 {
    let request = answer_raw_frame(manager, reply).await;
    u32::from_le_bytes(*request.first_chunk::<4>().unwrap())
}

/// Answers the next request stream `manager` accepts with `reply` and returns
/// the whole request frame: the little-endian request code and the body.
async fn answer_raw_frame(manager: &Connection, reply: &[u8]) -> Vec<u8> {
    use oinq::frame::{FramedReader, FramedWriter};

    let (send, recv) = manager.accept_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut reader = FramedReader::new(recv, limit);
    let mut writer = FramedWriter::new(send, limit);
    let request = reader.read().await.unwrap().unwrap().into_bytes();
    writer.start_raw(reply).unwrap();
    writer.flush().await.unwrap();
    let _ = writer.into_inner().finish();
    request
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn typed_agent_operations_preserve_legacy_request_codes_and_bodies() {
    use review_protocol::types::{
        ColumnStatisticsUpdate, DataSource, DataSourceKey, DataType, DetectionEvent,
        HostNetworkGroup, OutlierInfo, TimeSeriesGenerationPolicy, TimeSeriesUpdate,
        UpdateClusterRequest,
    };

    fn source(id: u32) -> DataSource {
        DataSource {
            id,
            name: "source".into(),
            server_name: "server".into(),
            address: "127.0.0.1:8080".parse().unwrap(),
            data_type: DataType::Csv,
            source: "payload".into(),
            kind: None,
            description: "description".into(),
        }
    }

    let (agent, manager) = agent_with_raw_manager(SessionOptions::legacy_compatible()).await;

    macro_rules! check {
        ($call:expr, $code:expr, $input:expr, $reply:expr) => {{
            let expected = bincode::serde::encode_to_vec(
                (($code as u32).to_le_bytes(), &$input),
                bincode::config::standard(),
            )
            .unwrap();
            let reply = bincode::serde::encode_to_vec($reply, bincode::config::standard()).unwrap();
            let (result, request) = tokio::join!($call, answer_raw_frame(&manager, &reply));
            assert_eq!(request, expected);
            result.unwrap();
        }};
    }

    let statistics: &[ColumnStatisticsUpdate] = &[];
    let time_series: &[TimeSeriesUpdate] = &[];
    let clusters: &[UpdateClusterRequest] = &[];
    let outliers: &[OutlierInfo] = &[];
    let events: &[DetectionEvent] = &[];
    let inserted_source = source(2);

    check!(
        agent.get_data_source(&DataSourceKey::Name("source")),
        0,
        DataSourceKey::Name("source"),
        Ok::<Option<DataSource>, String>(Some(source(1)))
    );
    check!(
        agent.get_indicator("indicator"),
        1,
        "indicator",
        Ok::<std::collections::HashSet<Vec<String>>, String>(std::collections::HashSet::default())
    );
    check!(
        agent.get_internal_network_list(),
        31,
        (),
        Ok::<HostNetworkGroup, String>(HostNetworkGroup::default())
    );
    check!(
        agent.get_labeldb_patterns(&[("labeldb", "pattern")]),
        15,
        &[("labeldb", "pattern")][..],
        Ok::<Vec<(String, Option<review_protocol::types::LabelDb>)>, String>(Vec::new())
    );
    check!(
        agent.get_tor_exit_node_list(),
        26,
        (),
        Ok::<Vec<String>, String>(Vec::new())
    );
    check!(
        agent.get_trusted_domain_list(),
        24,
        (),
        Ok::<Vec<String>, String>(Vec::new())
    );
    check!(
        agent.get_trusted_user_agent_list(),
        35,
        (),
        Ok::<Vec<String>, String>(Vec::new())
    );
    check!(
        agent.get_time_series_generation_policy_list(),
        39,
        (),
        Ok::<Vec<TimeSeriesGenerationPolicy>, String>(Vec::new())
    );
    check!(
        agent.renew_certificate(),
        23,
        (),
        Ok::<(String, String), String>(("certificate".into(), "key".into()))
    );
    check!(
        agent.insert_column_statistics(statistics, 7, 8),
        5,
        (statistics, 7_u32, 8_i64),
        Ok::<(), String>(())
    );
    check!(
        agent.insert_time_series(time_series, 7, 8),
        7,
        (time_series, 7_u32, 8_i64),
        Ok::<(), String>(())
    );
    check!(
        agent.update_clusters(clusters, 7),
        10,
        (clusters, 7_u32),
        Ok::<(), String>(())
    );
    check!(
        agent.update_outliers(outliers, 7, 8),
        12,
        (outliers, 7_u32, 8_i64),
        Ok::<(), String>(())
    );
    check!(
        agent.insert_detection_events(7, 8, events),
        13,
        (7_u32, 8_u32, events),
        Ok::<(), String>(())
    );
    check!(
        agent.insert_data_source(&inserted_source),
        20,
        inserted_source,
        Ok::<u32, String>(2)
    );
    check!(
        agent.get_outliers(7, 8),
        25,
        (7_u32, 8_i64),
        Ok::<Vec<(String, Vec<i64>)>, String>(Vec::new())
    );

    let reply = bincode::serde::encode_to_vec(
        Ok::<Option<DataSource>, String>(None),
        bincode::config::standard(),
    )
    .unwrap();
    let (result, _) = tokio::join!(
        agent.get_data_source(&DataSourceKey::Id(9)),
        answer_raw_frame(&manager, &reply)
    );
    assert!(result.unwrap().is_none());

    let reply = bincode::serde::encode_to_vec(
        Err::<Vec<String>, String>("list unavailable".into()),
        bincode::config::standard(),
    )
    .unwrap();
    let (result, _) = tokio::join!(
        agent.get_tor_exit_node_list(),
        answer_raw_frame(&manager, &reply)
    );
    assert!(matches!(
        result,
        Err(SessionError::RemoteRejection(message)) if message == "list unavailable"
    ));
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn typed_agent_dai_operations_preserve_legacy_request_codes_and_bodies() {
    use review_protocol::test;

    let (agent, manager) = agent_with_raw_manager(SessionOptions::legacy_compatible()).await;

    macro_rules! check {
        ($call:expr, $code:expr, $input:expr, $reply:expr) => {{
            let expected = bincode::serde::encode_to_vec(
                (($code as u32).to_le_bytes(), &$input),
                bincode::config::standard(),
            )
            .unwrap();
            let reply = bincode::serde::encode_to_vec($reply, bincode::config::standard()).unwrap();
            let (result, request) = tokio::join!($call, answer_raw_frame(&manager, &reply));
            assert_eq!(request, expected);
            result.unwrap();
        }};
    }

    let sensors = test::dai_sensors();
    let batch = test::dai_observation_batches().remove(0);
    let unit = test::dai_range_unit();
    let day = test::dai_range_days().remove(0);
    let late = test::dai_range_late();

    check!(
        agent.get_dai_extractor_config(&sensors),
        45,
        sensors,
        Ok::<review_protocol::types::DaiExtractorConfig, String>(test::dai_extractor_config())
    );
    check!(
        agent.get_dai_cursors(&sensors),
        46,
        sensors,
        Ok::<review_protocol::types::DaiCursors, String>(test::dai_cursors())
    );
    check!(
        agent.send_dai_observations(&batch),
        47,
        batch,
        Ok::<review_protocol::types::DaiStoreAck, String>(test::dai_store_acks().remove(0))
    );
    check!(
        agent.begin_dai_range_day(&unit, 7),
        48,
        (&unit, 7_u64),
        Ok::<review_protocol::types::DaiRangeGrant, String>(test::dai_range_grants().remove(0))
    );
    check!(
        agent.renew_dai_range_day(&unit, 7),
        49,
        (&unit, 7_u64),
        Ok::<Option<i64>, String>(Some(test::DAI_RENEWED_LEASE_END))
    );
    check!(
        agent.send_dai_range_day(&day),
        50,
        day,
        Ok::<review_protocol::types::DaiStoreAck, String>(test::dai_store_acks().remove(0))
    );
    check!(
        agent.report_dai_range_late(&late),
        51,
        late,
        Ok::<Vec<review_protocol::types::DaiRangeMark>, String>(test::dai_range_marks())
    );

    let reply = bincode::serde::encode_to_vec(
        Err::<review_protocol::types::DaiStoreAck, String>("store rejected".into()),
        bincode::config::standard(),
    )
    .unwrap();
    let (result, _) = tokio::join!(
        agent.send_dai_observations(&batch),
        answer_raw_frame(&manager, &reply)
    );
    assert!(matches!(
        result,
        Err(SessionError::RemoteRejection(message)) if message == "store rejected"
    ));
}

/// Checks that `agent` refuses both list pulls for `version` without sending
/// them: the first request `manager` then receives is `get_config`.
async fn assert_list_pulls_refused_locally(
    agent: &AgentHandle,
    manager: &Connection,
    version: &str,
) {
    for result in [
        agent.get_exclusion_list().await,
        agent.get_watchlist().await,
    ] {
        let error = result.unwrap_err();
        assert!(
            matches!(&error, SessionError::IncompatibleProtocol { version: v, required }
                if v == version && required == ">=0.50.0"),
            "{error:?}"
        );
    }
    let config =
        bincode::serde::encode_to_vec(Ok::<_, String>("cfg"), bincode::config::standard()).unwrap();
    let (code, ()) = tokio::join!(answer_raw(manager, &config), async {
        assert_eq!(agent.get_config().await.unwrap(), "cfg");
    });
    assert_eq!(code, 36, "no list pull reached the manager");
}

/// An agent that advertised `0.49.0` refuses its own exclusion-list and watchlist
/// pulls before sending them, even to a manager whose ceiling is `0.50.0`.
#[tokio::test]
async fn list_pulls_refuse_an_agent_advertising_0_49_0() {
    assert_legacy_list_reply_decodes_in_full();
    let options = SessionOptions::legacy_compatible();
    let (manager, node) = connections().await;
    let info = claims();
    assert_eq!(info.protocol_version, "0.49.0");
    let (server, agent) = tokio::join!(
        ServerHandle::from_transport(
            manager.clone(),
            options.clone(),
            ">=0.48.0",
            PROTOCOL_VERSION
        ),
        AgentHandle::from_transport(node, options, &info),
    );
    let _server = server.unwrap();
    let (agent, _) = agent.unwrap();
    assert_list_pulls_refused_locally(&agent, &manager, "0.49.0").await;
}

/// An agent that advertised `0.50.0` refuses its exclusion-list and watchlist pulls
/// before sending them when the manager's handshake reply is `0.49.0`.
#[tokio::test]
async fn list_pulls_refuse_a_manager_replying_0_49_0() {
    use oinq::frame::{FramedReader, FramedWriter};

    assert_legacy_list_reply_decodes_in_full();
    let options = SessionOptions::legacy_compatible();
    let (manager, node) = connections().await;
    let mut info = claims();
    info.protocol_version = PROTOCOL_VERSION.into();
    let ((), agent) = tokio::join!(
        async {
            let (send, recv) = manager.accept_bi().await.unwrap();
            let limit = FrameLimit::new(4096).unwrap();
            let mut reader = FramedReader::new(recv, limit);
            reader.read().await.unwrap().unwrap();
            let mut writer = FramedWriter::new(send, limit);
            writer.start(Ok::<_, String>("0.49.0".to_string())).unwrap();
            writer.flush().await.unwrap();
            writer.into_inner().finish().unwrap();
        },
        AgentHandle::from_transport(node, options, &info),
    );
    let (agent, _) = agent.unwrap();
    assert_list_pulls_refused_locally(&agent, &manager, "0.49.0").await;
}

#[tokio::test]
async fn time_sync_status_decodes_current_release_bytes() {
    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::types::node::{NodeTimeSyncRequest, NodeTimeSyncResponse};
    let (manager, agent) = raw_agent(SessionOptions::legacy_compatible(), "0.49.0").await;
    let (result, ()) = tokio::join!(manager.node_time_sync(NodeTimeSyncRequest::Status), async {
        let (send, recv) = agent.accept_bi().await.unwrap();
        let limit = FrameLimit::new(1024).unwrap();
        let mut reader = FramedReader::new(recv, limit);
        let frame = reader.read().await.unwrap().unwrap();
        assert_eq!(frame.into_bytes(), [103, 0, 0, 0, 4]);
        let mut writer = FramedWriter::new(send, limit);
        // Ok(Status), enabled, synchronized, Some("ntp"), Some(-12).
        // These bytes are independent of the session and legacy encoders.
        writer
            .start_raw(&[0, 1, 1, 1, 1, 3, b'n', b't', b'p', 1, 23])
            .unwrap();
        writer.flush().await.unwrap();
        writer.into_inner().finish().unwrap();
    });
    assert_eq!(
        result.unwrap(),
        NodeTimeSyncResponse::Status {
            enabled: true,
            synchronized: true,
            server: Some("ntp".into()),
            offset_micros: Some(-12),
        }
    );
}

#[tokio::test]
async fn agent_answers_unserved_and_undecodable_requests_like_the_legacy_dispatcher() {
    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::types::node::{NodeHostnameRequest, NodeHostnameResponse};
    let (_, mut incoming, manager, _) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let (send, recv) = manager.open_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut writer = FramedWriter::new(send, limit);
    let mut reader = FramedReader::new(recv, limit);
    let ((), ()) = tokio::join!(
        async {
            // An unknown code is rejected without consuming the stream.
            writer.start((999_u32.to_le_bytes(), ())).unwrap();
            writer.flush().await.unwrap();
            let answer = reader.read().await.unwrap().unwrap();
            assert_eq!(
                answer.decode::<Result<(), String>>().unwrap(),
                Err("unknown request code: 999".to_string())
            );
            // The stream continues after the unserved code.
            writer
                .start((
                    102_u32.to_le_bytes(),
                    NodeHostnameRequest::Set {
                        hostname: "served".into(),
                    },
                ))
                .unwrap();
            writer.flush().await.unwrap();
            let answer = reader.read().await.unwrap().unwrap();
            assert_eq!(
                answer
                    .decode::<Result<NodeHostnameResponse, String>>()
                    .unwrap(),
                Ok(NodeHostnameResponse::Done)
            );
            // Variant 200 does not exist: the arguments cannot be decoded.
            writer.start_raw(&[102, 0, 0, 0, 200]).unwrap();
            writer.flush().await.unwrap();
            let answer = reader.read().await.unwrap().unwrap();
            assert_eq!(
                answer.decode::<Result<(), String>>().unwrap(),
                Err(
                    "request code 102: the arguments could not be decoded; the manager and the \
                     agent may be built against different review-protocol releases"
                        .to_string()
                )
            );
            // The stream ends with FIN after the answer, not with a reset.
            assert!(reader.read().await.unwrap().is_none());
        },
        async {
            let mut stream = incoming.accept().await.unwrap();
            let AgentRequest::Hostname { reply, .. } = stream.next().await.unwrap().unwrap() else {
                panic!("wrong request");
            };
            reply.respond(Ok(NodeHostnameResponse::Done)).await.unwrap();
            let error = stream.next().await.err().unwrap();
            assert!(matches!(
                error,
                SessionError::Malformed {
                    certainty: None,
                    ..
                }
            ));
        }
    );
}

#[tokio::test]
async fn agent_list_pushes_reject_trailing_bytes_like_the_legacy_dispatcher() {
    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::types::{HostNetworkGroup, NetworkListItem};

    let group = HostNetworkGroup {
        hosts: Vec::new(),
        networks: vec!["192.0.2.0/24".parse().unwrap()],
        ip_ranges: Vec::new(),
    };
    let body = bincode::serde::encode_to_vec(&group, bincode::config::standard()).unwrap();
    let (prefix, _) = bincode::serde::decode_from_slice::<Vec<NetworkListItem>, _>(
        &body,
        bincode::config::standard(),
    )
    .unwrap();
    assert_eq!(prefix, Vec::<NetworkListItem>::new());
    let (_, mut incoming, manager, _) = raw_sessions(SessionOptions::legacy_compatible()).await;
    for code in [15_u32, 16] {
        let (send, recv) = manager.open_bi().await.unwrap();
        let limit = FrameLimit::new(1024).unwrap();
        let mut writer = FramedWriter::new(send, limit);
        let mut reader = FramedReader::new(recv, limit);
        let ((), ()) = tokio::join!(
            async {
                // A legacy group with no hosts is an empty item-list prefix plus trailing data.
                let mut frame = code.to_le_bytes().to_vec();
                frame.extend(&body);
                writer.start_raw(&frame).unwrap();
                writer.flush().await.unwrap();
                assert_eq!(
                    reader
                        .read()
                        .await
                        .unwrap()
                        .unwrap()
                        .decode::<Result<(), String>>()
                        .unwrap(),
                    Err(format!(
                        "request code {code}: the arguments could not be decoded; the manager and the agent may be built against different review-protocol releases"
                    ))
                );
                assert!(reader.read().await.unwrap().is_none());
            },
            async {
                let mut stream = incoming.accept().await.unwrap();
                assert!(matches!(
                    stream.next_command().await,
                    Err(SessionError::Malformed { .. })
                ));
                assert!(stream.next_command().await.is_err());
            }
        );
    }
}

#[tokio::test]
async fn manager_answers_unserved_codes_like_the_legacy_dispatcher() {
    use oinq::frame::{FramedReader, FramedWriter};
    let (mut incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let (send, recv) = node.open_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut writer = FramedWriter::new(send, limit);
    let mut reader = FramedReader::new(recv, limit);
    let ((), ()) = tokio::join!(
        async {
            for code in [999_u32, 23, 36] {
                writer.start((code.to_le_bytes(), ())).unwrap();
                writer.flush().await.unwrap();
            }
            writer.into_inner().finish().unwrap();
            for _ in 0..2 {
                let answer = reader.read().await.unwrap().unwrap();
                assert_eq!(
                    answer.decode::<Result<String, String>>().unwrap(),
                    Err("unknown request code".to_string())
                );
            }
            let answer = reader.read().await.unwrap().unwrap();
            assert_eq!(
                answer.decode::<Result<String, String>>().unwrap(),
                Ok("configuration".to_string())
            );
            assert!(reader.read().await.unwrap().is_none());
        },
        async {
            let mut stream = request_stream(&mut incoming).await;
            let ServerRequest::GetConfig { reply, .. } = stream.next().await.unwrap().unwrap()
            else {
                panic!("wrong request");
            };
            reply.respond(Ok("configuration".into())).await.unwrap();
            assert!(stream.next().await.unwrap().is_none());
        }
    );
}

#[tokio::test]
async fn undecodable_event_leaves_the_stream_aligned() {
    let (mut incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let event = detection_event(3.0);
    let payload = bincode::serde::encode_to_vec(&event, bincode::config::standard()).unwrap();
    let mut send = node.open_uni().await.unwrap();
    send.write_all(&[0, 0]).await.unwrap();
    // A frame that is complete but does not decode as an event.
    send.write_all(&1_u32.to_be_bytes()).await.unwrap();
    send.write_all(&[255]).await.unwrap();
    send.write_all(&u32::try_from(payload.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    send.write_all(&payload).await.unwrap();
    send.finish().unwrap();
    let mut sequence = event_stream(&mut incoming).await;
    assert!(matches!(
        sequence.next().await,
        Err(SessionError::Malformed { .. })
    ));
    assert_eq!(sequence.next().await.unwrap().unwrap(), event);
    assert!(sequence.next().await.unwrap().is_none());
}

#[tokio::test]
async fn install_failure_is_answered_after_draining_the_payload() {
    use review_protocol::types::node::NodePackageResponse;
    let mut options = SessionOptions::legacy_compatible();
    options.package_chunks = FrameLimit::new(1024).unwrap();
    let (server, _, _, mut incoming) = sessions(options).await;
    let mut source = std::io::Cursor::new(vec![3; 4000]);
    let (result, ()) = tokio::join!(
        server.node_package_install(install_request(4000), &mut source),
        async {
            let mut stream = incoming.accept().await.unwrap();
            let AgentRequest::Package { reply, .. } = stream.next().await.unwrap().unwrap() else {
                panic!("wrong request");
            };
            let mut transfer = reply
                .preflight(Ok(InstallPreflight::Proceed))
                .await
                .unwrap()
                .unwrap();
            let mut buffer = Vec::new();
            assert!(transfer.next_chunk(&mut buffer).await.unwrap());
            // Storing failed after the first chunk; the rest is drained.
            transfer
                .respond(Err::<NodePackageResponse, _>("disk full".into()))
                .await
                .unwrap();
            assert!(stream.next().await.unwrap().is_none());
        }
    );
    assert!(matches!(result, Err(SessionError::RemoteRejection(text)) if text == "disk full"));
    assert_eq!(source.position(), 4000);
}

#[tokio::test]
async fn undecodable_or_oversized_response_after_sending_is_unknown() {
    use oinq::frame::{FramedReader, FramedWriter};
    let mut options = SessionOptions::legacy_compatible();
    options.unary = FrameLimit::new(64).unwrap();
    let (manager, node) = connections().await;
    let info = claims();
    let (server, agent) = tokio::join!(
        ServerHandle::from_transport(manager.clone(), options.clone(), ">=0.48.0", "0.49.0"),
        AgentHandle::from_transport(node, options, &info),
    );
    // Keep the manager session alive without accepting its streams.
    let _server = server.unwrap();
    let (agent, _) = agent.unwrap();
    for response in [vec![7_u8], vec![0; 65]] {
        let (result, ()) = tokio::join!(agent.get_config(), async {
            let (send, recv) = manager.accept_bi().await.unwrap();
            let limit = FrameLimit::new(1024).unwrap();
            let mut reader = FramedReader::new(recv, limit);
            let mut writer = FramedWriter::new(send, limit);
            reader.read().await.unwrap().unwrap();
            writer.start_raw(&response).unwrap();
            writer.flush().await.unwrap();
            let _ = writer.into_inner().finish();
        });
        let error = result.unwrap_err();
        assert!(matches!(
            error,
            SessionError::Malformed { .. } | SessionError::LimitExceeded { .. }
        ));
        assert_eq!(error.certainty(), Some(OutcomeCertainty::Unknown));
    }
    // An oversized local request is refused before anything is sent.
    let error = agent.upload_run_model(1, &[0; 128]).await.unwrap_err();
    assert!(matches!(error, SessionError::LimitExceeded { .. }));
    assert_eq!(error.certainty(), Some(OutcomeCertainty::NotSent));
}

#[tokio::test]
async fn incomplete_install_cannot_send_a_terminal_success() {
    use review_protocol::types::node::NodePackageResponse;
    let mut options = SessionOptions::legacy_compatible();
    options.package_chunks = FrameLimit::new(1024).unwrap();
    let (server, _, _, mut incoming) = sessions(options).await;
    let (result, ()) = tokio::join!(
        server.node_package_install(install_request(4000), std::io::Cursor::new(vec![3; 4000])),
        async {
            let mut stream = incoming.accept().await.unwrap();
            let AgentRequest::Package { reply, .. } = stream.next().await.unwrap().unwrap() else {
                panic!("wrong request");
            };
            let mut transfer = reply
                .preflight(Ok(InstallPreflight::Proceed))
                .await
                .unwrap()
                .unwrap();
            let mut buffer = Vec::new();
            assert!(transfer.next_chunk(&mut buffer).await.unwrap());
            assert!(matches!(
                transfer.respond(Ok(NodePackageResponse::Done)).await,
                Err(SessionError::Malformed { .. })
            ));
        }
    );
    assert!(matches!(
        result,
        Err(SessionError::Transport {
            certainty: OutcomeCertainty::Unknown,
            ..
        })
    ));
}

#[path = "session_transport/server_integration.rs"]
mod server_integration;
#[path = "session_transport/server_processing.rs"]
mod server_processing;
#[path = "session_transport/server_pushes.rs"]
mod server_pushes;

#[tokio::test]
async fn split_report_run_resumes_a_partial_response_frame() {
    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::types::ReportedRunState;
    use tokio::io::AsyncWriteExt;

    let (agent, manager) = agent_with_raw_manager(SessionOptions::legacy_compatible()).await;
    let mut exchange = agent
        .start_report_run(42, ReportedRunState::Failed, Some("reason"))
        .await
        .unwrap();
    let (send, recv) = manager.accept_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut reader = FramedReader::new(recv, limit);
    let send = FramedWriter::new(send, limit);
    let request = reader.read().await.unwrap().unwrap();
    let expected = bincode::serde::encode_to_vec(
        (
            42_u32.to_le_bytes(),
            (42_u32, ReportedRunState::Failed, Some("reason")),
        ),
        bincode::config::standard(),
    )
    .unwrap();
    assert_eq!(request.as_bytes(), expected);

    let mut send = send.into_inner();
    send.write_all(&[0, 0]).await.unwrap();
    {
        let response = exchange.response();
        tokio::pin!(response);
        assert!(
            tokio_test::task::spawn(response.as_mut())
                .poll()
                .is_pending()
        );
    }
    send.write_all(&[0, 1, 0]).await.unwrap();
    send.finish().unwrap();
    exchange.response().await.unwrap();
    assert!(reader.read().await.unwrap().is_none());
}

#[tokio::test]
async fn split_report_run_response_deadline_is_unknown_and_resumable() {
    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::types::ReportedRunState;

    let mut options = SessionOptions::legacy_compatible();
    options.operation_timeout = Some(Duration::from_millis(50));
    let (agent, manager) = agent_with_raw_manager(options).await;
    let mut exchange = agent
        .start_report_run(42, ReportedRunState::Started, None)
        .await
        .unwrap();
    let (send, recv) = manager.accept_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut reader = FramedReader::new(recv, limit);
    let mut writer = FramedWriter::new(send, limit);
    reader.read().await.unwrap().unwrap();
    assert!(matches!(
        exchange.response().await,
        Err(SessionError::Deadline {
            certainty: OutcomeCertainty::Unknown,
            ..
        })
    ));
    let rejection = bincode::serde::encode_to_vec(
        Err::<(), String>("rejected".into()),
        bincode::config::standard(),
    )
    .unwrap();
    writer.start_raw(&rejection).unwrap();
    writer.flush().await.unwrap();
    writer.into_inner().finish().unwrap();
    assert!(matches!(
        exchange.response().await,
        Err(SessionError::RemoteRejection(message)) if message == "rejected"
    ));
}

#[tokio::test]
async fn dropping_report_run_exchange_aborts_both_directions() {
    use oinq::frame::FramedReader;
    use review_protocol::types::ReportedRunState;

    let (agent, manager) = agent_with_raw_manager(SessionOptions::legacy_compatible()).await;
    let exchange = agent
        .start_report_run(42, ReportedRunState::Started, None)
        .await
        .unwrap();
    let (send, recv) = manager.accept_bi().await.unwrap();
    let mut reader = FramedReader::new(recv, FrameLimit::new(1024).unwrap());
    reader.read().await.unwrap().unwrap();
    drop(exchange);
    assert_eq!(send.stopped().await.unwrap().unwrap().get(), 1);
    let mut recv = reader.into_inner();
    assert!(recv.read(&mut [0]).await.is_err());
}

#[tokio::test]
async fn update_config_command_reaches_agent_request_stream() {
    let (server, _, _, mut incoming) = sessions(SessionOptions::legacy_compatible()).await;
    let (result, ()) = tokio::join!(server.send_config_update_cmd(), async {
        let mut stream = incoming.accept().await.unwrap();
        let AgentCommand::UpdateConfig { reply, .. } =
            stream.next_command().await.unwrap().unwrap()
        else {
            panic!("wrong request");
        };
        reply.respond(Ok(())).await.unwrap();
        stream.finish().unwrap();
    });
    result.unwrap();
}

#[tokio::test]
async fn signature_rule_command_reaches_authorized_agent_runner() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::{
        auth::{AuthorizationContext, PeerContext},
        request::Handler,
        service_id,
        types::SignatureRules,
    };

    struct Policy;
    impl review_protocol::auth::AuthorizerV2 for Policy {
        fn authorize_with_context(
            &self,
            _context: &AuthorizationContext,
            service: &review_protocol::service_id::ServiceId,
        ) -> Result<(), review_protocol::auth::AuthorizationError> {
            assert_eq!(*service, service_id::COMMON_SIGNATURE_RULES);
            Ok(())
        }
    }

    struct CountingHandler(AtomicUsize);
    #[async_trait::async_trait]
    impl Handler for CountingHandler {
        async fn signature_rules(&mut self, rules: SignatureRules) -> Result<(), String> {
            assert_eq!(rules.revision, 7);
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let rules = SignatureRules {
        revision: 7,
        sets: Vec::new(),
        disabled_rules: Vec::new(),
    };
    let (_, mut incoming, manager, _) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let (send, recv) = manager.open_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut writer = FramedWriter::new(send, limit);
    let mut reader = FramedReader::new(recv, limit);
    let mut handler = CountingHandler(AtomicUsize::new(0));
    let context = AuthorizationContext::from_peer_context(&PeerContext::new("manager"));
    let policy = Policy;
    let ((), ()) = tokio::join!(
        async {
            writer.start((27_u32.to_le_bytes(), &rules)).unwrap();
            writer.flush().await.unwrap();
            assert_eq!(
                reader
                    .read()
                    .await
                    .unwrap()
                    .unwrap()
                    .decode::<Result<(), String>>()
                    .unwrap(),
                Ok(())
            );
            writer.into_inner().finish().unwrap();
        },
        async {
            incoming
                .accept()
                .await
                .unwrap()
                .run_authorized(&mut handler, &context, &policy)
                .await
                .unwrap();
        }
    );
    assert_eq!(handler.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn hog_event_message_wire_shape_is_preserved() {
    #[derive(serde::Serialize)]
    enum HogKind {
        DnsCovertChannel,
    }
    #[derive(serde::Serialize)]
    // Mirrors Hog output::EventMessage, including serde_bytes serialization.
    struct HogEvent {
        time: i64,
        kind: HogKind,
        #[serde(with = "serde_bytes")]
        fields: Vec<u8>,
    }
    let (server, agent) = connections().await;
    let info = claims();
    let (_, agent) = tokio::join!(
        ServerHandle::from_transport(
            server.clone(),
            SessionOptions::legacy_compatible(),
            ">=0.48.0",
            "0.49.0"
        ),
        AgentHandle::from_transport(agent, SessionOptions::legacy_compatible(), &info),
    );
    let (agent, _) = agent.unwrap();
    let ((), ()) = tokio::join!(
        async {
            let mut sender = agent.open_detection_event_stream().await.unwrap();
            sender
                .start_serialized(&HogEvent {
                    time: 1,
                    kind: HogKind::DnsCovertChannel,
                    fields: vec![1, 2],
                })
                .unwrap();
            sender.finish().await.unwrap();
        },
        async {
            let mut stream = server.accept_uni().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, [0, 0, 0, 0, 0, 5, 2, 0, 2, 1, 2]);
        }
    );
}

#[tokio::test]
async fn agent_runner_authorizes_each_command_on_one_stream() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::{
        auth::{AuthorizationContext, AuthorizationError, AuthorizerV2, PeerContext},
        service_id::{self, ServiceId},
    };
    struct Policy(AtomicUsize);
    impl AuthorizerV2 for Policy {
        fn authorize_with_context(
            &self,
            _context: &AuthorizationContext,
            service: &ServiceId,
        ) -> Result<(), AuthorizationError> {
            assert_eq!(*service, service_id::COMMON_UPDATE_CONFIG);
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(AuthorizationError::new("denied"))
            }
        }
    }
    struct Handler(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl review_protocol::request::Handler for Handler {
        async fn update_config(&mut self) -> Result<(), String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let (_, mut incoming, manager, _) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let (send, recv) = manager.open_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut writer = FramedWriter::new(send, limit);
    let mut reader = FramedReader::new(recv, limit);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handler = Handler(calls.clone());
    let context = AuthorizationContext::from_peer_context(&PeerContext::new("manager"));
    let policy = Policy(AtomicUsize::new(0));
    let ((), ()) = tokio::join!(
        async {
            for expected in [Ok(()), Err("authorization denied".to_string())] {
                writer.start((12_u32.to_le_bytes(), ())).unwrap();
                writer.flush().await.unwrap();
                assert_eq!(
                    reader
                        .read()
                        .await
                        .unwrap()
                        .unwrap()
                        .decode::<Result<(), String>>()
                        .unwrap(),
                    expected
                );
            }
            writer.into_inner().finish().unwrap();
        },
        async {
            let stream = incoming.accept().await.unwrap();
            let error = stream
                .run_authorized(&mut handler, &context, &policy)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                AgentRunError::AuthorizationDenied { service, source }
                    if service == service_id::COMMON_UPDATE_CONFIG
                        && source.to_string() == "authorization denied: denied"
            ));
            assert_eq!(policy.0.load(Ordering::SeqCst), 2);
        }
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn agent_runner_immediate_power_denial_is_typed_and_has_no_response() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::{
        auth::{AuthorizationContext, AuthorizationError, AuthorizerV2, PeerContext},
        request::Handler,
        service_id::{self, ServiceId},
    };

    struct Policy;
    impl AuthorizerV2 for Policy {
        fn authorize_with_context(
            &self,
            _context: &AuthorizationContext,
            service: &ServiceId,
        ) -> Result<(), AuthorizationError> {
            assert_eq!(*service, service_id::NODE_POWER_REBOOT);
            Err(AuthorizationError::new("private policy detail"))
        }
    }

    struct CountingHandler(AtomicUsize);
    #[async_trait::async_trait]
    impl Handler for CountingHandler {
        async fn node_power(
            &mut self,
            _request: NodePowerRequest,
        ) -> Result<review_protocol::types::node::NodePowerResponse, String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(review_protocol::types::node::NodePowerResponse::Initiated)
        }
    }

    let (_, mut incoming, manager, _) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let (send, recv) = manager.open_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut writer = FramedWriter::new(send, limit);
    let mut reader = FramedReader::new(recv, limit);
    let mut handler = CountingHandler(AtomicUsize::new(0));
    let context = AuthorizationContext::from_peer_context(&PeerContext::new("manager"));
    let policy = Policy;
    let ((), ()) = tokio::join!(
        async {
            writer
                .start((106_u32.to_le_bytes(), NodePowerRequest::Reboot))
                .unwrap();
            writer.flush().await.unwrap();
            assert!(reader.read().await.unwrap().is_none());
            writer.into_inner().finish().unwrap();
        },
        async {
            let error = incoming
                .accept()
                .await
                .unwrap()
                .run_authorized(&mut handler, &context, &policy)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                AgentRunError::AuthorizationDenied { service, source }
                    if service == service_id::NODE_POWER_REBOOT
                        && source.to_string() == "authorization denied: private policy detail"
            ));
        }
    );
    assert_eq!(handler.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn agent_runner_oversized_response_after_handler_is_unknown() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::{
        auth::{AuthorizationContext, AuthorizerV2Adapter, NoopAuthorizer, PeerContext},
        request::Handler,
        types::node::{NodeHostnameRequest, NodeHostnameResponse},
    };

    struct HostnameHandler(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl Handler for HostnameHandler {
        async fn node_hostname(
            &mut self,
            request: NodeHostnameRequest,
        ) -> Result<NodeHostnameResponse, String> {
            assert_eq!(
                request,
                NodeHostnameRequest::Set {
                    hostname: "a".into()
                }
            );
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(NodeHostnameResponse::Get {
                hostname: "x".repeat(128),
            })
        }
    }

    let mut options = SessionOptions::legacy_compatible();
    options.unary = FrameLimit::new(32).unwrap();
    let (_, mut incoming, manager, _) = raw_sessions(options).await;
    let (send, recv) = manager.open_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut writer = FramedWriter::new(send, limit);
    let _reader = FramedReader::new(recv, limit);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handler = HostnameHandler(calls.clone());
    let context = AuthorizationContext::from_peer_context(&PeerContext::new("manager"));
    let policy = AuthorizerV2Adapter::new(NoopAuthorizer);
    let (result, ()) = tokio::join!(
        async {
            incoming
                .accept()
                .await
                .unwrap()
                .run_authorized(&mut handler, &context, &policy)
                .await
        },
        async {
            writer
                .start((
                    102_u32.to_le_bytes(),
                    NodeHostnameRequest::Set {
                        hostname: "a".into(),
                    },
                ))
                .unwrap();
            writer.flush().await.unwrap();
            writer.into_inner().finish().unwrap();
        }
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        result,
        Err(AgentRunError::Session(SessionError::LimitExceeded {
            certainty: Some(OutcomeCertainty::Unknown),
            ..
        }))
    ));
}

#[tokio::test]
async fn agent_runner_preserves_typed_denial_when_peer_disconnects() {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, Sender},
    };

    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::{
        auth::{AuthorizationContext, AuthorizationError, AuthorizerV2, PeerContext},
        request::Handler,
        service_id::{self, ServiceId},
    };

    struct Policy {
        notify: Sender<()>,
        dropped: Mutex<Receiver<()>>,
    }
    impl AuthorizerV2 for Policy {
        fn authorize_with_context(
            &self,
            _context: &AuthorizationContext,
            service: &ServiceId,
        ) -> Result<(), AuthorizationError> {
            assert_eq!(*service, service_id::COMMON_UPDATE_CONFIG);
            self.notify.send(()).unwrap();
            self.dropped.lock().unwrap().recv().unwrap();
            Err(AuthorizationError::new("private policy detail"))
        }
    }

    struct CountingHandler(AtomicUsize);
    #[async_trait::async_trait]
    impl Handler for CountingHandler {
        async fn update_config(&mut self) -> Result<(), String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let (_server_incoming, mut incoming, manager, _node) =
        raw_sessions(SessionOptions::legacy_compatible()).await;
    let (send, recv) = manager.open_bi().await.unwrap();
    let limit = FrameLimit::new(1024).unwrap();
    let mut writer = FramedWriter::new(send, limit);
    let reader = FramedReader::new(recv, limit);
    let (notify, authorized) = std::sync::mpsc::channel();
    let (dropped, disconnected) = std::sync::mpsc::channel();
    let connection = std::thread::spawn(move || {
        authorized.recv().unwrap();
        drop(manager);
        dropped.send(()).unwrap();
    });
    let policy = Policy {
        notify,
        dropped: Mutex::new(disconnected),
    };
    let mut handler = CountingHandler(AtomicUsize::new(0));
    let context = AuthorizationContext::from_peer_context(&PeerContext::new("manager"));
    let ((), error) = tokio::join!(
        async {
            writer.start((12_u32.to_le_bytes(), ())).unwrap();
            writer.flush().await.unwrap();
        },
        async {
            tokio::time::timeout(Duration::from_secs(5), async {
                incoming
                    .accept()
                    .await
                    .unwrap()
                    .run_authorized(&mut handler, &context, &policy)
                    .await
            })
            .await
            .unwrap()
        }
    );
    connection.join().unwrap();
    drop(writer);
    drop(reader);
    assert!(matches!(
        error,
        Err(AgentRunError::AuthorizationDenied { service, source })
            if service == service_id::COMMON_UPDATE_CONFIG
                && source.to_string() == "authorization denied: private policy detail"
    ));
    assert_eq!(handler.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn agent_node_runner_rejects_non_node_commands_drains_package_and_continues() {
    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::{
        auth::{AuthorizationContext, AuthorizerV2Adapter, NoopAuthorizer, PeerContext},
        request::{NodeHandler, PackageReader},
        types::node::NodePackageResponse,
    };
    struct Handler;
    #[async_trait::async_trait]
    impl NodeHandler for Handler {
        async fn node_package_install_preflight(
            &mut self,
            _: &NodePackageRequest,
        ) -> Result<InstallPreflight, String> {
            Ok(InstallPreflight::Proceed)
        }
        async fn node_package_install(
            &mut self,
            _: NodePackageRequest,
            reader: &mut PackageReader<'_>,
        ) -> Result<NodePackageResponse, String> {
            assert_eq!((reader.size(), reader.remaining()), (3, 3));
            let mut chunk = Vec::new();
            assert!(reader.next_chunk(&mut chunk).await.unwrap());
            assert_eq!(chunk, b"a");
            assert_eq!(reader.remaining(), 2);
            Ok(NodePackageResponse::Done)
        }
    }
    let (_, mut incoming, manager, _) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let (send, recv) = manager.open_bi().await.unwrap();
    let limit = FrameLimit::new(4096).unwrap();
    let mut writer = FramedWriter::new(send, limit);
    let mut reader = FramedReader::new(recv, limit);
    let context = AuthorizationContext::from_peer_context(&PeerContext::new("manager"));
    let policy = AuthorizerV2Adapter::new(NoopAuthorizer);
    let ((), ()) = tokio::join!(
        async {
            for code in [
                0_u32, 1, 2, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27,
            ] {
                writer.start((code.to_le_bytes(), ())).unwrap();
                writer.flush().await.unwrap();
                assert_eq!(
                    reader
                        .read()
                        .await
                        .unwrap()
                        .unwrap()
                        .decode::<Result<(), String>>()
                        .unwrap(),
                    Err(format!("unknown request code: {code}"))
                );
            }
            writer
                .start((109_u32.to_le_bytes(), install_request(3)))
                .unwrap();
            writer.flush().await.unwrap();
            assert_eq!(
                reader
                    .read()
                    .await
                    .unwrap()
                    .unwrap()
                    .decode::<Result<InstallPreflight, String>>()
                    .unwrap(),
                Ok(InstallPreflight::Proceed)
            );
            for chunk in [b"a".as_slice(), b"bc".as_slice()] {
                writer.start_raw(chunk).unwrap();
                writer.flush().await.unwrap();
            }
            assert_eq!(
                reader
                    .read()
                    .await
                    .unwrap()
                    .unwrap()
                    .decode::<Result<NodePackageResponse, String>>()
                    .unwrap(),
                Ok(NodePackageResponse::Done)
            );
            writer.start((17_u32.to_le_bytes(), ())).unwrap();
            writer.flush().await.unwrap();
            assert_eq!(
                reader
                    .read()
                    .await
                    .unwrap()
                    .unwrap()
                    .decode::<Result<(), String>>()
                    .unwrap(),
                Err("unknown request code: 17".into())
            );
            writer.into_inner().finish().unwrap();
        },
        async {
            incoming
                .accept()
                .await
                .unwrap()
                .run_node_authorized(&mut Handler, &context, &policy)
                .await
                .unwrap();
        }
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn agent_package_reader_preserves_legacy_io_error_kinds() {
    use std::sync::Mutex;

    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::{
        auth::{AuthorizationContext, AuthorizerV2Adapter, NoopAuthorizer, PeerContext},
        request::{NodeHandler, PackageReader},
        types::node::NodePackageResponse,
    };
    use tokio::io::AsyncWriteExt;

    struct Handler(Arc<Mutex<Vec<std::io::ErrorKind>>>);
    #[async_trait::async_trait]
    impl NodeHandler for Handler {
        async fn node_package_install_preflight(
            &mut self,
            _: &NodePackageRequest,
        ) -> Result<InstallPreflight, String> {
            Ok(InstallPreflight::Proceed)
        }

        async fn node_package_install(
            &mut self,
            _: NodePackageRequest,
            reader: &mut PackageReader<'_>,
        ) -> Result<NodePackageResponse, String> {
            let mut chunk = Vec::new();
            loop {
                match reader.next_chunk(&mut chunk).await {
                    Ok(true) => {}
                    Ok(false) => panic!("payload ended before the expected error"),
                    Err(error) => {
                        self.0.lock().unwrap().push(error.kind());
                        break;
                    }
                }
            }
            Err("handler failure".into())
        }
    }

    for (size, payload, expected) in [
        (
            3_u64,
            vec![0, 0, 0, 1, b'a'],
            std::io::ErrorKind::UnexpectedEof,
        ),
        (
            1_u64,
            vec![0, 0, 0, 2, b'a', b'b'],
            std::io::ErrorKind::InvalidData,
        ),
        (
            3_u64,
            vec![0, 0, 0, 2, b'a'],
            std::io::ErrorKind::UnexpectedEof,
        ),
    ] {
        let (_, mut incoming, manager, _) = raw_sessions(SessionOptions::legacy_compatible()).await;
        let (send, recv) = manager.open_bi().await.unwrap();
        let limit = FrameLimit::new(4096).unwrap();
        let mut writer = FramedWriter::new(send, limit);
        let mut reader = FramedReader::new(recv, limit);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut handler = Handler(seen.clone());
        let context = AuthorizationContext::from_peer_context(&PeerContext::new("manager"));
        let policy = AuthorizerV2Adapter::new(NoopAuthorizer);
        let (result, ()) = tokio::join!(
            async {
                incoming
                    .accept()
                    .await
                    .unwrap()
                    .run_node_authorized(&mut handler, &context, &policy)
                    .await
            },
            async {
                writer
                    .start((109_u32.to_le_bytes(), install_request(size)))
                    .unwrap();
                writer.flush().await.unwrap();
                assert_eq!(
                    reader
                        .read()
                        .await
                        .unwrap()
                        .unwrap()
                        .decode::<Result<InstallPreflight, String>>()
                        .unwrap(),
                    Ok(InstallPreflight::Proceed)
                );
                let mut send = writer.into_inner();
                send.write_all(&payload).await.unwrap();
                send.finish().unwrap();
                assert_eq!(
                    reader
                        .read()
                        .await
                        .unwrap()
                        .unwrap()
                        .decode::<Result<NodePackageResponse, String>>()
                        .unwrap(),
                    Err("handler failure".into())
                );
            }
        );
        result.unwrap();
        assert_eq!(*seen.lock().unwrap(), [expected]);
    }
}

#[tokio::test]
async fn commands_progress_while_agent_request_and_event_are_open() {
    use review_protocol::types::node::{NodeHostnameRequest, NodeHostnameResponse};
    let (server, mut server_incoming, agent, mut agent_incoming) =
        sessions(SessionOptions::legacy_compatible()).await;
    let event = detection_event(1.0);
    let (config, hostname, (), ()) = tokio::join!(
        agent.get_config(),
        server.node_hostname(NodeHostnameRequest::Get),
        async {
            let mut command = agent_incoming.accept().await.unwrap();
            let AgentRequest::Hostname { reply, .. } = command.next().await.unwrap().unwrap()
            else {
                panic!("expected hostname");
            };
            reply
                .respond(Ok(NodeHostnameResponse::Get {
                    hostname: "node".into(),
                }))
                .await
                .unwrap();
            command.finish().unwrap();
        },
        async {
            let mut events = agent.open_detection_event_stream().await.unwrap();
            events.start(&event).unwrap();
            events.flush().await.unwrap();
            let mut answered_config = false;
            let mut answered_event = false;
            while !answered_config || !answered_event {
                match server_incoming.accept().await.unwrap() {
                    ServerStream::Requests(mut stream) => {
                        let Some(ServerRequest::GetConfig { reply, .. }) =
                            stream.next().await.unwrap()
                        else {
                            panic!("expected config");
                        };
                        reply.respond(Ok("config".into())).await.unwrap();
                        stream.finish().unwrap();
                        answered_config = true;
                    }
                    ServerStream::DetectionEvents(mut stream) => {
                        assert!(stream.next().await.unwrap().is_some());
                        answered_event = true;
                    }
                }
            }
            events.finish().await.unwrap();
        }
    );
    assert_eq!(config.unwrap(), "config");
    assert_eq!(
        hostname.unwrap(),
        NodeHostnameResponse::Get {
            hostname: "node".into()
        }
    );
}

#[tokio::test]
async fn event_sender_resumes_after_backpressure() {
    let (manager, node) = connections().await;
    let mut options = SessionOptions::legacy_compatible();
    options.detection_events = FrameLimit::new(32 * 1024 * 1024).unwrap();
    let info = claims();
    let (manager_session, agent_session) = tokio::join!(
        ServerHandle::from_transport(manager.clone(), options.clone(), ">=0.48.0", "0.49.0"),
        AgentHandle::from_transport(node, options, &info)
    );
    let _server = manager_session.unwrap();
    let (agent, _) = agent_session.unwrap();
    let mut sender = agent.open_detection_event_stream().await.unwrap();
    let payload = vec![42_u8; 24 * 1024 * 1024];
    sender.start_serialized(&payload).unwrap();
    assert!(sender.start_serialized(&payload).is_err());
    {
        let flush = sender.flush();
        tokio::pin!(flush);
        assert!(tokio_test::task::spawn(flush.as_mut()).poll().is_pending());
    }
    let (result, received) = tokio::join!(
        async {
            sender.flush().await.unwrap();
            sender.finish().await
        },
        async {
            let mut recv = manager.accept_uni().await.unwrap();
            let mut bytes = Vec::new();
            recv.read_to_end(&mut bytes).await.unwrap();
            bytes
        }
    );
    result.unwrap();
    assert_eq!(&received[..2], &[0, 0]);
    let decoded: (Vec<u8>, _) =
        bincode::serde::decode_from_slice(&received[6..], bincode::config::standard()).unwrap();
    assert_eq!(decoded.0, payload);
}

#[tokio::test]
async fn dropping_event_sender_aborts_stream() {
    let (manager, node) = connections().await;
    let info = claims();
    let (server, agent) = tokio::join!(
        ServerHandle::from_transport(
            manager.clone(),
            SessionOptions::legacy_compatible(),
            ">=0.48.0",
            "0.49.0"
        ),
        AgentHandle::from_transport(node, SessionOptions::legacy_compatible(), &info)
    );
    let _server = server.unwrap();
    let (agent, _) = agent.unwrap();
    let sender = agent.open_detection_event_stream().await.unwrap();
    let mut recv = manager.accept_uni().await.unwrap();
    drop(sender);
    let mut bytes = Vec::new();
    assert!(recv.read_to_end(&mut bytes).await.is_err());
}
