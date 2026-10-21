//! External session API fixtures deliberately import no Quinn types.
#![cfg(all(feature = "client", feature = "server"))]
// Test assertions and local transport setup deliberately panic on failure.
#![allow(clippy::unwrap_used)]

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use review_protocol::{
    AgentInfo,
    session::{
        AgentHandle, AgentIncoming, AgentRequest, ApplicationCode, CloseReason, Connection,
        Endpoint, EventReceiver, FrameLimit, OutcomeCertainty, ServerHandle, ServerIncoming,
        ServerRequest, ServerRequestStream, ServerStream, SessionError, SessionOptions,
        TransportOptions,
    },
    types::{
        ManifestFormatRange, Status,
        node::{InstallPreflight, NodePackageRequest, NodePowerRequest, NodePowerResponse},
    },
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    let (server, agent) = connections().await;
    let claims = claims();
    let (server, agent) = tokio::join!(
        ServerHandle::from_transport(server, options.clone(), ">=0.48.0", "0.49.0"),
        AgentHandle::from_transport(agent, options, &claims)
    );
    let (server, server_incoming) = server.unwrap();
    let (agent, agent_incoming) = agent.unwrap();
    (server, server_incoming, agent, agent_incoming)
}

async fn raw_agent(options: SessionOptions) -> (ServerHandle, Connection) {
    let (server, agent) = connections().await;
    let claims = claims();
    let (server, _) = tokio::join!(
        ServerHandle::from_transport(server, options.clone(), ">=0.48.0", "0.49.0"),
        AgentHandle::from_transport(agent.clone(), options, &claims)
    );
    (server.unwrap().0, agent)
}

async fn request_stream(incoming: &mut ServerIncoming) -> ServerRequestStream {
    let ServerStream::Requests(stream) = incoming.accept().await.unwrap() else {
        panic!("expected a request stream");
    };
    stream
}

async fn event_stream(incoming: &mut ServerIncoming) -> EventReceiver {
    let ServerStream::Events(stream) = incoming.accept().await.unwrap() else {
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
            assert!(matches!(error, SessionError::LimitExceeded(_)));
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
    let (server, agent) = raw_agent(SessionOptions::legacy_compatible()).await;
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
}

#[tokio::test]
async fn timeout_reports_certainty_and_aborts_exchange() {
    let mut options = SessionOptions::legacy_compatible();
    options.operation_timeout = Some(Duration::from_secs(1));
    let (server, agent) = raw_agent(options).await;
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
        // Only 203 encoded bytes, but at least 4800 bytes of String elements.
        writer
            .start(Ok::<_, String>(vec![String::new(); 200]))
            .unwrap();
        writer.flush().await.unwrap();
        writer.into_inner().finish().unwrap();
    });
    assert!(matches!(result, Err(SessionError::LimitExceeded(_))));
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
    use review_protocol::types::{EventKind, EventMessage};
    let (server, mut incoming, agent, _) = sessions(SessionOptions::legacy_compatible()).await;
    let event = EventMessage {
        time: jiff::Timestamp::UNIX_EPOCH,
        kind: EventKind::HttpThreat,
        fields: vec![1, 2, 3],
    };
    let ((), received) = tokio::join!(
        async {
            let mut sender = agent.open_event_stream().await.unwrap();
            sender.start(&event).unwrap();
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
    assert_eq!(received.fields, event.fields);
    assert!(matches!(received.kind, EventKind::HttpThreat));
    // Handles retain the connection after the event owners finish.
    assert_eq!(server.id(), server.clone().id());
}

#[tokio::test]
async fn retained_event_header_and_payload_resume_after_cancellation() {
    use review_protocol::types::{EventKind, EventMessage};
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
    let event = EventMessage {
        time: jiff::Timestamp::UNIX_EPOCH,
        kind: EventKind::HttpThreat,
        fields: vec![4, 5, 6],
    };
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
    assert_eq!(sequence.next().await.unwrap().unwrap().fields, event.fields);
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
        Err(SessionError::LimitExceeded(_))
    ));
    assert!(node_result.is_err());
}

// Keep raw transport clones to exercise sequential requests on one legacy wire stream.
async fn raw_sessions(
    options: SessionOptions,
) -> (ServerIncoming, AgentIncoming, Connection, Connection) {
    let (manager, node) = connections().await;
    let info = claims();
    let (server, agent) = tokio::join!(
        ServerHandle::from_transport(manager.clone(), options.clone(), ">=0.48.0", "0.49.0"),
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
                ServerStream::Events(stream) => events = Some(stream),
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
            Err(SessionError::Malformed(_))
        ));
        assert!(stream.next().await.is_err());
        assert!(recv.read(&mut [0]).await.is_err());
    }
}
