//! The integrated server path: listener, handshake, admission, request and
//! event runners, an outbound command, TLS reload, and shutdown.
//!
//! The per-component properties are covered by `tests/server_listener.rs` and
//! `server_processing.rs`; this file checks that the pieces compose through
//! public APIs and still reproduce the pinned wire fixtures.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use oinq::{Connection, Endpoint, TransportOptions};
use review_protocol::{
    MIN_PROTOCOL_VERSION_REQ, PROTOCOL_VERSION,
    session::{
        AgentConnector, AgentHandle, AgentIncoming, AgentRequest, AgentTransportOptions,
        ProtocolWindow, ServerHandle, ServerIncoming, ServerListener, ServerListenerOptions,
        ServerRequestOutcome, ServerSessionControl, ServerTransportOptions, SessionOptions,
    },
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use tokio::{io::AsyncReadExt, time::timeout};

use super::server_processing::{
    EVENTS, EventLog, FixtureHandler, Policy, REQUESTS, RESPONSES, check_dispatch_trace,
    check_events, context, open_events, open_requests,
};

const LOOPBACK: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const DETECTOR_ID: i32 = 7;
const SHUTDOWN_REASON: &[u8] = b"server shutdown";

struct Certificate {
    der: CertificateDer<'static>,
    key: Vec<u8>,
}

impl Certificate {
    fn generate() -> Self {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        Self {
            der: certificate.cert.into(),
            key: certificate.signing_key.serialize_der(),
        }
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.der.clone()).unwrap();
        roots
    }
}

fn server_tls(certificate: &Certificate, client: &Certificate) -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(client.roots()),
        provider.clone(),
    )
    .build()
    .unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![certificate.der.clone()],
                PrivatePkcs8KeyDer::from(certificate.key.clone()).into(),
            )
            .unwrap(),
    )
}

fn agent_tls(server: &Certificate, client: &Certificate) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(server.roots())
        .with_client_auth_cert(
            vec![client.der.clone()],
            PrivatePkcs8KeyDer::from(client.key.clone()).into(),
        )
        .unwrap();
    Arc::new(config)
}

/// Admits a raw fixture sender with the current protocol and fixture identity.
/// Raw stream access is required to inject the pinned bytes without re-encoding.
async fn admitted(
    listener: &ServerListener,
    endpoint: &Endpoint,
    policy: Policy,
) -> (
    (ServerHandle, ServerIncoming, ServerSessionControl),
    Connection,
) {
    let mut claims = super::claims();
    claims.protocol_version = PROTOCOL_VERSION.into();
    let address = listener.local_addr().unwrap();
    let (unadmitted, node) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            async { listener.accept().await.unwrap().unwrap().handshake().await },
            async {
                let node = endpoint.connect(address, "localhost").await.unwrap();
                super::raw_agent_handshake(&node, &claims).await;
                node
            },
        )
    })
    .await
    .unwrap();
    let unadmitted = unadmitted.unwrap();
    assert_eq!(unadmitted.agent_claims().protocol_version, PROTOCOL_VERSION);
    assert_eq!(unadmitted.peer_certificates().unwrap().chain().len(), 1);
    let control = unadmitted.control();
    let (handle, incoming) = unadmitted.admit(context(), Arc::new(policy));
    ((handle, incoming, control), node)
}

/// Answers one `RunDetectorOnce` command on the agent's incoming owner.
async fn answer_detector_command(incoming: &mut AgentIncoming) -> i32 {
    let mut stream = incoming.accept().await.unwrap();
    let AgentRequest::RunDetectorOnce { request, reply } = stream.next().await.unwrap().unwrap()
    else {
        panic!("expected RunDetectorOnce");
    };
    reply.respond(Ok(())).await.unwrap();
    stream.finish().unwrap();
    request
}

/// Binds a listener accepting the crate's protocol window.
fn listen(certificate: &Certificate, client: &Certificate) -> ServerListener {
    let options = ServerListenerOptions {
        transport: ServerTransportOptions::default(),
        session: SessionOptions::legacy_compatible(),
        protocol: ProtocolWindow::new(MIN_PROTOCOL_VERSION_REQ, PROTOCOL_VERSION).unwrap(),
        handshake_timeout: TEST_TIMEOUT,
    };
    ServerListener::bind(LOOPBACK, server_tls(certificate, client), options).unwrap()
}

/// Reloads the listener with a replacement certificate and admits an agent
/// that trusts only the replacement, then exchanges a typed command.
async fn reload_and_admit(
    listener: &ServerListener,
    client: &Certificate,
) -> (ServerSessionControl, AgentHandle) {
    let replacement = Certificate::generate();
    listener
        .reload_tls(server_tls(&replacement, client))
        .unwrap();
    let connector = AgentConnector::bind(
        LOOPBACK,
        agent_tls(&replacement, client),
        AgentTransportOptions::default(),
        SessionOptions::legacy_compatible(),
    )
    .unwrap();
    let mut claims = super::claims();
    claims.protocol_version = PROTOCOL_VERSION.into();
    let (unadmitted, agent) = tokio::join!(
        async {
            listener
                .accept()
                .await
                .unwrap()
                .unwrap()
                .handshake()
                .await
                .unwrap()
        },
        connector.connect(listener.local_addr().unwrap(), "localhost", &claims),
    );
    let control = unadmitted.control();
    let (handle, _incoming) = unadmitted.admit(context(), Arc::new(Policy::default()));
    let (agent, mut incoming) = agent.unwrap();
    assert_eq!(
        agent.peer_certificates().unwrap().chain(),
        &[replacement.der.as_ref().to_vec()]
    );
    let (command, detector) = tokio::join!(
        handle.send_run_detector_once(DETECTOR_ID),
        answer_detector_command(&mut incoming),
    );
    command.unwrap();
    assert_eq!(detector, DETECTOR_ID);
    (control, agent)
}

#[tokio::test]
async fn integrated_server_path_reproduces_fixtures_and_shuts_down_cleanly() {
    let server_certificate = Certificate::generate();
    let client_certificate = Certificate::generate();
    let listener = listen(&server_certificate, &client_certificate);
    let endpoint = Endpoint::client(
        agent_tls(&server_certificate, &client_certificate),
        LOOPBACK,
        TransportOptions::default(),
    )
    .unwrap();

    let handler = Arc::new(FixtureHandler::default());
    let trace = handler.0.clone();
    let policy = Policy {
        trace: trace.clone(),
        deny: None,
    };
    let ((_manager, mut incoming, control), node) = admitted(&listener, &endpoint, policy).await;

    // Accept each stream before the agent opens the next one: `accept` selects
    // both stream directions without bias.
    let (mut requests, mut responses) = timeout(TEST_TIMEOUT, open_requests(&node, REQUESTS))
        .await
        .unwrap();
    let request_runner = tokio::spawn(
        timeout(TEST_TIMEOUT, super::request_stream(&mut incoming))
            .await
            .unwrap()
            .run(handler),
    );
    let mut events = timeout(TEST_TIMEOUT, open_events(&node, EVENTS))
        .await
        .unwrap();
    let log = EventLog::default();
    let event_runner = tokio::spawn(
        timeout(TEST_TIMEOUT, super::event_stream(&mut incoming))
            .await
            .unwrap()
            .run(log.clone()),
    );

    // Every request is answered while both streams remain open.
    let mut answered = vec![0; RESPONSES.len()];
    timeout(TEST_TIMEOUT, responses.read_exact(&mut answered))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answered, RESPONSES);

    assert!(!request_runner.is_finished());
    assert!(!event_runner.is_finished());

    // A reload serves new connections with the replacement certificate while
    // the admitted session keeps its streams. The new session exchanges a typed
    // command through AgentIncoming and Reply while both runners remain active.
    let (reloaded_control, reloaded_agent) = timeout(
        TEST_TIMEOUT,
        reload_and_admit(&listener, &client_certificate),
    )
    .await
    .unwrap();
    assert!(!request_runner.is_finished());
    assert!(!event_runner.is_finished());

    // The agent finishes the streams it opened; both runners return only at
    // the peer's clean EOF.
    requests.finish().unwrap();
    events.finish().unwrap();

    listener.shutdown();
    assert!(
        timeout(TEST_TIMEOUT, listener.accept())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );

    // Drain each admitted session, join its runners, then close it.
    control.drain();
    assert!(
        timeout(TEST_TIMEOUT, incoming.accept_next())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    let requests_outcome = timeout(TEST_TIMEOUT, request_runner).await.unwrap();
    let requests_label = match &requests_outcome {
        Ok(Ok(ServerRequestOutcome::Finished)) => "finished".to_owned(),
        Ok(Ok(ServerRequestOutcome::Unhandled(_))) => "unhandled".to_owned(),
        Ok(Err(error)) => format!("runner error: {error}"),
        Err(error) => format!("join error: {error}"),
    };
    assert!(
        matches!(requests_outcome, Ok(Ok(ServerRequestOutcome::Finished))),
        "{requests_label}"
    );
    let events_outcome = timeout(TEST_TIMEOUT, event_runner).await.unwrap();
    assert!(matches!(events_outcome, Ok(Ok(()))), "{events_outcome:?}");
    // The request runner finished its response direction at the clean EOF.
    let mut rest = Vec::new();
    timeout(TEST_TIMEOUT, responses.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rest, Vec::<u8>::new());
    control.close(SHUTDOWN_REASON);
    reloaded_control.drain();
    reloaded_control.close(SHUTDOWN_REASON);
    timeout(TEST_TIMEOUT, listener.wait_idle()).await.unwrap();

    check_dispatch_trace(&trace);
    check_events(&log);
    check_shutdown(&node, &reloaded_agent).await;
}

async fn check_shutdown(node: &Connection, reloaded_agent: &AgentHandle) {
    assert!(matches!(
        timeout(TEST_TIMEOUT, node.closed()).await.unwrap(),
        oinq::CloseInfo::Application { reason, .. } if reason == SHUTDOWN_REASON
    ));
    assert!(matches!(
        timeout(TEST_TIMEOUT, reloaded_agent.closed()).await.unwrap(),
        review_protocol::session::CloseReason::Application { reason, .. } if reason == SHUTDOWN_REASON
    ));
}
