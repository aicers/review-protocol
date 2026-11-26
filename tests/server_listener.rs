//! Loopback lifecycle and wire regressions for the server-only listener surface.
#![cfg(feature = "server")]
// Test setup and assertions intentionally panic on failure.
#![allow(clippy::unwrap_used)]

use std::{
    future::Future,
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use oinq::{ApplicationCode, CloseInfo, Connection, Endpoint, TransportOptions};
use review_protocol::{
    auth::{AuthorizationContext, AuthorizationError, AuthorizerV2, PeerContext},
    server::Handler,
    service_id::ServiceId,
    session::{
        PendingSession, ProtocolWindow, ServerHandle, ServerIncoming, ServerListener,
        ServerListenerOptions, ServerRequestOutcome, ServerSessionClose, ServerSessionControl,
        ServerStream, ServerTransportOptions, SessionError, SessionOptions, UnadmittedSession,
    },
    types::{AuditHealth, ProvisioningFingerprint, Status, node::NodePowerRequest},
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

const LOOPBACK: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const FULL: &[u8] = include_bytes!("fixtures/current/handshake-tail.bin");
const BASE: &[u8] = include_bytes!("fixtures/current/handshake-base.bin");
const ACCEPTED: &[u8] = include_bytes!("fixtures/current/handshake-acceptance.bin");
const REJECTED: &[u8] = include_bytes!("fixtures/current/handshake-rejection.bin");

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
}

fn roots(certificate: &Certificate) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certificate.der.clone()).unwrap();
    roots
}

fn server_tls(
    certificate: &Certificate,
    trusted_client: &Certificate,
) -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots(trusted_client)),
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

fn client_endpoint(trusted_server: &Certificate, certificate: &Certificate) -> Endpoint {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots(trusted_server))
    .with_client_auth_cert(
        vec![certificate.der.clone()],
        PrivatePkcs8KeyDer::from(certificate.key.clone()).into(),
    )
    .unwrap();
    Endpoint::client(Arc::new(config), LOOPBACK, TransportOptions::default()).unwrap()
}

fn options() -> ServerListenerOptions {
    ServerListenerOptions {
        transport: ServerTransportOptions::default(),
        session: SessionOptions::legacy_compatible(),
        protocol: ProtocolWindow::new(">=0.49.0", "0.49.0").unwrap(),
        handshake_timeout: TEST_TIMEOUT,
    }
}

fn setup(options: ServerListenerOptions) -> (ServerListener, Endpoint) {
    let server = Certificate::generate();
    let client = Certificate::generate();
    let listener = ServerListener::bind(LOOPBACK, server_tls(&server, &client), options).unwrap();
    (listener, client_endpoint(&server, &client))
}

async fn accept_attempt<'a>(
    listener: &ServerListener,
    endpoint: &'a Endpoint,
) -> (
    PendingSession,
    impl Future<Output = Result<Connection, oinq::TransportError>> + Unpin + use<'a>,
) {
    let mut accept = Box::pin(listener.accept());
    let mut connect = Box::pin(endpoint.connect(listener.local_addr().unwrap(), "localhost"));
    let pending = timeout(TEST_TIMEOUT, async {
        tokio::select! {
            pending = &mut accept => pending.unwrap().unwrap(),
            result = &mut connect => panic!("TLS completed before listener acceptance: {result:?}"),
        }
    })
    .await
    .unwrap();
    (pending, connect)
}

async fn connect_pending(
    listener: &ServerListener,
    endpoint: &Endpoint,
) -> (
    Connection,
    impl Future<Output = Result<UnadmittedSession, SessionError>> + use<>,
) {
    let (pending, mut connect) = accept_attempt(listener, endpoint).await;
    let mut handshake = Box::pin(pending.handshake());
    let transport = timeout(TEST_TIMEOUT, async {
        tokio::select! {
            result = &mut connect => result.unwrap(),
            result = &mut handshake => panic!("protocol handshake completed before the peer sent claims: {:?}", result.err()),
        }
    })
    .await
    .unwrap();
    (transport, handshake)
}

async fn exchange_claims(peer: &Connection, payload: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = peer.open_bi().await.unwrap();
    send.write_all(&u32::try_from(payload.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    send.write_all(payload).await.unwrap();
    send.finish().unwrap();
    let mut reply = Vec::new();
    let result = recv.read_to_end(&mut reply).await;
    if !reply.is_empty() {
        result.unwrap(); // Read the full reply and verify clean EOF.
    }
    reply
}

async fn handshake(
    listener: &ServerListener,
    endpoint: &Endpoint,
    payload: &[u8],
) -> (Connection, Result<UnadmittedSession, SessionError>, Vec<u8>) {
    let (peer, pending) = connect_pending(listener, endpoint).await;
    let (reply, session) = timeout(TEST_TIMEOUT, async {
        tokio::join!(exchange_claims(&peer, payload), pending)
    })
    .await
    .unwrap();
    (peer, session, reply)
}

async fn peer_close(peer: &Connection, code: ApplicationCode, reason: &[u8]) {
    let closed = timeout(TEST_TIMEOUT, peer.closed()).await.unwrap();
    assert!(
        matches!(&closed,
            CloseInfo::Application { code: actual, reason: text } if *actual == code && text == reason),
        "unexpected close reason: {closed:?}",
    );
}

#[derive(Default)]
struct Observations {
    authorizations: AtomicUsize,
    calls: AtomicUsize,
}

impl AuthorizerV2 for Observations {
    fn authorize_with_context(
        &self,
        context: &AuthorizationContext,
        service: &ServiceId,
    ) -> Result<(), AuthorizationError> {
        assert_eq!(context.peer_identity().name(), "checked-agent");
        assert_eq!(service, &review_protocol::service_id::SERVER_CONFIG_GET);
        self.authorizations.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[async_trait::async_trait]
impl Handler for Observations {
    async fn get_config(&self, peer: &str) -> Result<String, String> {
        assert_eq!(peer, "checked-agent");
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok("configuration".into())
    }
}

#[derive(Clone, Copy)]
enum Admission {
    Admit,
    Refuse,
    Drop,
}

fn decide(
    owner: UnadmittedSession,
    admission: Admission,
    observations: &Arc<Observations>,
) -> Option<(ServerHandle, ServerIncoming)> {
    match admission {
        Admission::Admit => {
            let context =
                AuthorizationContext::from_peer_context(&PeerContext::new("checked-agent"));
            Some(owner.admit(context, observations.clone()))
        }
        Admission::Refuse => {
            owner.control().abort(b"application refused admission");
            None
        }
        Admission::Drop => None,
    }
}

async fn send_get_config(peer: &Connection) -> oinq::RecvStream {
    let (mut send, recv) = peer.open_bi().await.unwrap();
    // GetConfig (36), followed by the standard serde encoding of unit.
    send.write_all(&[0, 0, 0, 4, 36, 0, 0, 0]).await.unwrap();
    send.finish().unwrap();
    recv
}

async fn run_request(stream: ServerStream, observations: &Arc<Observations>) {
    let ServerStream::Requests(stream) = stream else {
        panic!("expected an incoming request stream");
    };
    assert!(matches!(
        stream.run(observations.clone()).await.unwrap(),
        ServerRequestOutcome::Finished
    ));
}

async fn assert_config_response(mut recv: oinq::RecvStream) {
    let mut response = Vec::new();
    recv.read_to_end(&mut response).await.unwrap();
    assert_eq!(&response[..6], &[0, 0, 0, 15, 0, 13]);
    assert_eq!(&response[6..], b"configuration");
}

#[tokio::test]
async fn adopt_socket_cancel_accept_and_shutdown_without_closing_session() {
    let server = Certificate::generate();
    let client = Certificate::generate();
    let endpoint = client_endpoint(&server, &client);
    let socket = UdpSocket::bind(LOOPBACK).unwrap();
    let expected = socket.local_addr().unwrap();
    let listener =
        ServerListener::from_socket(socket, server_tls(&server, &client), options()).unwrap();
    assert_eq!(listener.local_addr().unwrap(), expected);
    let mut canceled_accept = tokio_test::task::spawn(listener.accept());
    assert!(canceled_accept.poll().is_pending());
    let mut connecting = tokio_test::task::spawn(endpoint.connect(expected, "localhost"));
    assert!(connecting.poll().is_pending());
    timeout(TEST_TIMEOUT, async {
        while !canceled_accept.is_woken() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(canceled_accept);

    let (session, (peer, reply)) = timeout(TEST_TIMEOUT, async {
        let pending = listener.accept().await.unwrap().unwrap();
        tokio::join!(pending.handshake(), async {
            let peer = connecting.await.unwrap();
            let reply = exchange_claims(&peer, FULL).await;
            (peer, reply)
        })
    })
    .await
    .unwrap();
    assert_eq!(reply, ACCEPTED);
    let session = session.unwrap();
    assert_eq!(
        session.peer_certificates().unwrap().chain(),
        &[client.der.as_ref()]
    );
    let control = session.control();
    let mut accept = tokio_test::task::spawn(listener.accept());
    assert!(accept.poll().is_pending());
    listener.shutdown();
    assert!(accept.await.unwrap().is_none());
    assert!(listener.accept().await.unwrap().is_none());
    drop(listener);

    let observations = Arc::new(Observations::default());
    let (_server, mut incoming) = decide(session, Admission::Admit, &observations).unwrap();
    assert!(
        tokio_test::task::spawn(control.closed())
            .poll()
            .is_pending()
    );
    let recv = send_get_config(&peer).await;
    run_request(
        incoming.accept_next().await.unwrap().unwrap(),
        &observations,
    )
    .await;
    assert_config_response(recv).await;
    control.close(b"finished");
    assert!(incoming.accept_next().await.unwrap().is_none());
    peer_close(&peer, ApplicationCode::default(), b"finished").await;
}

#[test]
fn listener_accept_reports_unexpected_endpoint_shutdown() {
    let listener = {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async { setup(options()).0 })
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    assert!(matches!(
        runtime.block_on(listener.accept()),
        Err(SessionError::Transport { .. })
    ));
}

#[tokio::test]
async fn stalled_handshake_does_not_block_acceptance_and_hits_deadline() {
    let mut config = options();
    config.protocol = ProtocolWindow::new(">=0.48.0", "0.49.0").unwrap();
    config.handshake_timeout = Duration::from_secs(5);
    let (listener, endpoint) = setup(config);
    assert_ne!(listener.local_addr().unwrap().port(), 0);
    let (stalled, pending) = connect_pending(&listener, &endpoint).await;
    let mut pending = std::pin::pin!(pending);
    let mut claims = FULL.to_vec();
    claims[16] = b'8'; // 0.48.0
    let (peer, second, reply) = tokio::select! {
        result = handshake(&listener, &endpoint, &claims) => result,
        _ = &mut pending => panic!("the other connection should proceed while this one stalls"),
    };
    assert_eq!(reply, ACCEPTED);
    let second = second.unwrap();
    assert_eq!(second.agent_claims().protocol_version, "0.48.0");
    drop(second);
    drop(peer);

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(matches!(
        pending.await,
        Err(SessionError::Deadline {
            source: Some(_),
            ..
        })
    ));
    tokio::time::resume();
    peer_close(
        &stalled,
        ApplicationCode::new(1).unwrap(),
        b"handshake did not complete",
    )
    .await;
}

#[tokio::test]
async fn accepted_attempt_can_finish_after_listener_drop() {
    let (listener, endpoint) = setup(options());
    let (pending, connecting) = accept_attempt(&listener, &endpoint).await;
    listener.shutdown();
    drop(listener);
    let (session, (_peer, reply)) = timeout(TEST_TIMEOUT, async {
        tokio::join!(pending.handshake(), async {
            let peer = connecting.await.unwrap();
            let reply = exchange_claims(&peer, BASE).await;
            (peer, reply)
        })
    })
    .await
    .unwrap();
    assert_eq!(reply, ACCEPTED);
    assert_eq!(session.unwrap().agent_claims().agent_name, "agent");
}

#[tokio::test]
async fn dropping_a_pending_owner_abandons_tls() {
    let (listener, endpoint) = setup(options());
    let (pending, connecting) = accept_attempt(&listener, &endpoint).await;
    drop(pending);
    assert!(timeout(TEST_TIMEOUT, connecting).await.unwrap().is_err());

    let (_, session, reply) = handshake(&listener, &endpoint, BASE).await;
    assert!(session.is_ok());
    assert_eq!(reply, ACCEPTED);
}

#[tokio::test]
async fn pending_deadline_includes_time_before_first_poll() {
    let (listener, endpoint) = setup(options());
    let (pending, connecting) = accept_attempt(&listener, &endpoint).await;
    tokio::time::pause();
    tokio::time::advance(TEST_TIMEOUT).await;
    assert!(matches!(
        pending.handshake().await,
        Err(SessionError::Deadline { source: None, .. })
    ));
    tokio::time::resume();
    assert!(timeout(TEST_TIMEOUT, connecting).await.unwrap().is_err());
}

#[tokio::test]
async fn abort_closes_a_handshaking_connection() {
    let (listener, endpoint) = setup(options());
    let (peer, pending) = connect_pending(&listener, &endpoint).await;
    // Wait for a 1-RTT packet to be acknowledged, so the transport can
    // deliver application close reasons even though the protocol is stalled.
    let mut probe = peer.open_uni().await.unwrap();
    probe.finish().unwrap();
    assert_eq!(
        timeout(TEST_TIMEOUT, probe.stopped())
            .await
            .unwrap()
            .unwrap(),
        None
    );
    listener.abort(b"listener aborted");
    assert!(listener.accept().await.unwrap().is_none());
    assert!(matches!(
        timeout(TEST_TIMEOUT, pending).await.unwrap(),
        Err(SessionError::Transport { .. })
    ));
    peer_close(&peer, ApplicationCode::new(1).unwrap(), b"listener aborted").await;
    timeout(TEST_TIMEOUT, listener.wait_idle()).await.unwrap();
}

/// Opens a stream on `peer` and waits until the listener's transport has
/// acknowledged it, polling the pending handshake first meanwhile so that it
/// has taken the established connection and is reading the protocol claims.
async fn acknowledged_probe(
    peer: &Connection,
    pending: &mut (impl Future<Output = Result<UnadmittedSession, SessionError>> + Unpin),
) {
    let mut probe = peer.open_uni().await.unwrap();
    probe.finish().unwrap();
    timeout(TEST_TIMEOUT, async {
        tokio::select! {
            biased;
            result = pending => panic!("the protocol handshake ended early: {:?}", result.err()),
            stopped = probe.stopped() => assert_eq!(stopped.unwrap(), None),
        }
    })
    .await
    .unwrap();
}

const CLOSE_REASON: &[u8] = b"listener closed";

#[tokio::test]
async fn close_delivers_code_zero_to_admitted_unadmitted_and_pending_peers() {
    let (listener, endpoint) = setup(options());
    let observations = Arc::new(Observations::default());
    let (admitted_peer, owner, reply) = handshake(&listener, &endpoint, FULL).await;
    assert_eq!(reply, ACCEPTED);
    let (_handle, mut incoming) = decide(owner.unwrap(), Admission::Admit, &observations).unwrap();
    let admitted = incoming.control();
    let (unadmitted_peer, owner, reply) = handshake(&listener, &endpoint, FULL).await;
    assert_eq!(reply, ACCEPTED);
    let owner = owner.unwrap();
    let unadmitted = owner.control();
    let (pending_peer, pending) = connect_pending(&listener, &endpoint).await;
    let mut pending = Box::pin(pending);
    acknowledged_probe(&pending_peer, &mut pending).await;

    listener.close(CLOSE_REASON);
    assert!(listener.accept().await.unwrap().is_none());
    // Neither a later abort nor the owners' own code-one closes replace the
    // listener's code zero.
    listener.abort(b"listener aborted");
    drop(owner);
    assert!(matches!(
        timeout(TEST_TIMEOUT, pending).await.unwrap(),
        Err(SessionError::Transport { .. })
    ));
    for control in [&admitted, &unadmitted] {
        assert!(matches!(
            timeout(TEST_TIMEOUT, control.closed()).await.unwrap(),
            ServerSessionClose::Local
        ));
    }
    // An accepted stream runner observes the closed transport.
    assert!(incoming.accept().await.is_err());
    for peer in [&admitted_peer, &unadmitted_peer, &pending_peer] {
        peer_close(peer, ApplicationCode::default(), CLOSE_REASON).await;
    }
    timeout(TEST_TIMEOUT, listener.wait_idle()).await.unwrap();
    assert_eq!(observations.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn close_wakes_accept_and_fails_an_unawaited_attempt() {
    let (listener, endpoint) = setup(options());
    let (pending, connecting) = accept_attempt(&listener, &endpoint).await;
    let mut accept = tokio_test::task::spawn(listener.accept());
    assert!(accept.poll().is_pending());
    listener.close(CLOSE_REASON);
    assert!(accept.await.unwrap().is_none());
    assert!(listener.accept().await.unwrap().is_none());
    // The attempt had not started TLS, so it carries no application code,
    // and it is never admitted.
    assert!(
        timeout(TEST_TIMEOUT, pending.handshake())
            .await
            .unwrap()
            .is_err()
    );
    assert!(timeout(TEST_TIMEOUT, connecting).await.unwrap().is_err());
    timeout(TEST_TIMEOUT, listener.wait_idle()).await.unwrap();
}

#[tokio::test]
async fn cancelling_accept_or_handshake_around_close_leaves_nothing_open() {
    let (listener, endpoint) = setup(options());
    let mut canceled_accept = tokio_test::task::spawn(listener.accept());
    assert!(canceled_accept.poll().is_pending());
    drop(canceled_accept);
    let (peer, pending) = connect_pending(&listener, &endpoint).await;
    let mut pending = Box::pin(pending);
    acknowledged_probe(&peer, &mut pending).await;

    listener.close(CLOSE_REASON);
    // The pending owner's code-one close on cancellation repeats the
    // listener's close instead.
    drop(pending);
    peer_close(&peer, ApplicationCode::default(), CLOSE_REASON).await;
    // A close after close leaves the code alone.
    listener.close(b"closed again");
    assert!(listener.accept().await.unwrap().is_none());
    timeout(TEST_TIMEOUT, listener.wait_idle()).await.unwrap();
}

/// Dropping an admitted session right after a listener-wide close would let
/// the transport's implicit close, code zero with no reason, overtake the
/// endpoint's; the session repeats the listener's close instead.
#[tokio::test]
async fn dropping_a_session_right_after_a_listener_close_keeps_its_code() {
    for code in [0, 1] {
        let (listener, endpoint) = setup(options());
        let observations = Arc::new(Observations::default());
        let (peer, owner, reply) = handshake(&listener, &endpoint, FULL).await;
        assert_eq!(reply, ACCEPTED);
        let (handle, incoming) = decide(owner.unwrap(), Admission::Admit, &observations).unwrap();
        if code == 0 {
            listener.close(CLOSE_REASON);
        } else {
            listener.abort(CLOSE_REASON);
        }
        drop(handle);
        drop(incoming);
        peer_close(&peer, ApplicationCode::new(code).unwrap(), CLOSE_REASON).await;
        timeout(TEST_TIMEOUT, listener.wait_idle()).await.unwrap();
    }
}

/// An accepted stream can outlive every session owner. Dropping it right after
/// a listener-wide close releases the last transport reference, whose
/// implicit close, code zero with no reason, would overtake the endpoint's;
/// the stream repeats the listener's close instead.
#[tokio::test]
async fn dropping_a_retained_stream_right_after_a_listener_close_keeps_its_code() {
    for events in [false, true] {
        for code in [0, 1] {
            let (listener, endpoint) = setup(options());
            let observations = Arc::new(Observations::default());
            let (peer, owner, reply) = handshake(&listener, &endpoint, FULL).await;
            assert_eq!(reply, ACCEPTED);
            let (handle, mut incoming) =
                decide(owner.unwrap(), Admission::Admit, &observations).unwrap();
            // The peer writes a partial frame so the stream reaches the
            // listener; acceptance does not read it.
            let _peer_stream = if events {
                let mut send = peer.open_uni().await.unwrap();
                send.write_all(&[0]).await.unwrap();
                (send, None)
            } else {
                let (mut send, recv) = peer.open_bi().await.unwrap();
                send.write_all(&[0]).await.unwrap();
                (send, Some(recv))
            };
            let stream = timeout(TEST_TIMEOUT, incoming.accept())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(matches!(stream, ServerStream::DetectionEvents(_)), events);
            drop(handle);
            drop(incoming);
            if code == 0 {
                listener.close(CLOSE_REASON);
            } else {
                listener.abort(CLOSE_REASON);
            }
            drop(stream);
            peer_close(&peer, ApplicationCode::new(code).unwrap(), CLOSE_REASON).await;
            timeout(TEST_TIMEOUT, listener.wait_idle()).await.unwrap();
            assert_eq!(observations.calls.load(Ordering::Relaxed), 0);
        }
    }
}

#[tokio::test]
async fn pending_remote_addr_precedes_tls_and_protocol_failures() {
    let server = Certificate::generate();
    let client = Certificate::generate();
    let stranger = Certificate::generate();
    let listener = ServerListener::bind(LOOPBACK, server_tls(&server, &client), options()).unwrap();

    // TLS fails: the listener does not trust the client certificate.
    let untrusted = client_endpoint(&server, &stranger);
    let (pending, connecting) = accept_attempt(&listener, &untrusted).await;
    assert_eq!(pending.remote_addr(), untrusted.local_addr().unwrap());
    let (result, _) = timeout(TEST_TIMEOUT, async {
        tokio::join!(pending.handshake(), connecting)
    })
    .await
    .unwrap();
    assert!(matches!(result, Err(SessionError::Transport { .. })));

    // The protocol handshake fails: the version is outside the window.
    let trusted = client_endpoint(&server, &client);
    let (pending, connecting) = accept_attempt(&listener, &trusted).await;
    assert_eq!(pending.remote_addr(), trusted.local_addr().unwrap());
    let mut claims = FULL.to_vec();
    claims[13..19].copy_from_slice(b"0.48.0");
    let (result, (_peer, reply)) = timeout(TEST_TIMEOUT, async {
        tokio::join!(pending.handshake(), async {
            let peer = connecting.await.unwrap();
            let reply = exchange_claims(&peer, &claims).await;
            (peer, reply)
        })
    })
    .await
    .unwrap();
    assert_eq!(reply, REJECTED);
    assert!(matches!(
        result,
        Err(SessionError::IncompatibleProtocol { .. })
    ));
}

#[tokio::test]
async fn admitted_session_binds_authorization_and_keeps_outbound_operations() {
    let (listener, endpoint) = setup(options());
    let (peer, session, reply) = handshake(&listener, &endpoint, FULL).await;
    // The handshake exchange has reached EOF while the session is still unadmitted.
    assert_eq!(reply, ACCEPTED);
    let observations = Arc::new(Observations::default());
    let requests = send_get_config(&peer).await;
    assert_eq!(observations.calls.load(Ordering::Relaxed), 0);
    let (handle, mut incoming) = decide(session.unwrap(), Admission::Admit, &observations).unwrap();
    assert!(
        tokio_test::task::spawn(peer.accept_bi())
            .poll()
            .is_pending()
    );
    assert!(
        tokio_test::task::spawn(peer.accept_uni())
            .poll()
            .is_pending()
    );

    run_request(
        incoming.accept_next().await.unwrap().unwrap(),
        &observations,
    )
    .await;
    assert_config_response(requests).await;
    assert_eq!(observations.authorizations.load(Ordering::Relaxed), 1);
    assert_eq!(observations.calls.load(Ordering::Relaxed), 1);

    let (result, ()) = timeout(TEST_TIMEOUT, async {
        tokio::join!(handle.node_power(NodePowerRequest::GracefulReboot), async {
            let (mut send, mut recv) = peer.accept_bi().await.unwrap();
            let mut frame = [0_u8; 9];
            recv.read_exact(&mut frame).await.unwrap();
            assert_eq!(frame, [0, 0, 0, 5, 106, 0, 0, 0, 2]);
            send.write_all(&[0, 0, 0, 2, 0, 0]).await.unwrap();
            send.finish().unwrap();
        })
    })
    .await
    .unwrap();
    assert!(matches!(
        result.unwrap(),
        review_protocol::server::node::NodePowerOutcome::Response(
            review_protocol::types::node::NodePowerResponse::Initiated
        )
    ));
}

#[tokio::test]
async fn protocol_reply_precedes_immediate_refusal() {
    let (listener, endpoint) = setup(options());
    let (peer, pending) = connect_pending(&listener, &endpoint).await;

    let reply = timeout(TEST_TIMEOUT, async {
        let ((), reply) = tokio::join!(
            async {
                let session = pending.await.unwrap();
                session.control().abort(b"refused");
            },
            exchange_claims(&peer, BASE),
        );
        reply
    })
    .await
    .unwrap();
    assert_eq!(reply, ACCEPTED);
    peer_close(&peer, ApplicationCode::new(1).unwrap(), b"refused").await;
}

#[tokio::test]
async fn refusal_and_unadmitted_drop_never_dispatch_buffered_requests() {
    let (listener, endpoint) = setup(options());
    let observations = Arc::new(Observations::default());
    for (admission, reason) in [
        (
            Admission::Refuse,
            b"application refused admission".as_slice(),
        ),
        (
            Admission::Drop,
            b"session dropped before admission".as_slice(),
        ),
    ] {
        let (peer, session, reply) = handshake(&listener, &endpoint, FULL).await;
        assert_eq!(reply, ACCEPTED);
        let session = session.unwrap();
        let control: ServerSessionControl = session.control();
        let monitor = control.clone();
        // The peer writes an ordinary frame and receives transport
        // acknowledgment before the application makes its decision.
        let (mut send, mut recv) = peer.open_bi().await.unwrap();
        send.write_all(&[0, 0, 0, 4, 36, 0, 0, 0]).await.unwrap();
        send.finish().unwrap();
        assert_eq!(
            timeout(TEST_TIMEOUT, send.stopped())
                .await
                .unwrap()
                .unwrap(),
            None
        );
        assert!(decide(session, admission, &observations).is_none());
        assert!(matches!(monitor.closed().await, ServerSessionClose::Local));
        peer_close(&peer, ApplicationCode::new(1).unwrap(), reason).await;
        let mut bytes = Vec::new();
        assert!(recv.read_to_end(&mut bytes).await.is_err());
        assert_eq!(bytes, [] as [u8; 0]);
        assert_eq!(observations.authorizations.load(Ordering::Relaxed), 0);
        assert_eq!(observations.calls.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn incoming_accept_is_cancel_safe_and_drain_preserves_owned_streams() {
    let (listener, endpoint) = setup(options());
    let (peer, owner, _) = handshake(&listener, &endpoint, FULL).await;
    let observations = Arc::new(Observations::default());
    let (_, mut incoming) = decide(owner.unwrap(), Admission::Admit, &observations).unwrap();

    let mut accept = tokio_test::task::spawn(incoming.accept());
    assert!(accept.poll().is_pending());
    let mut events = peer.open_uni().await.unwrap();
    events.write_all(&[0, 0]).await.unwrap();
    events.finish().unwrap();
    assert_eq!(
        timeout(TEST_TIMEOUT, events.stopped())
            .await
            .unwrap()
            .unwrap(),
        None
    );
    assert!(accept.is_woken());
    drop(accept);
    assert!(matches!(
        incoming.accept().await.unwrap(),
        ServerStream::DetectionEvents(_)
    ));

    assert!(
        tokio_test::task::spawn(incoming.accept_next())
            .poll()
            .is_pending()
    );
    let recv = send_get_config(&peer).await;
    let stream = incoming.accept_next().await.unwrap().unwrap();
    let control = incoming.control();
    let mut accept = tokio_test::task::spawn(incoming.accept_next());
    assert!(accept.poll().is_pending());
    control.drain();
    assert!(accept.await.unwrap().is_none());
    assert!(incoming.accept_next().await.unwrap().is_none());
    assert!(matches!(
        incoming.accept().await,
        Err(SessionError::Transport { .. })
    ));
    drop(incoming);
    run_request(stream, &observations).await;
    assert_config_response(recv).await;
    listener.abort(b"endpoint aborted");
    assert!(listener.accept().await.unwrap().is_none());
    assert!(matches!(control.closed().await, ServerSessionClose::Local));
    peer_close(&peer, ApplicationCode::new(1).unwrap(), b"endpoint aborted").await;
    timeout(TEST_TIMEOUT, listener.wait_idle()).await.unwrap();
}

#[tokio::test]
async fn peer_close_classification_preserves_legacy_accept() {
    let (listener, endpoint) = setup(options());
    for code in [0, 7] {
        let (peer, owner, _) = handshake(&listener, &endpoint, FULL).await;
        let (_, mut incoming) = decide(
            owner.unwrap(),
            Admission::Admit,
            &Arc::new(Observations::default()),
        )
        .unwrap();
        peer.close(ApplicationCode::new(code).unwrap(), b"peer shutdown");
        let control = incoming.control();
        assert!(matches!(
            timeout(TEST_TIMEOUT, control.closed()).await.unwrap(),
            ServerSessionClose::Peer { code: received, reason }
                if received == code && reason == b"peer shutdown"
        ));
        match code {
            0 => assert!(incoming.accept_next().await.unwrap().is_none()),
            _ => assert!(matches!(
                incoming.accept_next().await,
                Err(SessionError::Transport { .. })
            )),
        }
        assert!(matches!(
            incoming.accept().await,
            Err(SessionError::Transport { .. })
        ));
    }
}

#[tokio::test]
async fn tls_reload_changes_new_connections_and_preserves_the_old_session() {
    let server = Certificate::generate();
    let replacement = Certificate::generate();
    let client = Certificate::generate();
    let replacement_client = Certificate::generate();
    let mut options = options();
    options.transport.max_concurrent_uni_streams = 0;
    let listener = ServerListener::bind(LOOPBACK, server_tls(&server, &client), options).unwrap();
    let client_before = client_endpoint(&server, &client);
    let (old_peer, owner, _) = handshake(&listener, &client_before, FULL).await;
    assert_eq!(old_peer.peer_certificates().unwrap(), &[server.der]);
    let observations = Arc::new(Observations::default());
    let (_handle, mut old_incoming) =
        decide(owner.unwrap(), Admission::Admit, &observations).unwrap();

    listener
        .reload_tls(server_tls(&replacement, &replacement_client))
        .unwrap();
    let client_after = client_endpoint(&replacement, &replacement_client);
    let (new_peer, owner, _) = handshake(&listener, &client_after, FULL).await;
    assert_eq!(
        new_peer.peer_certificates().unwrap(),
        std::slice::from_ref(&replacement.der)
    );
    assert!(
        tokio_test::task::spawn(new_peer.open_uni())
            .poll()
            .is_pending()
    );
    assert!(
        tokio_test::task::spawn(old_peer.open_uni())
            .poll()
            .is_pending()
    );

    // The reloaded verifier refuses a client credential previously accepted.
    let previous_client = client_endpoint(&replacement, &client);
    let (bad_peer, result) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            previous_client.connect(listener.local_addr().unwrap(), "localhost"),
            async { listener.accept().await.unwrap().unwrap().handshake().await }
        )
    })
    .await
    .unwrap();
    assert!(matches!(result, Err(SessionError::Transport { .. })));
    if let Ok(peer) = bad_peer {
        let _ = timeout(TEST_TIMEOUT, peer.closed()).await.unwrap();
    }
    drop(owner.unwrap());

    let response = send_get_config(&old_peer).await;
    run_request(
        old_incoming.accept_next().await.unwrap().unwrap(),
        &observations,
    )
    .await;
    assert_config_response(response).await;
}

#[tokio::test]
async fn wire_reply_snapshots_and_handshake_tail_boundaries() {
    let (listener, endpoint) = setup(options());
    let legacy_success = include_bytes!("fixtures/0.21.0/handshake-acceptance.bin");
    let legacy_reject = include_bytes!("fixtures/0.21.0/handshake-rejection.bin");
    assert_eq!(legacy_success, ACCEPTED);
    assert_eq!(legacy_reject, b"\0\0\0\x0a\x01\x08>=0.49.0");

    // Independent serialized field ends: base, capabilities, trust epoch,
    // manifest formats, provisioning fingerprint, and audit health.
    for end in [BASE.len(), 52, 54, 57, 58, FULL.len()] {
        let (_peer, session, reply) = handshake(&listener, &endpoint, &FULL[..end]).await;
        assert_eq!(reply, legacy_success);
        let session = session.unwrap();
        let claims = session.agent_claims();
        assert_eq!(claims.status, Status::Ready);
        assert_eq!(claims.capabilities.contains("registrar"), end >= 52);
        assert_eq!(claims.active_trust_epoch, (end >= 54).then_some(42));
        assert_eq!(claims.manifest_formats.is_some(), end >= 57);
        assert!(claims.provisioning_fingerprint.is_none());
        assert!(claims.audit_health.is_none());
    }
    let fingerprint = ProvisioningFingerprint {
        components: [("agent".into(), "sha256:abc".into())].into(),
        domain: "example.org".into(),
    };
    let health = AuditHealth {
        below_low_water: true,
        intent_without_outcome: 3,
    };
    let mut complete = FULL[..57].to_vec();
    complete.extend(
        bincode::serde::encode_to_vec(
            (Some(&fingerprint), Some(&health)),
            bincode::config::standard(),
        )
        .unwrap(),
    );
    let (_peer, session, reply) = handshake(&listener, &endpoint, &complete).await;
    assert_eq!(reply, legacy_success);
    let session = session.unwrap();
    assert_eq!(
        session.agent_claims().provisioning_fingerprint.as_ref(),
        Some(&fingerprint)
    );
    assert_eq!(session.agent_claims().audit_health.as_ref(), Some(&health));

    for end in [BASE.len() - 1, 51, 53, 55, 56] {
        let (_peer, result, bytes) = handshake(&listener, &endpoint, &FULL[..end]).await;
        assert!(matches!(result, Err(SessionError::Malformed { .. })));
        assert_eq!(bytes, [] as [u8; 0]);
    }
    for index in [57, 58] {
        let mut invalid = FULL[..=index].to_vec();
        invalid[index] = 1; // Field is present, but the Some payload is truncated.
        let (_peer, result, bytes) = handshake(&listener, &endpoint, &invalid).await;
        assert!(matches!(result, Err(SessionError::Malformed { .. })));
        assert_eq!(bytes, [] as [u8; 0]);
    }
    for version in [b"0.48.0", b"0.50.0", b"broken"] {
        let mut claims = FULL.to_vec();
        claims[13..19].copy_from_slice(version);
        let (_peer, result, reply) = handshake(&listener, &endpoint, &claims).await;
        assert!(matches!(
            result,
            Err(SessionError::IncompatibleProtocol { version: actual, required })
                if actual.as_bytes() == version && required == ">=0.49.0, <=0.49.0"
        ));
        assert_eq!(reply, REJECTED);
    }
}

#[cfg(feature = "client")]
#[tokio::test]
async fn agent_connector_preserves_tls_name_and_session_lifetime() {
    use review_protocol::session::{AgentConnector, AgentTransportOptions};

    let server = Certificate::generate();
    let client = Certificate::generate();
    let listener = ServerListener::bind(LOOPBACK, server_tls(&server, &client), options()).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots(&server))
    .with_client_auth_cert(
        vec![client.der.clone()],
        PrivatePkcs8KeyDer::from(client.key.clone()).into(),
    )
    .unwrap();
    let connector = AgentConnector::bind(
        LOOPBACK,
        Arc::new(tls),
        AgentTransportOptions::default(),
        SessionOptions::legacy_compatible(),
    )
    .unwrap();
    assert_ne!(connector.local_addr().unwrap().port(), 0);
    let claims: review_protocol::AgentInfo =
        bincode::serde::decode_from_slice(FULL, bincode::config::standard())
            .unwrap()
            .0;
    let address = listener.local_addr().unwrap();
    let (failed_agent, failed_server) = tokio::join!(
        connector.connect(address, "wrong.example", &claims),
        async { listener.accept().await.unwrap().unwrap().handshake().await },
    );
    assert!(failed_agent.is_err());
    assert!(failed_server.is_err());
    let (agent, server) = tokio::join!(connector.connect(address, "localhost", &claims), async {
        listener.accept().await.unwrap().unwrap().handshake().await
    },);
    let (agent, _incoming) = agent.unwrap();
    let server = server.unwrap();
    drop(connector);
    assert_eq!(agent.remote_addr(), address);
    agent.close(ApplicationCode::new(0).unwrap(), b"done");
    drop(server);
    listener.close(b"done");
    listener.wait_idle().await;
}
