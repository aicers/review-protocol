//! Runs a complete local protocol server and drives it with in-process agents.
//!
//! ```sh
//! cargo run --example session_server --features client,server
//! ```
//!
//! The `server` module is the part an application writes. It binds a
//! listener, supervises handshakes, admits or refuses agents, serves request
//! and event streams, sends an outbound command, reloads TLS and shuts down,
//! all through protocol-owned APIs: it imports nothing from Quinn or oinq.
//! TLS verification, identity and authorization policy stay in its own code.
//!
//! The `agent` module plays the peer, and `pki` generates throwaway TLS
//! material at start-up. Nothing leaves the loopback interface.

use std::{error::Error, net::SocketAddr, time::Duration};

/// The error type of the example's fallible steps.
type BoxError = Box<dyn Error + Send + Sync>;

const LOOPBACK: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
/// The longest the whole demonstration may take before it is reported as hung.
const DEMO_TIMEOUT: Duration = Duration::from_secs(30);
const DETECTOR_ID: i32 = 7;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), BoxError> {
    tokio::time::timeout(DEMO_TIMEOUT, run())
        .await
        .map_err(|_| "the demonstration did not finish in time")?
}

async fn run() -> Result<(), BoxError> {
    let first = pki::Credential::generate("localhost")?;
    let replacement = pki::Credential::generate("localhost")?;
    let sensor_a = pki::Credential::generate("sensor-a")?;
    let sensor_b = pki::Credential::generate("sensor-b")?;

    // The application's enrolment records: which verified client certificate
    // speaks for which agent.
    let mut registry = server::Registry::default();
    registry.enroll(&sensor_a, "sensor-a");
    registry.enroll(&sensor_b, "sensor-b");
    let trusted_clients = [&sensor_a, &sensor_b];

    let mut server = server::Server::start(
        LOOPBACK,
        pki::server_config(&first, &trusted_clients)?,
        registry,
    )?;
    let address = server.local_addr()?;
    println!("[server] listening on {address}");

    // An enrolled certificate claiming another agent's name is refused after a
    // successful protocol handshake.
    let impostor = agent::Agent::connect(address, "impostor", &sensor_b, &first).await?;
    impostor.wait_for_refusal().await;

    // A matching certificate and claim is admitted.
    let sensor = agent::Agent::connect(address, "sensor-a", &sensor_a, &first).await?;
    let mut session = server
        .next_admitted()
        .await
        .ok_or("the server stopped before admitting sensor-a")?;

    // The agent's request and event streams run while the server's outbound
    // command completes on the same session.
    let (command, opened) = tokio::join!(
        session.run_detector_once(DETECTOR_ID),
        sensor.run_workload(),
    );
    command?;
    let opened = opened?;
    // Every stream the agent opened has been served before shutdown begins.
    session.wait_for_finished_streams(opened).await;

    server.reload_tls(pki::server_config(&replacement, &trusted_clients)?)?;
    // This agent trusts only the replacement certificate.
    let late = agent::Agent::connect(address, "sensor-b", &sensor_b, &replacement).await?;
    let late_session = server
        .next_admitted()
        .await
        .ok_or("the server stopped before admitting sensor-b")?;

    server.shutdown(vec![session, late_session]).await?;
    sensor.join().await?;
    late.join().await?;
    println!("[demo] every task joined; exiting");
    Ok(())
}

/// The application's server: protocol-owned session APIs, rustls for the TLS
/// policy, and the application's own identity and authorization decisions.
mod server {
    use std::{
        io,
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use review_protocol::{
        AgentInfo, MIN_PROTOCOL_VERSION_REQ, PROTOCOL_VERSION,
        auth::{AuthorizationContext, AuthorizationError, AuthorizerV2, PeerContext},
        server::{DetectionEventStreamHandler, Handler},
        service_id::{self, ServiceId},
        session::{
            PeerCertificates, PendingSession, ProtocolWindow, ServerHandle, ServerIncoming,
            ServerListener, ServerListenerOptions, ServerRequestOutcome, ServerRunError,
            ServerSessionClose, ServerSessionControl, ServerStream, ServerTransportOptions,
            SessionError, SessionOptions, UnadmittedSession,
        },
        types::DetectionEvent,
    };
    use rustls::pki_types::CertificateDer;
    use tokio::{
        sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
        task::{JoinError, JoinHandle, JoinSet},
    };

    use super::{BoxError, pki::Credential};

    /// Handshakes in progress at once; further connection attempts wait in
    /// the transport until a permit frees up.
    const MAX_PENDING_HANDSHAKES: usize = 4;
    /// Stream runners per admitted session at once.
    const MAX_STREAMS_PER_SESSION: usize = 8;
    /// The deadline for TLS and the protocol handshake together.
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
    /// How long a drained session's runners may take before they are aborted.
    const DRAIN_GRACE: Duration = Duration::from_secs(5);
    /// The only services this deployment grants to agents.
    const GRANTED: &[ServiceId] = &[service_id::SERVER_CONFIG_GET];
    const SHUTDOWN_REASON: &[u8] = b"server shutdown";

    /// Verified client certificates and the agent identity each one speaks for.
    #[derive(Default)]
    pub(super) struct Registry(Vec<(CertificateDer<'static>, String)>);

    impl Registry {
        pub(super) fn enroll(&mut self, credential: &Credential, identity: &str) {
            self.0
                .push((credential.certificate().clone(), identity.to_owned()));
        }

        /// Decides admission from the TLS-verified chain and the agent's claims.
        ///
        /// TLS already proved possession of the certificate's key. Its public
        /// bytes only select the enrolment record, so plain equality is fine.
        fn admit(
            &self,
            certificates: Option<&PeerCertificates>,
            claims: &AgentInfo,
        ) -> Result<String, String> {
            let leaf = certificates
                .and_then(|certificates| certificates.chain().first())
                .ok_or("no client certificate")?;
            let (_, identity) = self
                .0
                .iter()
                .find(|(certificate, _)| certificate.as_ref() == leaf.as_slice())
                .ok_or("certificate not enrolled")?;
            if claims.agent_name != *identity {
                return Err(format!("certificate is enrolled as {identity}"));
            }
            Ok(identity.clone())
        }
    }

    /// A policy evaluated before every request, not once per session.
    #[derive(Default)]
    struct SitePolicy {
        evaluations: AtomicUsize,
    }

    impl AuthorizerV2 for SitePolicy {
        fn authorize_with_context(
            &self,
            context: &AuthorizationContext,
            service: &ServiceId,
        ) -> Result<(), AuthorizationError> {
            let evaluation = self.evaluations.fetch_add(1, Ordering::Relaxed) + 1;
            let granted = GRANTED.contains(service);
            println!(
                "[server] policy evaluation #{evaluation}: {} -> {service}: {}",
                context.peer_identity().name(),
                if granted { "allowed" } else { "denied" },
            );
            if granted {
                Ok(())
            } else {
                Err(AuthorizationError::new("not granted to agents"))
            }
        }
    }

    /// Serves the built-in requests this deployment implements.
    struct ConfigStore;

    #[async_trait::async_trait]
    impl Handler for ConfigStore {
        async fn get_config(&self, peer: &str) -> Result<String, String> {
            println!("[server] request served: configuration for {peer}");
            Ok(format!("{{\"agent\":\"{peer}\",\"interval_secs\":30}}"))
        }
    }

    /// Receives one detection event stream.
    struct EventSink {
        identity: String,
        received: usize,
    }

    #[async_trait::async_trait]
    impl DetectionEventStreamHandler for EventSink {
        async fn handle_detection_event(&mut self, event: DetectionEvent) -> io::Result<()> {
            self.received += 1;
            println!(
                "[server] event received from {}: {:?}, score {}",
                self.identity, event.detection_model, event.score
            );
            Ok(())
        }

        async fn on_stream_end(&mut self) -> io::Result<()> {
            println!(
                "[server] events received: {} from {}; stream ended",
                self.received, self.identity
            );
            Ok(())
        }
    }

    struct App {
        registry: Registry,
        policy: Arc<SitePolicy>,
        handler: Arc<ConfigStore>,
    }

    /// The listener, its accept loop, and the sessions it admits.
    pub(super) struct Server {
        listener: Arc<ServerListener>,
        acceptor: JoinHandle<Result<(), SessionError>>,
        admitted: mpsc::UnboundedReceiver<Session>,
    }

    impl Server {
        /// Binds the listener and starts accepting connections.
        pub(super) fn start(
            address: SocketAddr,
            tls: Arc<rustls::ServerConfig>,
            registry: Registry,
        ) -> Result<Self, SessionError> {
            let options = ServerListenerOptions {
                transport: ServerTransportOptions::default(),
                // Frame budgets of the legacy wire; an application can lower
                // each message family's `FrameLimit` instead.
                session: SessionOptions::legacy_compatible(),
                protocol: ProtocolWindow::new(MIN_PROTOCOL_VERSION_REQ, PROTOCOL_VERSION)?,
                handshake_timeout: HANDSHAKE_TIMEOUT,
            };
            let listener = Arc::new(ServerListener::bind(address, tls, options)?);
            let app = Arc::new(App {
                registry,
                policy: Arc::new(SitePolicy::default()),
                handler: Arc::new(ConfigStore),
            });
            let (sender, admitted) = mpsc::unbounded_channel();
            let acceptor = tokio::spawn(accept_loop(listener.clone(), app, sender));
            Ok(Self {
                listener,
                acceptor,
                admitted,
            })
        }

        pub(super) fn local_addr(&self) -> Result<SocketAddr, SessionError> {
            self.listener.local_addr()
        }

        /// Waits for the next admitted session.
        pub(super) async fn next_admitted(&mut self) -> Option<Session> {
            self.admitted.recv().await
        }

        /// Serves new connections with `tls`; established sessions keep theirs.
        pub(super) fn reload_tls(
            &self,
            tls: Arc<rustls::ServerConfig>,
        ) -> Result<(), SessionError> {
            self.listener.reload_tls(tls)?;
            println!("[server] TLS reloaded: new connections get the replacement certificate");
            Ok(())
        }

        /// Stops acceptance, drains and closes every admitted session, then
        /// waits for the endpoint to go idle.
        pub(super) async fn shutdown(mut self, mut sessions: Vec<Session>) -> Result<(), BoxError> {
            self.listener.shutdown();
            println!("[server] shutdown: listener stopped accepting");
            // The accept loop joins its handshake tasks before returning.
            self.acceptor.await??;
            while let Ok(session) = self.admitted.try_recv() {
                sessions.push(session);
            }
            for session in sessions {
                session.shut_down().await?;
            }
            self.listener.wait_idle().await;
            println!("[server] shutdown: endpoint idle");
            Ok(())
        }
    }

    async fn accept_loop(
        listener: Arc<ServerListener>,
        app: Arc<App>,
        admitted: mpsc::UnboundedSender<Session>,
    ) -> Result<(), SessionError> {
        let permits = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
        let mut handshakes = JoinSet::new();
        let result = loop {
            // Both branches are cancel-safe: a lost accept consumes no attempt,
            // and a lost permit acquisition holds nothing.
            tokio::select! {
                Some(joined) = handshakes.join_next() => report_handshake_task(joined),
                accepted = accept_with_permit(&listener, &permits) => match accepted {
                    Ok(Some((pending, permit))) => {
                        handshakes.spawn(establish(pending, permit, app.clone(), admitted.clone()));
                    }
                    Ok(None) => break Ok(()),
                    Err(error) => break Err(error),
                },
            }
        };
        while let Some(joined) = handshakes.join_next().await {
            report_handshake_task(joined);
        }
        result
    }

    fn report_handshake_task(joined: Result<(), JoinError>) {
        if let Err(error) = joined {
            println!("[server] handshake task failed: {error}");
        }
    }

    async fn accept_with_permit(
        listener: &ServerListener,
        permits: &Arc<Semaphore>,
    ) -> Result<Option<(PendingSession, OwnedSemaphorePermit)>, SessionError> {
        let Ok(permit) = permits.clone().acquire_owned().await else {
            return Ok(None);
        };
        Ok(listener.accept().await?.map(|pending| (pending, permit)))
    }

    /// Handshakes one attempt under its permit and decides its admission.
    async fn establish(
        pending: PendingSession,
        _permit: OwnedSemaphorePermit,
        app: Arc<App>,
        admitted: mpsc::UnboundedSender<Session>,
    ) {
        let unadmitted = match pending.handshake().await {
            Ok(unadmitted) => unadmitted,
            Err(error) => {
                println!("[server] handshake failed: {error}");
                return;
            }
        };
        if let Some(session) = admit(&app, unadmitted)
            && let Err(mpsc::error::SendError(session)) = admitted.send(session)
        {
            // Nobody will shut this session down; do it here.
            session.control.abort(b"server stopped");
            let _ = session.supervisor.await;
        }
    }

    /// Admission adds no wire message: the handshake reply was already sent,
    /// so refusal is closing the connection.
    fn admit(app: &Arc<App>, unadmitted: UnadmittedSession) -> Option<Session> {
        let claims = unadmitted.agent_claims();
        let identity = match app.registry.admit(unadmitted.peer_certificates(), claims) {
            Ok(identity) => identity,
            Err(reason) => {
                println!(
                    "[server] refused {} from {}: {reason}",
                    claims.agent_name, claims.addr
                );
                unadmitted.control().abort(reason.as_bytes());
                return None;
            }
        };
        println!(
            "[server] admitted {identity} from {} ({} {}, protocol {})",
            claims.addr, claims.agent_name, claims.agent_version, claims.protocol_version
        );
        let control = unadmitted.control();
        let context = AuthorizationContext::from_peer_context(&PeerContext::new(identity.clone()));
        let (handle, incoming) = unadmitted.admit(context, app.policy.clone());
        let (finished, finished_streams) = watch::channel(0);
        let (draining, drain_signal) = watch::channel(false);
        let supervisor = tokio::spawn(supervise(
            identity.clone(),
            incoming,
            app.clone(),
            finished,
            drain_signal,
        ));
        Some(Session {
            identity,
            handle,
            control,
            draining,
            finished_streams,
            supervisor,
        })
    }

    /// How one stream runner ended.
    enum StreamReport {
        Requests(Result<ServerRequestOutcome, ServerRunError>),
        Events(Result<(), ServerRunError>),
    }

    type Joined = Result<StreamReport, JoinError>;

    /// Accepts and runs the session's streams until it is drained, then joins
    /// every runner it started.
    ///
    /// `drain_signal` turns true when shutdown begins. `drain` wakes only an
    /// `accept_next` in progress, and while every permit is held the
    /// supervisor waits for a permit instead, so it watches the signal too.
    async fn supervise(
        identity: String,
        mut incoming: ServerIncoming,
        app: Arc<App>,
        finished: watch::Sender<usize>,
        mut drain_signal: watch::Receiver<bool>,
    ) -> Vec<Joined> {
        let permits = Arc::new(Semaphore::new(MAX_STREAMS_PER_SESSION));
        let mut runners = JoinSet::new();
        let mut reports = Vec::new();
        loop {
            // Every branch is cancel-safe: a lost `accept_next` consumes no
            // stream, and a lost permit acquisition or signal wait holds
            // nothing.
            tokio::select! {
                // A dropped sender means nobody will drain this session.
                _ = drain_signal.wait_for(|draining| *draining) => break,
                Some(joined) = runners.join_next() => {
                    reports.push(joined);
                    finished.send_modify(|count| *count += 1);
                }
                accepted = accept_stream(&mut incoming, &permits) => match accepted {
                    Ok(Some((stream, permit))) => spawn_runner(&mut runners, stream, permit, &identity, &app),
                    Ok(None) => break,
                    Err(error) => {
                        println!("[server] {identity}: stream acceptance failed: {error}");
                        break;
                    }
                },
            }
        }
        let joined = tokio::time::timeout(DRAIN_GRACE, async {
            while let Some(joined) = runners.join_next().await {
                reports.push(joined);
            }
        })
        .await;
        if joined.is_err() {
            println!("[server] {identity}: runners outlived the drain grace; aborting them");
            runners.abort_all();
            while let Some(joined) = runners.join_next().await {
                reports.push(joined);
            }
        }
        reports
    }

    async fn accept_stream(
        incoming: &mut ServerIncoming,
        permits: &Arc<Semaphore>,
    ) -> Result<Option<(ServerStream, OwnedSemaphorePermit)>, SessionError> {
        let Ok(permit) = permits.clone().acquire_owned().await else {
            return Ok(None);
        };
        Ok(incoming.accept_next().await?.map(|stream| (stream, permit)))
    }

    fn spawn_runner(
        runners: &mut JoinSet<StreamReport>,
        stream: ServerStream,
        permit: OwnedSemaphorePermit,
        identity: &str,
        app: &App,
    ) {
        match stream {
            ServerStream::Requests(stream) => {
                let handler = app.handler.clone();
                runners.spawn(async move {
                    let _permit = permit;
                    StreamReport::Requests(stream.run(handler).await)
                });
            }
            ServerStream::DetectionEvents(stream) => {
                let sink = EventSink {
                    identity: identity.to_owned(),
                    received: 0,
                };
                runners.spawn(async move {
                    let _permit = permit;
                    StreamReport::Events(stream.run(sink).await)
                });
            }
        }
    }

    fn describe(joined: &Joined) -> String {
        match joined {
            Err(error) => format!("runner task failed: {error}"),
            Ok(StreamReport::Requests(Ok(ServerRequestOutcome::Finished))) => {
                "request stream finished".into()
            }
            Ok(StreamReport::Requests(Ok(ServerRequestOutcome::Unhandled(request)))) => {
                format!("request code {} left unserved", request.code())
            }
            Ok(StreamReport::Requests(Err(error))) => format!("request stream ended: {error}"),
            Ok(StreamReport::Events(Ok(()))) => "event stream finished".into(),
            Ok(StreamReport::Events(Err(error))) => format!("event stream ended: {error}"),
        }
    }

    /// An admitted session with its supervisor.
    pub(super) struct Session {
        identity: String,
        handle: ServerHandle,
        control: ServerSessionControl,
        draining: watch::Sender<bool>,
        finished_streams: watch::Receiver<usize>,
        supervisor: JoinHandle<Vec<Joined>>,
    }

    impl Session {
        /// Sends a typed outbound command and waits for the agent's answer.
        pub(super) async fn run_detector_once(&self, detector_id: i32) -> Result<(), SessionError> {
            self.handle.send_run_detector_once(detector_id).await?;
            println!(
                "[server] outbound command answered: {} ran detector {detector_id}",
                self.identity
            );
            Ok(())
        }

        /// Waits until `count` stream runners of this session have returned.
        pub(super) async fn wait_for_finished_streams(&mut self, count: usize) {
            // The sender lives in the supervisor, which runs until drained.
            let _ = self.finished_streams.wait_for(|done| *done >= count).await;
        }

        /// Drains the session, joins its runners, then closes it.
        async fn shut_down(self) -> Result<(), JoinError> {
            self.control.drain();
            self.draining.send_replace(true);
            for report in self.supervisor.await? {
                println!(
                    "[server] shutdown: {}: {}",
                    self.identity,
                    describe(&report)
                );
            }
            self.control.close(SHUTDOWN_REASON);
            let closed = match self.control.closed().await {
                ServerSessionClose::Local => "closed locally".to_owned(),
                ServerSessionClose::Peer { code, .. } => format!("closed by the agent ({code})"),
                ServerSessionClose::Transport(error) => format!("transport closed: {error}"),
            };
            println!("[server] shutdown: {}: {closed}", self.identity);
            Ok(())
        }
    }
}

/// The in-process peer, using the public agent connector.
mod agent {
    use std::{collections::BTreeSet, net::SocketAddr};

    use review_protocol::{
        AgentInfo, PROTOCOL_VERSION,
        session::{
            AgentConnector, AgentHandle, AgentIncoming, AgentRequest, AgentTransportOptions,
            CloseReason, SessionError, SessionOptions,
        },
        types::{
            Detail, DetectionEvent, DetectionModel, PortScanDetail, PrimarySubject, RawEventKind,
            Status, Target, TimeWindow,
        },
    };
    use tokio::task::JoinHandle;

    use super::{BoxError, LOOPBACK, pki};

    pub(super) struct Agent {
        name: &'static str,
        handle: AgentHandle,
        commands: JoinHandle<usize>,
    }

    impl Agent {
        /// Connects, performs the protocol handshake, and starts answering
        /// the manager's commands.
        pub(super) async fn connect(
            address: SocketAddr,
            name: &'static str,
            credential: &pki::Credential,
            trusted_server: &pki::Credential,
        ) -> Result<Self, BoxError> {
            let tls = pki::client_config(credential, trusted_server)?;
            let connector = AgentConnector::bind(
                LOOPBACK,
                tls,
                AgentTransportOptions::default(),
                SessionOptions::legacy_compatible(),
            )?;
            let claims = AgentInfo {
                agent_name: name.into(),
                agent_version: env!("CARGO_PKG_VERSION").into(),
                protocol_version: PROTOCOL_VERSION.into(),
                addr: connector.local_addr()?,
                status: Status::Ready,
                capabilities: BTreeSet::new(),
                active_trust_epoch: None,
                manifest_formats: None,
                provisioning_fingerprint: None,
                audit_health: None,
            };
            let (handle, incoming) = connector.connect(address, "localhost", &claims).await?;
            println!("[agent {name}] handshake accepted");
            let commands = tokio::spawn(answer_commands(name, incoming));
            Ok(Self {
                name,
                handle,
                commands,
            })
        }

        /// Waits for the server to close the connection after the handshake.
        pub(super) async fn wait_for_refusal(self) {
            println!(
                "[agent {}] {}",
                self.name,
                describe(self.handle.closed().await)
            );
            // Command acceptance ends with the connection.
            let _ = self.commands.await;
        }

        /// Streams detection events while making requests, then finishes
        /// every stream it opened. Returns the number of streams opened.
        pub(super) async fn run_workload(&self) -> Result<usize, BoxError> {
            let mut events = self.handle.open_detection_event_stream().await?;
            events.start(&detection_event(1, 0.9))?;
            events.flush().await?;

            let config = self.handle.get_config().await?;
            println!("[agent {}] configuration: {config}", self.name);
            match self.handle.get_model("ransomware").await {
                Err(SessionError::RemoteRejection(reason)) => {
                    println!("[agent {}] model request refused: {reason}", self.name);
                }
                Err(error) => return Err(error.into()),
                Ok(_) => return Err("the policy unexpectedly granted a model".into()),
            }

            events.start(&detection_event(2, 0.7))?;
            events.finish().await?;
            // One event stream and two single-request streams.
            Ok(3)
        }

        /// Joins the agent's tasks after the server closed the connection.
        pub(super) async fn join(self) -> Result<(), BoxError> {
            let closed = describe(self.handle.closed().await);
            let answered = self.commands.await?;
            println!(
                "[agent {}] {closed}; answered {answered} command(s)",
                self.name
            );
            Ok(())
        }
    }

    /// Answers commands until the connection closes, returning how many.
    async fn answer_commands(name: &str, mut incoming: AgentIncoming) -> usize {
        let mut answered = 0;
        while let Ok(mut stream) = incoming.accept().await {
            while let Ok(Some(request)) = stream.next().await {
                let AgentRequest::RunDetectorOnce { request, reply } = request else {
                    println!("[agent {name}] ignoring an unexpected command");
                    break;
                };
                println!("[agent {name}] running detector {request} once");
                if reply.respond(Ok(())).await.is_ok() {
                    answered += 1;
                }
            }
            let _ = stream.finish();
        }
        answered
    }

    fn describe(closed: CloseReason) -> String {
        match closed {
            CloseReason::Application { code, reason } => format!(
                "connection closed by the server (code {}): {}",
                code.get(),
                String::from_utf8_lossy(&reason)
            ),
            other => format!("connection closed: {other:?}"),
        }
    }

    fn detection_event(cluster_id: u32, score: f64) -> DetectionEvent {
        DetectionEvent {
            time: jiff::Timestamp::now(),
            sensor: None,
            detection_model: DetectionModel::PortScan,
            raw_event_kind: RawEventKind::Conn,
            category: None,
            target: Target::Subject {
                primary: PrimarySubject::Cluster {
                    clustering_model: 0,
                    cluster_id,
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
}

/// Throwaway self-signed credentials and the rustls configurations built from
/// them. Dev builds compile both the `ring` and `aws_lc_rs` providers, so the
/// configurations name one explicitly.
mod pki {
    use std::sync::Arc;

    use rustls::{
        RootCertStore,
        crypto::CryptoProvider,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        server::WebPkiClientVerifier,
    };

    use super::BoxError;

    /// A certificate and its private key.
    pub(super) struct Credential {
        certificate: CertificateDer<'static>,
        key: PrivatePkcs8KeyDer<'static>,
    }

    impl Credential {
        pub(super) fn generate(name: &str) -> Result<Self, rcgen::Error> {
            let generated = rcgen::generate_simple_self_signed(vec![name.to_owned()])?;
            Ok(Self {
                certificate: generated.cert.into(),
                key: PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()),
            })
        }

        pub(super) fn certificate(&self) -> &CertificateDer<'static> {
            &self.certificate
        }

        fn key(&self) -> PrivateKeyDer<'static> {
            self.key.clone_key().into()
        }
    }

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    fn roots<'a>(
        trusted: impl IntoIterator<Item = &'a Credential>,
    ) -> Result<RootCertStore, BoxError> {
        let mut roots = RootCertStore::empty();
        for credential in trusted {
            roots.add(credential.certificate.clone())?;
        }
        Ok(roots)
    }

    /// Requires a client certificate issued by one of `trusted_clients`.
    pub(super) fn server_config(
        credential: &Credential,
        trusted_clients: &[&Credential],
    ) -> Result<Arc<rustls::ServerConfig>, BoxError> {
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots(trusted_clients.iter().copied())?),
            provider(),
        )
        .build()?;
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![credential.certificate.clone()], credential.key())?;
        Ok(Arc::new(config))
    }

    pub(super) fn client_config(
        credential: &Credential,
        trusted_server: &Credential,
    ) -> Result<Arc<rustls::ClientConfig>, BoxError> {
        let config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots([trusted_server])?)
            .with_client_auth_cert(vec![credential.certificate.clone()], credential.key())?;
        Ok(Arc::new(config))
    }
}
