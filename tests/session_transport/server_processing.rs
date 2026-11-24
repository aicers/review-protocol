use std::{
    collections::HashSet,
    io,
    sync::{Arc, Mutex},
};

use review_protocol::{
    auth::{AuthorizationContext, AuthorizationError, AuthorizerV2, PeerContext},
    server::{DetectionEventStreamHandler, Handler},
    service_id::{self, ServiceId},
    session::{
        Connection, FrameLimit, OutcomeCertainty, ServerRequestOutcome, ServerRunError,
        SessionError, SessionOptions,
    },
    types::{
        ColumnStatisticsUpdate, CustomerDataDeletionReport, DataSource, DataSourceKey, Detail,
        DetectionEvent, DetectionModel, DetectorStatusReport, HostNetworkGroup, LabelDb,
        NetworkListItem, OutlierInfo, PrimarySubject, RawEventKind, ReportedRunState, Target,
        TimeSeriesGenerationPolicy, TimeSeriesUpdate, TimeWindow, UpdateClusterRequest,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{event_stream, raw_sessions, raw_sessions_at, request_stream};

const REQUESTS: &[u8] = include_bytes!("../fixtures/current/server-requests.bin");
const RESPONSES: &[u8] = include_bytes!("../fixtures/current/server-responses.bin");
const DENIED_REQUESTS: &[u8] = include_bytes!("../fixtures/current/server-denied-requests.bin");
const DENIED_RESPONSES: &[u8] = include_bytes!("../fixtures/current/server-denied-responses.bin");
const UNKNOWN_REQUESTS: &[u8] = include_bytes!("../fixtures/current/server-unknown-requests.bin");
const UNKNOWN_RESPONSES: &[u8] = include_bytes!("../fixtures/current/server-unknown-responses.bin");
const MALFORMED_REQUEST: &[u8] = include_bytes!("../fixtures/current/server-malformed-request.bin");
const TRUNCATED_REQUEST: &[u8] = include_bytes!("../fixtures/current/server-truncated-request.bin");
const DELEGATED_REQUESTS: &[u8] =
    include_bytes!("../fixtures/current/server-delegated-requests.bin");
const EVENTS: &[u8] = include_bytes!("../fixtures/current/server-events.bin");
const TRUNCATED_EVENT: &[u8] = include_bytes!("../fixtures/current/server-truncated-event.bin");

const GET_CONFIG: &[u8] = &[0, 0, 0, 4, 36, 0, 0, 0];
const GET_ALLOWLIST: &[u8] = &[0, 0, 0, 4, 32, 0, 0, 0];
const GET_BLOCKLIST: &[u8] = &[0, 0, 0, 4, 33, 0, 0, 0];
const GET_LABEL_DB_PATTERNS: u32 = 15;

/// Returns the detection event a fixture frame carries: a `LockyRansomware`
/// detection about cluster `cluster_id` of clustering model 0, at time 0.
fn fixture_event(cluster_id: u32, score: f64) -> DetectionEvent {
    DetectionEvent {
        time: jiff::Timestamp::UNIX_EPOCH,
        sensor: None,
        detection_model: DetectionModel::LockyRansomware,
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
        detail: Detail::LockyRansomware,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Observation {
    Authorization(ServiceId),
    Handler(ServiceId),
}

type Trace = Arc<Mutex<Vec<Observation>>>;

#[derive(Default)]
struct FixtureHandler(Trace);

impl FixtureHandler {
    fn record(&self, service: ServiceId) {
        self.0.lock().unwrap().push(Observation::Handler(service));
    }

    fn unsupported<T>(&self, service: ServiceId) -> Result<T, String> {
        self.record(service);
        Err("not supported".into())
    }
}

#[derive(Default)]
struct Policy {
    trace: Trace,
    deny: Option<ServiceId>,
}

impl Policy {
    fn deny_model() -> Self {
        Self {
            deny: Some(service_id::SERVER_MODEL_GET),
            ..Self::default()
        }
    }
}

impl AuthorizerV2 for Policy {
    fn authorize_with_context(
        &self,
        context: &AuthorizationContext,
        service: &ServiceId,
    ) -> Result<(), AuthorizationError> {
        assert_eq!(context.peer_identity().name(), "verified-peer");
        self.trace
            .lock()
            .unwrap()
            .push(Observation::Authorization(*service));
        if self.deny.as_ref() == Some(service) {
            return Err(AuthorizationError::new("private policy reason"));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Handler for FixtureHandler {
    async fn get_config(&self, peer: &str) -> Result<String, String> {
        self.record(service_id::SERVER_CONFIG_GET);
        assert_eq!(peer, "verified-peer");
        Ok("configuration".into())
    }

    async fn get_model(&self, name: &str) -> Result<Vec<u8>, String> {
        self.record(service_id::SERVER_MODEL_GET);
        assert_eq!(name, "m");
        Err("model unavailable".into())
    }

    async fn get_data_source(&self, key: &DataSourceKey<'_>) -> Result<Option<DataSource>, String> {
        self.record(service_id::SERVER_DATA_SOURCE_GET);
        assert!(matches!(key, DataSourceKey::Name("source")));
        Ok(None)
    }

    async fn get_labeldb_patterns(
        &self,
        names: &[(&str, &str)],
    ) -> Result<Vec<(String, Option<LabelDb>)>, String> {
        self.record(service_id::SERVER_LABEL_GET_DB_PATTERNS);
        assert_eq!(names, &[("db", "rule")]);
        Ok(vec![("db".into(), None)])
    }

    async fn renew_certificate(&self, peer: &str) -> Result<(String, String), String> {
        self.record(service_id::SERVER_CERTIFICATE_RENEW);
        assert_eq!(peer, "verified-peer");
        Ok(("certificate".into(), "key".into()))
    }

    async fn get_indicator(&self, name: &str) -> Result<HashSet<Vec<String>>, String> {
        assert_eq!(name, "indicator");
        self.unsupported(service_id::SERVER_INDICATOR_GET)
    }

    async fn insert_column_statistics(
        &self,
        statistics: &[ColumnStatisticsUpdate],
        model_id: u32,
        timestamp: i64,
    ) -> Result<(), String> {
        assert_eq!((statistics.len(), model_id, timestamp), (0, 9, -3));
        self.unsupported(service_id::SERVER_STATISTICS_INSERT_COLUMN)
    }

    async fn insert_model(&self, model: &[u8]) -> Result<u32, String> {
        assert_eq!(model, [1, 2]);
        self.unsupported(service_id::SERVER_MODEL_INSERT)
    }

    async fn insert_time_series(
        &self,
        series: &[TimeSeriesUpdate],
        model_id: u32,
        timestamp: i64,
    ) -> Result<(), String> {
        assert_eq!((series[0].cluster_id, model_id, timestamp), (2, 9, -3));
        self.unsupported(service_id::SERVER_STATISTICS_INSERT_TIME_SERIES)
    }

    async fn remove_model(&self, name: &str) -> Result<(), String> {
        assert_eq!(name, "m");
        self.unsupported(service_id::SERVER_MODEL_REMOVE)
    }

    async fn update_clusters(
        &self,
        clusters: &[UpdateClusterRequest],
        model_id: u32,
    ) -> Result<(), String> {
        assert_eq!((clusters.len(), model_id), (0, 5));
        self.unsupported(service_id::SERVER_CLUSTER_UPDATE)
    }

    async fn update_model(&self, model: &[u8]) -> Result<u32, String> {
        assert_eq!(model, [2, 3]);
        self.unsupported(service_id::SERVER_MODEL_UPDATE)
    }

    async fn update_outliers(
        &self,
        outliers: &[OutlierInfo],
        model_id: u32,
        timestamp: i64,
    ) -> Result<(), String> {
        assert_eq!((outliers.len(), model_id, timestamp), (0, 5, -7));
        self.unsupported(service_id::SERVER_OUTLIER_UPDATE)
    }

    async fn insert_detection_events(
        &self,
        model_id: u32,
        round: u32,
        events: &[DetectionEvent],
    ) -> Result<(), String> {
        assert_eq!((model_id, round), (1, 2));
        assert_eq!(events, [fixture_event(1, 1.0)]);
        self.unsupported(service_id::SERVER_EVENT_INSERT_LABELS)
    }

    async fn insert_data_source(&self, source: &DataSource) -> Result<u32, String> {
        assert_eq!((source.id, source.address.port()), (1, 42));
        self.unsupported(service_id::SERVER_DATA_SOURCE_INSERT)
    }

    async fn get_trusted_domain_list(&self) -> Result<Vec<String>, String> {
        self.unsupported(service_id::SERVER_LIST_TRUSTED_DOMAIN)
    }

    async fn get_outliers(
        &self,
        model_id: u32,
        timestamp: i64,
    ) -> Result<Vec<(String, Vec<i64>)>, String> {
        assert_eq!((model_id, timestamp), (2, -1));
        self.unsupported(service_id::SERVER_OUTLIER_GET)
    }

    async fn get_tor_exit_node_list(&self) -> Result<Vec<String>, String> {
        self.unsupported(service_id::SERVER_LIST_TOR_EXIT_NODE)
    }

    async fn get_internal_network_list(&self, peer: &str) -> Result<HostNetworkGroup, String> {
        assert_eq!(peer, "verified-peer");
        self.unsupported(service_id::SERVER_LIST_INTERNAL_NETWORK)
    }

    async fn get_allowlist(&self, peer: &str) -> Result<Vec<NetworkListItem>, String> {
        assert_eq!(peer, "verified-peer");
        self.unsupported(service_id::SERVER_LIST_ALLOWLIST)
    }

    async fn get_blocklist(&self, peer: &str) -> Result<Vec<NetworkListItem>, String> {
        assert_eq!(peer, "verified-peer");
        self.unsupported(service_id::SERVER_LIST_BLOCKLIST)
    }

    async fn get_pretrained_model(&self, name: &str) -> Result<Vec<u8>, String> {
        assert_eq!(name, "pretrained");
        self.unsupported(service_id::SERVER_MODEL_GET_PRETRAINED)
    }

    async fn get_trusted_user_agent_list(&self) -> Result<Vec<String>, String> {
        self.unsupported(service_id::SERVER_LIST_TRUSTED_USER_AGENT)
    }

    async fn get_time_series_generation_policy_list(
        &self,
        peer: &str,
    ) -> Result<Vec<TimeSeriesGenerationPolicy>, String> {
        assert_eq!(peer, "verified-peer");
        self.unsupported(service_id::SERVER_LIST_TIME_SERIES_GENERATION_POLICY)
    }

    async fn report_customer_data_deletion(
        &self,
        report: &CustomerDataDeletionReport,
    ) -> Result<(), String> {
        assert_eq!((report.id, report.completed_at), (3, Some(-2)));
        self.unsupported(service_id::SERVER_CUSTOMER_DATA_DELETION_REPORT)
    }

    async fn upload_run_model(&self, peer: &str, run_id: u32, model: &[u8]) -> Result<(), String> {
        assert_eq!((peer, run_id, model), ("verified-peer", 7, &[0, 1][..]));
        self.unsupported(service_id::SERVER_RUN_UPLOAD_MODEL)
    }

    async fn report_run(
        &self,
        peer: &str,
        run_id: u32,
        state: ReportedRunState,
        reason: Option<&str>,
    ) -> Result<(), String> {
        assert_eq!(
            (peer, run_id, state, reason),
            ("verified-peer", 7, ReportedRunState::Failed, Some("reason"))
        );
        self.unsupported(service_id::SERVER_RUN_REPORT)
    }

    async fn report_active_runs(&self, peer: &str, ids: &[u32]) -> Result<(), String> {
        assert_eq!(peer, "verified-peer");
        assert_eq!(ids, [7, 8]);
        self.unsupported(service_id::SERVER_RUN_REPORT_ACTIVE)
    }

    async fn report_detector_status(
        &self,
        peer: &str,
        report: &DetectorStatusReport,
    ) -> Result<(), String> {
        assert_eq!((peer, report.detector_id), ("verified-peer", 3));
        assert!(report.detection_models.is_empty() && report.excluded.is_empty());
        self.unsupported(service_id::SERVER_DETECTOR_REPORT_STATUS)
    }
}

fn context() -> AuthorizationContext {
    AuthorizationContext::from_peer_context(&PeerContext::new("verified-peer"))
}

#[derive(Clone, Default)]
struct EventLog {
    entries: Arc<Mutex<Vec<String>>>,
    fail_callback: Option<&'static str>,
}

impl EventLog {
    fn record(&self, callback: &str, detail: String) -> io::Result<()> {
        self.entries.lock().unwrap().push(detail);
        if self.fail_callback == Some(callback) {
            return Err(io::Error::other(format!("{callback} failed")));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl DetectionEventStreamHandler for EventLog {
    async fn handle_detection_event(&mut self, message: DetectionEvent) -> io::Result<()> {
        self.record("event", format!("{message:?}"))
    }

    async fn on_error(&mut self, error: &str) -> io::Result<()> {
        self.record("error", error.to_string())
    }

    async fn on_stream_end(&mut self) -> io::Result<()> {
        self.record("end", "end".into())
    }
}

#[cfg(feature = "test-support")]
mod legacy {
    use review_protocol::{
        auth::AuthorizerV2Adapter,
        server::{handle_authorized_with_context, process_detection_event_stream},
        test::TEST_ENV,
    };

    use super::*;

    async fn legacy_requests(
        server: &review_protocol::server::Connection,
        client: &review_protocol::client::Connection,
        requests: &[u8],
        policy: &dyn review_protocol::auth::AuthorizerV2,
    ) -> (Vec<u8>, io::Result<Option<(u32, Vec<u8>)>>) {
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        send.write_all(requests).await.unwrap();
        send.finish().unwrap();
        let (result, responses) = tokio::join!(
            async {
                let (mut send, mut recv) = server.as_quinn().accept_bi().await.unwrap();
                let result = handle_authorized_with_context(
                    &mut FixtureHandler::default(),
                    &mut send,
                    &mut recv,
                    &context(),
                    policy,
                )
                .await;
                send.finish().unwrap();
                result
            },
            recv.read_to_end(8192),
        );
        (responses.unwrap(), result)
    }

    async fn legacy_events(
        server: &review_protocol::server::Connection,
        client: &review_protocol::client::Connection,
        bytes: &[u8],
        handler: EventLog,
    ) -> io::Result<()> {
        let mut send = client.open_uni().await.unwrap();
        send.write_all(bytes).await.unwrap();
        send.finish().unwrap();
        process_detection_event_stream(server.accept_uni().await.unwrap(), handler).await
    }

    #[tokio::test]
    async fn legacy_dispatch_matches_pinned_requests_and_responses() {
        let env = TEST_ENV.lock().await;
        let (server, client) = env.setup().await;
        let allow = AuthorizerV2Adapter::new(review_protocol::auth::NoopAuthorizer);
        let (responses, result) = legacy_requests(&server, &client, REQUESTS, &allow).await;
        assert!(result.unwrap().is_none());
        assert_eq!(responses, RESPONSES);

        let (responses, result) =
            legacy_requests(&server, &client, DENIED_REQUESTS, &Policy::deny_model()).await;
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            review_protocol::ProtocolErrorKind::of_io_error(&error),
            review_protocol::ProtocolErrorKind::Forbidden
        );
        assert_eq!(responses, DENIED_RESPONSES);

        let (responses, result) = legacy_requests(&server, &client, UNKNOWN_REQUESTS, &allow).await;
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            review_protocol::ProtocolErrorKind::of_io_error(&error),
            review_protocol::ProtocolErrorKind::NotSupported
        );
        assert_eq!(responses, UNKNOWN_RESPONSES);

        for code in [2_u8, 9, 14] {
            let requests = delegated_requests(code);
            let (responses, result) = legacy_requests(&server, &client, &requests, &allow).await;
            assert_eq!(
                result.unwrap(),
                Some((u32::from(code), b"\x06opaque".to_vec()))
            );
            assert_eq!(responses, Vec::<u8>::new());
        }

        let (responses, result) =
            legacy_requests(&server, &client, MALFORMED_REQUEST, &allow).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(responses, Vec::<u8>::new());

        let (responses, result) =
            legacy_requests(&server, &client, TRUNCATED_REQUEST, &allow).await;
        assert!(result.unwrap().is_none());
        assert_eq!(responses, Vec::<u8>::new());
    }

    #[tokio::test]
    async fn legacy_event_callbacks_match_pinned_stream() {
        let env = TEST_ENV.lock().await;
        let (server, client) = env.setup().await;
        let log = EventLog::default();
        legacy_events(&server, &client, EVENTS, log.clone())
            .await
            .unwrap();
        check_events(&log);

        let log = EventLog::default();
        legacy_events(&server, &client, TRUNCATED_EVENT, log.clone())
            .await
            .unwrap();
        assert_eq!(*log.entries.lock().unwrap(), ["end"]);
        assert_eq!(
            legacy_events(&server, &client, &EVENTS[..1], EventLog::default())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof,
        );
    }
}

fn delegated_requests(code: u8) -> Vec<u8> {
    let mut bytes = DELEGATED_REQUESTS.to_vec();
    bytes[4] = code;
    bytes
}

fn check_events(log: &EventLog) {
    let entries = log.entries.lock().unwrap();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0], format!("{:?}", fixture_event(1, 1.0)));
    assert_eq!(
        entries[1],
        "decoding error: InvalidIntegerType { expected: I128, found: Reserved }"
    );
    assert_eq!(
        &entries[2..],
        [format!("{:?}", fixture_event(2, 2.0)), "end".to_string()]
    );
}

async fn open_requests(node: &Connection, bytes: &[u8]) -> (oinq::SendStream, oinq::RecvStream) {
    let (mut send, recv) = node.open_bi().await.unwrap();
    send.write_all(bytes).await.unwrap();
    (send, recv)
}

async fn open_events(node: &Connection, bytes: &[u8]) -> oinq::SendStream {
    let mut send = node.open_uni().await.unwrap();
    send.write_all(bytes).await.unwrap();
    send
}

#[tokio::test]
async fn runner_dispatches_every_built_in_on_one_stream() {
    use review_protocol::service_id::*;

    let expected_services = [
        SERVER_DATA_SOURCE_GET,
        SERVER_INDICATOR_GET,
        SERVER_MODEL_GET,
        SERVER_MODEL_GET_NAMES,
        SERVER_STATISTICS_INSERT_COLUMN,
        SERVER_MODEL_INSERT,
        SERVER_STATISTICS_INSERT_TIME_SERIES,
        SERVER_MODEL_REMOVE,
        SERVER_CLUSTER_UPDATE,
        SERVER_MODEL_UPDATE,
        SERVER_OUTLIER_UPDATE,
        SERVER_EVENT_INSERT_LABELS,
        SERVER_LABEL_GET_DB_PATTERNS,
        SERVER_DATA_SOURCE_INSERT,
        SERVER_CERTIFICATE_RENEW,
        SERVER_LIST_TRUSTED_DOMAIN,
        SERVER_OUTLIER_GET,
        SERVER_LIST_TOR_EXIT_NODE,
        SERVER_LIST_INTERNAL_NETWORK,
        SERVER_LIST_ALLOWLIST,
        SERVER_LIST_BLOCKLIST,
        SERVER_MODEL_GET_PRETRAINED,
        SERVER_LIST_TRUSTED_USER_AGENT,
        SERVER_CONFIG_GET,
        SERVER_LIST_TIME_SERIES_GENERATION_POLICY,
        SERVER_CUSTOMER_DATA_DELETION_REPORT,
        SERVER_RUN_UPLOAD_MODEL,
        SERVER_RUN_REPORT,
        SERVER_RUN_REPORT_ACTIVE,
        SERVER_DETECTOR_REPORT_STATUS,
    ];
    // The agent speaks the current protocol, so the list pulls reach the
    // handler; an earlier agent's are answered without it.
    let (incoming, _, _, node) = raw_sessions_at(
        SessionOptions::legacy_compatible(),
        review_protocol::PROTOCOL_VERSION,
    )
    .await;
    let handler = Arc::new(FixtureHandler::default());
    let trace = handler.0.clone();
    let policy = Policy {
        trace: trace.clone(),
        deny: None,
    };
    let mut incoming = incoming.with_authorization(context(), Arc::new(policy));

    let (mut send, mut recv) = open_requests(&node, REQUESTS).await;
    send.finish().unwrap();
    let runner = tokio::spawn(request_stream(&mut incoming).await.run(handler));
    assert!(matches!(
        runner.await.unwrap(),
        Ok(ServerRequestOutcome::Finished)
    ));
    let mut responses = Vec::new();
    recv.read_to_end(&mut responses).await.unwrap();
    assert_eq!(responses, RESPONSES);

    let mut expected = Vec::new();
    for service in expected_services {
        expected.push(Observation::Authorization(service));
        // This method uses the actual default implementation.
        if service != SERVER_MODEL_GET_NAMES {
            expected.push(Observation::Handler(service));
        }
    }
    assert_eq!(*trace.lock().unwrap(), expected);
}

#[tokio::test]
async fn runner_denies_a_later_request_before_parsing_or_dispatch() {
    let (incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let handler = Arc::new(FixtureHandler::default());
    let trace = handler.0.clone();
    let policy = Policy {
        trace: trace.clone(),
        ..Policy::deny_model()
    };
    let mut incoming = incoming.with_authorization(context(), Arc::new(policy));

    let (mut send, mut recv) = open_requests(&node, &DENIED_REQUESTS[..GET_CONFIG.len()]).await;
    let runner = tokio::spawn(request_stream(&mut incoming).await.run(handler));
    let mut first = [0; 19];
    recv.read_exact(&mut first).await.unwrap();
    assert_eq!(first, DENIED_RESPONSES[..first.len()]);

    // Even an invalid argument to the denied service gets the legacy denial.
    send.write_all(MALFORMED_REQUEST).await.unwrap();
    send.write_all(GET_CONFIG).await.unwrap();
    send.finish().unwrap();
    let Err(error) = runner.await.unwrap() else {
        panic!("expected denial");
    };
    assert_eq!(error.certainty(), Some(OutcomeCertainty::Rejected));
    assert!(
        matches!(error, ServerRunError::AuthorizationDenied { service, source }
        if service == service_id::SERVER_MODEL_GET && source.reason() == "private policy reason")
    );
    let mut rest = Vec::new();
    recv.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, DENIED_RESPONSES[first.len()..]);
    assert_eq!(
        *trace.lock().unwrap(),
        [
            Observation::Authorization(service_id::SERVER_CONFIG_GET),
            Observation::Handler(service_id::SERVER_CONFIG_GET),
            Observation::Authorization(service_id::SERVER_MODEL_GET),
        ]
    );
}

#[tokio::test]
async fn runner_reevaluates_policy_for_the_same_service() {
    #[derive(Default)]
    struct AllowFirst(std::sync::atomic::AtomicUsize);

    impl AuthorizerV2 for AllowFirst {
        fn authorize_with_context(
            &self,
            _: &AuthorizationContext,
            service: &ServiceId,
        ) -> Result<(), AuthorizationError> {
            assert_eq!(*service, service_id::SERVER_CONFIG_GET);
            if self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                Ok(())
            } else {
                Err(AuthorizationError::new("later policy decision"))
            }
        }
    }

    let (incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let handler = Arc::new(FixtureHandler::default());
    let mut incoming = incoming.with_authorization(context(), Arc::new(AllowFirst::default()));
    let (mut send, mut recv) = open_requests(&node, GET_CONFIG).await;
    send.write_all(GET_CONFIG).await.unwrap();
    send.finish().unwrap();
    assert!(matches!(
        request_stream(&mut incoming)
            .await
            .run(handler.clone())
            .await,
        Err(ServerRunError::AuthorizationDenied { .. }),
    ));
    let mut responses = Vec::new();
    recv.read_to_end(&mut responses).await.unwrap();
    assert_eq!(responses, DENIED_RESPONSES);
    assert_eq!(
        *handler.0.lock().unwrap(),
        [Observation::Handler(service_id::SERVER_CONFIG_GET)]
    );
}

#[tokio::test]
async fn runner_unknown_code_is_terminal_and_unbound_runner_fails_closed() {
    let (mut incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let handler = Arc::new(FixtureHandler::default());
    let policy = Arc::new(Policy::default());

    let (send, mut recv) = open_requests(&node, GET_CONFIG).await;
    assert!(matches!(
        request_stream(&mut incoming)
            .await
            .run(handler.clone())
            .await,
        Err(ServerRunError::MissingAuthorization),
    ));
    assert_eq!(send.stopped().await.unwrap().unwrap().get(), 1);
    assert_eq!(
        recv.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );

    let mut incoming = incoming.with_authorization(context(), policy.clone());
    let (mut send, mut recv) = open_requests(&node, UNKNOWN_REQUESTS).await;
    send.finish().unwrap();
    let Err(error) = request_stream(&mut incoming)
        .await
        .run(handler.clone())
        .await
    else {
        panic!("expected unknown request error");
    };
    assert_eq!(error.certainty(), Some(OutcomeCertainty::Rejected));
    assert!(matches!(
        error,
        ServerRunError::UnknownRequestCode { code: 999 }
    ));
    let mut replies = Vec::new();
    recv.read_to_end(&mut replies).await.unwrap();
    assert_eq!(replies, UNKNOWN_RESPONSES);
    assert!(handler.0.lock().unwrap().is_empty());
    assert!(policy.trace.lock().unwrap().is_empty());
}

#[tokio::test]
async fn runner_preserves_local_rejections_when_the_reply_exceeds_the_budget() {
    let mut options = SessionOptions::legacy_compatible();
    // A GetConfig request and its successful reply fit this limit.
    options.unary = FrameLimit::new(16).unwrap();
    let (incoming, _, _, node) = raw_sessions(options).await;
    let policy = Arc::new(Policy {
        deny: Some(service_id::SERVER_CONFIG_GET),
        ..Policy::default()
    });
    let mut incoming = incoming.with_authorization(context(), policy.clone());
    let handler = Arc::new(FixtureHandler::default());

    for (request, denied_service) in [
        (GET_CONFIG, Some(service_id::SERVER_CONFIG_GET)),
        (UNKNOWN_REQUESTS, None),
    ] {
        let (mut send, mut recv) = open_requests(&node, request).await;
        send.finish().unwrap();
        let Err(error) = request_stream(&mut incoming)
            .await
            .run(handler.clone())
            .await
        else {
            panic!("expected a local rejection");
        };
        match (denied_service, &error) {
            (Some(expected), ServerRunError::AuthorizationDenied { service, source }) => {
                assert_eq!(*service, expected);
                assert_eq!(source.reason(), "private policy reason");
            }
            (None, ServerRunError::UnknownRequestCode { code }) => assert_eq!(*code, 999),
            (_, error) => panic!("unexpected rejection: {error:?}"),
        }
        assert_eq!(error.certainty(), Some(OutcomeCertainty::Rejected));
        assert_eq!(
            recv.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
    }
    assert_eq!(
        *policy.trace.lock().unwrap(),
        [Observation::Authorization(service_id::SERVER_CONFIG_GET)]
    );
    assert!(handler.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn runner_delegates_registered_codes_and_can_resume() {
    let (incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let handler = Arc::new(FixtureHandler::default());
    let trace = handler.0.clone();
    let policy = Policy {
        trace: trace.clone(),
        deny: None,
    };
    let mut incoming = incoming.with_authorization(context(), Arc::new(policy));

    for (code, service) in [
        (2, service_id::SERVER_EVENT_GET_MAX_ID_NUM),
        (9, service_id::SERVER_OUTLIER_REMOVE),
        (14, service_id::SERVER_DATA_SOURCE_LIST),
    ] {
        let (mut send, mut recv) = open_requests(&node, &delegated_requests(code)).await;
        send.finish().unwrap();
        let ServerRequestOutcome::Unhandled(request) = request_stream(&mut incoming)
            .await
            .run(handler.clone())
            .await
            .unwrap()
        else {
            panic!("expected legacy handoff");
        };
        assert_eq!(request.code(), u32::from(code));
        assert_eq!(request.body(), b"\x06opaque");
        assert_eq!(
            *trace.lock().unwrap(),
            [Observation::Authorization(service)]
        );

        let stream = request.respond(Ok(7_u32)).await.unwrap();
        assert!(matches!(
            stream.run(handler.clone()).await.unwrap(),
            ServerRequestOutcome::Finished
        ));
        let mut responses = Vec::new();
        recv.read_to_end(&mut responses).await.unwrap();
        let delegated_response = &[0, 0, 0, 2, 0, 7];
        assert_eq!(&responses[..delegated_response.len()], delegated_response);
        assert_eq!(
            &responses[delegated_response.len()..],
            &DENIED_RESPONSES[..19]
        );
        assert_eq!(
            *trace.lock().unwrap(),
            [
                Observation::Authorization(service),
                Observation::Authorization(service_id::SERVER_CONFIG_GET),
                Observation::Handler(service_id::SERVER_CONFIG_GET),
            ]
        );
        trace.lock().unwrap().clear();
    }
}

#[tokio::test]
async fn runner_separates_malformed_arguments_and_truncation_from_clean_eof() {
    let (incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let handler = Arc::new(FixtureHandler::default());
    let policy = Arc::new(Policy::default());
    let mut incoming = incoming.with_authorization(context(), policy.clone());

    // A complete label-lookup frame with one pair and an invalid UTF-8 name.
    let malformed_label = [
        &[0, 0, 0, 9][..],
        &GET_LABEL_DB_PATTERNS.to_le_bytes(),
        &[1, 1, 0xff, 1, b'r'],
    ]
    .concat();
    for (bytes, service) in [
        (MALFORMED_REQUEST, service_id::SERVER_MODEL_GET),
        (&malformed_label, service_id::SERVER_LABEL_GET_DB_PATTERNS),
    ] {
        let (mut send, mut recv) = open_requests(&node, bytes).await;
        send.finish().unwrap();
        assert!(matches!(
            request_stream(&mut incoming)
                .await
                .run(handler.clone())
                .await,
            Err(ServerRunError::Session(SessionError::Malformed {
                certainty: None,
                ..
            }))
        ));
        assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
        assert_eq!(
            std::mem::take(&mut *policy.trace.lock().unwrap()),
            [Observation::Authorization(service)]
        );
    }

    for bytes in [TRUNCATED_REQUEST, &[0, 0, 0, 1, 36][..]] {
        let (mut send, mut recv) = open_requests(&node, bytes).await;
        send.finish().unwrap();
        assert!(matches!(
            request_stream(&mut incoming)
                .await
                .run(handler.clone())
                .await,
            Err(ServerRunError::Session(SessionError::Malformed { .. }))
        ));
        assert_eq!(
            recv.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
    }
    assert!(handler.0.lock().unwrap().is_empty());
}

struct ConfigResponse(usize);

#[async_trait::async_trait]
impl Handler for ConfigResponse {
    async fn get_config(&self, _: &str) -> Result<String, String> {
        Ok("x".repeat(self.0))
    }
}

#[tokio::test]
async fn owned_request_runner_abort_at_read_handler_and_write_boundaries() {
    use tokio::{
        sync::Notify,
        time::{Duration, timeout},
    };

    struct SlowHandler(Arc<Notify>);
    #[async_trait::async_trait]
    impl Handler for SlowHandler {
        async fn get_config(&self, _: &str) -> Result<String, String> {
            self.0.notify_one();
            std::future::pending().await
        }
    }

    let (incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let mut incoming = incoming.with_authorization(context(), Arc::new(Policy::default()));

    let (send, mut recv) = open_requests(&node, &GET_CONFIG[..2]).await;
    let runner = request_stream(&mut incoming)
        .await
        .run(Arc::new(FixtureHandler::default()));
    {
        let mut runner = tokio_test::task::spawn(runner);
        assert!(runner.poll().is_pending());
    }
    assert_eq!(send.stopped().await.unwrap().unwrap().get(), 1);
    assert_eq!(
        recv.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );

    let entered = Arc::new(Notify::new());
    let (send, mut recv) = open_requests(&node, GET_CONFIG).await;
    let runner = tokio::spawn(
        request_stream(&mut incoming)
            .await
            .run(Arc::new(SlowHandler(entered.clone()))),
    );
    entered.notified().await;
    runner.abort();
    assert!(runner.await.err().unwrap().is_cancelled());
    assert_eq!(send.stopped().await.unwrap().unwrap().get(), 1);
    assert_eq!(
        recv.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );

    let (send, mut recv) = open_requests(&node, GET_CONFIG).await;
    // The response exceeds the peer’s receive window while it waits to read.
    let runner = tokio::spawn(
        request_stream(&mut incoming)
            .await
            .run(Arc::new(ConfigResponse(4 * 1024 * 1024))),
    );
    assert!(
        timeout(Duration::from_secs(5), recv.read_u32())
            .await
            .unwrap()
            .unwrap()
            > 4 * 1024 * 1024
    );
    runner.abort();
    assert!(runner.await.err().unwrap().is_cancelled());
    assert_eq!(send.stopped().await.unwrap().unwrap().get(), 1);
    assert_eq!(
        recv.read_to_end(&mut Vec::new()).await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
}

#[tokio::test]
async fn owned_event_runner_resumes_split_header_and_matches_legacy_callbacks() {
    let (mut incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let mut send = open_events(&node, &EVENTS[..1]).await;
    let mut receiver = event_stream(&mut incoming).await;
    {
        let mut pending = tokio_test::task::spawn(receiver.next());
        assert!(pending.poll().is_pending());
    }
    let log = EventLog::default();
    let runner = tokio::spawn(receiver.run(log.clone()));
    send.write_all(&EVENTS[1..]).await.unwrap();
    send.finish().unwrap();
    runner.await.unwrap().unwrap();
    check_events(&log);
}

#[tokio::test]
async fn event_runner_distinguishes_clean_end_truncation_and_callback_failures() {
    let (mut incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;

    for (bytes, expected_header_error) in [
        (&EVENTS[..1], true),
        (&EVENTS[..3], false),
        (TRUNCATED_EVENT, false),
    ] {
        let mut send = open_events(&node, bytes).await;
        send.finish().unwrap();
        let log = EventLog::default();
        let error = event_stream(&mut incoming)
            .await
            .run(log.clone())
            .await
            .unwrap_err();
        if expected_header_error {
            assert!(
                matches!(error, ServerRunError::Session(SessionError::Transport { source, .. }) if
                source.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == io::ErrorKind::UnexpectedEof))
            );
        } else {
            assert!(
                matches!(error, ServerRunError::Session(SessionError::Malformed { source, .. }) if
                matches!(source.downcast_ref::<review_protocol::session::FrameError>(),
                    Some(review_protocol::session::FrameError::Truncated { .. })))
            );
        }
        assert!(log.entries.lock().unwrap().is_empty());
    }
    for (callback, bytes, count) in [
        ("event", EVENTS, 1),
        ("error", EVENTS, 2),
        ("end", &EVENTS[..2], 1),
    ] {
        let mut send = open_events(&node, bytes).await;
        send.finish().unwrap();
        let log = EventLog {
            fail_callback: Some(callback),
            ..EventLog::default()
        };
        assert!(
            matches!(event_stream(&mut incoming).await.run(log.clone()).await,
            Err(ServerRunError::DetectionEventHandler(error)) if error.to_string() == format!("{callback} failed"))
        );
        assert_eq!(log.entries.lock().unwrap().len(), count);
    }

    let send = open_events(&node, &EVENTS[..1]).await;
    let log = EventLog::default();
    {
        let mut runner =
            tokio_test::task::spawn(event_stream(&mut incoming).await.run(log.clone()));
        assert!(runner.poll().is_pending());
    }
    assert_eq!(send.stopped().await.unwrap().unwrap().get(), 1);
    assert!(log.entries.lock().unwrap().is_empty());
}

#[tokio::test]
async fn processing_enforces_explicit_frame_limits() {
    use review_protocol::session::FrameError;

    let mut options = SessionOptions::legacy_compatible();
    for limit in [
        options.handshake,
        options.unary,
        options.detection_events,
        options.package_chunks,
    ] {
        assert_eq!(limit.get(), u32::MAX as usize);
    }
    assert!(options.operation_timeout.is_none());
    options.unary = FrameLimit::new(32).unwrap();
    options.detection_events = FrameLimit::new(4).unwrap();
    let (incoming, _, _, node) = raw_sessions(options).await;
    let policy = Arc::new(Policy::default());
    let handler = Arc::new(FixtureHandler::default());
    let mut incoming = incoming.with_authorization(context(), policy.clone());
    let (_send, _recv) = open_requests(&node, &[0, 0, 0, 33]).await;
    assert!(matches!(
        request_stream(&mut incoming)
            .await
            .run(handler.clone())
            .await,
        Err(ServerRunError::Session(SessionError::LimitExceeded {
            source: FrameError::TooLarge { .. },
            ..
        }))
    ));
    assert!(policy.trace.lock().unwrap().is_empty());

    let (_send, mut recv) = open_requests(&node, GET_CONFIG).await;
    assert!(matches!(
        request_stream(&mut incoming)
            .await
            .run(Arc::new(ConfigResponse(33)))
            .await,
        Err(ServerRunError::Session(SessionError::LimitExceeded {
            source: FrameError::TooLarge { .. },
            certainty: Some(OutcomeCertainty::Unknown),
        }))
    ));
    assert_eq!(
        recv.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );

    let _send = open_events(&node, &[0, 0, 0, 0, 0, 5]).await;
    assert!(matches!(
        event_stream(&mut incoming)
            .await
            .run(EventLog::default())
            .await,
        Err(ServerRunError::Session(SessionError::LimitExceeded {
            source: FrameError::TooLarge { .. },
            ..
        }))
    ));
}

#[tokio::test]
async fn label_lookup_uses_the_borrowed_argument_budget() {
    use std::sync::atomic::{AtomicBool, Ordering};

    use review_protocol::session::FrameError;

    const NAMES: [(&str, &str); 32] = [("d", "r"); 32];

    #[derive(Default)]
    struct LabelLookup(AtomicBool);

    #[async_trait::async_trait]
    impl Handler for LabelLookup {
        async fn get_labeldb_patterns(
            &self,
            names: &[(&str, &str)],
        ) -> Result<Vec<(String, Option<LabelDb>)>, String> {
            assert_eq!(names, NAMES);
            self.0.store(true, Ordering::Relaxed);
            Ok(Vec::new())
        }
    }

    let mut payload = GET_LABEL_DB_PATTERNS.to_le_bytes().to_vec();
    bincode::serde::encode_into_std_write(
        NAMES.as_slice(),
        &mut payload,
        bincode::config::standard(),
    )
    .unwrap();
    let mut request = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    request.extend_from_slice(&payload);
    let budget = size_of_val(&NAMES)
        + NAMES
            .iter()
            .map(|(db, rule)| db.len() + rule.len())
            .sum::<usize>();
    assert!(payload.len() < budget - 1);

    for limit in [budget, budget - 1] {
        let mut options = SessionOptions::legacy_compatible();
        options.unary = FrameLimit::new(limit).unwrap();
        let (incoming, _, _, node) = raw_sessions(options).await;
        let mut incoming = incoming.with_authorization(context(), Arc::new(Policy::default()));
        let handler = Arc::new(LabelLookup::default());
        let (mut send, mut recv) = open_requests(&node, &request).await;
        send.finish().unwrap();
        let outcome = request_stream(&mut incoming)
            .await
            .run(handler.clone())
            .await;

        if limit == budget {
            assert!(matches!(outcome, Ok(ServerRequestOutcome::Finished)));
            assert!(handler.0.load(Ordering::Relaxed));
        } else {
            assert!(matches!(
                outcome,
                Err(ServerRunError::Session(SessionError::LimitExceeded {
                    source: FrameError::Decode(_),
                    ..
                }))
            ));
            assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
            assert!(!handler.0.load(Ordering::Relaxed));
        }
    }
}

/// Request 13 with every detection event of the batch, one of which fails
/// `validate` between valid ones, reaches `insert_detection_events` whole and
/// in order through the owned runner, which answers success. The request is
/// authorized as `server.event.insert_labels`.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn runner_delivers_every_detection_event_unvalidated() {
    use review_protocol::test::{INVALID_DETECTION_EVENT, detection_events};

    type Received = (u32, u32, Vec<DetectionEvent>);

    #[derive(Default)]
    struct Collect(Mutex<Vec<Received>>);

    #[async_trait::async_trait]
    impl Handler for Collect {
        async fn insert_detection_events(
            &self,
            model_id: u32,
            round: u32,
            events: &[DetectionEvent],
        ) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .push((model_id, round, events.to_vec()));
            Ok(())
        }
    }

    let events = detection_events();
    assert!(events[INVALID_DETECTION_EVENT].validate().is_err());
    // Independent legacy request layout: big-endian length, little-endian
    // code 13, bincode 2 standard arguments.
    let arguments =
        bincode::serde::encode_to_vec((7_u32, 8_u32, &events), bincode::config::standard())
            .unwrap();
    let mut request = u32::try_from(4 + arguments.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    request.extend(13_u32.to_le_bytes());
    request.extend(arguments);

    let (incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let policy = Policy::default();
    let trace = policy.trace.clone();
    let mut incoming = incoming.with_authorization(context(), Arc::new(policy));
    let handler = Arc::new(Collect::default());
    let (mut send, mut recv) = open_requests(&node, &request).await;
    send.finish().unwrap();
    assert!(matches!(
        request_stream(&mut incoming)
            .await
            .run(handler.clone())
            .await,
        Ok(ServerRequestOutcome::Finished)
    ));
    let mut responses = Vec::new();
    recv.read_to_end(&mut responses).await.unwrap();
    // One frame holding `Ok(())`.
    assert_eq!(responses, [0, 0, 0, 1, 0]);
    assert_eq!(*handler.0.lock().unwrap(), [(7, 8, events)]);
    assert_eq!(
        *trace.lock().unwrap(),
        [Observation::Authorization(
            service_id::SERVER_EVENT_INSERT_LABELS
        )]
    );
}

/// Splits a response stream into its frame bodies: a four-byte big-endian
/// length, then that many bytes.
fn response_frames(mut bytes: &[u8]) -> Vec<&[u8]> {
    let mut frames = Vec::new();
    while let Some((len, rest)) = bytes.split_first_chunk::<4>() {
        let (body, rest) = rest.split_at(usize::try_from(u32::from_be_bytes(*len)).unwrap());
        frames.push(body);
        bytes = rest;
    }
    assert!(bytes.is_empty(), "a response frame is truncated");
    frames
}

/// Checks that the answers to an allowlist pull, a blocklist pull and
/// `get_config`, in that order, refuse both pulls for the advertised `0.49.0`
/// and answer `get_config`.
fn assert_list_pulls_refused(responses: &[u8]) {
    let frames = response_frames(responses);
    let [allowlist, blocklist, config] = frames.as_slice() else {
        panic!("expected three responses, got {}", frames.len());
    };
    for (code, frame) in [(32, allowlist), (33, blocklist)] {
        let (answer, _) = bincode::serde::decode_from_slice::<
            Result<Vec<NetworkListItem>, String>,
            _,
        >(frame, bincode::config::standard())
        .unwrap();
        assert_eq!(
            answer,
            Err(format!(
                "request code {code} requires protocol >=0.50.0, but the agent advertised 0.49.0"
            ))
        );
    }
    let (answer, _) = bincode::serde::decode_from_slice::<Result<String, String>, _>(
        config,
        bincode::config::standard(),
    )
    .unwrap();
    assert_eq!(answer, Ok("configuration".to_string()));
}

/// The runner answers an allowlist or blocklist pull from an agent that
/// advertised `0.49.0` with an error, without invoking the handler, and
/// continues: the `0.50.0` item list it would send can decode on that agent as
/// a different list.
#[tokio::test]
async fn runner_refuses_list_pulls_from_an_agent_before_item_lists() {
    let (incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let handler = Arc::new(FixtureHandler::default());
    let trace = handler.0.clone();
    let policy = Policy {
        trace: trace.clone(),
        deny: None,
    };
    let mut incoming = incoming.with_authorization(context(), Arc::new(policy));

    let requests = [GET_ALLOWLIST, GET_BLOCKLIST, GET_CONFIG].concat();
    let (mut send, mut recv) = open_requests(&node, &requests).await;
    send.finish().unwrap();
    assert!(matches!(
        request_stream(&mut incoming).await.run(handler).await,
        Ok(ServerRequestOutcome::Finished)
    ));
    let mut responses = Vec::new();
    recv.read_to_end(&mut responses).await.unwrap();
    assert_list_pulls_refused(&responses);
    // The policy still runs first; only the handler is skipped.
    assert_eq!(
        *trace.lock().unwrap(),
        [
            Observation::Authorization(service_id::SERVER_LIST_ALLOWLIST),
            Observation::Authorization(service_id::SERVER_LIST_BLOCKLIST),
            Observation::Authorization(service_id::SERVER_CONFIG_GET),
            Observation::Handler(service_id::SERVER_CONFIG_GET),
        ]
    );
}

/// The low-level stream answers the same list pulls with the same error and
/// returns only the next request.
#[tokio::test]
async fn low_level_stream_refuses_list_pulls_from_an_agent_before_item_lists() {
    use review_protocol::session::ServerRequest;

    let (mut incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
    let requests = [GET_ALLOWLIST, GET_BLOCKLIST, GET_CONFIG].concat();
    let (mut send, mut recv) = open_requests(&node, &requests).await;
    send.finish().unwrap();
    let mut stream = request_stream(&mut incoming).await;
    let Some(ServerRequest::GetConfig { reply, .. }) = stream.next().await.unwrap() else {
        panic!("expected get_config");
    };
    reply
        .respond(Ok("configuration".to_string()))
        .await
        .unwrap();
    assert!(stream.next().await.unwrap().is_none());
    stream.finish().unwrap();
    let mut responses = Vec::new();
    recv.read_to_end(&mut responses).await.unwrap();
    assert_list_pulls_refused(&responses);
}

/// Returns a legacy request frame: big-endian length, little-endian `code`,
/// bincode 2 standard `arguments`.
fn request_frame<T: serde::Serialize>(code: u32, arguments: &T) -> Vec<u8> {
    let arguments = bincode::serde::encode_to_vec(arguments, bincode::config::standard()).unwrap();
    let mut frame = u32::try_from(4 + arguments.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    frame.extend(code.to_le_bytes());
    frame.extend(arguments);
    frame
}

/// Decodes a response frame body as `Result<T, String>`, consuming it whole.
fn decode_response<T: serde::de::DeserializeOwned>(frame: &[u8]) -> Result<T, String> {
    let (answer, len) = bincode::serde::decode_from_slice::<Result<T, String>, _>(
        frame,
        bincode::config::standard(),
    )
    .unwrap();
    assert_eq!(len, frame.len());
    answer
}

/// The owned runner serves each DAI request (codes 45 through 51) on one
/// stream through the handler, returns the handler's replies intact, and
/// authorizes each with its own service ID.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn runner_serves_every_dai_request() {
    use review_protocol::{
        test::{
            DAI_RENEWED_LEASE_END, DaiTestHandler, dai_cursors, dai_extractor_config,
            dai_observation_batches, dai_range_days, dai_range_grants, dai_range_late,
            dai_range_marks, dai_range_unit, dai_sensors, dai_store_acks,
        },
        types::{DaiCursors, DaiExtractorConfig, DaiRangeGrant, DaiRangeMark, DaiStoreAck},
    };

    let requests = [
        request_frame(45, &dai_sensors()),
        request_frame(46, &dai_sensors()),
        request_frame(47, &dai_observation_batches()[0]),
        request_frame(48, &(dai_range_unit(), 5_u64)),
        request_frame(49, &(dai_range_unit(), 0x0bad_cafe_0bad_cafe_u64)),
        request_frame(50, &dai_range_days()[0]),
        request_frame(51, &dai_range_late()),
    ]
    .concat();

    let (incoming, _, _, node) = raw_sessions_at(
        SessionOptions::legacy_compatible(),
        review_protocol::PROTOCOL_VERSION,
    )
    .await;
    let policy = Policy::default();
    let trace = policy.trace.clone();
    let mut incoming = incoming.with_authorization(context(), Arc::new(policy));
    let handler = Arc::new(DaiTestHandler {
        peer: "verified-peer",
    });
    let (mut send, mut recv) = open_requests(&node, &requests).await;
    send.finish().unwrap();
    assert!(matches!(
        request_stream(&mut incoming).await.run(handler).await,
        Ok(ServerRequestOutcome::Finished)
    ));
    let mut responses = Vec::new();
    recv.read_to_end(&mut responses).await.unwrap();

    let frames = response_frames(&responses);
    let [config, cursors, observations, begin, renew, range_day, late] = frames.as_slice() else {
        panic!("expected seven responses, got {}", frames.len());
    };
    assert_eq!(
        decode_response::<DaiExtractorConfig>(config),
        Ok(dai_extractor_config())
    );
    assert_eq!(decode_response::<DaiCursors>(cursors), Ok(dai_cursors()));
    assert_eq!(
        decode_response::<DaiStoreAck>(observations),
        Ok(dai_store_acks().remove(1))
    );
    assert_eq!(
        decode_response::<DaiRangeGrant>(begin),
        Ok(dai_range_grants().remove(0))
    );
    assert_eq!(
        decode_response::<Option<i64>>(renew),
        Ok(Some(DAI_RENEWED_LEASE_END))
    );
    assert_eq!(
        decode_response::<DaiStoreAck>(range_day),
        Ok(dai_store_acks().remove(1))
    );
    assert_eq!(
        decode_response::<Vec<DaiRangeMark>>(late),
        Ok(dai_range_marks())
    );
    assert_eq!(
        *trace.lock().unwrap(),
        [
            service_id::SERVER_DAI_GET_EXTRACTOR_CONFIG,
            service_id::SERVER_DAI_GET_CURSORS,
            service_id::SERVER_DAI_SEND_OBSERVATIONS,
            service_id::SERVER_DAI_BEGIN_RANGE_DAY,
            service_id::SERVER_DAI_RENEW_RANGE_DAY,
            service_id::SERVER_DAI_SEND_RANGE_DAY,
            service_id::SERVER_DAI_REPORT_RANGE_LATE,
        ]
        .map(Observation::Authorization)
    );
}

/// The retired host report codes 37 and 38 are unknown to the owned runner:
/// it answers `unknown request code` and stops dispatch.
#[tokio::test]
async fn runner_answers_retired_host_report_codes_as_unknown() {
    for code in [37_u32, 38] {
        let (incoming, _, _, node) = raw_sessions(SessionOptions::legacy_compatible()).await;
        let handler = Arc::new(FixtureHandler::default());
        let trace = handler.0.clone();
        let policy = Policy {
            trace: trace.clone(),
            deny: None,
        };
        let mut incoming = incoming.with_authorization(context(), Arc::new(policy));
        let requests = [request_frame(code, &()), GET_CONFIG.to_vec()].concat();
        let (mut send, mut recv) = open_requests(&node, &requests).await;
        send.finish().unwrap();
        assert!(
            request_stream(&mut incoming)
                .await
                .run(handler)
                .await
                .is_err()
        );
        let mut responses = Vec::new();
        recv.read_to_end(&mut responses).await.unwrap();
        let frames = response_frames(&responses);
        let [answer] = frames.as_slice() else {
            panic!("expected one response, got {}", frames.len());
        };
        assert_eq!(
            decode_response::<()>(answer),
            Err("unknown request code".to_string())
        );
        assert_eq!(*trace.lock().unwrap(), []);
    }
}
