//! Shared test code
//!
//! This module is exposed for integration tests and benchmarks.

#![allow(clippy::unwrap_used)]

#[cfg(all(feature = "client", feature = "server"))]
use std::collections::HashSet;
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::LazyLock,
};

use quinn::{Connection, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::sync::Mutex;

#[cfg(all(feature = "client", feature = "server"))]
use crate::types::{
    DataSource, DataSourceKey, DataType, EventCategory, HostNetworkGroup, LabelDb, LabelDbKind,
    LabelDbRule, NetworkListItem, SamplingKind, SamplingPolicy,
};

#[allow(dead_code)]
pub(crate) struct Channel {
    pub(crate) server: Endpoint,
    pub(crate) client: Endpoint,
}

#[allow(dead_code)]
pub(crate) struct Endpoint {
    pub(crate) conn: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
}

#[allow(dead_code)]
pub(crate) static TOKEN: LazyLock<Mutex<u32>> = LazyLock::new(|| Mutex::new(0));

/// Creates a bidirectional channel, returning server's send and receive and
/// client's send and receive streams.
#[allow(dead_code)]
pub(crate) async fn channel() -> Channel {
    use std::sync::Arc;

    const TEST_SERVER_NAME: &str = "test-server";
    const TEST_PORT: u16 = 60190;

    let cert =
        rcgen::generate_simple_self_signed([TEST_SERVER_NAME.to_string()]).expect("infallible");
    let cert_der = vec![CertificateDer::from(cert.cert)];
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let server_config = quinn::ServerConfig::with_single_cert(cert_der.clone(), key_der.into())
        .expect("infallible");
    let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT);

    let server_endpoint = {
        loop {
            break match quinn::Endpoint::server(server_config.clone(), server_addr) {
                Ok(e) => e,
                Err(e) => {
                    if e.kind() == tokio::io::ErrorKind::AddrInUse {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                    panic!("{}", e);
                }
            };
        }
    };

    let handle = tokio::spawn(async move {
        let server_connection = match server_endpoint.accept().await {
            Some(conn) => match conn.await {
                Ok(conn) => conn,
                Err(e) => panic!("{}", e.to_string()),
            },
            None => panic!("connection closed"),
        };
        let (server_send, mut server_recv) = server_connection.accept_bi().await.unwrap();
        let mut server_buf = [0; 5];
        server_recv.read_exact(&mut server_buf).await.unwrap();
        (server_connection, server_send, server_recv)
    });

    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_parsable_certificates(cert_der);
    let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(root_cert_store))
        .expect("invalid client config");
    let client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).unwrap();
    let client_connecting = client_endpoint
        .connect_with(client_config, server_addr, TEST_SERVER_NAME)
        .unwrap();

    let client_connection = client_connecting.await.unwrap();
    let (mut client_send, client_recv) = client_connection.open_bi().await.unwrap();
    client_send.write_all(b"ready").await.unwrap();

    let (server_connection, server_send, server_recv) = handle.await.unwrap();

    Channel {
        server: self::Endpoint {
            conn: server_connection,
            send: server_send,
            recv: server_recv,
        },
        client: self::Endpoint {
            conn: client_connection,
            send: client_send,
            recv: client_recv,
        },
    }
}

#[cfg(all(feature = "client", feature = "server"))]
pub struct TestEnvironment {
    server_cert_pem: String,
    server_config: quinn::ServerConfig,
}

#[cfg(all(feature = "client", feature = "server"))]
impl TestEnvironment {
    // server configuration
    const SERVER_NAME: &str = "test-server";
    const SERVER_PORT: u16 = 60192;
    const SERVER_ADDR: SocketAddr =
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), Self::SERVER_PORT);

    fn new() -> Self {
        let server_certified_key =
            rcgen::generate_simple_self_signed([Self::SERVER_NAME.to_string()])
                .expect("infallible");
        let server_cert_pem = server_certified_key.cert.pem();
        let server_certs_der = vec![CertificateDer::from(server_certified_key.cert)];
        let server_key_der =
            PrivatePkcs8KeyDer::from(server_certified_key.signing_key.serialize_der());
        let server_config =
            quinn::ServerConfig::with_single_cert(server_certs_der.clone(), server_key_der.into())
                .expect("valid certificate");

        Self {
            server_cert_pem,
            server_config,
        }
    }

    pub async fn setup(&self) -> (crate::server::Connection, crate::client::Connection) {
        let (server_conn, client_conn, _agent_info) = self.setup_with(|_builder| {}).await;
        (server_conn, client_conn)
    }

    /// Establishes a connection like [`setup`](Self::setup), letting the caller
    /// configure the client's `ConnectionBuilder` first, and additionally
    /// returning the `AgentInfo` the manager received at the handshake.
    pub async fn setup_with<F>(
        &self,
        configure: F,
    ) -> (
        crate::server::Connection,
        crate::client::Connection,
        crate::AgentInfo,
    )
    where
        F: FnOnce(&mut crate::client::ConnectionBuilder),
    {
        use crate::Status;

        // client configuration
        const CLIENT_NAME: &str = "test-client";
        const AGENT_NAME: &str = "test-agent";
        const AGENT_VERSION: &str = "1.0.0";
        const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

        let server_endpoint = loop {
            break match quinn::Endpoint::server(self.server_config.clone(), Self::SERVER_ADDR) {
                Ok(e) => e,
                Err(e) => {
                    if e.kind() == tokio::io::ErrorKind::AddrInUse {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    panic!("cannot create the test server: {e}");
                }
            };
        };

        let handler_endpoint = server_endpoint.clone();
        let server_handle = tokio::spawn(async move {
            let server_conn = match handler_endpoint.accept().await {
                Some(conn) => match conn.await {
                    Ok(conn) => conn,
                    Err(e) => panic!("{e}"),
                },
                None => panic!("no connection"),
            };
            let client_addr = server_conn.remote_address();
            let agent_info = crate::server::handshake(
                &server_conn,
                client_addr,
                PROTOCOL_VERSION,
                PROTOCOL_VERSION,
            )
            .await
            .unwrap();
            (server_conn, agent_info)
        });

        let client_certified_key =
            rcgen::generate_simple_self_signed([CLIENT_NAME.to_string()]).expect("infallible");
        let client_cert_pem = client_certified_key.cert.pem();
        let client_key_pem = client_certified_key.signing_key.serialize_pem();
        let mut builder = crate::client::ConnectionBuilder::new(
            Self::SERVER_NAME,
            Self::SERVER_ADDR,
            AGENT_NAME,
            AGENT_VERSION,
            PROTOCOL_VERSION,
            Status::Ready,
            client_cert_pem.as_bytes(),
            client_key_pem.as_bytes(),
        )
        .unwrap();
        let mut server_cert_pem_buf = std::io::Cursor::new(self.server_cert_pem.as_bytes());
        builder.add_root_certs(&mut server_cert_pem_buf).unwrap();
        configure(&mut builder);

        // Connect to the server
        let client_conn = builder.connect().await.unwrap();
        let (server_conn, agent_info) = server_handle.await.unwrap();
        assert_eq!(agent_info.agent_name, AGENT_NAME);
        assert_eq!(agent_info.agent_version, AGENT_VERSION);

        (
            crate::server::Connection::from_quinn(server_conn),
            client_conn,
            agent_info,
        )
    }

    pub fn teardown(&self, server_conn: &crate::server::Connection) {
        let _ = self; // Silence unused warning for `self`
        server_conn.close();
    }
}

#[cfg(all(feature = "client", feature = "server"))]
pub static TEST_ENV: LazyLock<Mutex<TestEnvironment>> =
    LazyLock::new(|| Mutex::new(TestEnvironment::new()));

/// The run whose model, state and listing `TestServerHandler` accepts.
#[cfg(all(feature = "client", feature = "server"))]
#[allow(dead_code)] // used by tests only, like `TestServerHandler`
pub(crate) const RUN_ID: u32 = 7;

/// The model ID `TestServerHandler` requires with [`detection_events`].
#[cfg(all(feature = "client", feature = "server"))]
#[allow(dead_code)] // used by tests only, like `TestServerHandler`
pub(crate) const DETECTION_EVENTS_MODEL_ID: u32 = 1;

/// The round `TestServerHandler` requires with [`detection_events`].
#[cfg(all(feature = "client", feature = "server"))]
#[allow(dead_code)] // used by tests only, like `TestServerHandler`
pub(crate) const DETECTION_EVENTS_ROUND: u32 = 100;

/// The run `TestServerHandler` rejects with "report rejected".
#[cfg(all(feature = "client", feature = "server"))]
#[allow(dead_code)] // used by tests only, like `TestServerHandler`
pub(crate) const REJECTED_RUN_ID: u32 = 99;

/// The model bytes `TestServerHandler` accepts for [`RUN_ID`].
#[cfg(all(feature = "client", feature = "server"))]
#[allow(dead_code)] // used by tests only, like `TestServerHandler`
pub(crate) const RUN_MODEL: &[u8] = &[0x00, 0x01, 0xfe, 0xff];

/// The run reports `TestServerHandler` accepts.
#[cfg(all(feature = "client", feature = "server"))]
#[allow(dead_code)] // used by tests only, like `TestServerHandler`
pub(crate) const RUN_REPORTS: &[(u32, crate::types::ReportedRunState, Option<&str>)] = &[
    (RUN_ID, crate::types::ReportedRunState::Started, None),
    (
        RUN_ID,
        crate::types::ReportedRunState::Failed,
        Some("training failed"),
    ),
    (
        RUN_ID,
        crate::types::ReportedRunState::Cancelled,
        Some("cancelled by operator"),
    ),
];

/// The active-run listing `TestServerHandler` accepts.
#[cfg(all(feature = "client", feature = "server"))]
#[allow(dead_code)] // used by tests only, like `TestServerHandler`
pub(crate) const ACTIVE_RUN_IDS: &[u32] = &[RUN_ID, 8, u32::MAX];

/// The detector whose status `TestServerHandler` rejects with "report
/// rejected".
#[cfg(all(feature = "client", feature = "server"))]
#[allow(dead_code)] // used by tests only, like `TestServerHandler`
pub(crate) const REJECTED_DETECTOR_ID: i32 = -1;

/// Returns the detector status reports `TestServerHandler` accepts.
///
/// Between them they carry every `DetectorState`, `RoundOutcome` and
/// `SourceState`, both `None` and `Some` for every optional field, and both
/// empty and non-empty `detection_models` and `excluded`.
#[cfg(feature = "server")]
#[allow(dead_code)] // used by tests only, like `TestServerHandler`
#[allow(clippy::too_many_lines)] // One literal report per covered shape.
pub(crate) fn detector_status_reports() -> Vec<crate::types::DetectorStatusReport> {
    use crate::types::{
        DetectionModel, DetectionModelStatus, DetectorState, DetectorStatusReport, ExcludedCount,
        RoundOutcome, SourceState, SourceStatus,
    };

    vec![
        DetectorStatusReport {
            detector_id: 1,
            state: DetectorState::Running,
            finished_at: Some(1_760_000_000_000_000_000),
            outcome: Some(RoundOutcome::Succeeded),
            reason: None,
            events: 12_345,
            sources: vec![
                SourceStatus {
                    source: "piglet.node1.example.com".to_string(),
                    state: SourceState::Served,
                    reason: None,
                },
                SourceStatus {
                    source: "piglet.node2.example.com".to_string(),
                    state: SourceState::ServedByNoNode,
                    reason: None,
                },
            ],
            detection_models: vec![
                DetectionModelStatus {
                    detection_model: DetectionModel::PortScan,
                    skipped: None,
                    truncated: 0,
                },
                DetectionModelStatus {
                    detection_model: DetectionModel::TorExitNode,
                    skipped: Some("no Tor exit node list".to_string()),
                    truncated: 0,
                },
                DetectionModelStatus {
                    detection_model: DetectionModel::UnusualDestinationPattern,
                    skipped: None,
                    truncated: 1_000,
                },
            ],
            excluded: vec![
                ExcludedCount {
                    entry: (1 << 53) + 3,
                    day: jiff::civil::date(2026, 3, 14),
                    count: 17,
                },
                ExcludedCount {
                    entry: 7,
                    day: jiff::civil::date(2026, 3, 15),
                    count: u64::MAX,
                },
            ],
        },
        DetectorStatusReport {
            detector_id: 2,
            state: DetectorState::Disabled,
            finished_at: Some(1_760_000_300_000_000_000),
            outcome: Some(RoundOutcome::Failed),
            reason: Some("source piglet.node3.example.com failed".to_string()),
            events: 0,
            sources: vec![SourceStatus {
                source: "piglet.node3.example.com".to_string(),
                state: SourceState::Failed,
                reason: Some("connection refused".to_string()),
            }],
            detection_models: vec![DetectionModelStatus {
                detection_model: DetectionModel::WatchlistMatch,
                skipped: Some("source failed".to_string()),
                truncated: 0,
            }],
            excluded: Vec::new(),
        },
        DetectorStatusReport {
            detector_id: 3,
            state: DetectorState::NoModel,
            finished_at: None,
            outcome: None,
            reason: None,
            events: 0,
            sources: Vec::new(),
            detection_models: Vec::new(),
            excluded: Vec::new(),
        },
        DetectorStatusReport {
            detector_id: i32::MAX,
            state: DetectorState::PausedForRun,
            finished_at: Some(-1),
            outcome: Some(RoundOutcome::Succeeded),
            reason: None,
            events: u64::MAX,
            sources: vec![SourceStatus {
                source: "piglet.node1.example.com".to_string(),
                state: SourceState::Served,
                reason: None,
            }],
            detection_models: Vec::new(),
            excluded: vec![ExcludedCount {
                entry: 0,
                day: jiff::civil::date(1970, 1, 1),
                count: 1,
            }],
        },
    ]
}

/// The index in [`detection_events`] of the event that fails
/// [`DetectionEvent::validate`](crate::types::DetectionEvent::validate).
pub const INVALID_DETECTION_EVENT: usize = 9;

/// Returns a batch of synthetic detection events.
///
/// Between them they carry every `Detail` variant, both `Target` kinds and
/// every `PrimarySubject`. Every event is valid except the one at
/// [`INVALID_DETECTION_EVENT`], which carries a detail of another model and
/// sits between valid events.
#[allow(clippy::too_many_lines)] // One synthetic event per detection model.
#[must_use]
pub fn detection_events() -> Vec<crate::types::DetectionEvent> {
    use std::net::Ipv4Addr;

    use crate::types::{
        CryptocurrencyMiningPoolDetail, Detail, DetectionEvent, DetectionModel, EndpointRole,
        EventCategory, ExternalDdosDetail, FtpBruteForceDetail, LdapBruteForceDetail,
        MultiHostPortScanDetail, PortScanDetail, PrimarySubject, RawEventBody, RawEventKind,
        RdpBruteForceDetail, RelatedIp, RepeatedHttpSessionsDetail, Target, ThreatRole, TimeWindow,
        UnusualDestinationPatternDetail, WatchlistMatchDetail, raw_event,
    };

    const BASE: i128 = 1_773_586_804_120_000_000;

    let at = |offset: i128| {
        jiff::Timestamp::from_nanosecond(BASE + offset).expect("the test timestamps are in range")
    };
    let conn = RawEventBody::Conn(raw_event::Conn {
        orig_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        orig_port: 46378,
        resp_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        resp_port: 443,
        proto: 6,
        conn_state: "SF".to_string(),
        start_time: 1_773_586_804_000_000_000,
        duration: 1_234_567,
        service: "tls".to_string(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 3,
        resp_pkts: 4,
        orig_l2_bytes: 200,
        resp_l2_bytes: 400,
    });
    let ftp_conn = || {
        let RawEventBody::Conn(mut body) = conn.clone() else {
            unreachable!("`conn` is a `Conn` body");
        };
        body.resp_port = 21;
        RawEventBody::Conn(body)
    };
    let related = |count: u8| {
        (1..=count)
            .map(|i| RelatedIp {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, i)),
                role: if i % 2 == 0 {
                    EndpointRole::Source
                } else {
                    EndpointRole::Destination
                },
            })
            .collect::<Vec<_>>()
    };
    let window = |start: i128, end: i128| TimeWindow {
        start: at(start),
        end: at(end),
    };
    let host = |last: u8, role| PrimarySubject::Host {
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
        role,
    };
    let raw_event = |offset: i128,
                     detection_model: DetectionModel,
                     category: Option<EventCategory>,
                     body: RawEventBody,
                     score: f64,
                     detail: Detail| DetectionEvent {
        time: at(offset),
        sensor: Some("sensor-1".to_string()),
        detection_model,
        raw_event_kind: RawEventKind::Conn,
        category,
        target: Target::RawEvent {
            time: at(offset),
            body,
        },
        score,
        detail,
    };
    let subject = |offset: i128,
                   sensor: Option<&str>,
                   detection_model: DetectionModel,
                   category: Option<EventCategory>,
                   primary: PrimarySubject,
                   related_ips: Vec<RelatedIp>,
                   window: TimeWindow,
                   score: f64,
                   detail: Detail| DetectionEvent {
        time: at(offset),
        sensor: sensor.map(str::to_string),
        detection_model,
        raw_event_kind: RawEventKind::Conn,
        category,
        target: Target::Subject {
            primary,
            related_ips,
            window,
        },
        score,
        detail,
    };

    vec![
        subject(
            0,
            Some("sensor-1"),
            DetectionModel::WatchlistMatch,
            None,
            host(10, ThreatRole::Target),
            related(3),
            window(-5_000, 0),
            1.0,
            Detail::WatchlistMatch(WatchlistMatchDetail {
                entry_id: (1 << 53) + 1,
                matched_side: EndpointRole::Destination,
                raw_event_count: 7,
                truncated_related_ips: 0,
                closed_early: true,
            }),
        ),
        raw_event(
            1,
            DetectionModel::CryptocurrencyMiningPool,
            Some(EventCategory::Impact),
            conn.clone(),
            0.9,
            Detail::CryptocurrencyMiningPool(CryptocurrencyMiningPoolDetail {
                coins: vec!["xmr".to_string(), "eth".to_string()],
            }),
        ),
        raw_event(
            2,
            DetectionModel::LockyRansomware,
            Some(EventCategory::Impact),
            conn.clone(),
            0.8,
            Detail::LockyRansomware,
        ),
        raw_event(
            3,
            DetectionModel::SuspiciousTlsTraffic,
            None,
            conn.clone(),
            0.7,
            Detail::SuspiciousTlsTraffic,
        ),
        subject(
            4,
            None,
            DetectionModel::PortScan,
            Some(EventCategory::Reconnaissance),
            host(11, ThreatRole::Actor),
            related(1),
            window(-10, 4),
            12.5,
            Detail::PortScan(PortScanDetail {
                resp_ports: vec![22, 80, 443, 8080],
                proto: 6,
            }),
        ),
        subject(
            5,
            None,
            DetectionModel::MultiHostPortScan,
            Some(EventCategory::Reconnaissance),
            host(12, ThreatRole::Actor),
            related(64),
            window(5, 5),
            40.0,
            Detail::MultiHostPortScan(MultiHostPortScanDetail {
                resp_port: 445,
                proto: 6,
                truncated_related_ips: 36,
            }),
        ),
        subject(
            6,
            None,
            DetectionModel::ExternalDdos,
            Some(EventCategory::Impact),
            host(13, ThreatRole::Target),
            related(4),
            window(-1_000_000, 6),
            99.0,
            Detail::ExternalDdos(ExternalDdosDetail {
                proto: 17,
                truncated_related_ips: 0,
            }),
        ),
        subject(
            7,
            None,
            DetectionModel::RdpBruteForce,
            Some(EventCategory::CredentialAccess),
            PrimarySubject::Cluster {
                clustering_model: 3,
                cluster_id: 41,
            },
            related(2),
            window(0, 7),
            5.0,
            Detail::RdpBruteForce(RdpBruteForceDetail {
                proto: 6,
                truncated_related_ips: 1,
            }),
        ),
        raw_event(
            8,
            DetectionModel::FtpBruteForce,
            Some(EventCategory::CredentialAccess),
            ftp_conn(),
            0.6,
            Detail::FtpBruteForce(FtpBruteForceDetail {
                resp_port: 21,
                proto: 6,
                user_list: vec!["user-a".to_string(), "user-b".to_string()],
                is_internal: true,
            }),
        ),
        // Decodable, but fails `validate`: the detail is another model's.
        raw_event(
            9,
            DetectionModel::FtpPlainText,
            Some(EventCategory::CredentialAccess),
            ftp_conn(),
            0.5,
            Detail::LockyRansomware,
        ),
        subject(
            10,
            Some("sensor-2"),
            DetectionModel::LdapBruteForce,
            Some(EventCategory::CredentialAccess),
            PrimarySubject::Sensor,
            Vec::new(),
            window(0, 10),
            3.0,
            Detail::LdapBruteForce(LdapBruteForceDetail {
                resp_port: 389,
                proto: 6,
                user_pw_list: vec![("user-a".to_string(), "synthetic-1".to_string())],
            }),
        ),
        raw_event(
            11,
            DetectionModel::RepeatedHttpSessions,
            Some(EventCategory::CommandAndControl),
            conn.clone(),
            0.4,
            Detail::RepeatedHttpSessions(RepeatedHttpSessionsDetail {
                orig_port: 46378,
                resp_port: 443,
                proto: 6,
            }),
        ),
        raw_event(
            12,
            DetectionModel::FtpPlainText,
            Some(EventCategory::CredentialAccess),
            ftp_conn(),
            0.3,
            Detail::FtpPlainText,
        ),
        raw_event(
            13,
            DetectionModel::LdapPlainText,
            Some(EventCategory::CredentialAccess),
            conn.clone(),
            0.2,
            Detail::LdapPlainText,
        ),
        raw_event(
            14,
            DetectionModel::NonBrowser,
            Some(EventCategory::CommandAndControl),
            conn.clone(),
            -0.1,
            Detail::NonBrowser,
        ),
        subject(
            15,
            None,
            DetectionModel::TorExitNode,
            Some(EventCategory::CommandAndControl),
            PrimarySubject::Network {
                customer: 2,
                name: "office".to_string(),
                role: ThreatRole::Actor,
            },
            related(2),
            window(0, 15),
            0.0,
            Detail::TorExitNode,
        ),
        raw_event(
            16,
            DetectionModel::DomainGenerationAlgorithm,
            Some(EventCategory::CommandAndControl),
            conn.clone(),
            0.95,
            Detail::DomainGenerationAlgorithm,
        ),
        raw_event(
            17,
            DetectionModel::DnsCovertChannel,
            Some(EventCategory::Exfiltration),
            conn,
            0.85,
            Detail::DnsCovertChannel,
        ),
        subject(
            18,
            None,
            DetectionModel::UnusualDestinationPattern,
            None,
            host(14, ThreatRole::Actor),
            related(5),
            window(-60_000_000_000, 18),
            4.2,
            Detail::UnusualDestinationPattern(UnusualDestinationPatternDetail {
                count: 40,
                expected_mean: 2.5,
                std_deviation: 1.25,
                z_score: 30.0,
                truncated_related_ips: 2,
            }),
        ),
    ]
}

/// Returns synthetic allowlist or blocklist items, listed out of id order.
///
/// One id is above 2^53, and items with distinct ids have groups that
/// overlap or are equal.
#[must_use]
pub fn network_list_items() -> Vec<crate::types::NetworkListItem> {
    use std::net::Ipv4Addr;

    use crate::types::{HostNetworkGroup, NetworkListItem};

    let net = |s: &str| s.parse().expect("the test network is valid");
    let shared = HostNetworkGroup {
        hosts: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))],
        networks: vec![net("198.51.100.0/24")],
        ip_ranges: vec![
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))..=IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)),
        ],
    };
    vec![
        NetworkListItem {
            id: (1 << 53) + 3,
            name: "above 2^53".to_string(),
            group: shared.clone(),
        },
        NetworkListItem {
            id: 7,
            name: "equal group".to_string(),
            group: shared,
        },
        NetworkListItem {
            id: 2,
            name: "overlapping".to_string(),
            group: HostNetworkGroup {
                hosts: vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
                networks: vec![net("198.51.100.128/25"), net("2001:db8::/32")],
                ip_ranges: Vec::new(),
            },
        },
        NetworkListItem {
            id: u64::MAX,
            name: "empty".to_string(),
            group: HostNetworkGroup::default(),
        },
    ]
}

#[cfg(all(feature = "client", feature = "server"))]
#[allow(dead_code)]
pub(crate) struct TestServerHandler;

#[cfg(all(feature = "client", feature = "server"))]
#[async_trait::async_trait]
impl crate::server::Handler for TestServerHandler {
    async fn report_customer_data_deletion(
        &self,
        report: &crate::types::CustomerDataDeletionReport,
    ) -> Result<(), String> {
        if report.host_fqdn == "reject.example.test" {
            Err("report rejected".to_string())
        } else {
            Ok(())
        }
    }

    // Returns `Some` for `id` 5 and `name` "name5" only.
    async fn get_data_source(&self, key: &DataSourceKey<'_>) -> Result<Option<DataSource>, String> {
        let ds = DataSource {
            id: 5,
            name: "name5".to_string(),
            server_name: "test-server".to_string(),
            address: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            data_type: DataType::Log,
            source: "source5".to_string(),
            kind: Some("kind5".to_string()),
            description: "description5".to_string(),
        };

        match key {
            DataSourceKey::Id(5) | DataSourceKey::Name("test5") => Ok(Some(ds)),
            _ => Ok(None),
        }
    }

    // Returns `Some` for `db1` with version "1.0.0" only.
    async fn get_labeldb_patterns(
        &self,
        db_names: &[(&str, &str)],
    ) -> Result<Vec<(String, Option<LabelDb>)>, String> {
        let db = [(
            "db1".to_string(),
            LabelDb {
                id: 1,
                name: "name1".to_string(),
                description: Some("description1".to_string()),
                kind: LabelDbKind::Token,
                category: Some(EventCategory::Execution),
                version: "1.0.0".to_string(),
                patterns: vec![LabelDbRule {
                    rule_id: 9,
                    category: None,
                    name: "rule1".to_string(),
                    kind: None,
                    description: Some("description1".to_string()),
                    references: Some(vec!["ref1".to_string()]),
                    samples: Some(vec!["sample1".to_string()]),
                    signatures: Some(vec!["sig1".to_string()]),
                    confidence: None,
                }],
            },
        )];

        Ok(db_names
            .iter()
            .map(|&(name, ver)| {
                let patterns = if name == "db1" && ver == "1.0.0" {
                    Some(db[0].1.clone())
                } else {
                    None
                };
                (name.to_string(), patterns)
            })
            .collect())
    }

    async fn get_config(&self, _peer: &str) -> Result<String, String> {
        Ok("test-config".to_string())
    }

    // Returns `network_list_items()`.
    async fn get_allowlist(&self, peer: &str) -> Result<Vec<NetworkListItem>, String> {
        if peer != "test-peer" {
            return Err(format!("unexpected peer: {peer}"));
        }
        Ok(network_list_items())
    }

    // Returns `network_list_items()` in reverse order.
    async fn get_blocklist(&self, peer: &str) -> Result<Vec<NetworkListItem>, String> {
        if peer != "test-peer" {
            return Err(format!("unexpected peer: {peer}"));
        }
        let mut items = network_list_items();
        items.reverse();
        Ok(items)
    }

    async fn get_indicator(&self, name: &str) -> Result<HashSet<Vec<String>>, String> {
        if name == "test-indicator" {
            let mut set = HashSet::new();
            set.insert(vec!["indicator1".to_string(), "value1".to_string()]);
            set.insert(vec!["indicator2".to_string(), "value2".to_string()]);
            Ok(set)
        } else {
            Ok(HashSet::new())
        }
    }

    async fn get_internal_network_list(&self, _peer: &str) -> Result<HostNetworkGroup, String> {
        use std::net::{IpAddr, Ipv4Addr};
        Ok(HostNetworkGroup {
            hosts: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            networks: vec![],
            ip_ranges: vec![],
        })
    }

    async fn get_sampling_policy_list(&self, _peer: &str) -> Result<Vec<SamplingPolicy>, String> {
        Ok(vec![SamplingPolicy {
            id: 1,
            kind: SamplingKind::Conn,
            interval: std::time::Duration::from_mins(1),
            period: std::time::Duration::from_hours(1),
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: Some("node1".to_string()),
            column: None,
        }])
    }

    async fn get_pretrained_model(&self, name: &str) -> Result<Vec<u8>, String> {
        if name == "test-model" {
            Ok(vec![0x01, 0x02, 0x03, 0x04])
        } else {
            Err("model not found".to_string())
        }
    }

    async fn get_tor_exit_node_list(&self) -> Result<Vec<String>, String> {
        Ok(vec!["192.168.1.10".to_string(), "192.168.1.11".to_string()])
    }

    async fn get_trusted_domain_list(&self) -> Result<Vec<String>, String> {
        Ok(vec!["trusted1.com".to_string(), "trusted2.com".to_string()])
    }

    async fn get_trusted_user_agent_list(&self) -> Result<Vec<String>, String> {
        Ok(vec![
            "Mozilla/5.0 (trusted)".to_string(),
            "Chrome/test".to_string(),
        ])
    }

    async fn renew_certificate(&self, _peer: &str) -> Result<(String, String), String> {
        Ok(("new-cert".to_string(), "new-key".to_string()))
    }

    async fn get_model(&self, name: &str) -> Result<Vec<u8>, String> {
        if name == "test-model" {
            Ok(vec![0x01, 0x02, 0x03, 0x04, 0x05])
        } else {
            Err("model not found".to_string())
        }
    }

    async fn get_model_names(&self) -> Result<Vec<String>, String> {
        Ok(vec![
            "model1".to_string(),
            "model2".to_string(),
            "model3".to_string(),
        ])
    }

    async fn insert_column_statistics(
        &self,
        _statistics: &[crate::types::ColumnStatisticsUpdate],
        _model_id: u32,
        _batch_ts: i64,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn insert_model(&self, _model: &[u8]) -> Result<u32, String> {
        Ok(42)
    }

    async fn insert_time_series(
        &self,
        _time_series: &[crate::types::TimeSeriesUpdate],
        _model_id: u32,
        _batch_ts: i64,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn remove_model(&self, _name: &str) -> Result<(), String> {
        Ok(())
    }

    async fn update_clusters(
        &self,
        _input: &[crate::types::UpdateClusterRequest],
        _model_id: u32,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn update_model(&self, _model: &[u8]) -> Result<u32, String> {
        Ok(55)
    }

    async fn update_outliers(
        &self,
        _outliers: &[crate::types::OutlierInfo],
        _model_id: u32,
        _timestamp: i64,
    ) -> Result<(), String> {
        Ok(())
    }

    // Accepts only `DETECTION_EVENTS_MODEL_ID`, `DETECTION_EVENTS_ROUND`
    // and exactly `detection_events()`, in order, and rejects anything else,
    // so a dropped, reordered or swapped argument fails the caller.
    async fn insert_detection_events(
        &self,
        model_id: u32,
        round: u32,
        events: &[crate::types::DetectionEvent],
    ) -> Result<(), String> {
        if model_id == DETECTION_EVENTS_MODEL_ID
            && round == DETECTION_EVENTS_ROUND
            && events == detection_events().as_slice()
        {
            Ok(())
        } else {
            Err(format!(
                "unexpected detection event request: model {model_id}, round {round}, \
                 events {events:?}"
            ))
        }
    }

    async fn insert_data_source(
        &self,
        _data_source: &crate::types::DataSource,
    ) -> Result<u32, String> {
        Ok(123)
    }

    async fn get_outliers(
        &self,
        model_id: u32,
        _timestamp: i64,
    ) -> Result<Vec<(String, Vec<i64>)>, String> {
        if model_id == 10 {
            Ok(vec![
                ("sensor1".to_string(), vec![1, 2, 3]),
                ("sensor2".to_string(), vec![4, 5, 6]),
            ])
        } else {
            Ok(vec![])
        }
    }

    async fn update_host_ports(
        &self,
        _peer: &str,
        _hosts: &std::collections::HashMap<IpAddr, std::collections::HashMap<(u16, u8), u32>>,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn update_host_user_agents(
        &self,
        _peer: &str,
        _hosts: &[(IpAddr, Vec<crate::types::UserAgent>, Vec<String>)],
    ) -> Result<(), String> {
        Ok(())
    }

    // Accepts `RUN_MODEL` for `RUN_ID` and rejects `REJECTED_RUN_ID`.
    async fn upload_run_model(&self, peer: &str, run_id: u32, model: &[u8]) -> Result<(), String> {
        if peer != "test-peer" {
            return Err(format!("unexpected peer: {peer}"));
        }
        if run_id == REJECTED_RUN_ID {
            Err("report rejected".to_string())
        } else if run_id == RUN_ID && model == RUN_MODEL {
            Ok(())
        } else {
            Err(format!("unexpected run model upload: {run_id} {model:?}"))
        }
    }

    // Accepts each of `RUN_REPORTS` and rejects `REJECTED_RUN_ID`.
    async fn report_run(
        &self,
        peer: &str,
        run_id: u32,
        state: crate::types::ReportedRunState,
        reason: Option<&str>,
    ) -> Result<(), String> {
        if peer != "test-peer" {
            return Err(format!("unexpected peer: {peer}"));
        }
        if run_id == REJECTED_RUN_ID {
            Err("report rejected".to_string())
        } else if RUN_REPORTS.contains(&(run_id, state, reason)) {
            Ok(())
        } else {
            Err(format!(
                "unexpected run report: {run_id} {state:?} {reason:?}"
            ))
        }
    }

    // Accepts `ACTIVE_RUN_IDS` and rejects a listing with `REJECTED_RUN_ID`.
    async fn report_active_runs(&self, peer: &str, run_ids: &[u32]) -> Result<(), String> {
        if peer != "test-peer" {
            return Err(format!("unexpected peer: {peer}"));
        }
        if run_ids.contains(&REJECTED_RUN_ID) {
            Err("report rejected".to_string())
        } else if run_ids == ACTIVE_RUN_IDS {
            Ok(())
        } else {
            Err(format!("unexpected active runs: {run_ids:?}"))
        }
    }

    // Accepts each of `detector_status_reports()` and rejects
    // `REJECTED_DETECTOR_ID`.
    async fn report_detector_status(
        &self,
        peer: &str,
        report: &crate::types::DetectorStatusReport,
    ) -> Result<(), String> {
        if peer != "test-peer" {
            return Err(format!("unexpected peer: {peer}"));
        }
        if report.detector_id == REJECTED_DETECTOR_ID {
            Err("report rejected".to_string())
        } else if detector_status_reports().contains(report) {
            Ok(())
        } else {
            Err(format!("unexpected detector status report: {report:?}"))
        }
    }
}
