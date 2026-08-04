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
    LabelDbRule, SamplingKind, SamplingPolicy,
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

    async fn get_allowlist(&self, peer: &str) -> Result<HostNetworkGroup, String> {
        use std::net::{IpAddr, Ipv6Addr};
        if peer != "test-peer" {
            return Err(format!("unexpected peer: {peer}"));
        }
        Ok(HostNetworkGroup {
            hosts: vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
            networks: vec![],
            ip_ranges: vec![],
        })
    }

    async fn get_blocklist(&self, peer: &str) -> Result<HostNetworkGroup, String> {
        use std::net::{IpAddr, Ipv4Addr};
        if peer != "test-peer" {
            return Err(format!("unexpected peer: {peer}"));
        }
        Ok(HostNetworkGroup {
            hosts: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            networks: vec![],
            ip_ranges: vec![],
        })
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

    async fn insert_event_labels(
        &self,
        _model_id: u32,
        _round: u32,
        _event_labels: &[crate::types::EventMessage],
    ) -> Result<(), String> {
        Ok(())
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
}
