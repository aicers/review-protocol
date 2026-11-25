//! The manager-to-agent configuration and list pushes on `ServerHandle`.
//!
//! Every request frame is compared with bytes written out here by hand: the
//! little-endian request code followed by the bincode 2 standard encoding of
//! the argument, as the legacy `server::Connection` method of the same name
//! sends it. None of them comes from `wire::request` or the session encoder.

use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use review_protocol::{
    PROTOCOL_VERSION,
    session::{
        ApplicationCode, FrameLimit, OutcomeCertainty, ServerHandle, SessionError, SessionOptions,
    },
    types::{
        CounterpartScope, CustomerDataDeletionRequest, EndpointRole, GroupByUnit, HostNetworkGroup,
        Measure, NetworkListItem, RawEventKind, TimeSeriesGenerationPolicy, TimeSeriesTypeRef,
        TrafficFilterRule,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{answer_raw, answer_raw_frame, raw_agent};

/// `Ok::<(), String>(())`.
const ACCEPTED: &[u8] = &[0];
/// `Err::<(), String>("text".into())`.
const REJECTED: &[u8] = &[1, 4, b't', b'e', b'x', b't'];

/// One push and its argument.
enum Push {
    ExclusionList(Vec<NetworkListItem>),
    Watchlist(Vec<NetworkListItem>),
    ConfigUpdate,
    DeleteCustomerData(CustomerDataDeletionRequest),
    FilteringRules(Vec<TrafficFilterRule>),
    InternalNetworkList(HostNetworkGroup),
    TimeSeriesGenerationPolicies(Vec<TimeSeriesGenerationPolicy>),
    TorExitNodeList(Vec<String>),
    TrustedDomainList(Vec<String>),
    TrustedUserAgentList(Vec<String>),
}

impl Push {
    async fn send(&self, handle: &ServerHandle) -> Result<(), SessionError> {
        match self {
            Self::ExclusionList(list) => handle.send_exclusion_list(list).await,
            Self::Watchlist(list) => handle.send_watchlist(list).await,
            Self::ConfigUpdate => handle.send_config_update_cmd().await,
            Self::DeleteCustomerData(request) => {
                handle.send_delete_customer_data_cmd(request).await
            }
            Self::FilteringRules(list) => handle.send_filtering_rules(list).await,
            Self::InternalNetworkList(list) => handle.send_internal_network_list(list).await,
            Self::TimeSeriesGenerationPolicies(list) => {
                handle.send_time_series_generation_policies(list).await
            }
            Self::TorExitNodeList(list) => handle.send_tor_exit_node_list(list).await,
            Self::TrustedDomainList(list) => handle.send_trusted_domain_list(list).await,
            Self::TrustedUserAgentList(list) => handle.send_trusted_user_agent_list(list).await,
        }
    }
}

fn item(id: u64, name: &str, hosts: Vec<IpAddr>) -> NetworkListItem {
    NetworkListItem {
        id,
        name: name.into(),
        group: HostNetworkGroup {
            hosts,
            networks: Vec::new(),
            ip_ranges: Vec::new(),
        },
    }
}

const DOC_HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// Unsorted, with a duplicate: `b` (7), `a` (3), then `b` (7) again.
fn exclusion_list() -> Vec<NetworkListItem> {
    vec![
        item(7, "b", vec![DOC_HOST]),
        item(3, "a", Vec::new()),
        item(7, "b", vec![DOC_HOST]),
    ]
}

/// Unsorted, with a duplicate: `w` (9), `v` (1), then `w` (9) again.
fn watchlist() -> Vec<NetworkListItem> {
    vec![
        item(9, "w", Vec::new()),
        item(1, "v", Vec::new()),
        item(9, "w", Vec::new()),
    ]
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|&value| value.to_owned()).collect()
}

/// Concatenates the pieces of a hand-written encoding.
fn bytes(pieces: &[&[u8]]) -> Vec<u8> {
    pieces.concat()
}

/// Each push, the request number it must carry, and its pinned body.
#[allow(clippy::too_many_lines)] // One table entry per push, each with its bytes.
fn cases() -> Vec<(Push, u32, Vec<u8>)> {
    // An item `b` (7) holding host 192.0.2.1: id, name, then the group's
    // hosts (one V4, variant 0), no networks and no ranges.
    let item_b: &[u8] = &[7, 1, b'b', 1, 0, 192, 0, 2, 1, 0, 0];
    let item_a: &[u8] = &[3, 1, b'a', 0, 0, 0];
    let item_w: &[u8] = &[9, 1, b'w', 0, 0, 0];
    let item_v: &[u8] = &[1, 1, b'v', 0, 0, 0];
    vec![
        (
            Push::ExclusionList(exclusion_list()),
            15,
            bytes(&[&[3], item_b, item_a, item_b]),
        ),
        (
            Push::Watchlist(watchlist()),
            16,
            bytes(&[&[3], item_w, item_v, item_w]),
        ),
        (Push::ConfigUpdate, 12, Vec::new()),
        (
            Push::DeleteCustomerData(CustomerDataDeletionRequest {
                id: 300,
                host_fqdn: "a.example".into(),
            }),
            22,
            // 300 is `fb 2c 01`, then the length-prefixed FQDN.
            bytes(&[&[0xfb, 0x2c, 0x01, 9], b"a.example"]),
        ),
        (
            Push::FilteringRules(vec![(
                "10.0.0.0/8".parse().unwrap(),
                Some(vec![80, 443]),
                None,
            )]),
            10,
            // One rule: V4 network (variant 0, octets, prefix), Some of two
            // ports (443 is `fb bb 01`), and None.
            vec![1, 0, 10, 0, 0, 0, 8, 1, 2, 80, 0xfb, 0xbb, 0x01, 0],
        ),
        (
            Push::InternalNetworkList(HostNetworkGroup {
                hosts: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
                networks: vec!["192.168.0.0/16".parse().unwrap()],
                ip_ranges: vec![
                    IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))
                        ..=IpAddr::V4(Ipv4Addr::new(172, 16, 0, 9)),
                ],
            }),
            14,
            vec![
                1, 0, 10, 0, 0, 1, // hosts
                1, 0, 192, 168, 0, 0, 16, // networks
                1, 0, 172, 16, 0, 1, 0, 172, 16, 0, 9, // ranges
            ],
        ),
        (
            Push::TimeSeriesGenerationPolicies(vec![TimeSeriesGenerationPolicy {
                id: 5,
                raw_event_kind: RawEventKind::Http,
                measure: Measure::Count,
                group_by: Some(EndpointRole::Destination),
                group_by_unit: GroupByUnit::Ip,
                counterpart_scope: CounterpartScope::External,
                slot_size: Duration::from_mins(10),
                window_size: Duration::from_hours(24),
                utc_offset: -18_000,
                src_ip: Some(DOC_HOST),
                dst_ip: None,
                sensors: strings(&["s1"]),
                time_series_type: Some(TimeSeriesTypeRef {
                    id: "t".into(),
                    version: 2,
                }),
                internal_networks: HostNetworkGroup::default(),
            }]),
            9,
            vec![
                1, // one policy
                5, // id
                3, // Http, by its `repr` value
                0, // Count
                1, 1, // Some(Destination)
                0, // Ip
                2, // External
                0xfb, 0x58, 0x02, 0, // 600 s, 0 ns
                0xfc, 0x80, 0x51, 0x01, 0x00, 0, // 86 400 s, 0 ns
                0xfb, 0x9f, 0x8c, // -18 000, zigzag 35 999
                1, 0, 192, 0, 2, 1, // Some(192.0.2.1)
                0, // None
                1, 2, b's', b'1', // sensors
                1, 1, b't', 2, // Some({ id: "t", version: 2 })
                0, 0, 0, // empty internal networks
            ],
        ),
        (
            Push::TorExitNodeList(strings(&["1.2.3.4", "5.6.7.8"])),
            8,
            bytes(&[&[2, 7], b"1.2.3.4", &[7], b"5.6.7.8"]),
        ),
        (
            Push::TrustedDomainList(strings(&["example.org", "example.com"])),
            0,
            bytes(&[&[2, 11], b"example.org", &[11], b"example.com"]),
        ),
        (
            Push::TrustedUserAgentList(strings(&["curl/8", "agent"])),
            18,
            bytes(&[&[2, 6], b"curl/8", &[5], b"agent"]),
        ),
    ]
}

/// Every push sends its request number and pinned body, and maps `Ok(())` to
/// `Ok(())` and `Err(text)` to `RemoteRejection(text)`.
#[tokio::test]
async fn pushes_send_pinned_requests_and_map_replies() {
    let (server, agent) = raw_agent(SessionOptions::legacy_compatible(), PROTOCOL_VERSION).await;
    for (push, code, body) in cases() {
        for reply in [ACCEPTED, REJECTED] {
            let (result, frame) = tokio::join!(push.send(&server), answer_raw_frame(&agent, reply));
            let (number, received) = frame.split_at(4);
            assert_eq!(number, code.to_le_bytes(), "request number for code {code}");
            assert_eq!(received, body, "body for code {code}");
            if reply == ACCEPTED {
                result.unwrap();
            } else {
                assert!(
                    matches!(&result, Err(SessionError::RemoteRejection(text)) if text == "text"),
                    "{result:?}"
                );
            }
        }
    }
}

/// The agent decodes unsorted exclusion-list and watchlist entries, duplicates
/// included, in the order the manager gave them.
#[tokio::test]
async fn network_list_pushes_preserve_order_and_duplicates() {
    let (server, agent) = raw_agent(SessionOptions::legacy_compatible(), PROTOCOL_VERSION).await;
    for (list, watch) in [(exclusion_list(), false), (watchlist(), true)] {
        let (result, frame) = tokio::join!(
            async {
                if watch {
                    server.send_watchlist(&list).await
                } else {
                    server.send_exclusion_list(&list).await
                }
            },
            answer_raw_frame(&agent, ACCEPTED)
        );
        result.unwrap();
        let (decoded, consumed) = bincode::serde::decode_from_slice::<Vec<NetworkListItem>, _>(
            &frame[4..],
            bincode::config::standard(),
        )
        .unwrap();
        assert_eq!(consumed, frame.len() - 4);
        assert_eq!(decoded, list);
    }
}

/// An agent that advertised `0.49.0` gets neither list: both pushes fail
/// before a stream opens, and the first request it then receives is the
/// config-update command.
#[tokio::test]
async fn network_list_pushes_refuse_an_agent_advertising_0_49_0() {
    let (server, agent) = raw_agent(SessionOptions::legacy_compatible(), "0.49.0").await;
    for result in [
        server.send_exclusion_list(&exclusion_list()).await,
        server.send_watchlist(&watchlist()).await,
    ] {
        let error = result.unwrap_err();
        assert!(
            matches!(&error, SessionError::IncompatibleProtocol { version, required }
                if version == "0.49.0" && required == ">=0.50.0"),
            "{error:?}"
        );
    }
    let (result, code) = tokio::join!(
        server.send_config_update_cmd(),
        answer_raw(&agent, ACCEPTED)
    );
    result.unwrap();
    assert_eq!(code, 12, "no list push reached the agent");
}

/// A list whose encoding exceeds the unary budget is refused before sending.
#[tokio::test]
async fn oversized_push_is_not_sent() {
    let mut options = SessionOptions::legacy_compatible();
    options.unary = FrameLimit::new(64).unwrap();
    let (server, agent) = raw_agent(options, PROTOCOL_VERSION).await;
    let long = vec![item(1, &"x".repeat(64), Vec::new())];
    let error = server.send_exclusion_list(&long).await.unwrap_err();
    assert!(
        matches!(
            error,
            SessionError::LimitExceeded {
                certainty: Some(OutcomeCertainty::NotSent),
                ..
            }
        ),
        "{error:?}"
    );
    // The refused push's stream, if the agent sees it at all, carries no byte;
    // the next request on the wire is the following push.
    let ((), ()) = tokio::join!(
        async { server.send_config_update_cmd().await.unwrap() },
        async {
            loop {
                let (mut send, mut recv) = agent.accept_bi().await.unwrap();
                let mut request = [0_u8; 8];
                match recv.read(&mut request).await {
                    Ok(length) => {
                        assert_ne!(length, 0);
                        recv.read_exact(&mut request[length..]).await.unwrap();
                        // The config-update request: its code and an empty body.
                        assert_eq!(request, [0, 0, 0, 4, 12, 0, 0, 0]);
                        send.write_all(&[0, 0, 0, 1, 0]).await.unwrap();
                        send.finish().unwrap();
                        break;
                    }
                    // The refused push's stream: reset before any byte.
                    Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
                }
            }
        }
    );
}

/// A push on a closed connection fails before sending.
#[tokio::test]
async fn push_on_a_closed_connection_is_not_sent() {
    let (server, _agent) = raw_agent(SessionOptions::legacy_compatible(), PROTOCOL_VERSION).await;
    server.close(ApplicationCode::default(), b"closed before the push");
    let list = strings(&["example.org"]);
    let error = server.send_trusted_domain_list(&list).await.unwrap_err();
    assert!(matches!(error, SessionError::Transport { .. }), "{error:?}");
    assert_eq!(error.certainty(), Some(OutcomeCertainty::NotSent));
}

/// A peer that reads the push and closes without replying leaves the outcome
/// unknown.
#[tokio::test]
async fn push_without_a_reply_is_unknown() {
    use oinq::frame::FramedReader;

    let (server, agent) = raw_agent(SessionOptions::legacy_compatible(), PROTOCOL_VERSION).await;
    let (result, ()) = tokio::join!(server.send_config_update_cmd(), async {
        let (_send, recv) = agent.accept_bi().await.unwrap();
        let mut reader = FramedReader::new(recv, FrameLimit::new(1024).unwrap());
        reader.read().await.unwrap().unwrap();
        agent.close(ApplicationCode::default(), b"read and left");
    });
    let error = result.unwrap_err();
    assert_eq!(
        error.certainty(),
        Some(OutcomeCertainty::Unknown),
        "{error:?}"
    );
}

/// A silent peer runs the push into the operation deadline.
#[tokio::test]
async fn push_to_a_silent_peer_hits_the_deadline() {
    use oinq::frame::FramedReader;

    let mut options = SessionOptions::legacy_compatible();
    options.operation_timeout = Some(Duration::from_secs(1));
    let (server, agent) = raw_agent(options, PROTOCOL_VERSION).await;
    let list = strings(&["1.2.3.4"]);
    let (result, ()) = tokio::join!(server.send_tor_exit_node_list(&list), async {
        let (send, recv) = agent.accept_bi().await.unwrap();
        let mut reader = FramedReader::new(recv, FrameLimit::new(1024).unwrap());
        reader.read().await.unwrap().unwrap();
        // The expired exchange stops the agent's reply direction.
        assert_eq!(send.stopped().await.unwrap().unwrap().get(), 1);
    });
    assert!(
        matches!(
            result,
            Err(SessionError::Deadline {
                certainty: OutcomeCertainty::Unknown,
                source: Some(_),
            })
        ),
        "{result:?}"
    );
}

/// Dropping a push future mid-exchange resets and stops both directions.
#[tokio::test]
async fn abandoned_push_resets_the_stream() {
    use oinq::frame::FramedReader;

    let (server, agent) = raw_agent(SessionOptions::legacy_compatible(), PROTOCOL_VERSION).await;
    let caller = server.clone();
    let operation = tokio::spawn(async move {
        caller
            .send_internal_network_list(&HostNetworkGroup::default())
            .await
    });
    let (send, recv) = agent.accept_bi().await.unwrap();
    let mut reader = FramedReader::new(recv, FrameLimit::new(1024).unwrap());
    reader.read().await.unwrap().unwrap();
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    assert_eq!(send.stopped().await.unwrap().unwrap().get(), 1);
    let mut recv = reader.into_inner();
    let error = recv.read_u8().await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
}
