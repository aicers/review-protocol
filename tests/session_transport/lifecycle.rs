//! Deterministic lifecycle races for the shared drain control.
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use super::*;

#[tokio::test]
async fn both_roles_refuse_new_outgoing_exchanges_after_drain() {
    let (server, incoming, agent, agent_incoming) =
        sessions(SessionOptions::legacy_compatible()).await;
    let server_control = incoming.control();
    let agent_control = agent_incoming.control();

    assert_eq!(server.lifecycle().active_work(), 0);
    assert_eq!(agent.lifecycle().active_work(), 0);

    server_control.drain();
    server_control.drain();
    assert!(server.lifecycle().is_draining());
    let error = server.send_run_detector_once(1).await.unwrap_err();
    assert!(matches!(error, SessionError::Draining), "{error:?}");
    assert_eq!(error.certainty(), Some(OutcomeCertainty::NotSent));

    agent_control.drain();
    agent_control.drain();
    assert!(agent.lifecycle().is_draining());
    let error = agent.get_config().await.unwrap_err();
    assert!(matches!(error, SessionError::Draining), "{error:?}");
    assert_eq!(error.certainty(), Some(OutcomeCertainty::NotSent));

    server_control.close(b"done");
    agent_control.close(b"done");
}

#[tokio::test]
async fn cloned_controls_share_active_work_and_idle_wait() {
    let (_server, incoming, _agent, _agent_incoming) =
        sessions(SessionOptions::legacy_compatible()).await;
    let control = incoming.control();
    let clone = control.lifecycle();

    let activity = clone.try_admit().unwrap();
    assert_eq!(control.lifecycle().active_work(), 1);
    assert_eq!(clone.active_work(), 1);

    let mut idle = tokio_test::task::spawn(async {
        control.wait_idle().await;
    });
    assert!(idle.poll().is_pending());
    control.drain();
    assert!(idle.poll().is_pending());
    drop(activity);
    idle.await;
    assert_eq!(clone.active_work(), 0);
    control.close(b"done");
}

#[tokio::test]
async fn drain_wakes_blocked_accepts_on_both_roles() {
    let (_server, mut incoming, _agent, mut agent_incoming) =
        sessions(SessionOptions::legacy_compatible()).await;
    let server_control = incoming.control();
    let agent_control = agent_incoming.control();

    let mut server_accept = tokio_test::task::spawn(incoming.accept_next());
    let mut agent_accept = tokio_test::task::spawn(agent_incoming.accept_next());
    assert!(server_accept.poll().is_pending());
    assert!(agent_accept.poll().is_pending());

    server_control.drain();
    assert!(server_accept.await.unwrap().is_none());
    assert!(incoming.accept_next().await.unwrap().is_none());
    assert!(matches!(
        incoming.accept().await,
        Err(SessionError::Transport { .. })
    ));

    agent_control.drain();
    assert!(agent_accept.await.unwrap().is_none());
    assert!(agent_incoming.accept_next().await.unwrap().is_none());
    assert!(matches!(
        agent_incoming.accept().await,
        Err(SessionError::Draining)
    ));

    server_control.close(b"done");
    agent_control.close(b"done");
}

#[tokio::test]
async fn drain_finishes_current_invocation_and_skips_buffered_next() {
    use oinq::frame::FramedReader;

    let (mut incoming, _agent_incoming, _manager, node) =
        raw_sessions(SessionOptions::legacy_compatible()).await;
    let control = incoming.control();
    let limit = FrameLimit::new(1024).unwrap();
    let (mut send, recv) = node.open_bi().await.unwrap();
    // Two complete GetConfig requests, buffered before the runner starts.
    // Length 4, little-endian code 36, and the bincode unit body.
    for _ in 0..2 {
        send.write_all(&[0, 0, 0, 4, 36, 0, 0, 0]).await.unwrap();
    }
    send.flush().await.unwrap();

    let stream = request_stream(&mut incoming).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let runner_calls = calls.clone();
    let runner_control = control.clone();
    let runner = tokio::spawn(async move {
        let mut stream = stream;
        loop {
            match stream.next().await {
                Ok(Some(ServerRequest::GetConfig { reply, .. })) => {
                    runner_calls.fetch_add(1, Ordering::SeqCst);
                    reply.respond(Ok("configuration".into())).await.unwrap();
                    // Drain during the current invocation after its response;
                    // the next buffered request must not execute.
                    runner_control.drain();
                }
                Ok(Some(_)) => panic!("unexpected request"),
                Ok(None) => break,
                Err(error) => panic!("request stream failed: {error}"),
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut reader = FramedReader::new(recv, limit);
    let response = reader
        .read()
        .await
        .unwrap()
        .unwrap()
        .decode::<Result<String, String>>()
        .unwrap();
    assert_eq!(response, Ok("configuration".into()));
    assert!(reader.read().await.unwrap().is_none());

    drop(send);
    control.close(b"done");
}

#[tokio::test]
async fn idle_request_runner_wakes_on_drain_and_finishes_cleanly() {
    let (mut incoming, _agent_incoming, _manager, node) =
        raw_sessions(SessionOptions::legacy_compatible()).await;
    let (mut send, _recv) = node.open_bi().await.unwrap();
    // One complete GetConfig request makes the incoming stream observable and
    // exercises the current invocation; the runner then waits idle.
    send.write_all(&[0, 0, 0, 4, 36, 0, 0, 0]).await.unwrap();
    send.flush().await.unwrap();
    let mut stream = request_stream(&mut incoming).await;
    let control = incoming.control();

    match stream.next().await.unwrap().unwrap() {
        ServerRequest::GetConfig { reply, .. } => {
            reply.respond(Ok("configuration".into())).await.unwrap();
        }
        _ => panic!("unexpected request"),
    }

    let mut next = tokio_test::task::spawn(stream.next());
    assert!(next.poll().is_pending());
    control.drain();
    assert!(next.await.unwrap().is_none());
    drop(stream);
    assert_eq!(control.lifecycle().active_work(), 0);
    control.close(b"done");
}

#[tokio::test]
async fn event_preparation_after_drain_is_refused() {
    let (_server, _incoming, agent, _agent_incoming) =
        sessions(SessionOptions::legacy_compatible()).await;
    let mut sender = agent.open_detection_event_stream().await.unwrap();
    let event = detection_event(1.0);
    sender.start(&event).unwrap();
    sender.flush().await.unwrap();
    agent.drain();
    let error = sender.start(&event).unwrap_err();
    assert!(matches!(error, SessionError::Draining), "{error:?}");
    assert_eq!(error.certainty(), Some(OutcomeCertainty::NotSent));
    sender.finish().await.unwrap();
}

#[tokio::test]
async fn admitted_server_outgoing_exchange_completes_after_drain() {
    use oinq::frame::{FramedReader, FramedWriter};

    let (server, node) = raw_agent(SessionOptions::legacy_compatible(), "0.49.0").await;
    let drainer = server.clone();
    let limit = FrameLimit::new(1024).unwrap();
    let (result, ()) = tokio::join!(async { server.send_run_detector_once(7).await }, async {
        let (send, recv) = node.accept_bi().await.unwrap();
        let mut reader = FramedReader::new(recv, limit);
        reader.read().await.unwrap().unwrap();
        drainer.drain();
        let mut writer = FramedWriter::new(send, limit);
        writer.start(Ok::<(), String>(())).unwrap();
        writer.flush().await.unwrap();
        writer.into_inner().finish().unwrap();
    });
    assert!(result.is_ok(), "{result:?}");
    assert!(server.lifecycle().is_draining());
    assert_eq!(server.lifecycle().active_work(), 0);
    drainer.close(ApplicationCode::default(), b"done");
}

#[tokio::test]
async fn admitted_agent_outgoing_exchange_completes_after_drain() {
    use oinq::frame::{FramedReader, FramedWriter};

    let (agent, manager) = agent_with_raw_manager(SessionOptions::legacy_compatible()).await;
    let drainer = agent.clone();
    let limit = FrameLimit::new(1024).unwrap();
    let (result, ()) = tokio::join!(async { agent.get_config().await }, async {
        let (send, recv) = manager.accept_bi().await.unwrap();
        let mut reader = FramedReader::new(recv, limit);
        reader.read().await.unwrap().unwrap();
        drainer.drain();
        let mut writer = FramedWriter::new(send, limit);
        writer
            .start(Ok::<String, String>("configuration".into()))
            .unwrap();
        writer.flush().await.unwrap();
        writer.into_inner().finish().unwrap();
    });
    assert_eq!(result.unwrap(), "configuration");
    assert!(agent.lifecycle().is_draining());
    assert_eq!(agent.lifecycle().active_work(), 0);
    drainer.close(ApplicationCode::default(), b"done");
}

/// A source that yields exactly one queued part per read, pinning chunk frames.
struct SplitSource(VecDeque<Vec<u8>>);

impl SplitSource {
    fn new(parts: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self(parts.into_iter().collect())
    }
}

impl AsyncRead for SplitSource {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(part) = self.0.pop_front() {
            let length = part.len().min(buffer.remaining());
            buffer.put_slice(&part[..length]);
            if length < part.len() {
                self.0.push_front(part[length..].to_vec());
            }
        }
        Poll::Ready(Ok(()))
    }
}

async fn read_wire_frame(recv: &mut oinq::RecvStream) -> Vec<u8> {
    let mut header = [0_u8; 4];
    recv.read_exact(&mut header).await.unwrap();
    let length = usize::try_from(u32::from_be_bytes(header)).unwrap();
    let mut body = vec![0; length];
    recv.read_exact(&mut body).await.unwrap();
    let mut frame = header.to_vec();
    frame.extend_from_slice(&body);
    frame
}

#[tokio::test]
async fn package_proceed_sequence_matches_pinned_fixtures() {
    use review_protocol::{server::node::InstallOutcome, types::node::NodePackageResponse};

    let (server, node) = raw_agent(SessionOptions::legacy_compatible(), "0.49.0").await;
    let request = include_bytes!("../fixtures/current/package-request.bin");
    let proceed = include_bytes!("../fixtures/current/package-proceed.bin");
    let chunks = include_bytes!("../fixtures/current/package-chunks.bin");
    let final_response = include_bytes!("../fixtures/current/package-final.bin");
    let source = SplitSource::new([vec![1, 2], vec![3, 4, 5]]);
    let server_drain = server.clone();

    let (result, ()) = tokio::join!(
        async {
            server
                .node_package_install(install_request(5), source)
                .await
        },
        async {
            let (mut send, mut recv) = node.accept_bi().await.unwrap();
            assert_eq!(read_wire_frame(&mut recv).await, request);
            server_drain.drain();
            send.write_all(proceed).await.unwrap();
            let mut received_chunks = read_wire_frame(&mut recv).await;
            received_chunks.extend_from_slice(&read_wire_frame(&mut recv).await);
            assert_eq!(received_chunks, chunks);
            send.write_all(final_response).await.unwrap();
            send.finish().unwrap();
            let mut rest = Vec::new();
            recv.read_to_end(&mut rest).await.unwrap();
            assert_eq!(rest, [] as [u8; 0]);
        }
    );
    assert!(matches!(
        result.unwrap(),
        InstallOutcome::Applied(NodePackageResponse::Done)
    ));
    assert!(server.lifecycle().is_draining());
    assert_eq!(server.lifecycle().active_work(), 0);
    server.close(ApplicationCode::default(), b"done");
}

#[tokio::test]
async fn package_terminal_preflight_matches_pinned_fixture() {
    use review_protocol::server::node::{InstallOutcome, TerminalPreflight};

    let (server, node) = raw_agent(SessionOptions::legacy_compatible(), "0.49.0").await;
    let request = include_bytes!("../fixtures/current/package-request.bin");
    let terminal = include_bytes!("../fixtures/current/package-terminal-preflight.bin");
    let mut source = std::io::Cursor::new(vec![1, 2, 3, 4, 5]);

    let (result, ()) = tokio::join!(
        async {
            server
                .node_package_install(install_request(5), &mut source)
                .await
        },
        async {
            let (mut send, mut recv) = node.accept_bi().await.unwrap();
            assert_eq!(read_wire_frame(&mut recv).await, request);
            send.write_all(terminal).await.unwrap();
            send.finish().unwrap();
            let mut rest = Vec::new();
            recv.read_to_end(&mut rest).await.unwrap();
            assert_eq!(rest, [] as [u8; 0]);
        }
    );
    assert!(matches!(
        result.unwrap(),
        InstallOutcome::Preflight(TerminalPreflight::AlreadyApplied)
    ));
    assert_eq!(source.position(), 0);
    server.close(ApplicationCode::default(), b"done");
}

#[tokio::test]
async fn split_report_run_admitted_before_drain_completes() {
    use oinq::frame::{FramedReader, FramedWriter};
    use review_protocol::types::ReportedRunState;

    let (agent, manager) = agent_with_raw_manager(SessionOptions::legacy_compatible()).await;
    let drainer = agent.clone();
    let limit = FrameLimit::new(1024).unwrap();
    let (result, ()) = tokio::join!(
        async {
            let mut exchange = agent
                .start_report_run(7, ReportedRunState::Started, None)
                .await
                .unwrap();
            exchange.response().await
        },
        async {
            let (send, recv) = manager.accept_bi().await.unwrap();
            let mut reader = FramedReader::new(recv, limit);
            reader.read().await.unwrap().unwrap();
            drainer.drain();
            let mut writer = FramedWriter::new(send, limit);
            writer.start(Ok::<(), String>(())).unwrap();
            writer.flush().await.unwrap();
            writer.into_inner().finish().unwrap();
        }
    );
    assert!(result.is_ok(), "{result:?}");
    assert!(agent.lifecycle().is_draining());
    assert_eq!(agent.lifecycle().active_work(), 0);
    drainer.close(ApplicationCode::default(), b"done");
}

#[tokio::test]
async fn event_runner_finishes_frame_and_callback_then_stops_between_frames() {
    use review_protocol::{server::DetectionEventStreamHandler, types::DetectionEvent};
    use tokio::sync::{Notify, mpsc};

    struct Gated {
        entered: mpsc::UnboundedSender<()>,
        release: Arc<Notify>,
        events: Arc<AtomicUsize>,
        ended: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl DetectionEventStreamHandler for Gated {
        async fn handle_detection_event(&mut self, _event: DetectionEvent) -> io::Result<()> {
            self.entered.send(()).unwrap();
            self.release.notified().await;
            self.events.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn on_stream_end(&mut self) -> io::Result<()> {
            self.ended.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let (server, node) = raw_agent_setup(
        SessionOptions::legacy_compatible(),
        "0.49.0",
        TransportOptions::default(),
    )
    .await;
    let (_, mut incoming) = server.unwrap();

    let mut send = node.open_uni().await.unwrap();
    send.write_all(&[0, 0]).await.unwrap();
    // Two complete events are buffered before the runner starts. The runner
    // must finish the first frame and its callback, then stop rather than
    // reading the second frame after the drain.
    for scale in [1.0, 2.0] {
        let event = detection_event(scale);
        let payload = bincode::serde::encode_to_vec(&event, bincode::config::standard()).unwrap();
        send.write_all(&u32::try_from(payload.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        send.write_all(&payload).await.unwrap();
    }
    send.flush().await.unwrap();

    let stream = event_stream(&mut incoming).await;
    let control = incoming.control();
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let release = Arc::new(Notify::new());
    let events = Arc::new(AtomicUsize::new(0));
    let ended = Arc::new(AtomicUsize::new(0));
    let runner = tokio::spawn(stream.run(Gated {
        entered: entered_tx,
        release: release.clone(),
        events: events.clone(),
        ended: ended.clone(),
    }));

    entered_rx.recv().await.unwrap();
    control.drain();
    release.notify_one();

    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(events.load(Ordering::SeqCst), 1);
    assert_eq!(ended.load(Ordering::SeqCst), 0);
    assert!(control.lifecycle().is_draining());
    control.close(b"done");
}
