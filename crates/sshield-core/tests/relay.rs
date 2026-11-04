//! Needs a running relay: `SSHIELD_RELAY=http://localhost:8799 cargo test -p sshield-core --test relay`
//! (e.g. `npx wrangler dev --local --port 8799` in server/cloudflare). Skipped otherwise.
use sshield_core::share::*;
use std::time::Duration;

fn wait<T>(rx: &std::sync::mpsc::Receiver<Event>, mut f: impl FnMut(Event) -> Option<T>) -> T {
    loop {
        let ev = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("timed out waiting for event");
        if let Some(v) = f(ev) {
            return v;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_and_guest_exchange_encrypted_frames() {
    let Ok(server) = std::env::var("SSHIELD_RELAY") else {
        return;
    };
    let link = ShareLink::create(&server).unwrap();
    // guest cannot join before the host is online
    let guest_link = ShareLink::parse(
        &link
            .to_link()
            .replace("sshield://share?s=", "sshield://share?s="),
    )
    .unwrap_or_else(|_| {
        // http://localhost is allowed by parse
        panic!("parse failed")
    });
    assert!(connect(&guest_link, Role::Guest, || {}).await.is_err());

    let host = connect(&link, Role::Host, || {}).await.unwrap();
    let guest = connect(&guest_link, Role::Guest, || {}).await.unwrap();
    wait(&host.rx, |e| matches!(e, Event::Guests(1)).then_some(()));

    guest.tx.send(Frame::Hello).unwrap();
    wait(&host.rx, |e| {
        matches!(e, Event::Frame(Frame::Hello, _)).then_some(())
    });
    host.tx
        .send(Frame::Snapshot {
            cols: 100,
            rows: 30,
            data: b"\x1b[2Jhello".to_vec(),
        })
        .unwrap();
    host.tx
        .send(Frame::Allow {
            allowed: true,
            epoch: 42,
        })
        .unwrap();
    host.tx.send(Frame::Output(b"world".to_vec())).unwrap();
    wait(&guest.rx, |e| {
        matches!(
            e,
            Event::Frame(
                Frame::Snapshot {
                    cols: 100,
                    rows: 30,
                    ..
                },
                _
            )
        )
        .then_some(())
    });
    wait(&guest.rx, |e| {
        matches!(
            e,
            Event::Frame(
                Frame::Allow {
                    allowed: true,
                    epoch: 42
                },
                _
            )
        )
        .then_some(())
    });
    wait(&guest.rx, |e| {
        matches!(e, Event::Frame(Frame::Output(ref d), m) if d == b"world" && m.in_order)
            .then_some(())
    });
    guest
        .tx
        .send(Frame::Input {
            epoch: 42,
            data: b"ls\r".to_vec(),
        })
        .unwrap();
    wait(&host.rx, |e| {
        matches!(e, Event::Frame(Frame::Input { epoch: 42, ref data }, m) if data == b"ls\r" && m.in_order).then_some(())
    });

    // an impostor with the wrong host secret is refused
    let mut evil = link.clone();
    evil.host_secret = Some("0".repeat(32));
    assert!(connect(&evil, Role::Host, || {}).await.is_err());

    host.tx.send(Frame::End).unwrap();
    wait(&guest.rx, |e| {
        matches!(e, Event::Frame(Frame::End, _)).then_some(())
    });
    drop(host);
    wait(&guest.rx, |e| matches!(e, Event::Closed(_)).then_some(()));
}

/// A relay that re-sends a captured keystroke frame must not get it executed twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_replay_of_input_is_rejected() {
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let Ok(server) = std::env::var("SSHIELD_RELAY") else {
        return;
    };
    let link = ShareLink::create(&server).unwrap();
    let host = connect(&link, Role::Host, || {}).await.unwrap();

    // raw guest socket so the test can send the very same ciphertext twice (what a hostile relay would do)
    let url = format!(
        "{}/v1/room/{}?role=guest",
        server.replacen("http", "ws", 1),
        link.room
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(url.as_str())
        .await
        .unwrap();
    let mut sealer = Sealer::new(&link, Role::Guest);
    for f in [
        Frame::Hello,
        Frame::Input {
            epoch: 5,
            data: b"reboot\r".to_vec(),
        },
    ] {
        let wire = sealer.seal(&f).unwrap();
        ws.send(Message::Binary(wire.clone().into())).await.unwrap();
        if matches!(f, Frame::Input { .. }) {
            ws.send(Message::Binary(wire.into())).await.unwrap(); // replay
        }
    }
    let mut inputs = 0;
    let mut rejected = 0;
    while let Ok(ev) = host.rx.recv_timeout(Duration::from_secs(2)) {
        match ev {
            Event::Frame(Frame::Input { .. }, m) if m.in_order => inputs += 1,
            Event::Rejected(n) => rejected = n,
            _ => {}
        }
    }
    assert_eq!((inputs, rejected), (1, 1));
}
