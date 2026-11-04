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
        matches!(e, Event::Frame(Frame::Hello)).then_some(())
    });
    host.tx
        .send(Frame::Snapshot {
            cols: 100,
            rows: 30,
            data: b"\x1b[2Jhello".to_vec(),
        })
        .unwrap();
    host.tx.send(Frame::Allow(true)).unwrap();
    host.tx.send(Frame::Output(b"world".to_vec())).unwrap();
    wait(&guest.rx, |e| {
        matches!(
            e,
            Event::Frame(Frame::Snapshot {
                cols: 100,
                rows: 30,
                ..
            })
        )
        .then_some(())
    });
    wait(&guest.rx, |e| {
        matches!(e, Event::Frame(Frame::Allow(true))).then_some(())
    });
    wait(&guest.rx, |e| {
        matches!(e, Event::Frame(Frame::Output(ref d)) if d == b"world").then_some(())
    });
    guest.tx.send(Frame::Input(b"ls\r".to_vec())).unwrap();
    wait(&host.rx, |e| {
        matches!(e, Event::Frame(Frame::Input(ref d)) if d == b"ls\r").then_some(())
    });

    // an impostor with the wrong host secret is refused
    let mut evil = link.clone();
    evil.host_secret = Some("0".repeat(32));
    assert!(connect(&evil, Role::Host, || {}).await.is_err());

    host.tx.send(Frame::End).unwrap();
    wait(&guest.rx, |e| {
        matches!(e, Event::Frame(Frame::End)).then_some(())
    });
    drop(host);
    wait(&guest.rx, |e| matches!(e, Event::Closed(_)).then_some(()));
}
