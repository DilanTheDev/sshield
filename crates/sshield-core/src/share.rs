//! Shared terminal sessions: end-to-end encrypted frames relayed by the sync Worker.
//!
//! The share link carries `server`, `room` and a random 256-bit `key`. The key is only ever
//! in the link (never sent to the relay), and every frame is sealed with XChaCha20-Poly1305,
//! so the relay only forwards ciphertext. AAD binds a frame to its room and sender role.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use futures::{SinkExt, StreamExt};
use std::sync::mpsc::{channel, Receiver};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Debug, PartialEq)]
pub struct ShareLink {
    pub server: String,
    pub room: String,
    pub key: [u8; 32],
    /// Only the sharer holds this; it authorises being the room's host.
    pub host_secret: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Role {
    Host = 1,
    Guest = 2,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl ShareLink {
    pub fn create(server: &str) -> Result<ShareLink, String> {
        let (mut room, mut key, mut hs) = ([0u8; 16], [0u8; 32], [0u8; 16]);
        for b in [&mut room[..], &mut key[..], &mut hs[..]] {
            getrandom::fill(b).map_err(|e| e.to_string())?;
        }
        Ok(ShareLink {
            server: server.trim_end_matches('/').to_string(),
            room: hex(&room),
            key,
            host_secret: Some(hex(&hs)),
        })
    }

    /// `sshield://share?s=<server>&r=<room>&k=<key>`
    pub fn to_link(&self) -> String {
        format!(
            "sshield://share?s={}&r={}&k={}",
            B64.encode(&self.server),
            self.room,
            B64.encode(self.key)
        )
    }

    pub fn parse(link: &str) -> Result<ShareLink, String> {
        let q = link
            .trim()
            .strip_prefix("sshield://share?")
            .ok_or("not an sshield share link")?;
        let get = |name: &str| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
        };
        let server = String::from_utf8(
            B64.decode(get("s").ok_or("missing server")?)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let room = get("r").ok_or("missing room")?.to_string();
        if room.len() != 32 || !room.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("bad room id".into());
        }
        let key: [u8; 32] = B64
            .decode(get("k").ok_or("missing key")?)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "bad key length")?;
        if !server.starts_with("https://") && !server.starts_with("http://localhost") {
            return Err("server must be https".into());
        }
        Ok(ShareLink {
            server,
            room,
            key,
            host_secret: None,
        })
    }

    fn ws_url(&self, role: Role) -> String {
        let base = self
            .server
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        match (role, &self.host_secret) {
            (Role::Host, Some(hs)) => format!("{base}/v1/room/{}?role=host&hs={hs}", self.room),
            _ => format!("{base}/v1/room/{}?role=guest", self.room),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Frame {
    /// host -> guests: raw terminal output
    Output(Vec<u8>),
    /// host -> guests: full screen state + grid size
    Snapshot { cols: u16, rows: u16, data: Vec<u8> },
    /// guest -> host: keystrokes. `epoch` must equal the host's current epoch (learned from
    /// `Allow`), so frames captured in any other host session are useless. The host ignores
    /// input unless it is currently allowed.
    Input { epoch: u64, data: Vec<u8> },
    /// host -> guests: whether typing is currently allowed, plus the host's session epoch
    Allow { allowed: bool, epoch: u64 },
    /// guest -> host: "send me the screen"
    Hello,
    /// host -> guests: the session is over
    End,
}

fn aad(room: &str, sender: Role) -> Vec<u8> {
    let mut a = b"sshield-share-v1|".to_vec();
    a.extend_from_slice(room.as_bytes());
    a.push(sender as u8);
    a
}

fn encode(f: &Frame, out: &mut Vec<u8>) {
    match f {
        Frame::Output(d) => {
            out.push(1);
            out.extend_from_slice(d);
        }
        Frame::Snapshot { cols, rows, data } => {
            out.push(2);
            out.extend_from_slice(&cols.to_be_bytes());
            out.extend_from_slice(&rows.to_be_bytes());
            out.extend_from_slice(data);
        }
        Frame::Input { epoch, data } => {
            out.push(3);
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(data);
        }
        Frame::Allow { allowed, epoch } => {
            out.extend_from_slice(&[4, *allowed as u8]);
            out.extend_from_slice(&epoch.to_be_bytes());
        }
        Frame::Hello => out.push(5),
        Frame::End => out.push(6),
    }
}

fn decode(pt: &[u8]) -> Result<Frame, String> {
    let (t, rest) = pt.split_first().ok_or("empty frame")?;
    let u64_at =
        |b: &[u8]| -> Option<u64> { Some(u64::from_be_bytes(b.get(..8)?.try_into().ok()?)) };
    Ok(match t {
        1 => Frame::Output(rest.to_vec()),
        2 if rest.len() >= 4 => Frame::Snapshot {
            cols: u16::from_be_bytes([rest[0], rest[1]]),
            rows: u16::from_be_bytes([rest[2], rest[3]]),
            data: rest[4..].to_vec(),
        },
        3 => Frame::Input {
            epoch: u64_at(rest).ok_or("short input frame")?,
            data: rest[8..].to_vec(),
        },
        4 if rest.len() >= 9 => Frame::Allow {
            allowed: rest[0] != 0,
            epoch: u64_at(&rest[1..]).ok_or("short allow frame")?,
        },
        5 => Frame::Hello,
        6 => Frame::End,
        _ => return Err("unknown frame".into()),
    })
}

/// A random value for session epochs / sender ids.
pub fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    u64::from_be_bytes(b)
}

/// Seals outgoing frames. Every frame carries this connection's random sender id and a strictly
/// increasing counter *inside* the authenticated plaintext, so a relay that captures a frame can
/// neither replay it nor slip it into a different position without the receiver noticing.
pub struct Sealer {
    link: ShareLink,
    role: Role,
    id: [u8; 8],
    counter: u64,
}

impl Sealer {
    pub fn new(link: &ShareLink, role: Role) -> Sealer {
        Sealer {
            link: link.clone(),
            role,
            id: random_u64().to_be_bytes(),
            counter: 0,
        }
    }

    pub fn seal(&mut self, f: &Frame) -> Result<Vec<u8>, String> {
        let mut pt = Vec::with_capacity(32);
        pt.extend_from_slice(&self.id);
        pt.extend_from_slice(&self.counter.to_be_bytes());
        encode(f, &mut pt);
        self.counter += 1;
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
        let ct = XChaCha20Poly1305::new((&self.link.key).into())
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &pt,
                    aad: &aad(&self.link.room, self.role),
                },
            )
            .map_err(|e| e.to_string())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Meta {
    pub sender: [u8; 8],
    /// True only for a sender we have already seen and whose counter is exactly the previous
    /// one + 1 - i.e. nothing was dropped, reordered or injected before this frame.
    pub in_order: bool,
}

#[derive(Debug, PartialEq)]
pub enum OpenError {
    /// Failed authentication (wrong key, wrong sender role, or tampered).
    Invalid,
    /// Authentic but already seen / older than one already accepted: a replay.
    Replay,
}

/// Opens incoming frames from `peer` and enforces freshness.
pub struct Opener {
    link: ShareLink,
    peer: Role,
    seen: std::collections::HashMap<[u8; 8], u64>,
}

const MAX_SENDERS: usize = 64;

impl Opener {
    pub fn new(link: &ShareLink, peer: Role) -> Opener {
        Opener {
            link: link.clone(),
            peer,
            seen: Default::default(),
        }
    }

    pub fn open(&mut self, wire: &[u8]) -> Result<(Frame, Meta), OpenError> {
        if wire.len() < 24 + 16 + 17 {
            return Err(OpenError::Invalid);
        }
        let (nonce, ct) = wire.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| OpenError::Invalid)?;
        let pt = XChaCha20Poly1305::new((&self.link.key).into())
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: ct,
                    aad: &aad(&self.link.room, self.peer),
                },
            )
            .map_err(|_| OpenError::Invalid)?;
        let sender: [u8; 8] = pt[..8].try_into().map_err(|_| OpenError::Invalid)?;
        let counter = u64::from_be_bytes(pt[8..16].try_into().map_err(|_| OpenError::Invalid)?);
        let in_order = match self.seen.get(&sender) {
            Some(&last) if counter <= last => return Err(OpenError::Replay),
            Some(&last) => counter == last + 1,
            None if self.seen.len() >= MAX_SENDERS => return Err(OpenError::Invalid),
            None => false,
        };
        let frame = decode(&pt[16..]).map_err(|_| OpenError::Invalid)?;
        // only advance after the frame authenticated and parsed
        self.seen.insert(sender, counter);
        Ok((frame, Meta { sender, in_order }))
    }
}

#[derive(Debug)]
pub enum Event {
    Frame(Frame, Meta),
    /// A replayed (or otherwise stale) frame was discarded; carries the running count.
    Rejected(u64),
    /// Number of guests currently connected (host side only).
    Guests(usize),
    Closed(String),
}

pub struct Connection {
    pub tx: UnboundedSender<Frame>,
    pub rx: Receiver<Event>,
}

/// Connect to the relay as `role`. `wake` is called whenever an event is queued (e.g. egui repaint).
pub async fn connect(
    link: &ShareLink,
    role: Role,
    wake: impl Fn() + Send + 'static,
) -> Result<Connection, String> {
    let (ws, _) = tokio_tungstenite::connect_async(link.ws_url(role).as_str())
        .await
        .map_err(|e| match e {
            tokio_tungstenite::tungstenite::Error::Http(r) => match r.status().as_u16() {
                404 => "session not found or the host is offline".to_string(),
                403 => "not allowed to host this session".to_string(),
                429 => "the session is full".to_string(),
                c => format!("relay refused the connection (HTTP {c})"),
            },
            e => e.to_string(),
        })?;
    let (mut sink, mut stream) = ws.split();
    let (ftx, mut frx) = unbounded_channel::<Frame>();
    let (etx, erx) = channel::<Event>();
    let (me, peer) = (
        role,
        if role == Role::Host {
            Role::Guest
        } else {
            Role::Host
        },
    );
    let mut sealer = Sealer::new(link, me);
    let mut opener = Opener::new(link, peer);
    let mut rejected = 0u64;
    tokio::spawn(async move {
        let reason = loop {
            tokio::select! {
                out = frx.recv() => match out {
                    Some(f) => match sealer.seal(&f) {
                        Ok(b) => if sink.send(Message::Binary(b.into())).await.is_err() { break "connection lost".to_string() },
                        Err(e) => break e,
                    },
                    None => break "closed".to_string(),
                },
                msg = stream.next() => match msg {
                    Some(Ok(Message::Binary(b))) => match opener.open(&b) {
                        Ok((f, meta)) => { let _ = etx.send(Event::Frame(f, meta)); }
                        Err(OpenError::Replay) => { rejected += 1; let _ = etx.send(Event::Rejected(rejected)); }
                        Err(OpenError::Invalid) => {} // not from our peer / wrong key
                    },
                    Some(Ok(Message::Text(t))) => {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t.as_str()) {
                            if let Some(n) = v.get("n").and_then(|n| n.as_u64()) {
                                let _ = etx.send(Event::Guests(n as usize));
                            }
                        }
                    }
                    Some(Ok(Message::Close(c))) => break c.map(|c| c.reason.to_string()).filter(|r| !r.is_empty()).unwrap_or_else(|| "session ended".into()),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => break e.to_string(),
                    None => break "session ended".to_string(),
                },
            }
            wake();
        };
        if std::env::var("SSHIELD_DEBUG").is_ok() {
            eprintln!("share: {me:?} task ended: {reason}");
        }
        let _ = etx.send(Event::Closed(reason));
        wake();
    });
    Ok(Connection { tx: ftx, rx: erx })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_roundtrip_and_validation() {
        let l = ShareLink::create("https://relay.example.com/").unwrap();
        let p = ShareLink::parse(&l.to_link()).unwrap();
        assert_eq!(
            (p.server.as_str(), &p.room, p.key),
            ("https://relay.example.com", &l.room, l.key)
        );
        assert!(p.host_secret.is_none() && !l.to_link().contains(l.host_secret.as_ref().unwrap()));
        assert!(ShareLink::parse("https://x").is_err());
        assert!(ShareLink::parse(
            "sshield://share?s=aHR0cDovL2V2aWwuY29t&r=00000000000000000000000000000000&k=AA"
        )
        .is_err());
    }

    #[test]
    fn frames_roundtrip_and_resist_tampering() {
        let l = ShareLink::create("https://r.example").unwrap();
        let frames = [
            Frame::Output(b"ls\r\n".to_vec()),
            Frame::Snapshot {
                cols: 80,
                rows: 24,
                data: b"x".to_vec(),
            },
            Frame::Input {
                epoch: 7,
                data: b"a".to_vec(),
            },
            Frame::Allow {
                allowed: true,
                epoch: 9,
            },
            Frame::Hello,
            Frame::End,
        ];
        let mut sealer = Sealer::new(&l, Role::Host);
        let mut opener = Opener::new(&l, Role::Host);
        let mut wires = vec![];
        for f in &frames {
            let w = sealer.seal(f).unwrap();
            let (got, _) = opener.open(&w).unwrap();
            assert_eq!(&got, f);
            // a host-sealed frame must not verify as coming from a guest (no reflection)
            assert_eq!(
                Opener::new(&l, Role::Guest).open(&w).unwrap_err(),
                OpenError::Invalid
            );
            let mut bad = w.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert_eq!(
                Opener::new(&l, Role::Host).open(&bad).unwrap_err(),
                OpenError::Invalid
            );
            wires.push(w);
        }
        let other = ShareLink::create("https://r.example").unwrap();
        assert_eq!(
            Opener::new(&other, Role::Host).open(&wires[0]).unwrap_err(),
            OpenError::Invalid
        );
    }

    #[test]
    fn replayed_frames_are_rejected() {
        let l = ShareLink::create("https://r.example").unwrap();
        let mut guest = Sealer::new(&l, Role::Guest);
        let mut host_rx = Opener::new(&l, Role::Guest);
        let hello = guest.seal(&Frame::Hello).unwrap();
        let keys = guest
            .seal(&Frame::Input {
                epoch: 1,
                data: b"rm -rf build\r".to_vec(),
            })
            .unwrap();
        assert!(host_rx.open(&hello).is_ok());
        assert!(host_rx.open(&keys).is_ok());
        // the relay re-sends the captured keystrokes: authentic, but stale
        assert_eq!(host_rx.open(&keys).unwrap_err(), OpenError::Replay);
        assert_eq!(host_rx.open(&hello).unwrap_err(), OpenError::Replay);
        // a fresh receiver (e.g. after the host restarts) still can't be fed the same frame as
        // in-order input, because the sender is unknown there (in_order == false)
        let (_, meta) = Opener::new(&l, Role::Guest).open(&keys).unwrap();
        assert!(!meta.in_order);
    }

    #[test]
    fn drops_and_reordering_are_detected() {
        let l = ShareLink::create("https://r.example").unwrap();
        let mut host = Sealer::new(&l, Role::Host);
        let mut guest_rx = Opener::new(&l, Role::Host);
        let w: Vec<_> = (0..4)
            .map(|i| host.seal(&Frame::Output(vec![i])).unwrap())
            .collect();
        assert!(!guest_rx.open(&w[0]).unwrap().1.in_order); // first sight: baseline only
        assert!(guest_rx.open(&w[1]).unwrap().1.in_order);
        // w[2] dropped by the relay -> gap is visible on w[3]
        assert!(!guest_rx.open(&w[3]).unwrap().1.in_order);
        // and delivering the dropped one late is refused as stale
        assert_eq!(guest_rx.open(&w[2]).unwrap_err(), OpenError::Replay);
    }
}
