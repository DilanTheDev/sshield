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
    /// guest -> host: keystrokes (ignored by the host unless input is allowed)
    Input(Vec<u8>),
    /// host -> guests: whether typing is currently allowed
    Allow(bool),
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

pub fn seal(link: &ShareLink, sender: Role, f: &Frame) -> Result<Vec<u8>, String> {
    let mut pt = Vec::new();
    match f {
        Frame::Output(d) => {
            pt.push(1);
            pt.extend_from_slice(d);
        }
        Frame::Snapshot { cols, rows, data } => {
            pt.push(2);
            pt.extend_from_slice(&cols.to_be_bytes());
            pt.extend_from_slice(&rows.to_be_bytes());
            pt.extend_from_slice(data);
        }
        Frame::Input(d) => {
            pt.push(3);
            pt.extend_from_slice(d);
        }
        Frame::Allow(b) => pt.extend_from_slice(&[4, *b as u8]),
        Frame::Hello => pt.push(5),
        Frame::End => pt.push(6),
    }
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let ct = XChaCha20Poly1305::new((&link.key).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &pt,
                aad: &aad(&link.room, sender),
            },
        )
        .map_err(|e| e.to_string())?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(link: &ShareLink, sender: Role, wire: &[u8]) -> Result<Frame, String> {
    if wire.len() < 24 + 16 + 1 {
        return Err("short frame".into());
    }
    let (nonce, ct) = wire.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| "nonce")?;
    let pt = XChaCha20Poly1305::new((&link.key).into())
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ct,
                aad: &aad(&link.room, sender),
            },
        )
        .map_err(|_| "frame failed authentication".to_string())?;
    let (t, rest) = pt.split_first().ok_or("empty frame")?;
    Ok(match t {
        1 => Frame::Output(rest.to_vec()),
        2 if rest.len() >= 4 => Frame::Snapshot {
            cols: u16::from_be_bytes([rest[0], rest[1]]),
            rows: u16::from_be_bytes([rest[2], rest[3]]),
            data: rest[4..].to_vec(),
        },
        3 => Frame::Input(rest.to_vec()),
        4 if !rest.is_empty() => Frame::Allow(rest[0] != 0),
        5 => Frame::Hello,
        6 => Frame::End,
        _ => return Err("unknown frame".into()),
    })
}

#[derive(Debug)]
pub enum Event {
    Frame(Frame),
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
    let link = link.clone();
    tokio::spawn(async move {
        let reason = loop {
            tokio::select! {
                out = frx.recv() => match out {
                    Some(f) => match seal(&link, me, &f) {
                        Ok(b) => if sink.send(Message::Binary(b.into())).await.is_err() { break "connection lost".to_string() },
                        Err(e) => break e,
                    },
                    None => break "closed".to_string(),
                },
                msg = stream.next() => match msg {
                    Some(Ok(Message::Binary(b))) => match open(&link, peer, &b) {
                        Ok(f) => { let _ = etx.send(Event::Frame(f)); }
                        Err(e) => { if std::env::var("SSHIELD_DEBUG").is_ok() { eprintln!("share: dropped frame: {e}"); } }
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
        for f in [
            Frame::Output(b"ls\r\n".to_vec()),
            Frame::Snapshot {
                cols: 80,
                rows: 24,
                data: b"x".to_vec(),
            },
            Frame::Input(b"a".to_vec()),
            Frame::Allow(true),
            Frame::Hello,
            Frame::End,
        ] {
            let w = seal(&l, Role::Host, &f).unwrap();
            assert_eq!(open(&l, Role::Host, &w).unwrap(), f);
            // a frame sealed by the host must not verify as coming from a guest (no reflection)
            assert!(open(&l, Role::Guest, &w).is_err());
            let mut bad = w.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(open(&l, Role::Host, &bad).is_err());
        }
        let other = ShareLink::create("https://r.example").unwrap();
        assert!(open(
            &other,
            Role::Host,
            &seal(&l, Role::Host, &Frame::Hello).unwrap()
        )
        .is_err());
    }
}
