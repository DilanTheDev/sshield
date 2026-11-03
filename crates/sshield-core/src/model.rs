use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type Id = String;

/// Fresh random identifier (128 bit, hex).
pub fn new_id() -> Id {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("os rng");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// How a host authenticates. Secrets live inside the encrypted library, never
/// in plaintext on disk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Auth {
    /// Ask every time.
    #[default]
    Prompt,
    Password { password: String },
    /// Reference to an [`Identity`] stored in the library.
    Identity { id: Id },
    /// Try `~/.ssh/id_*` style key file on disk.
    KeyFile { path: String, passphrase: Option<String> },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Identity {
    pub id: Id,
    pub name: String,
    /// OpenSSH / PEM / PuTTY private key text.
    pub private_key: String,
    pub passphrase: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ForwardKind {
    /// `-L`: local listener -> remote target
    #[default]
    Local,
    /// `-R`: remote listener -> local target
    Remote,
    /// `-D`: local SOCKS5 proxy through the server
    Dynamic,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PortForward {
    pub kind: ForwardKind,
    pub bind_host: String,
    pub bind_port: u16,
    /// Unused for [`ForwardKind::Dynamic`].
    pub dest_host: String,
    pub dest_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Host {
    pub id: Id,
    pub label: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth: Auth,
    pub group: String,
    pub tags: Vec<String>,
    pub notes: String,
    /// Another host id used as a jump (ProxyJump) hop. Chains are followed.
    pub jump: Option<Id>,
    pub forwards: Vec<PortForward>,
    /// Commands typed after login.
    pub startup: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub keepalive_secs: u32,
    /// `None` = use global VPN policy, `Some(false)` = never route via VPN,
    /// `Some(true)` = require VPN (global policy must define one).
    pub require_vpn: Option<bool>,
    /// Terminal theme override (name).
    pub theme: Option<String>,
    pub favorite: bool,
    pub last_connected: Option<u64>,
}

impl Host {
    pub fn new(label: &str, hostname: &str, username: &str) -> Self {
        Host {
            id: new_id(),
            label: label.into(),
            hostname: hostname.into(),
            port: 22,
            username: username.into(),
            auth: Auth::Prompt,
            group: String::new(),
            tags: vec![],
            notes: String::new(),
            jump: None,
            forwards: vec![],
            startup: vec![],
            env: BTreeMap::new(),
            keepalive_secs: 30,
            require_vpn: None,
            theme: None,
            favorite: false,
            last_connected: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Snippet {
    pub id: Id,
    pub name: String,
    pub command: String,
    pub tags: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VpnKind {
    WireGuard,
    OpenVpn,
    /// Do not manage anything; just require that an interface exists and
    /// carries the traffic (e.g. a VPN client you start yourself).
    Existing,
}

/// "Force SSH through the VPN" configuration.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct VpnPolicy {
    pub enabled: bool,
    pub kind: VpnKind,
    /// `.conf` (WireGuard) or `.ovpn` (OpenVPN). Not needed for `Existing`.
    pub config_path: String,
    /// Network interface that must carry SSH traffic. If empty and the kind is
    /// WireGuard the config file stem is used (wg-quick convention).
    pub interface: String,
    /// Bring the tunnel up automatically when it is down.
    pub auto_start: bool,
    /// Tear down tunnels that sshield started once the last session closes.
    pub auto_stop: bool,
    /// Refuse to connect if the VPN cannot be verified (never fall back).
    pub fail_closed: bool,
    /// Seconds to wait for the interface to appear after starting.
    pub start_timeout_secs: u32,
    /// Override executable (wg-quick / wireguard.exe / openvpn).
    pub executable: String,
}

impl Default for VpnPolicy {
    fn default() -> Self {
        VpnPolicy {
            enabled: false,
            kind: VpnKind::WireGuard,
            config_path: String::new(),
            interface: String::new(),
            auto_start: true,
            auto_stop: false,
            fail_closed: true,
            start_timeout_secs: 30,
            executable: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub theme: String,
    pub font_size: f32,
    pub font_family: String,
    pub scrollback: usize,
    pub copy_on_select: bool,
    pub cursor_blink: bool,
    pub log_sessions: bool,
    pub log_dir: String,
    pub vpn: VpnPolicy,
    /// Optional folder (Dropbox / OneDrive / Syncthing / NAS) to which the
    /// encrypted vault is mirrored. The files are useless without the master
    /// password, so any dumb file sync is safe.
    pub sync_dir: String,
    /// UI accent colour as 0xRRGGBB.
    pub accent: u32,
    pub ui_scale: f32,
    /// Keyword highlighting rules (regex-free substring -> 0xRRGGBB).
    pub highlights: Vec<(String, u32)>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: "Tokyo Night".into(),
            font_size: 14.0,
            font_family: String::new(),
            scrollback: 10_000,
            copy_on_select: true,
                    cursor_blink: true,
            log_sessions: false,
            log_dir: String::new(),
            vpn: VpnPolicy::default(),
            sync_dir: String::new(),
            accent: 0x7aa2f7,
            ui_scale: 1.0,
            highlights: vec![
                ("ERROR".into(), 0xf7768e),
                ("WARN".into(), 0xe0af68),
                ("FAIL".into(), 0xf7768e),
                ("OK".into(), 0x9ece6a),
            ],
        }
    }
}

/// The whole user library. This is the plaintext that gets encrypted.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct Library {
    pub hosts: Vec<Host>,
    pub identities: Vec<Identity>,
    pub snippets: Vec<Snippet>,
    pub settings: Settings,
    /// Command history for autocompletion (most recent last).
    pub history: Vec<String>,
}

impl Library {
    pub fn host(&self, id: &str) -> Option<&Host> {
        self.hosts.iter().find(|h| h.id == id)
    }
    pub fn identity(&self, id: &str) -> Option<&Identity> {
        self.identities.iter().find(|i| i.id == id)
    }
    pub fn groups(&self) -> Vec<String> {
        let mut g: Vec<String> = self.hosts.iter().map(|h| h.group.clone()).collect();
        g.sort();
        g.dedup();
        g
    }
    /// Resolve the jump chain for a host, outermost hop first. Detects cycles.
    pub fn jump_chain(&self, host: &Host) -> Result<Vec<Host>, String> {
        let mut chain = vec![];
        let mut seen = vec![host.id.clone()];
        let mut cur = host.jump.clone();
        while let Some(id) = cur {
            if seen.contains(&id) {
                return Err("jump host cycle detected".into());
            }
            let h = self.host(&id).ok_or_else(|| format!("jump host {id} not found"))?;
            seen.push(id);
            chain.push(h.clone());
            cur = h.jump.clone();
        }
        chain.reverse();
        Ok(chain)
    }
    /// Add a command to history, de-duplicating and capping.
    pub fn push_history(&mut self, cmd: &str) {
        let cmd = cmd.trim();
        if cmd.is_empty() {
            return;
        }
        self.history.retain(|c| c != cmd);
        self.history.push(cmd.to_string());
        if self.history.len() > 5000 {
            self.history.drain(..self.history.len() - 5000);
        }
    }
    /// Prefix completions from history + snippets, most recent first.
    pub fn complete(&self, prefix: &str, limit: usize) -> Vec<String> {
        if prefix.is_empty() {
            return vec![];
        }
        let mut out: Vec<String> = vec![];
        for c in self.history.iter().rev().chain(self.snippets.iter().map(|s| &s.command)) {
            if c.starts_with(prefix) && c != prefix && !out.contains(c) {
                out.push(c.clone());
                if out.len() >= limit {
                    break;
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jump_chain_order_and_cycle() {
        let a = Host::new("a", "a", "u");
        let mut b = Host::new("b", "b", "u");
        let mut c = Host::new("c", "c", "u");
        b.jump = Some(a.id.clone());
        c.jump = Some(b.id.clone());
        let mut lib = Library::default();
        lib.hosts = vec![a.clone(), b.clone(), c.clone()];
        let chain = lib.jump_chain(&c).unwrap();
        assert_eq!(chain.iter().map(|h| h.label.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        lib.hosts[0].jump = Some(c.id.clone());
        assert!(lib.jump_chain(&c).is_err());
    }

    #[test]
    fn completion_prefers_recent() {
        let mut lib = Library::default();
        lib.push_history("ls -la");
        lib.push_history("ls /var");
        lib.push_history("ls -la"); // moves to most recent
        assert_eq!(lib.complete("ls", 5), vec!["ls -la", "ls /var"]);
        assert!(lib.complete("", 5).is_empty());
    }
}
