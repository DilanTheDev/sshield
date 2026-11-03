//! Import hosts from an OpenSSH `~/.ssh/config`.

use crate::model::{Auth, ForwardKind, Host, PortForward};
use std::collections::HashMap;

/// Parse ssh_config text into hosts. Wildcard `Host *` blocks provide defaults
/// for the others; `ProxyJump` is resolved to the referenced alias when present.
pub fn parse(text: &str) -> Vec<Host> {
    #[derive(Default, Clone)]
    struct Block {
        names: Vec<String>,
        kv: Vec<(String, String)>,
    }
    let mut blocks: Vec<Block> = vec![];
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (k.trim().to_lowercase(), v.trim().trim_start_matches('=').trim().trim_matches('"').to_string()),
            None => continue,
        };
        if k == "host" {
            blocks.push(Block { names: v.split_whitespace().map(str::to_string).collect(), kv: vec![] });
        } else if let Some(b) = blocks.last_mut() {
            b.kv.push((k, v));
        }
    }
    let defaults: Vec<(String, String)> =
        blocks.iter().filter(|b| b.names.iter().any(|n| n == "*")).flat_map(|b| b.kv.clone()).collect();

    let mut hosts: Vec<Host> = vec![];
    let mut jump_alias: HashMap<String, String> = HashMap::new(); // host id -> alias
    for b in &blocks {
        for name in &b.names {
            if name.contains('*') || name.contains('?') || name.starts_with('!') {
                continue;
            }
            let mut h = Host::new(name, name, &whoami());
            let get = |key: &str| b.kv.iter().find(|(k, _)| k == key).or_else(|| defaults.iter().find(|(k, _)| k == key)).map(|(_, v)| v.clone());
            if let Some(v) = get("hostname") {
                h.hostname = v;
            }
            if let Some(v) = get("user") {
                h.username = v;
            }
            if let Some(p) = get("port").and_then(|v| v.parse().ok()) {
                h.port = p;
            }
            if let Some(f) = get("identityfile") {
                h.auth = Auth::KeyFile { path: expand_tilde(&f), passphrase: None };
            }
            if let Some(v) = get("serveraliveinterval").and_then(|v| v.parse().ok()) {
                h.keepalive_secs = v;
            }
            for (k, v) in &b.kv {
                let kind = match k.as_str() {
                    "localforward" => ForwardKind::Local,
                    "remoteforward" => ForwardKind::Remote,
                    "dynamicforward" => ForwardKind::Dynamic,
                    _ => continue,
                };
                if let Some(f) = parse_forward(kind, v) {
                    h.forwards.push(f);
                }
            }
            if let Some(j) = get("proxyjump") {
                jump_alias.insert(h.id.clone(), j.split(',').next().unwrap_or("").trim().to_string());
            }
            hosts.push(h);
        }
    }
    // resolve jump aliases to ids
    let by_alias: HashMap<String, String> = hosts.iter().map(|h| (h.label.clone(), h.id.clone())).collect();
    for h in &mut hosts {
        if let Some(alias) = jump_alias.get(&h.id) {
            let alias = alias.rsplit('@').next().unwrap_or(alias);
            let alias = alias.split(':').next().unwrap_or(alias);
            h.jump = by_alias.get(alias).cloned();
        }
    }
    hosts
}

fn parse_forward(kind: ForwardKind, v: &str) -> Option<PortForward> {
    let mut it = v.split_whitespace();
    let (bind_host, bind_port) = split_hostport(it.next()?, "127.0.0.1")?;
    if kind == ForwardKind::Dynamic {
        return Some(PortForward { kind, bind_host, bind_port, dest_host: String::new(), dest_port: 0 });
    }
    let (dest_host, dest_port) = split_hostport(it.next()?, "127.0.0.1")?;
    Some(PortForward { kind, bind_host, bind_port, dest_host, dest_port })
}

fn split_hostport(s: &str, default_host: &str) -> Option<(String, u16)> {
    match s.rsplit_once(':') {
        Some((h, p)) => Some((h.trim_matches(|c| c == '[' || c == ']').to_string(), p.parse().ok()?)),
        None => Some((default_host.to_string(), s.parse().ok()?)),
    }
}

fn whoami() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "root".into())
}

fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(h) = dirs::home_dir() {
            return h.join(rest).to_string_lossy().into_owned();
        }
    }
    p.to_string()
}

/// Read and parse the user's `~/.ssh/config`, if any.
pub fn import_default() -> Vec<Host> {
    dirs::home_dir()
        .map(|h| h.join(".ssh").join("config"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| parse(&t))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_hosts_defaults_and_jump() {
        let cfg = r#"
Host *
    User deploy
    ServerAliveInterval 15

Host bastion
    HostName bastion.example.com
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host db1 db2
    HostName 10.1.0.5
    ProxyJump bastion
    LocalForward 5433 localhost:5432
    DynamicForward 1080

Host *.internal
    User nobody
"#;
        let hs = parse(cfg);
        assert_eq!(hs.iter().map(|h| h.label.as_str()).collect::<Vec<_>>(), ["bastion", "db1", "db2"]);
        let b = &hs[0];
        assert_eq!((b.hostname.as_str(), b.port, b.username.as_str(), b.keepalive_secs), ("bastion.example.com", 2222, "deploy", 15));
        assert!(matches!(b.auth, Auth::KeyFile { .. }));
        let d = &hs[1];
        assert_eq!(d.jump.as_deref(), Some(b.id.as_str()));
        assert_eq!(d.forwards.len(), 2);
        assert_eq!(d.forwards[0].dest_port, 5432);
        assert_eq!(d.forwards[1].kind, ForwardKind::Dynamic);
    }
}
