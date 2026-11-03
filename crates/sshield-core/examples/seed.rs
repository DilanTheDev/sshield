//! Writes a demo vault (hosts, snippets, a key) for trying the UI:
//!     cargo run -p sshield-core --example seed -- /path/to/vault.json "master password"
use sshield_core::model::*;
use sshield_core::ssh::generate_ed25519;
use sshield_core::vault::{KdfCost, Vault};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (path, pw) = (&a[1], &a[2]);
    let mut lib = Library::default();
    let (pem, _) = generate_ed25519("demo").unwrap();
    let key = Identity { id: new_id(), name: "laptop-ed25519".into(), private_key: pem, passphrase: None };

    let mut dev = Host::new("devserver", "127.0.0.1", "demo");
    dev.port = 2222;
    dev.auth = Auth::Password { password: "demo".into() };
    dev.group = "Local".into();
    dev.tags = vec!["demo".into()];
    dev.favorite = true;
    dev.forwards = vec![PortForward { kind: ForwardKind::Dynamic, bind_host: "127.0.0.1".into(), bind_port: 1080, dest_host: String::new(), dest_port: 0 }];

    let mut bastion = Host::new("bastion", "bastion.example.com", "ops");
    bastion.group = "Production".into();
    bastion.auth = Auth::Identity { id: key.id.clone() };
    bastion.tags = vec!["prod".into(), "eu-west".into()];
    bastion.require_vpn = Some(true);

    let mut db = Host::new("db-primary", "10.20.0.12", "postgres");
    db.group = "Production".into();
    db.jump = Some(bastion.id.clone());
    db.tags = vec!["prod".into(), "db".into()];
    db.forwards = vec![PortForward { kind: ForwardKind::Local, bind_host: "127.0.0.1".into(), bind_port: 5433, dest_host: "localhost".into(), dest_port: 5432 }];
    db.require_vpn = Some(true);

    let mut web = Host::new("web-staging", "staging.example.com", "deploy");
    web.group = "Staging".into();
    web.tags = vec!["staging".into()];
    web.last_connected = Some(1_700_000_000);

    lib.hosts = vec![dev, bastion, db, web];
    lib.identities = vec![key];
    lib.snippets = vec![
        Snippet { id: new_id(), name: "disk usage".into(), command: "df -h".into(), tags: vec![] },
        Snippet { id: new_id(), name: "top memory".into(), command: "ps aux --sort=-%mem | head".into(), tags: vec![] },
        Snippet { id: new_id(), name: "tail syslog".into(), command: "tail -f /var/log/syslog".into(), tags: vec![] },
    ];
    lib.settings.vpn = VpnPolicy { enabled: true, kind: VpnKind::Existing, interface: "lo".into(), ..Default::default() };
    Vault::create(std::path::Path::new(path), pw, &lib, KdfCost::STRONG).unwrap();
    eprintln!("wrote {path}");
}
