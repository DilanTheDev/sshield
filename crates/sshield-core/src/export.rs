//! Export hosts: sanitised JSON (no passwords / passphrases) and OpenSSH `config` text.

use crate::model::{Auth, Host, Library};

/// All hosts as pretty JSON. Saved passwords and key passphrases are never exported.
pub fn hosts_json(lib: &Library) -> String {
    let hosts: Vec<Host> = lib
        .hosts
        .iter()
        .cloned()
        .map(|mut h| {
            h.auth = match h.auth {
                Auth::Password { .. } => Auth::Prompt,
                Auth::KeyFile { path, .. } => Auth::KeyFile {
                    path,
                    passphrase: None,
                },
                other => other,
            };
            h
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ "sshield_export": 1, "hosts": hosts }))
        .unwrap_or_default()
}

fn alias(h: &Host) -> String {
    let a: String = (if h.label.is_empty() {
        &h.hostname
    } else {
        &h.label
    })
    .chars()
    .map(|c| {
        if c.is_whitespace() || c == '*' || c == '?' || c == '!' {
            '-'
        } else {
            c
        }
    })
    .collect();
    if a.is_empty() {
        "host".into()
    } else {
        a
    }
}

/// OpenSSH client config for all hosts (jump hosts become `ProxyJump`).
pub fn ssh_config(lib: &Library) -> String {
    let mut out = String::from("# Exported from sshield\n");
    for h in &lib.hosts {
        out.push_str(&format!(
            "\nHost {}\n    HostName {}\n",
            alias(h),
            h.hostname
        ));
        if !h.username.is_empty() {
            out.push_str(&format!("    User {}\n", h.username));
        }
        if h.port != 22 {
            out.push_str(&format!("    Port {}\n", h.port));
        }
        if let Auth::KeyFile { path, .. } = &h.auth {
            out.push_str(&format!("    IdentityFile {path}\n"));
        }
        if let Some(j) = h
            .jump
            .as_ref()
            .and_then(|id| lib.hosts.iter().find(|x| &x.id == id))
        {
            out.push_str(&format!("    ProxyJump {}\n", alias(j)));
        }
        if h.keepalive_secs > 0 {
            out.push_str(&format!("    ServerAliveInterval {}\n", h.keepalive_secs));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_strips_secrets_and_links_jump() {
        let mut lib = Library::default();
        let jump = Host::new("bastion", "b.example.com", "ops");
        let mut h = Host::new("web 1", "10.0.0.5", "root");
        h.port = 2222;
        h.auth = Auth::Password {
            password: "hunter2".into(),
        };
        h.jump = Some(jump.id.clone());
        lib.hosts = vec![jump, h];
        let j = hosts_json(&lib);
        assert!(!j.contains("hunter2"));
        let c = ssh_config(&lib);
        assert!(
            c.contains("Host web-1") && c.contains("Port 2222") && c.contains("ProxyJump bastion")
        );
    }
}
