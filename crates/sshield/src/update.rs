//! Update checks against GitHub Releases and (on Windows) one-click install.

use std::io::Read;

const LATEST: &str = "https://api.github.com/repos/DilanTheDev/sshield/releases/latest";
pub const RELEASES_PAGE: &str = "https://github.com/DilanTheDev/sshield/releases/latest";

#[derive(Clone, Debug, PartialEq)]
pub struct Release {
    pub version: String,
    /// Direct URL of the Windows installer, when this release has one.
    pub installer_url: Option<String>,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(300)))
        .user_agent(concat!("sshield/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// Parse "v1.2.3" / "1.2.3-beta" into comparable numbers.
pub fn parse_version(s: &str) -> Vec<u64> {
    s.trim_start_matches('v').split(['-', '+']).next().unwrap_or("").split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    let (mut a, mut b) = (parse_version(candidate), parse_version(current));
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    a > b
}

fn release_from_json(v: &serde_json::Value, current: &str) -> Option<Release> {
    let tag = v.get("tag_name")?.as_str()?;
    if !is_newer(tag, current) {
        return None;
    }
    let installer_url = v.get("assets")?.as_array()?.iter().find_map(|a| {
        let name = a.get("name")?.as_str()?;
        name.ends_with("-setup.exe").then(|| a.get("browser_download_url")?.as_str().map(String::from)).flatten()
    });
    Some(Release { version: tag.trim_start_matches('v').to_string(), installer_url })
}

/// Blocking: returns Some(release) when a newer version is published.
pub fn check() -> Result<Option<Release>, String> {
    let body = agent().get(LATEST).header("Accept", "application/vnd.github+json").call().map_err(|e| e.to_string())?.into_body().read_to_string().map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    Ok(release_from_json(&v, env!("CARGO_PKG_VERSION")))
}

/// Blocking: download the installer and launch it silently. The caller should exit afterwards
/// so the installer can replace the running executable.
pub fn download_and_run(url: &str) -> Result<(), String> {
    if !url.starts_with("https://github.com/DilanTheDev/sshield/") {
        return Err("refusing to download from an unexpected host".into());
    }
    let mut buf = Vec::new();
    agent().get(url).call().map_err(|e| e.to_string())?.into_body().into_reader().take(200 * 1024 * 1024).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let path = std::env::temp_dir().join("sshield-update-setup.exe");
    std::fs::write(&path, buf).map_err(|e| e.to_string())?;
    std::process::Command::new(&path).args(["/SILENT", "/SP-", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"]).spawn().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare() {
        assert!(is_newer("v0.2.0", "0.1.9"));
        assert!(is_newer("0.10.0", "0.9.0"));
        assert!(is_newer("1.0.0.1", "1.0.0"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
    }

    #[test]
    fn picks_installer_asset() {
        let j: serde_json::Value = serde_json::json!({"tag_name":"v0.2.0","assets":[
            {"name":"sshield-linux-x64","browser_download_url":"https://x/l"},
            {"name":"sshield-windows-x64-setup.exe","browser_download_url":"https://x/w"}]});
        let r = release_from_json(&j, "0.1.0").unwrap();
        assert_eq!((r.version.as_str(), r.installer_url.as_deref()), ("0.2.0", Some("https://x/w")));
        assert!(release_from_json(&j, "0.2.0").is_none());
    }
}
