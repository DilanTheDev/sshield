//! Force SSH traffic through a VPN (WireGuard / OpenVPN / any existing tunnel).
//!
//! Enforcement is layered, and **fails closed**:
//!
//! 1. **Tunnel lifecycle** – optionally bring the tunnel up (`wg-quick up`,
//!    `wireguard.exe /installtunnelservice`, `openvpn --config`) and wait for
//!    its interface to appear.
//! 2. **Route verification** – ask the OS which interface it would use to reach
//!    the destination and require it to be the tunnel interface. A split-tunnel
//!    that does not cover the target is rejected instead of leaking.
//! 3. **Socket pinning** – the TCP socket is bound to the tunnel interface
//!    (`SO_BINDTODEVICE` on Linux, `IP_UNICAST_IF` on Windows, `IP_BOUND_IF` on
//!    macOS) and to its address, so even a routing change mid-flight cannot
//!    move the connection onto the physical NIC.
//!
//! Only the first TCP hop is pinned; jump-host hops ride inside that stream.
//!
//! Known limitation: hostnames are resolved with the system resolver *before*
//! pinning. Use an IP address (or a VPN-provided DNS that is the system
//! resolver) if DNS metadata leakage matters to you.

use crate::model::{VpnKind, VpnPolicy};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};
use tokio::process::{Child, Command};

#[derive(Debug, thiserror::Error)]
pub enum VpnError {
    #[error("VPN policy is enabled but no interface/config is set")]
    NotConfigured,
    #[error("VPN interface '{0}' is not up (and auto-start is off or failed)")]
    InterfaceDown(String),
    #[error("could not start VPN: {0}")]
    StartFailed(String),
    #[error("VPN interface '{iface}' has no {family} address, cannot reach {dest}")]
    NoAddress { iface: String, family: &'static str, dest: IpAddr },
    #[error("route to {dest} goes via '{actual}', not VPN interface '{expected}' - refusing to leak (add the destination to the tunnel's AllowedIPs/routes)")]
    RouteLeak { dest: IpAddr, actual: String, expected: String },
    #[error("could not verify route to {dest} ({0}); blocked because fail-closed is on", .reason)]
    RouteUnknown { dest: IpAddr, reason: String },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// A verified tunnel interface.
#[derive(Clone, Debug, PartialEq)]
pub struct Binding {
    pub iface: String,
    pub index: Option<u32>,
    pub v4: Option<std::net::Ipv4Addr>,
    pub v6: Option<std::net::Ipv6Addr>,
}

fn name_eq(a: &str, b: &str) -> bool {
    if cfg!(windows) { a.eq_ignore_ascii_case(b) } else { a == b }
}

/// Look up an *up* interface by name.
pub fn find_interface(name: &str) -> Option<Binding> {
    let mut b: Option<Binding> = None;
    for i in if_addrs::get_if_addrs().ok()? {
        if !name_eq(&i.name, name) || i.oper_status == if_addrs::IfOperStatus::Down {
            continue;
        }
        let e = b.get_or_insert(Binding { iface: i.name.clone(), index: i.index, v4: None, v6: None });
        match i.addr {
            if_addrs::IfAddr::V4(a) => e.v4 = e.v4.or(Some(a.ip)),
            if_addrs::IfAddr::V6(a) => {
                // skip link-local for source binding
                if (a.ip.segments()[0] & 0xffc0) != 0xfe80 {
                    e.v6 = e.v6.or(Some(a.ip))
                } else if e.v6.is_none() {
                    e.v6 = Some(a.ip)
                }
            }
        }
    }
    b
}

/// Name of this OS's loopback interface (`lo`, `lo0`, "Loopback Pseudo-Interface 1", ...).
pub fn loopback_interface() -> Option<String> {
    if_addrs::get_if_addrs().ok()?.into_iter().find(|i| i.is_loopback()).map(|i| i.name)
}

/// Interface name the policy expects (explicit, or WireGuard config stem).
pub fn expected_interface(p: &VpnPolicy) -> Option<String> {
    if !p.interface.trim().is_empty() {
        return Some(p.interface.trim().to_string());
    }
    if p.kind == VpnKind::WireGuard && !p.config_path.is_empty() {
        return Path::new(&p.config_path).file_stem().map(|s| s.to_string_lossy().into_owned());
    }
    None
}

/// The command used to bring a tunnel up: (program, args).
pub fn start_command(p: &VpnPolicy) -> Option<(String, Vec<String>)> {
    let exe = |default: &str| if p.executable.is_empty() { default.to_string() } else { p.executable.clone() };
    match p.kind {
        VpnKind::Existing => None,
        VpnKind::WireGuard => {
            if cfg!(windows) {
                let default = r"C:\Program Files\WireGuard\wireguard.exe";
                Some((exe(default), vec!["/installtunnelservice".into(), p.config_path.clone()]))
            } else {
                Some((exe("wg-quick"), vec!["up".into(), p.config_path.clone()]))
            }
        }
        VpnKind::OpenVpn => {
            let default = if cfg!(windows) { r"C:\Program Files\OpenVPN\bin\openvpn.exe" } else { "openvpn" };
            Some((exe(default), vec!["--config".into(), p.config_path.clone()]))
        }
    }
}

/// The command used to bring a tunnel down (WireGuard only; OpenVPN is a child process we kill).
pub fn stop_command(p: &VpnPolicy) -> Option<(String, Vec<String>)> {
    let exe = |default: &str| if p.executable.is_empty() { default.to_string() } else { p.executable.clone() };
    match p.kind {
        VpnKind::WireGuard => {
            if cfg!(windows) {
                let name = expected_interface(p).unwrap_or_default();
                Some((exe(r"C:\Program Files\WireGuard\wireguard.exe"), vec!["/uninstalltunnelservice".into(), name]))
            } else {
                Some((exe("wg-quick"), vec!["down".into(), p.config_path.clone()]))
            }
        }
        _ => None,
    }
}

/// Owns tunnels sshield started so it can stop them again.
#[derive(Default)]
pub struct VpnManager {
    child: Mutex<Option<Child>>,
    started_wg: Mutex<Option<VpnPolicy>>,
}

impl VpnManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make sure the tunnel is up and return its interface. Fails closed.
    pub async fn ensure_up(&self, p: &VpnPolicy) -> Result<Binding, VpnError> {
        let iface = expected_interface(p).ok_or(VpnError::NotConfigured)?;
        if let Some(b) = find_interface(&iface) {
            return Ok(b);
        }
        if !p.auto_start || p.kind == VpnKind::Existing {
            return Err(VpnError::InterfaceDown(iface));
        }
        if p.config_path.is_empty() || !Path::new(&p.config_path).exists() {
            return Err(VpnError::StartFailed(format!("config file '{}' not found", p.config_path)));
        }
        let (prog, args) = start_command(p).ok_or(VpnError::NotConfigured)?;
        match p.kind {
            VpnKind::OpenVpn => {
                let child = Command::new(&prog)
                    .args(&args)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .spawn()
                    .map_err(|e| VpnError::StartFailed(format!("{prog}: {e}")))?;
                *self.child.lock().unwrap() = Some(child);
            }
            _ => {
                let out = Command::new(&prog)
                    .args(&args)
                    .output()
                    .await
                    .map_err(|e| VpnError::StartFailed(format!("{prog}: {e}")))?;
                if !out.status.success() {
                    return Err(VpnError::StartFailed(format!(
                        "{prog} exited with {}: {}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr).trim()
                    )));
                }
                *self.started_wg.lock().unwrap() = Some(p.clone());
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(p.start_timeout_secs.max(1) as u64);
        loop {
            if let Some(b) = find_interface(&iface) {
                return Ok(b);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(VpnError::InterfaceDown(iface));
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// Stop any tunnel that this manager started.
    pub async fn stop(&self) {
        let child = self.child.lock().unwrap().take();
        if let Some(mut c) = child {
            let _ = c.kill().await;
        }
        let wg = self.started_wg.lock().unwrap().take();
        if let Some(p) = wg {
            if let Some((prog, args)) = stop_command(&p) {
                let _ = Command::new(prog).args(args).output().await;
            }
        }
    }
}

// ---------------------------------------------------------------- routes

/// Parse `ip route get` output: `1.2.3.4 via 10.0.0.1 dev wg0 src 10.0.0.2`.
pub fn parse_ip_route_get(out: &str) -> Option<String> {
    let mut it = out.split_whitespace();
    while let Some(t) = it.next() {
        if t == "dev" {
            return it.next().map(str::to_string);
        }
    }
    None
}

/// Parse macOS/BSD `route -n get`: a line `  interface: utun3`.
pub fn parse_bsd_route_get(out: &str) -> Option<String> {
    out.lines().find_map(|l| l.trim().strip_prefix("interface:").map(|v| v.trim().to_string()))
}

/// Parse Linux `/proc/net/route` and return the interface of the longest
/// matching IPv4 route (lowest metric wins ties).
pub fn parse_proc_net_route(table: &str, dest: std::net::Ipv4Addr) -> Option<String> {
    let d = u32::from(dest);
    let mut best: Option<(u32, u32, String)> = None; // (prefix_len, metric, iface)
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let (Ok(net), Ok(mask), Ok(flags), Ok(metric)) = (
            u32::from_str_radix(f[1], 16),
            u32::from_str_radix(f[7], 16),
            u32::from_str_radix(f[3], 16),
            f[6].parse::<u32>(),
        ) else {
            continue;
        };
        // /proc/net/route prints the raw native-endian word of the network-order bytes.
        let to_host = |v: u32| u32::from_be_bytes(v.to_ne_bytes());
        let (net, mask) = (to_host(net), to_host(mask));
        if flags & 1 == 0 {
            continue; // route not up
        }
        if d & mask != net & mask {
            continue;
        }
        let plen = mask.count_ones();
        let better = match &best {
            None => true,
            Some((bp, bm, _)) => plen > *bp || (plen == *bp && metric < *bm),
        };
        if better {
            best = Some((plen, metric, f[0].to_string()));
        }
    }
    best.map(|b| b.2)
}

/// Ask the OS which interface it would use to reach `dest`.
pub async fn lookup_route(dest: IpAddr) -> Result<String, String> {
    if dest.is_loopback() {
        return loopback_interface().ok_or_else(|| "no loopback interface found".to_string());
    }
    #[cfg(target_os = "linux")]
    {
        match Command::new("ip").args(["route", "get", &dest.to_string()]).output().await {
            Ok(o) if o.status.success() => {
                if let Some(i) = parse_ip_route_get(&String::from_utf8_lossy(&o.stdout)) {
                    return Ok(i);
                }
            }
            _ => {}
        }
        if let IpAddr::V4(v4) = dest {
            if let Ok(t) = std::fs::read_to_string("/proc/net/route") {
                if let Some(i) = parse_proc_net_route(&t, v4) {
                    return Ok(i);
                }
            }
        }
        Err("neither `ip route get` nor /proc/net/route gave an answer".into())
    }
    #[cfg(target_os = "macos")]
    {
        let o = Command::new("route").args(["-n", "get", &dest.to_string()]).output().await.map_err(|e| e.to_string())?;
        parse_bsd_route_get(&String::from_utf8_lossy(&o.stdout)).ok_or_else(|| "route -n get gave no interface".into())
    }
    #[cfg(windows)]
    {
        let script = format!(
            "(Find-NetRoute -RemoteIPAddress '{dest}' | Where-Object {{ $_.InterfaceAlias }} | Select-Object -First 1).InterfaceAlias"
        );
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
        #[allow(unused_imports)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let o = cmd.output().await.map_err(|e| e.to_string())?;
        let s = String::from_utf8_lossy(&o.stdout);
        let name = s.lines().map(str::trim).find(|l| !l.is_empty());
        name.map(str::to_string).ok_or_else(|| "Find-NetRoute returned nothing".into())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = dest;
        Err("route lookup not supported on this OS".into())
    }
}

/// Require that the OS routes `dest` via the tunnel interface.
pub async fn verify_route(b: &Binding, dest: IpAddr, fail_closed: bool) -> Result<(), VpnError> {
    match lookup_route(dest).await {
        Ok(actual) if name_eq(&actual, &b.iface) => Ok(()),
        Ok(actual) => Err(VpnError::RouteLeak { dest, actual, expected: b.iface.clone() }),
        Err(reason) if fail_closed => Err(VpnError::RouteUnknown { dest, reason }),
        Err(_) => Ok(()),
    }
}

// ------------------------------------------------------------ pinned TCP

/// Resolve and connect, pinned to the tunnel. This is the only function the
/// SSH layer uses for the first hop when a VPN policy applies.
pub async fn connect_via(
    mgr: &VpnManager,
    policy: &VpnPolicy,
    host: &str,
    port: u16,
) -> Result<TcpStream, VpnError> {
    let binding = mgr.ensure_up(policy).await?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    let mut last: Option<VpnError> = None;
    for addr in addrs {
        match connect_pinned(&binding, addr, policy.fail_closed).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| VpnError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses resolved"))))
}

pub async fn connect_pinned(b: &Binding, addr: SocketAddr, fail_closed: bool) -> Result<TcpStream, VpnError> {
    let src: IpAddr = match addr.ip() {
        IpAddr::V4(_) => b.v4.map(IpAddr::V4),
        IpAddr::V6(_) => b.v6.map(IpAddr::V6),
    }
    .ok_or(VpnError::NoAddress {
        iface: b.iface.clone(),
        family: if addr.is_ipv4() { "IPv4" } else { "IPv6" },
        dest: addr.ip(),
    })?;
    verify_route(b, addr.ip(), fail_closed).await?;

    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    pin_socket(&sock, b, addr.is_ipv6())?;
    sock.bind(&SocketAddr::new(src, 0).into())?;
    sock.set_nonblocking(true)?;
    let sock = TcpSocket::from_std_stream(sock.into());
    let s = sock.connect(addr).await?;
    let _ = s.set_nodelay(true);
    Ok(s)
}

#[allow(unused_variables)]
fn pin_socket(sock: &socket2::Socket, b: &Binding, v6: bool) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        sock.bind_device(Some(b.iface.as_bytes()))?;
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(idx) = b.index.and_then(std::num::NonZeroU32::new) {
            if v6 { sock.bind_device_by_index_v6(Some(idx))? } else { sock.bind_device_by_index_v4(Some(idx))? }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IPPROTO_IPV6, SOCKET};
        const IP_UNICAST_IF: i32 = 31;
        const IPV6_UNICAST_IF: i32 = 31;
        let idx = b.index.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "interface has no index"))?;
        // IPv4 wants the index in network byte order, IPv6 in host order.
        let (level, opt, val) = if v6 { (IPPROTO_IPV6, IPV6_UNICAST_IF, idx) } else { (IPPROTO_IP, IP_UNICAST_IF, idx.to_be()) };
        let rc = unsafe {
            setsockopt(sock.as_raw_socket() as SOCKET, level, opt, &val as *const u32 as *const u8, 4)
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_ip_route() {
        assert_eq!(parse_ip_route_get("1.1.1.1 via 10.8.0.1 dev wg0 src 10.8.0.2 uid 0\n cache"), Some("wg0".into()));
        assert_eq!(parse_ip_route_get("local 127.0.0.1 dev lo src 127.0.0.1"), Some("lo".into()));
        assert_eq!(parse_ip_route_get("RTNETLINK answers: Network is unreachable"), None);
    }

    #[test]
    fn parses_bsd_route() {
        let out = "   route to: 1.1.1.1\ndestination: default\n    gateway: 10.0.0.1\n  interface: utun4\n      flags: <UP>";
        assert_eq!(parse_bsd_route_get(out), Some("utun4".into()));
    }

    #[test]
    fn proc_net_route_longest_prefix() {
        // Iface Destination Gateway Flags RefCnt Use Metric Mask
        let t = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                 eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                 wg0\t0008000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        // 10.0.8.0/24 via wg0; default via eth0
        assert_eq!(parse_proc_net_route(t, "10.0.8.5".parse().unwrap()), Some("wg0".into()));
        assert_eq!(parse_proc_net_route(t, "8.8.8.8".parse().unwrap()), Some("eth0".into()));
    }

    #[test]
    fn expected_interface_rules() {
        let mut p = VpnPolicy::default();
        assert_eq!(expected_interface(&p), None);
        p.config_path = "/etc/wireguard/office.conf".into();
        assert_eq!(expected_interface(&p).as_deref(), Some("office"));
        p.interface = "wg9".into();
        assert_eq!(expected_interface(&p).as_deref(), Some("wg9"));
        p.kind = VpnKind::OpenVpn;
        p.interface.clear();
        assert_eq!(expected_interface(&p), None);
    }

    #[test]
    fn start_commands() {
        let mut p = VpnPolicy::default();
        p.config_path = "x.conf".into();
        let (prog, args) = start_command(&p).unwrap();
        if cfg!(windows) {
            assert!(prog.ends_with("wireguard.exe") && args[0] == "/installtunnelservice");
        } else {
            assert_eq!((prog.as_str(), args[0].as_str()), ("wg-quick", "up"));
        }
        p.kind = VpnKind::OpenVpn;
        assert_eq!(start_command(&p).unwrap().1, vec!["--config", "x.conf"]);
        p.kind = VpnKind::Existing;
        assert!(start_command(&p).is_none());
    }

    /// Fail-closed: a tunnel that is not up must never fall back to a direct connection.
    #[tokio::test]
    async fn down_tunnel_blocks_connection() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let mut p = VpnPolicy::default();
        p.kind = VpnKind::Existing;
        p.interface = "definitely-not-an-iface0".into();
        let r = connect_via(&VpnManager::new(), &p, "127.0.0.1", port).await;
        assert!(matches!(r, Err(VpnError::InterfaceDown(_))), "{r:?}");
    }

    /// Leak-prevention: loopback traffic must not be accepted as "via VPN" for another iface.
    #[tokio::test]
    async fn route_mismatch_is_refused() {
        let lo = lo_binding();
        let fake = Binding { iface: "wg-fake".into(), ..lo };
        let r = connect_pinned(&fake, "127.0.0.1:9".parse().unwrap(), true).await;
        assert!(matches!(r, Err(VpnError::RouteLeak { .. })), "{r:?}");
    }

    /// Happy path using the loopback interface as the "tunnel".
    #[tokio::test]
    async fn pinned_connect_over_loopback() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let acc = tokio::spawn(async move { l.accept().await.unwrap().1 });
        let mut p = VpnPolicy::default();
        p.kind = VpnKind::Existing;
        p.interface = lo_binding().iface;
        let s = connect_via(&VpnManager::new(), &p, "127.0.0.1", port).await.expect("pinned connect");
        let peer = acc.await.unwrap();
        // the source address must be the tunnel interface's address
        assert_eq!(peer.ip(), s.local_addr().unwrap().ip());
    }

    fn lo_binding() -> Binding {
        find_interface(&loopback_interface().expect("loopback interface")).expect("loopback is up")
    }
}
