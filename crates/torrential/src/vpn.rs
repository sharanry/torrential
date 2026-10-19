use std::ffi::CStr;
use std::net::IpAddr;
use std::time::Duration;

use serde::Deserialize;
use torrential_core::{Error, ErrorCode};

/// Where a Surfshark user makes a new WireGuard key and downloads a config for a location.
pub const MANUAL_SETUP: &str = "https://my.surfshark.com/vpn/manual-setup/main";
const SERVERS: &str = "https://api.surfshark.com/v4/server/clusters/generic";
/// Answers with the address a request arrived from, and whether that address is Surfshark's.
const WHOAMI: &str = "https://api.surfshark.com/v1/server/user";
const PROBE_WITHIN: Duration = Duration::from_secs(8);

/// The `vpn` block of config.yaml. torrential keeps no keys: the WireGuard app holds them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Vpn {
    /// The tunnel's own address, from the config's `[Interface] Address`. Every connection binds
    /// to it, so nothing leaves while it is down.
    pub address: IpAddr,
    /// The server's host, from `[Peer] Endpoint`.
    pub server: String,
}

/// What a Surfshark WireGuard config file says.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WireGuard {
    pub address: IpAddr,
    pub server: String,
    pub server_key: String,
}

impl WireGuard {
    pub fn parse(text: &str) -> Result<WireGuard, Error> {
        let mut section = "";
        let (mut address, mut endpoint, mut key) = (None, None, None);
        for line in text.lines().map(|l| l.split('#').next().unwrap_or("").trim()) {
            if line.starts_with('[') {
                section = line;
                continue;
            }
            let Some((name, value)) = line.split_once('=') else { continue };
            let (name, value) = (name.trim(), value.trim());
            match (section, name) {
                ("[Interface]", "Address") => address = value.split(',').next().map(|a| a.trim().to_string()),
                ("[Peer]", "Endpoint") => endpoint = Some(value.to_string()),
                ("[Peer]", "PublicKey") => key = Some(value.to_string()),
                _ => {}
            }
        }
        let invalid = |what: &str| {
            Error::new(ErrorCode::Usage, format!("this is not a WireGuard config: it has no {what}"))
                .with_hint(format!("download a WireGuard config from {MANUAL_SETUP}"))
        };
        let address = address.ok_or_else(|| invalid("[Interface] Address"))?;
        let address = address.split('/').next().unwrap_or("").parse().map_err(|_| invalid("valid Address"))?;
        let endpoint = endpoint.ok_or_else(|| invalid("[Peer] Endpoint"))?;
        let server = endpoint.rsplit_once(':').map_or(endpoint.as_str(), |(host, _)| host).to_string();
        let server_key = key.ok_or_else(|| invalid("[Peer] PublicKey"))?;
        Ok(WireGuard { address, server, server_key })
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    pub connection_name: String,
    pub country: String,
    pub location: String,
    #[serde(default)]
    pub pub_key: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Server {
    pub fn p2p(&self) -> bool {
        self.tags.iter().any(|t| t == "p2p")
    }
}

/// Surfshark's public server list. It needs no login.
pub async fn servers() -> Result<Vec<Server>, Error> {
    let client = client(None)?;
    let response = client.get(SERVERS).send().await.and_then(|r| r.error_for_status()).map_err(unreachable)?;
    let body = response.bytes().await.map_err(unreachable)?;
    serde_json::from_slice(&body)
        .map_err(|e| Error::new(ErrorCode::FetchFailed, format!("Surfshark's server list did not parse: {e}")))
}

/// The tunnel interface holding `address`, if it is up.
pub fn tunnel(address: IpAddr) -> Option<String> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, which is freed below and not used after.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: `entry` is a node of the list getifaddrs returned.
        let ifa = unsafe { &*entry };
        let up = ifa.ifa_flags & (libc::IFF_UP as u32) != 0;
        if up && !ifa.ifa_addr.is_null() && sockaddr_ip(ifa.ifa_addr) == Some(address) {
            // SAFETY: ifa_name is a NUL-terminated string owned by the list.
            found = Some(unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned());
            break;
        }
        entry = ifa.ifa_next;
    }
    // SAFETY: `list` came from getifaddrs.
    unsafe { libc::freeifaddrs(list) };
    found
}

fn sockaddr_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    // SAFETY: the family says which sockaddr type `addr` points to.
    unsafe {
        match i32::from((*addr).sa_family) {
            libc::AF_INET => {
                let v4 = &*(addr as *const libc::sockaddr_in);
                Some(IpAddr::from(u32::from_be(v4.sin_addr.s_addr).to_be_bytes()))
            }
            libc::AF_INET6 => Some(IpAddr::from((*(addr as *const libc::sockaddr_in6)).sin6_addr.s6_addr)),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum State {
    /// Traffic from the tunnel's address reaches Surfshark, and leaves from `ip`.
    Secured { interface: String, ip: String, country: String },
    /// No interface holds the tunnel's address, so nothing can leave.
    Down,
    /// The tunnel is up but Surfshark does not answer through it. A revoked or expired key looks
    /// like this, because WireGuard drops a rejected handshake without saying why.
    Silent { interface: String },
    /// Surfshark answered, but not from one of its own addresses.
    Unsecured { interface: String, ip: String },
}

#[derive(Deserialize)]
struct Whoami {
    ip: String,
    #[serde(default)]
    country: String,
    secured: bool,
}

/// Asks Surfshark, from the tunnel's address, where the request came from.
pub async fn check(vpn: &Vpn) -> State {
    let Some(interface) = tunnel(vpn.address) else { return State::Down };
    let answer = async {
        let response = client(Some(vpn.address)).ok()?.get(WHOAMI).send().await.ok()?.error_for_status().ok()?;
        serde_json::from_slice::<Whoami>(&response.bytes().await.ok()?).ok()
    };
    match tokio::time::timeout(PROBE_WITHIN, answer).await {
        Ok(Some(Whoami { ip, country, secured: true })) => State::Secured { interface, ip, country },
        Ok(Some(Whoami { ip, .. })) => State::Unsecured { interface, ip },
        _ => State::Silent { interface },
    }
}

impl State {
    pub fn error(&self, vpn: &Vpn) -> Option<Error> {
        match self {
            State::Secured { .. } => None,
            State::Down => Some(
                Error::new(
                    ErrorCode::VpnDown,
                    format!("the Surfshark tunnel ({}) is down, so torrential is not sending anything", vpn.address),
                )
                .with_hint(format!("turn on the {} tunnel in the WireGuard app", vpn.server)),
            ),
            State::Silent { interface } => Some(
                Error::new(
                    ErrorCode::VpnRejected,
                    format!("the tunnel is up on {interface}, but Surfshark does not answer through it"),
                )
                .with_hint(format!(
                    "your key may have been revoked: make a new one at {MANUAL_SETUP}, then run torrential vpn surfshark \
                     <config>"
                )),
            ),
            State::Unsecured { interface, ip } => Some(
                Error::new(
                    ErrorCode::VpnDown,
                    format!("traffic from {interface} leaves from {ip}, which is not a Surfshark address"),
                )
                .with_hint("set the WireGuard tunnel's AllowedIPs to 0.0.0.0/0"),
            ),
        }
    }
}

fn client(bind: Option<IpAddr>) -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .user_agent(concat!("torrential/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(5))
        .local_address(bind)
        .build()
        .map_err(|e| Error::internal(format!("cannot build the HTTP client: {e}")))
}

fn unreachable(e: reqwest::Error) -> Error {
    Error::new(ErrorCode::NetworkUnavailable, format!("cannot reach Surfshark: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_surfshark_config() {
        let text = "[Interface]\nPrivateKey = aaaa\nAddress = 10.14.0.2/16\nDNS = 162.252.172.57, 149.154.159.92\n\n\
                    [Peer]\nPublicKey = l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw=\nAllowedIPs = 0.0.0.0/0\n\
                    Endpoint = al-tia.prod.surfshark.com:51820\n";
        assert_eq!(
            WireGuard::parse(text).unwrap(),
            WireGuard {
                address: "10.14.0.2".parse().unwrap(),
                server: "al-tia.prod.surfshark.com".into(),
                server_key: "l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw=".into(),
            }
        );
        assert_eq!(WireGuard::parse("[Peer]\nEndpoint = x:1\n").unwrap_err().code, ErrorCode::Usage);
    }

    #[test]
    fn finds_loopback_and_not_a_missing_address() {
        assert!(tunnel("127.0.0.1".parse().unwrap()).is_some());
        assert_eq!(tunnel("10.255.255.254".parse().unwrap()), None);
    }
}
