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
/// Every Surfshark manual WireGuard config gives the client this address.
const ADDRESS: &str = "10.14.0.2";
const DNS: &str = "162.252.172.57, 149.154.159.92";
const PORT: u16 = 51820;
/// Where the private key is kept: the macOS Keychain, or the Secret Service on Linux.
const KEY_SERVICE: &str = "torrential-surfshark";
const KEY_ACCOUNT: &str = "wireguard";

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
    pub private_key: Option<String>,
}

impl WireGuard {
    pub fn parse(text: &str) -> Result<WireGuard, Error> {
        let mut section = "";
        let (mut address, mut endpoint, mut key, mut private_key) = (None, None, None, None);
        for line in text.lines().map(|l| l.split('#').next().unwrap_or("").trim()) {
            if line.starts_with('[') {
                section = line;
                continue;
            }
            let Some((name, value)) = line.split_once('=') else { continue };
            let (name, value) = (name.trim(), value.trim());
            match (section, name) {
                ("[Interface]", "PrivateKey") => private_key = Some(value.to_string()),
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
        Ok(WireGuard { address, server, server_key, private_key })
    }

    /// A config for `server`, the way Surfshark's manual setup page writes one.
    pub fn render(server: &Server, private_key: &str) -> Result<(WireGuard, String), Error> {
        let server_key = server.pub_key.clone().ok_or_else(|| {
            Error::new(
                ErrorCode::FetchFailed,
                format!("Surfshark lists no WireGuard key for {}", server.connection_name),
            )
        })?;
        let text = format!(
            "[Interface]\nPrivateKey = {private_key}\nAddress = {ADDRESS}/16\nDNS = {DNS}\n\n[Peer]\nPublicKey = \
             {server_key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {}:{PORT}\n",
            server.connection_name
        );
        let wireguard = WireGuard {
            address: ADDRESS.parse().expect("a valid address"),
            server: server.connection_name.clone(),
            server_key,
            private_key: Some(private_key.to_string()),
        };
        Ok((wireguard, text))
    }
}

/// A WireGuard key is 32 bytes in base64: 43 characters and a `=`.
pub fn valid_key(key: &str) -> bool {
    key.len() == 44
        && key.ends_with('=')
        && key[..43].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// The least loaded P2P server matching `wanted` (a location, country, country code, or server
/// name such as `uk-man`), or else in `country`, or else anywhere.
pub fn choose<'a>(servers: &'a [Server], wanted: Option<&str>, country: Option<&str>) -> Result<&'a Server, Error> {
    let matches = |s: &Server, w: &str| {
        let w = w.to_lowercase();
        [&s.location, &s.country, &s.country_code].iter().any(|f| f.to_lowercase() == w)
            || s.connection_name.to_lowercase().starts_with(&w)
    };
    let p2p = || servers.iter().filter(|s| s.p2p());
    let best = |found: Vec<&'a Server>| found.into_iter().min_by_key(|s| s.load);
    if let Some(wanted) = wanted {
        return best(p2p().filter(|s| matches(s, wanted)).collect()).ok_or_else(|| {
            let countries: Vec<&str> =
                servers.iter().filter(|s| matches(s, wanted)).map(|s| s.country_code.as_str()).collect();
            let mut some: Vec<&str> =
                p2p().filter(|s| countries.contains(&s.country_code.as_str())).map(|s| s.location.as_str()).collect();
            if some.is_empty() {
                some = p2p().take(8).map(|s| s.location.as_str()).collect();
            }
            Error::new(ErrorCode::Usage, format!("Surfshark has no P2P server for {wanted:?}"))
                .with_hint(format!("try a P2P location such as {}", some.join(", ")))
        });
    }
    let local = country.and_then(|c| best(p2p().filter(|s| s.country_code.eq_ignore_ascii_case(c)).collect()));
    local
        .or_else(|| best(p2p().collect()))
        .ok_or_else(|| Error::new(ErrorCode::FetchFailed, "Surfshark lists no P2P servers"))
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
    pub country_code: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub load: u32,
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

/// The country this machine's traffic appears to come from, to pick a nearby server.
pub async fn country() -> Option<String> {
    let response = client(None).ok()?.get(WHOAMI).send().await.ok()?;
    let whoami: Whoami = serde_json::from_slice(&response.bytes().await.ok()?).ok()?;
    Some(whoami.country_code).filter(|c| !c.is_empty())
}

/// The private key saved by an earlier setup.
pub fn saved_key() -> Option<String> {
    let output = if cfg!(target_os = "macos") {
        std::process::Command::new("security")
            .args(["find-generic-password", "-s", KEY_SERVICE, "-a", KEY_ACCOUNT, "-w"])
            .output()
    } else {
        std::process::Command::new("secret-tool")
            .args(["lookup", "service", KEY_SERVICE, "account", KEY_ACCOUNT])
            .output()
    };
    let output = output.ok().filter(|o| o.status.success())?;
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string()).filter(|k| valid_key(k))
}

/// Keeps the key out of the process list: both tools read it from stdin.
pub fn save_key(key: &str) -> Result<(), Error> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let (mut command, input) = if cfg!(target_os = "macos") {
        let mut c = Command::new("security");
        c.arg("-i");
        (
            c,
            format!(
                "add-generic-password -U -s {KEY_SERVICE} -a {KEY_ACCOUNT} -l \"torrential Surfshark WireGuard key\" -w {key}\n"
            ),
        )
    } else {
        let mut c = Command::new("secret-tool");
        c.args(["store", "--label=torrential Surfshark WireGuard key", "service", KEY_SERVICE, "account", KEY_ACCOUNT]);
        (c, key.to_string())
    };
    let failed = |e: String| {
        let store = if cfg!(target_os = "macos") { "the Keychain" } else { "the Secret Service (secret-tool)" };
        Error::new(ErrorCode::StorageError, format!("cannot save the key in {store}: {e}"))
    };
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| failed(e.to_string()))?;
    child.stdin.take().expect("piped").write_all(input.as_bytes()).map_err(|e| failed(e.to_string()))?;
    let output = child.wait_with_output().map_err(|e| failed(e.to_string()))?;
    if !output.status.success() {
        return Err(failed(String::from_utf8_lossy(&output.stderr).trim().to_string()));
    }
    Ok(())
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
#[serde(rename_all = "camelCase")]
struct Whoami {
    ip: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    country_code: String,
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
        Ok(Some(Whoami { ip, country, secured: true, .. })) => State::Secured { interface, ip, country },
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
                private_key: Some("aaaa".into()),
            }
        );
        assert_eq!(WireGuard::parse("[Peer]\nEndpoint = x:1\n").unwrap_err().code, ErrorCode::Usage);
    }

    fn server(name: &str, code: &str, p2p: bool, load: u32) -> Server {
        Server {
            connection_name: name.into(),
            country: String::new(),
            location: name.into(),
            pub_key: Some("l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw=".into()),
            country_code: code.into(),
            tags: if p2p { vec!["p2p".into()] } else { Vec::new() },
            load,
        }
    }

    #[test]
    fn picks_the_least_loaded_p2p_server_asked_for_or_nearby() {
        let servers = [
            server("uk-lon.prod.surfshark.com", "GB", false, 5),
            server("uk-man.prod.surfshark.com", "GB", true, 40),
            server("uk-gla.prod.surfshark.com", "GB", true, 30),
            server("de-fra.prod.surfshark.com", "DE", true, 10),
        ];
        let name = |s: Result<&Server, Error>| s.unwrap().connection_name.clone();
        assert_eq!(name(choose(&servers, None, Some("gb"))), "uk-gla.prod.surfshark.com");
        assert_eq!(name(choose(&servers, None, Some("JP"))), "de-fra.prod.surfshark.com");
        assert_eq!(name(choose(&servers, Some("uk-man"), Some("DE"))), "uk-man.prod.surfshark.com");
        let refused = choose(&servers, Some("uk-lon"), None).unwrap_err();
        assert_eq!(
            refused.hint.as_deref(),
            Some("try a P2P location such as uk-man.prod.surfshark.com, uk-gla.prod.surfshark.com")
        );
    }

    #[test]
    fn writes_a_config_that_reads_back() {
        let key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        assert!(valid_key(key) && !valid_key("aaaa"));
        let (wireguard, text) = WireGuard::render(&server("de-fra.prod.surfshark.com", "DE", true, 1), key).unwrap();
        assert_eq!(WireGuard::parse(&text).unwrap(), wireguard);
    }

    #[test]
    fn finds_loopback_and_not_a_missing_address() {
        assert!(tunnel("127.0.0.1".parse().unwrap()).is_some());
        assert_eq!(tunnel("10.255.255.254".parse().unwrap()), None);
    }
}
