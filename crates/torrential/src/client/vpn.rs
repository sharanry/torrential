use serde::Serialize;
use torrential_core::{Error, ErrorCode};

use crate::cli::VpnCommand;
use crate::config::{self, Config};
use crate::env::Env;
use crate::output::theme::Token;
use crate::output::{Body, Cell, Doc, Mode, Typed};
use crate::paths::Paths;
use crate::skill::Writes;
use crate::vpn::{self, MANUAL_SETUP, State, Vpn, WireGuard};

#[derive(Serialize)]
struct Report {
    result: &'static str,
    provider: &'static str,
    address: String,
    server: String,
    location: Option<String>,
    /// `secured`, `down`, `silent`, or `unsecured`.
    tunnel: &'static str,
    interface: Option<String>,
    exit_ip: Option<String>,
}

pub fn run(command: Option<VpnCommand>, mode: Mode, env: &Env) -> Result<u8, Error> {
    let paths = Paths::from_process(env)?;
    let runtime = crate::update::runtime()?;
    match command.unwrap_or(VpnCommand::Status) {
        VpnCommand::Status => {
            let Some(vpn) = Config::load(&paths, env)?.vpn else {
                return Err(Error::new(ErrorCode::Usage, "the VPN lock is off").with_hint(format!(
                    "download a WireGuard config from {MANUAL_SETUP}, then run torrential vpn surfshark <config>"
                )));
            };
            let state = runtime.block_on(vpn::check(&vpn));
            if let Some(error) = state.error(&vpn) {
                return Err(error);
            }
            Ok(report(mode, "checked", &vpn, None, &state))
        }
        VpnCommand::Surfshark { config: file } => {
            let text = std::fs::read_to_string(&file)
                .map_err(|e| Error::new(ErrorCode::Usage, format!("cannot read {}: {e}", file.display())))?;
            let wireguard = WireGuard::parse(&text)?;
            let servers = runtime.block_on(vpn::servers())?;
            let server = servers
                .iter()
                .find(|s| s.connection_name == wireguard.server || s.pub_key.as_deref() == Some(&wireguard.server_key));
            let Some(server) = server else {
                return Err(Error::new(
                    ErrorCode::Usage,
                    format!("{} is not one of Surfshark's servers", wireguard.server),
                )
                .with_hint(format!("download a WireGuard config from {MANUAL_SETUP}")));
            };
            if !server.p2p() {
                let mut nearby: Vec<_> = servers
                    .iter()
                    .filter(|s| s.p2p() && s.country == server.country)
                    .map(|s| s.location.as_str())
                    .collect();
                if nearby.is_empty() {
                    nearby = servers.iter().filter(|s| s.p2p()).take(5).map(|s| s.location.as_str()).collect();
                }
                return Err(Error::new(
                    ErrorCode::Usage,
                    format!("Surfshark does not allow torrents on {}, {}", server.location, server.country),
                )
                .with_hint(format!(
                    "download a config for a P2P location such as {} from {MANUAL_SETUP}",
                    nearby.join(", ")
                )));
            }
            let vpn = Vpn { address: wireguard.address, server: wireguard.server.clone() };
            let writes = Writes::new(env, format!("torrential vpn surfshark {}", file.display()));
            config::save_vpn(&paths, Some(&vpn), &writes)?;
            restart_engine(&paths, env)?;
            let state = runtime.block_on(vpn::check(&vpn));
            let location = format!("{}, {}", server.location, server.country);
            Ok(report(mode, "locked", &vpn, Some(location), &state))
        }
        VpnCommand::Off => {
            let writes = Writes::new(env, "torrential vpn off".to_string());
            let (_, changed) = config::save_vpn(&paths, None, &writes)?;
            if changed {
                restart_engine(&paths, env)?;
            }
            let doc = Doc {
                body: Body::Fields {
                    title: vec![Cell::styled(if changed { "unlocked" } else { "already off" }, Token::Mint)],
                    fields: Vec::new(),
                },
                summary: vec!["downloads and search use whatever network this machine is on".to_string()],
                next: None,
            };
            #[derive(Serialize)]
            struct Off {
                result: &'static str,
            }
            let result = if changed { "unlocked" } else { "unchanged" };
            Ok(super::emit(mode, &doc, &Typed { kind: "vpn", body: Off { result } }))
        }
    }
}

/// The lock is read when the engine starts, so a running engine stops and the next command starts
/// it again with the new setting.
fn restart_engine(paths: &Paths, env: &Env) -> Result<(), Error> {
    if let Some(conn) = super::connect::existing(paths, env)? {
        super::connect::stop(conn)?;
    }
    Ok(())
}

fn report(mode: Mode, result: &'static str, vpn: &Vpn, location: Option<String>, state: &State) -> u8 {
    let (tunnel, interface, exit_ip, country) = match state {
        State::Secured { interface, ip, country } => ("secured", Some(interface), Some(ip), Some(country)),
        State::Down => ("down", None, None, None),
        State::Silent { interface } => ("silent", Some(interface), None, None),
        State::Unsecured { interface, ip } => ("unsecured", Some(interface), Some(ip), None),
    };
    let mut fields = vec![("server", Cell::new(location.clone().unwrap_or_else(|| vpn.server.clone())))];
    fields.push(("address", Cell::new(vpn.address.to_string())));
    let token = if tunnel == "secured" { Token::Mint } else { Token::Error };
    fields.push(("tunnel", Cell::styled(interface.map_or(tunnel.to_string(), |i| format!("{tunnel} on {i}")), token)));
    if let Some(ip) = exit_ip {
        let place = country.filter(|c| !c.is_empty()).map_or(String::new(), |c| format!(" ({c})"));
        fields.push(("exit", Cell::new(format!("{ip}{place}"))));
    }
    let mut summary = vec!["peers, DHT, trackers, and search leave only from the tunnel's address".to_string()];
    let next = match state.error(vpn) {
        Some(error) => {
            summary.push(error.message);
            error.hint
        }
        None => Some("torrential search <words>".to_string()),
    };
    let doc = Doc { body: Body::Fields { title: vec![Cell::styled(result, Token::Mint)], fields }, summary, next };
    let body = Report {
        result,
        provider: "surfshark",
        address: vpn.address.to_string(),
        server: vpn.server.clone(),
        location,
        tunnel,
        interface: interface.cloned(),
        exit_ip: exit_ip.cloned(),
    };
    super::emit(mode, &doc, &Typed { kind: "vpn", body })
}

/// Refuses network work while the lock's tunnel is down. The engine could not send it anyway; this
/// says why at once instead of after a timeout.
pub fn gate(paths: &Paths, env: &Env) -> Result<(), Error> {
    match Config::load(paths, env)?.vpn {
        Some(vpn) if vpn::tunnel(vpn.address).is_none() => Err(State::Down.error(&vpn).expect("down is an error")),
        _ => Ok(()),
    }
}

/// For commands that only show downloads: the lock holding them back is worth a line, not a failure.
pub fn warn(paths: &Paths, env: &Env, mode: Mode) {
    if mode != Mode::Human {
        return;
    }
    if let Err(error) = gate(paths, env) {
        let hint = error.hint.map_or(String::new(), |h| format!("\n  {h}"));
        anstream::eprintln!("warning: {}{hint}", error.message);
    }
}
