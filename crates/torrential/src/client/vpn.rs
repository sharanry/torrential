use std::io::{BufRead, IsTerminal, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

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
    /// The WireGuard config torrential wrote, to import into the WireGuard app.
    config: Option<String>,
    interface: Option<String>,
    exit_ip: Option<String>,
}

pub fn run(command: Option<VpnCommand>, mode: Mode, env: &Env) -> Result<u8, Error> {
    let paths = Paths::from_process(env)?;
    let runtime = crate::update::runtime()?;
    match command.unwrap_or(VpnCommand::Status) {
        VpnCommand::Status => {
            let Some(vpn) = Config::load(&paths, env)?.vpn else {
                return Err(
                    Error::new(ErrorCode::Usage, "the VPN lock is off").with_hint("run torrential vpn surfshark")
                );
            };
            let state = runtime.block_on(vpn::check(&vpn));
            if let Some(error) = state.error(&vpn) {
                return Err(error);
            }
            Ok(report(mode, "checked", &vpn, None, None, &state))
        }
        VpnCommand::Surfshark { config: file, location } => {
            let servers = runtime.block_on(vpn::servers())?;
            let writes = Writes::new(env, "torrential vpn surfshark".to_string());
            let (wireguard, written) = match &file {
                Some(file) => {
                    let text = std::fs::read_to_string(file)
                        .map_err(|e| Error::new(ErrorCode::Usage, format!("cannot read {}: {e}", file.display())))?;
                    let wireguard = WireGuard::parse(&text)?;
                    // Kept so later runs can write configs for other servers without a file.
                    if let Some(key) = wireguard.private_key.as_deref().filter(|k| vpn::valid_key(k)) {
                        vpn::save_key(key)?;
                    }
                    (wireguard, None)
                }
                None => {
                    let country = runtime.block_on(vpn::country());
                    let server = vpn::choose(&servers, location.as_deref(), country.as_deref())?;
                    let key = match vpn::saved_key() {
                        Some(key) => key,
                        None => {
                            let key = ask_key()?;
                            vpn::save_key(&key)?;
                            key
                        }
                    };
                    let (wireguard, text) = WireGuard::render(server, &key)?;
                    // wg-quick names the tunnel after the file, in at most 15 characters.
                    let short = server.connection_name.split('.').next().unwrap_or("surfshark");
                    let path = paths.config.join("surfshark").join(format!("{short}.conf"));
                    write_private(&path, &text).map_err(|e| writes.error(&path, e))?;
                    (wireguard, Some(path))
                }
            };
            let server = servers
                .iter()
                .find(|s| s.connection_name == wireguard.server || s.pub_key.as_deref() == Some(&wireguard.server_key));
            let Some(server) = server else {
                return Err(Error::new(
                    ErrorCode::Usage,
                    format!("{} is not one of Surfshark's servers", wireguard.server),
                )
                .with_hint("run torrential vpn surfshark without a file to have torrential write a config"));
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
                .with_hint(format!("run torrential vpn surfshark --location {}", nearby[0].to_lowercase())));
            }
            let vpn = Vpn { address: wireguard.address, server: wireguard.server.clone() };
            config::save_vpn(&paths, Some(&vpn), &writes)?;
            restart_engine(&paths, env)?;
            let state = runtime.block_on(vpn::check(&vpn));
            let location = format!("{}, {}", server.location, server.country);
            Ok(report(mode, "locked", &vpn, Some(location), written.as_deref(), &state))
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

fn report(
    mode: Mode,
    result: &'static str,
    vpn: &Vpn,
    location: Option<String>,
    written: Option<&Path>,
    state: &State,
) -> u8 {
    let (tunnel, interface, exit_ip, country) = match state {
        State::Secured { interface, ip, country } => ("secured", Some(interface), Some(ip), Some(country)),
        State::Down => ("down", None, None, None),
        State::Silent { interface } => ("silent", Some(interface), None, None),
        State::Unsecured { interface, ip } => ("unsecured", Some(interface), Some(ip), None),
    };
    let mut fields = vec![("server", Cell::new(location.clone().unwrap_or_else(|| vpn.server.clone())))];
    fields.push(("address", Cell::new(vpn.address.to_string())));
    if let Some(path) = written {
        fields.push(("config", Cell::new(path.display().to_string())));
    }
    let token = if tunnel == "secured" { Token::Mint } else { Token::Error };
    fields.push(("tunnel", Cell::styled(interface.map_or(tunnel.to_string(), |i| format!("{tunnel} on {i}")), token)));
    if let Some(ip) = exit_ip {
        let place = country.filter(|c| !c.is_empty()).map_or(String::new(), |c| format!(" ({c})"));
        fields.push(("exit", Cell::new(format!("{ip}{place}"))));
    }
    let mut summary = vec!["peers, DHT, trackers, and search leave only from the tunnel's address".to_string()];
    let next = match (state.error(vpn), written) {
        (Some(_), Some(path)) if *state == State::Down => {
            summary.push("the tunnel is not up yet, so nothing is sent".to_string());
            Some(if on_path("wg-quick") {
                format!("sudo wg-quick up {}, then run torrential vpn", path.display())
            } else {
                format!(
                    "in the WireGuard app, choose Import Tunnel(s) from File, pick {}, turn it on, then run torrential \
                     vpn",
                    path.display()
                )
            })
        }
        (Some(error), _) => {
            summary.push(error.message);
            error.hint
        }
        (None, _) => Some("torrential search <words>".to_string()),
    };
    let doc = Doc { body: Body::Fields { title: vec![Cell::styled(result, Token::Mint)], fields }, summary, next };
    let body = Report {
        result,
        provider: "surfshark",
        address: vpn.address.to_string(),
        server: vpn.server.clone(),
        location,
        tunnel,
        config: written.map(|p| p.display().to_string()),
        interface: interface.cloned(),
        exit_ip: exit_ip.cloned(),
    };
    super::emit(mode, &doc, &Typed { kind: "vpn", body })
}

/// Reads the private key without echoing it on a terminal, or as one line of piped input.
fn ask_key() -> Result<String, Error> {
    let stdin = std::io::stdin();
    let terminal = stdin.is_terminal();
    if terminal {
        eprintln!("torrential needs your Surfshark WireGuard private key, once. To get one:");
        eprintln!("  1. open {MANUAL_SETUP}");
        eprintln!("  2. choose WireGuard, then Generate a new key pair, and copy the private key");
        eprint!("Private key (hidden): ");
        let _ = std::io::stderr().flush();
    }
    let echo = terminal.then(Echo::off).flatten();
    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line);
    drop(echo);
    if terminal {
        eprintln!();
    }
    read.map_err(|e| Error::new(ErrorCode::Usage, format!("cannot read the key: {e}")))?;
    let key = line.trim().to_string();
    if !vpn::valid_key(&key) {
        return Err(Error::new(ErrorCode::Usage, "that is not a WireGuard private key")
            .with_hint(format!("copy the private key (44 characters ending in =) from {MANUAL_SETUP}")));
    }
    Ok(key)
}

/// Turns terminal echo off until dropped.
struct Echo(libc::termios);

impl Echo {
    fn off() -> Option<Echo> {
        // SAFETY: tcgetattr fills a plain struct for stdin, which is checked to be a terminal.
        unsafe {
            let mut saved = std::mem::zeroed::<libc::termios>();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut saved) != 0 {
                return None;
            }
            let mut quiet = saved;
            quiet.c_lflag &= !libc::ECHO;
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &quiet);
            Some(Echo(saved))
        }
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        // SAFETY: restores the settings read in `off`.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0) };
    }
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

/// The config holds the private key, so only this user can read it.
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    file.write_all(text.as_bytes())
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
