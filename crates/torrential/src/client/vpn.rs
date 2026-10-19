use std::io::{BufRead, IsTerminal, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

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
            Ok(report(mode, "checked", &vpn, None, None, &state, None))
        }
        VpnCommand::Locations { country } => {
            let servers = runtime.block_on(vpn::servers())?;
            let current = Config::load(&paths, env)?.vpn.map(|v| v.server);
            Ok(locations(mode, &servers, country.as_deref(), current.as_deref()))
        }
        VpnCommand::Surfshark { config: file, location, connect } => {
            let elevate = connect.then_some(Elevate::Terminal);
            let locked = lock(&paths, env, file.as_deref(), location.as_deref(), elevate, true)?;
            let vpn = &locked.vpn;
            let state = runtime.block_on(vpn::check(vpn));
            let moved = locked.previous.filter(|p| p.server != vpn.server && !connect && state != State::Down);
            let note = moved.map(|old| {
                format!(
                    "the tunnel still goes through {}; run torrential vpn surfshark --location {} --connect to switch",
                    old.server,
                    short(&vpn.server)
                )
            });
            Ok(report(mode, "locked", vpn, Some(locked.location), locked.written.as_deref(), &state, note))
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

pub struct Locked {
    pub vpn: Vpn,
    /// City and country.
    pub location: String,
    /// The config torrential wrote, when it was not given one.
    pub written: Option<PathBuf>,
    pub previous: Option<Vpn>,
}

/// How wg-quick gets root.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Elevate {
    /// sudo, asking for the password on this terminal.
    Terminal,
    /// The system's own password dialog, for the terminal UI, which owns the keyboard: macOS's
    /// administrator prompt, or pkexec on Linux.
    Dialog,
}

/// Locks torrential to `file`, or to a config it writes for `location` from the saved key. With
/// `connect`, brings that tunnel up first, taking the previous one down, so a failed connect
/// leaves the lock as it was. `ask` allows asking for a missing key on stdin.
pub fn lock(
    paths: &Paths,
    env: &Env,
    file: Option<&Path>,
    location: Option<&str>,
    connect: Option<Elevate>,
    ask: bool,
) -> Result<Locked, Error> {
    let runtime = crate::update::runtime()?;
    let previous = Config::load(paths, env)?.vpn;
    let servers = runtime.block_on(vpn::servers())?;
    let writes = Writes::new(env, "torrential vpn surfshark".to_string());
    let (wireguard, written) = match file {
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
            let server = vpn::choose(&servers, location, country.as_deref())?;
            let key = match vpn::saved_key() {
                Some(key) => key,
                None if ask => {
                    let key = ask_key()?;
                    vpn::save_key(&key)?;
                    key
                }
                None => {
                    return Err(Error::new(ErrorCode::Usage, "no Surfshark key is saved yet")
                        .with_hint("run torrential vpn surfshark in a terminal once to save it"));
                }
            };
            let (wireguard, text) = WireGuard::render(server, &key)?;
            let path = config_path(paths, &server.connection_name);
            write_private(&path, &text).map_err(|e| writes.error(&path, e))?;
            (wireguard, Some(path))
        }
    };
    let server = servers
        .iter()
        .find(|s| s.connection_name == wireguard.server || s.pub_key.as_deref() == Some(&wireguard.server_key));
    let Some(server) = server else {
        return Err(Error::new(ErrorCode::Usage, format!("{} is not one of Surfshark's servers", wireguard.server))
            .with_hint("run torrential vpn surfshark without a file to have torrential write a config"));
    };
    if !server.p2p() {
        let mut nearby: Vec<_> =
            servers.iter().filter(|s| s.p2p() && s.country == server.country).map(|s| s.location.as_str()).collect();
        if nearby.is_empty() {
            nearby = servers.iter().filter(|s| s.p2p()).take(5).map(|s| s.location.as_str()).collect();
        }
        return Err(Error::new(
            ErrorCode::Usage,
            format!("Surfshark does not allow torrents on {}, {}", server.location, server.country),
        )
        .with_hint(format!("run torrential vpn surfshark --location {}", nearby[0].to_lowercase())));
    }
    if let Some(elevate) = connect {
        let config = written.as_deref().or(file).expect("a file or a written config");
        let old = previous.as_ref().map(|p| config_path(paths, &p.server));
        bring_up(elevate, old.as_deref(), config)?;
    }
    let vpn = Vpn { address: wireguard.address, server: wireguard.server.clone() };
    config::save_vpn(paths, Some(&vpn), &writes)?;
    // Downloads keep going when only the server changes: the engine binds to the address.
    if previous.as_ref().map(|p| p.address) != Some(vpn.address) {
        restart_engine(paths, env)?;
    }
    let location = format!("{}, {}", server.location, server.country);
    Ok(Locked { vpn, location, written, previous })
}

/// Brings the locked tunnel up or takes it down. Down, the lock holds and nothing is sent.
pub fn set_tunnel(paths: &Paths, env: &Env, up: bool, elevate: Elevate) -> Result<(), Error> {
    let Some(vpn) = Config::load(paths, env)?.vpn else {
        return Err(Error::new(ErrorCode::Usage, "the VPN lock is off").with_hint("run torrential vpn surfshark"));
    };
    let path = config_path(paths, &vpn.server);
    if up {
        bring_up(elevate, None, &path)
    } else {
        as_root(elevate, &format!("wg-quick down {}", quote(&path)))
            .map_err(|e| Error::new(ErrorCode::VpnDown, format!("wg-quick could not take the tunnel down: {e}")))
    }
}

pub fn short(server: &str) -> &str {
    server.split('.').next().unwrap_or(server)
}

/// The lock is read when the engine starts, so a running engine restarts with the new setting.
fn restart_engine(paths: &Paths, env: &Env) -> Result<(), Error> {
    if let Some(conn) = super::connect::existing(paths, env)? {
        super::connect::stop(conn)?;
        super::connect::ensure(paths, env)?;
    }
    Ok(())
}

/// wg-quick names the tunnel after the file, in at most 15 characters, so the file is named for
/// the server's first label, such as `uk-gla.conf`.
fn config_path(paths: &Paths, server: &str) -> PathBuf {
    paths.config.join("surfshark").join(format!("{}.conf", short(server)))
}

/// Takes `old` down, if it is up, and brings `new` up, in one root shell so the password is asked
/// for once.
fn bring_up(elevate: Elevate, old: Option<&Path>, new: &Path) -> Result<(), Error> {
    if !on_path("wg-quick") {
        return Err(Error::new(ErrorCode::Usage, "switching the tunnel needs wg-quick, which is not installed")
            .with_hint("brew install wireguard-tools"));
    }
    // A tunnel that is not up fails to go down, harmlessly.
    let downs: Vec<String> = old
        .into_iter()
        .chain([new])
        .filter(|p| p.exists())
        .map(|p| format!("wg-quick down {} >/dev/null 2>&1; ", quote(p)))
        .collect();
    let script = format!("{}wg-quick up {}", downs.concat(), quote(new));
    as_root(elevate, &script).map_err(|e| {
        Error::new(ErrorCode::VpnDown, format!("wg-quick could not bring up {}: {e}", new.display()))
            .with_hint(format!("run sudo wg-quick up {} to see why", new.display()))
    })
}

/// Runs `script` as root. Homebrew's bin comes first on PATH: wg-quick needs its newer bash.
fn as_root(elevate: Elevate, script: &str) -> Result<(), String> {
    use std::process::{Command, Stdio};
    let script = format!("PATH=/opt/homebrew/bin:/usr/local/bin:$PATH; {script}");
    let mut command = match elevate {
        Elevate::Terminal => {
            let mut c = Command::new("sudo");
            c.args(["/bin/sh", "-c", &script]).stdout(std::io::stderr());
            c
        }
        Elevate::Dialog if cfg!(target_os = "macos") => {
            let escaped = script.replace('\\', "\\\\").replace('"', "\\\"");
            let apple = format!(
                "do shell script \"{escaped}\" with administrator privileges with prompt \"torrential is switching your \
                 VPN tunnel.\""
            );
            let mut c = Command::new("osascript");
            c.args(["-e", &apple]).stdout(Stdio::null()).stderr(Stdio::piped());
            c
        }
        Elevate::Dialog => {
            let mut c = Command::new("pkexec");
            c.args(["/bin/sh", "-c", &script]).stdout(Stdio::null()).stderr(Stdio::piped());
            c
        }
    };
    let output = command.output().map_err(|e| e.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if said.contains("-128") || said.contains("User canceled") {
        "the password prompt was cancelled".to_string()
    } else if said.is_empty() {
        format!("it exited with {}", output.status)
    } else {
        said.lines().last().unwrap_or(&said).to_string()
    })
}

fn quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn locations(mode: Mode, servers: &[vpn::Server], country: Option<&str>, current: Option<&str>) -> u8 {
    let wanted = |s: &vpn::Server| {
        country.is_none_or(|c| s.country.eq_ignore_ascii_case(c) || s.country_code.eq_ignore_ascii_case(c))
    };
    let mut rows: Vec<&vpn::Server> = servers.iter().filter(|s| s.p2p() && wanted(s)).collect();
    rows.sort_by(|a, b| (&a.country, &a.location).cmp(&(&b.country, &b.location)));
    let table = rows
        .iter()
        .map(|s| {
            let name = short(&s.connection_name);
            let token = if current == Some(s.connection_name.as_str()) { Token::Mint } else { Token::Text };
            vec![
                Cell::styled(name, token),
                Cell::new(&s.location),
                Cell::new(&s.country),
                Cell::new(format!("{}%", s.load)),
            ]
        })
        .collect();
    let doc = Doc {
        body: Body::Table { header: vec!["LOCATION", "CITY", "COUNTRY", "LOAD"], rows: table },
        summary: vec![format!("{} locations allow torrents", rows.len())],
        next: Some("torrential vpn surfshark --location <location> --connect".to_string()),
    };
    #[derive(Serialize)]
    struct Location<'a> {
        location: &'a str,
        server: &'a str,
        city: &'a str,
        country: &'a str,
        country_code: &'a str,
        load: u32,
    }
    let list: Vec<Location> = rows
        .iter()
        .map(|s| Location {
            location: short(&s.connection_name),
            server: &s.connection_name,
            city: &s.location,
            country: &s.country,
            country_code: &s.country_code,
            load: s.load,
        })
        .collect();
    super::emit(mode, &doc, &Typed { kind: "vpn_locations", body: list })
}

fn report(
    mode: Mode,
    result: &'static str,
    vpn: &Vpn,
    location: Option<String>,
    written: Option<&Path>,
    state: &State,
    note: Option<String>,
) -> u8 {
    let (tunnel, interface, exit_ip, country) = match state {
        State::Secured { interface, ip, country, .. } => ("secured", Some(interface), Some(ip), Some(country)),
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
    let next = note.or(next);
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
