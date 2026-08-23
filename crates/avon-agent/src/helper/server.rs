//! The privileged side. Runs as root (Linux/macOS) or LocalSystem (Windows),
//! owns the TUN, the routing table and the firewall, and does nothing else.
//!
//! Every request is validated against state the helper established itself
//! before it reaches the kernel, and only the uid the helper was started for
//! may connect at all.

use std::path::{Path, PathBuf};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tokio::net::{UnixListener, UnixStream};

use super::protocol::{validate, HelperError, HelperRequest, HelperResponse, HelperState};
use super::wire::Wire;

/// Everything one agent connection owns. Dropping it tears the TUN down, which
/// is what should happen when the unprivileged agent dies.
#[derive(Default)]
struct Session {
    tun: Option<avon_tun::Tun>,
    state: HelperState,
    installed_routes: Vec<IpNet>,
    firewall_applied: bool,
}

/// Serve until the task is cancelled. Only `uid` (or root) may connect; on a
/// multi-user machine another account must not be able to ask for a TUN.
pub async fn serve(socket: &Path, uid: u32) -> Result<(), HelperError> {
    if socket.exists() {
        std::fs::remove_file(socket)?;
    }
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let listener = UnixListener::bind(socket)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    }
    // The socket is created by root; the agent runs as `uid`, so ownership has
    // to move for the 0600 mode to still let exactly one account in.
    if nix::unistd::geteuid().is_root() && uid != 0 {
        let _ = nix::unistd::chown(socket, Some(nix::unistd::Uid::from_raw(uid)), None);
    }
    tracing::info!(socket = %socket.display(), uid, "helper listening");

    loop {
        let (stream, _) = listener.accept().await?;
        match peer_uid(&stream) {
            Ok(peer) if peer == uid || peer == 0 => {}
            Ok(peer) => {
                tracing::warn!(
                    peer,
                    expected = uid,
                    "rejecting helper connection from an unexpected uid"
                );
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not read peer credentials; rejecting");
                continue;
            }
        }
        if let Err(e) = handle(stream).await {
            tracing::warn!(error = %e, "helper session ended with an error");
        }
    }
}

fn peer_uid(stream: &UnixStream) -> Result<u32, HelperError> {
    Ok(stream.peer_cred()?.uid())
}

async fn handle(stream: UnixStream) -> Result<(), HelperError> {
    let mut wire = Wire::new(stream);
    let mut session = Session::default();

    while let Some((line, _fds)) = wire.read_line().await? {
        let request: HelperRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("malformed request: {e}");
                respond(&mut wire, HelperResponse::Error { message: msg }).await?;
                continue;
            }
        };
        let response = match validate(&request, &session.state) {
            Ok(()) => match apply(&mut session, request).await {
                Ok(r) => r,
                Err(e) => HelperResponse::Error {
                    message: e.to_string(),
                },
            },
            Err(e) => {
                tracing::warn!(error = %e, "rejecting helper request");
                HelperResponse::Error {
                    message: e.to_string(),
                }
            }
        };
        match (&response, session.tun.as_ref()) {
            // The TUN fd travels as ancillary data alongside its response.
            (HelperResponse::TunReady { .. }, Some(tun)) => {
                let line = serde_json::to_string(&response)
                    .map_err(|e| HelperError::Protocol(e.to_string()))?;
                wire.write_line_with_fd(&line, tun.raw_fd()).await?;
            }
            _ => respond(&mut wire, response).await?,
        }
    }

    // The agent went away: keep the firewall in place (fail closed) but drop the
    // TUN so the kernel tears the interface, and its routes, down.
    session.tun = None;
    Ok(())
}

async fn apply(
    session: &mut Session,
    request: HelperRequest,
) -> Result<HelperResponse, HelperError> {
    match request {
        HelperRequest::CreateTun { name, mtu } => {
            let tun = avon_tun::Tun::create(&name, mtu)
                .await
                .map_err(|e| HelperError::Tun(e.to_string()))?;
            session.tun = Some(tun);
            session.state.tun_name = Some(name.clone());
            Ok(HelperResponse::TunReady { name, mtu })
        }
        HelperRequest::Configure {
            v4,
            v6,
            mtu,
            allowed_routes,
        } => {
            let tun = session
                .tun
                .as_ref()
                .ok_or_else(|| HelperError::Protocol("configure before create_tun".into()))?;
            // `validate` already proved these parse.
            let v4: Ipv4Net = v4.parse().map_err(|_| HelperError::Protocol(v4.clone()))?;
            let v6 = match v6 {
                Some(s) => Some(
                    s.parse::<Ipv6Net>()
                        .map_err(|_| HelperError::Protocol(s.clone()))?,
                ),
                None => None,
            };
            session.state.allowed_routes = allowed_routes
                .iter()
                .filter_map(|r| r.parse::<IpNet>().ok())
                .collect();
            configure_tun(tun, v4, v6, mtu).await?;
            Ok(HelperResponse::Ok)
        }
        HelperRequest::SetRoutes { add, remove } => {
            let tun = session
                .tun
                .as_ref()
                .ok_or_else(|| HelperError::Protocol("set_routes before create_tun".into()))?;
            let add: Vec<IpNet> = add.iter().filter_map(|r| r.parse().ok()).collect();
            let remove: Vec<IpNet> = remove.iter().filter_map(|r| r.parse().ok()).collect();
            install_routes(tun, &add, &remove).await?;
            session.installed_routes.retain(|r| !remove.contains(r));
            for r in add {
                if !session.installed_routes.contains(&r) {
                    session.installed_routes.push(r);
                }
            }
            Ok(HelperResponse::Ok)
        }
        HelperRequest::ApplyFirewall { rules } => {
            crate::platform::firewall::apply(&rules)
                .await
                .map_err(|e| HelperError::Protocol(e.to_string()))?;
            session.firewall_applied = true;
            Ok(HelperResponse::Ok)
        }
        HelperRequest::ClearFirewall => {
            crate::platform::firewall::clear()
                .await
                .map_err(|e| HelperError::Protocol(e.to_string()))?;
            session.firewall_applied = false;
            Ok(HelperResponse::Ok)
        }
        HelperRequest::Shutdown => {
            if session.firewall_applied {
                let _ = crate::platform::firewall::clear().await;
                session.firewall_applied = false;
            }
            session.tun = None;
            Ok(HelperResponse::Ok)
        }
    }
}

async fn configure_tun(
    tun: &avon_tun::Tun,
    v4: Ipv4Net,
    v6: Option<Ipv6Net>,
    mtu: u16,
) -> Result<(), HelperError> {
    #[cfg(target_os = "linux")]
    let r = avon_tun::config::configure(tun, v4, v6, mtu).await;
    #[cfg(target_os = "macos")]
    let r = avon_tun::config::configure_macos(tun, v4, v6, mtu).await;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let r: Result<(), avon_tun::TunError> = {
        let _ = (tun, v4, v6, mtu);
        Err(avon_tun::TunError::Unsupported("configure"))
    };
    r.map_err(|e| HelperError::Tun(e.to_string()))
}

async fn install_routes(
    tun: &avon_tun::Tun,
    add: &[IpNet],
    remove: &[IpNet],
) -> Result<(), HelperError> {
    #[cfg(target_os = "linux")]
    let r = async {
        avon_tun::config::remove_routes(tun, remove).await?;
        avon_tun::config::set_routes(tun, add).await
    }
    .await;
    #[cfg(target_os = "macos")]
    let r = async {
        avon_tun::config::remove_routes_macos(tun, remove).await?;
        avon_tun::config::set_routes_macos(tun, add).await
    }
    .await;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let r: Result<(), avon_tun::TunError> = {
        let _ = (tun, add, remove);
        Err(avon_tun::TunError::Unsupported("set_routes"))
    };
    r.map_err(|e| HelperError::Tun(e.to_string()))
}

async fn respond(wire: &mut Wire, r: HelperResponse) -> Result<(), HelperError> {
    let line = serde_json::to_string(&r).map_err(|e| HelperError::Protocol(e.to_string()))?;
    wire.write_line(&line).await
}

/// Where the socket lives for a given data directory.
pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join("helper.sock")
}
