use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use super::protocol::{HelperRequest, HelperResponse, MAX_LINE_BYTES, MAX_ROUTES};

pub struct HelperServer {
    listener: UnixListener,
    allowed_routes: Vec<String>,
}

impl HelperServer {
    pub async fn bind(path: &Path) -> Result<Self> {
        if path.exists() {
            std::fs::remove_file(path).ok();
        }
        let listener = UnixListener::bind(path).context("bind helper socket")?;
        // 0600, owned by root — in tests we just use temp dir.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        Ok(Self {
            listener,
            allowed_routes: Vec::new(),
        })
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            if let Err(e) = self.handle_client(stream).await {
                tracing::warn!(error=%e, "helper client error");
            }
        }
    }

    async fn handle_client(&mut self, stream: UnixStream) -> Result<()> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }
            if line.len() > MAX_LINE_BYTES {
                let resp = HelperResponse::Error {
                    message: "line too long".into(),
                };
                let out = serde_json::to_string(&resp)? + "\n";
                reader.get_mut().write_all(out.as_bytes()).await?;
                break;
            }
            let req: HelperRequest = match serde_json::from_str(line.trim()) {
                Ok(r) => r,
                Err(e) => {
                    let resp = HelperResponse::Error {
                        message: format!("invalid request: {e}"),
                    };
                    let out = serde_json::to_string(&resp)? + "\n";
                    reader.get_mut().write_all(out.as_bytes()).await?;
                    continue;
                }
            };
            let resp = match req {
                HelperRequest::CreateTun { name, mtu } => {
                    // In real helper, create TUN and send FD via SCM_RIGHTS.
                    // Here we just acknowledge.
                    HelperResponse::TunReady { name, mtu }
                }
                HelperRequest::Configure { allowed_routes, .. } => {
                    if allowed_routes.len() > MAX_ROUTES {
                        HelperResponse::Error {
                            message: "too many routes".into(),
                        }
                    } else {
                        self.allowed_routes = allowed_routes;
                        HelperResponse::Ok
                    }
                }
                HelperRequest::SetRoutes { add, remove } => {
                    if add.len() + remove.len() > MAX_ROUTES {
                        HelperResponse::Error {
                            message: "too many routes".into(),
                        }
                    } else {
                        // Validate against allowed_routes
                        HelperResponse::Ok
                    }
                }
                HelperRequest::ApplyFirewall { rules } => {
                    if rules.rules.len() > MAX_ROUTES {
                        HelperResponse::Error {
                            message: "too many firewall rules".into(),
                        }
                    } else {
                        HelperResponse::Ok
                    }
                }
                HelperRequest::ClearFirewall => HelperResponse::Ok,
                HelperRequest::Shutdown => {
                    let resp = HelperResponse::Ok;
                    let out = serde_json::to_string(&resp)? + "\n";
                    reader.get_mut().write_all(out.as_bytes()).await?;
                    std::process::exit(0);
                }
            };
            let out = serde_json::to_string(&resp)? + "\n";
            reader.get_mut().write_all(out.as_bytes()).await?;
        }
        Ok(())
    }

    pub fn socket_path(data_dir: &Path) -> PathBuf {
        data_dir.join("helper.sock")
    }
}
