//! The privileged helper process. It is deliberately tiny: everything it can be
//! asked to do is in `helper::protocol`, and it does nothing else.
//!
//! Unix only. It exists to hand a kernel TUN descriptor to an unprivileged
//! agent, and Windows has no equivalent — a WinTun session cannot be adopted by
//! another process — so there the agent service owns the adapter itself.

#[cfg(unix)]
mod helper_main {
    use std::path::PathBuf;

    use clap::Parser;

    #[derive(Parser)]
    #[command(name = "avon-agent-helper", version)]
    struct Cli {
        /// Unix socket to serve (0600, owned by the agent's uid).
        #[arg(
            long,
            env = "AVON_HELPER_SOCKET",
            default_value = "/run/avon/helper.sock"
        )]
        socket: PathBuf,
        /// uid permitted to connect (the unprivileged agent's account).
        #[arg(long, env = "AVON_HELPER_UID", conflicts_with = "user")]
        uid: Option<u32>,
        /// Account name permitted to connect, resolved to a uid at startup. The
        /// service units use this: the uid is allocated at install time and is
        /// not known when the unit file is written.
        #[arg(long, env = "AVON_HELPER_USER")]
        user: Option<String>,
        #[arg(long, env = "AVON_LOG_LEVEL", default_value = "info")]
        log_level: String,
    }

    #[tokio::main(flavor = "current_thread")]
    pub async fn main() -> anyhow::Result<()> {
        let cli = Cli::parse();
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(&cli.log_level))
            .init();
        let uid = match (cli.uid, cli.user.as_deref()) {
            (Some(uid), _) => uid,
            (None, Some(name)) => nix::unistd::User::from_name(name)?
                .ok_or_else(|| anyhow::anyhow!("no such user: {name}"))?
                .uid
                .as_raw(),
            (None, None) => anyhow::bail!("one of --uid or --user is required"),
        };
        if let Some(dir) = cli.socket.parent() {
            std::fs::create_dir_all(dir)?;
        }
        avon_agent::helper::serve(&cli.socket, uid).await?;
        Ok(())
    }
}

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    helper_main::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("avon-agent-helper is Unix only; on Windows the agent service owns the adapter");
    std::process::exit(1);
}
