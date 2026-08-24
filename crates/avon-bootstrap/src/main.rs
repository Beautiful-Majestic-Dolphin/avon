//! One-shot initialisation for an AVON deployment.
//!
//! Runs with database access and the CA master key, so it loads `CaKeys`
//! directly rather than calling the CA over the network — the CA is not up yet
//! when its own TLS certificate has to be issued.
//!
//! The actual issuance/owner-creation logic lives in `lib.rs`; this file is
//! just CLI parsing and command dispatch.

use std::path::PathBuf;

use avon_bootstrap::{create_owner, issue_service_certs, resolve_tenant};
use avon_ca::keys::{load_or_init, SealedFileProvider};
use avon_config::{DatabaseArgs, Validate};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "avon-bootstrap", version)]
struct Cli {
    #[command(flatten)]
    db: DatabaseArgs,
    #[arg(long, env = "AVON_CA_MASTER_KEY_FILE")]
    master_key_file: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Everything a fresh deployment needs, in order and idempotently:
    /// migrations, master key, CA chain, service credentials, first owner.
    /// One command because the runtime image ships no shell.
    Init {
        #[arg(long, default_value = "/certs")]
        out: PathBuf,
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "ca,control,gateway,admin"
        )]
        services: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        dns: Vec<String>,
        #[arg(long, env = "ADMIN_EMAIL", default_value = "owner@example.com")]
        email: String,
        #[arg(long, env = "AVON_BOOTSTRAP_ADMIN_PASSWORD", hide_env_values = true)]
        password: String,
        #[arg(long, default_value = "default")]
        tenant: String,
    },
    /// Apply the embedded schema migrations.
    MigrateUp,
    /// Write a new 0600 sealed-file master key (fails if one already exists).
    GenerateMasterKey,
    /// Issue TLS credentials for infrastructure services into --out.
    ///
    /// This is a credential-rotation path: re-running it against a
    /// deployment already initialised with `init --tenant X` must land any
    /// tenant-scoped rows (currently: the gateway's `devices` row) in that
    /// same tenant `X`, not the seed default — so `--tenant` exists here for
    /// exactly the reason it exists on `init`, not as an incidental extra.
    Certs {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_delimiter = ',')]
        services: Vec<String>,
        /// DNS names per service, e.g. control=control+control.avon.svc
        #[arg(long, value_delimiter = ',')]
        dns: Vec<String>,
        #[arg(long, default_value = "default")]
        tenant: String,
    },
    /// Create the first owner user and print a one-time enrollment token.
    Admin {
        #[arg(long)]
        email: String,
        #[arg(long, env = "AVON_BOOTSTRAP_ADMIN_PASSWORD", hide_env_values = true)]
        password: String,
        #[arg(long, default_value = "default")]
        tenant: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    avon_tls::install_default_provider();
    let cli = Cli::parse();
    cli.db.validate()?;

    match cli.cmd {
        Cmd::MigrateUp => {
            let pool = avon_db::connect(&cli.db).await?;
            avon_db::migrate(&pool).await?;
            println!("migrations applied");
        }
        Cmd::GenerateMasterKey => {
            SealedFileProvider::generate_master_key(&cli.master_key_file)?;
            println!("master key written to {}", cli.master_key_file.display());
        }
        Cmd::Init {
            out,
            services,
            dns,
            email,
            password,
            tenant,
        } => {
            let pool = avon_db::connect(&cli.db).await?;
            avon_db::migrate(&pool).await?;
            println!("migrations applied");
            if !cli.master_key_file.exists() {
                SealedFileProvider::generate_master_key(&cli.master_key_file)?;
                println!("master key written to {}", cli.master_key_file.display());
            }
            let provider = SealedFileProvider::from_file(&cli.master_key_file)?;
            let keys = load_or_init(&pool, &provider, true).await?;
            // Resolved once and shared: the gateway's device row and the
            // owner's user row must land in the same tenant, not just
            // "whichever id each function happened to look up".
            let tenant_id = resolve_tenant(&pool, &tenant).await?;
            issue_service_certs(&pool, &keys, &out, &services, &dns, tenant_id).await?;
            let token = create_owner(&pool, &email, &password, tenant_id).await?;
            // Write enroll token for compose e2e agents.
            let token_path = out.join("enroll.token");
            let _ = std::fs::write(&token_path, &token);
            // Also ensure /certs/enroll.token if out is different but /certs exists (e2e volume).
            if token_path != std::path::Path::new("/certs/enroll.token")
                && std::path::Path::new("/certs").exists()
            {
                let _ = std::fs::write("/certs/enroll.token", &token);
            }
        }
        Cmd::Certs {
            out,
            services,
            dns,
            tenant,
        } => {
            let pool = avon_db::connect(&cli.db).await?;
            let provider = SealedFileProvider::from_file(&cli.master_key_file)?;
            let keys = load_or_init(&pool, &provider, true).await?;
            // Resolved the same way `init` resolves it, so a `certs`
            // rotation lands the gateway's device row in the same tenant
            // `init --tenant X` originally used, not the seed default.
            let tenant_id = resolve_tenant(&pool, &tenant).await?;
            issue_service_certs(&pool, &keys, &out, &services, &dns, tenant_id).await?;
        }
        Cmd::Admin {
            email,
            password,
            tenant,
        } => {
            let pool = avon_db::connect(&cli.db).await?;
            let tenant_id = resolve_tenant(&pool, &tenant).await?;
            create_owner(&pool, &email, &password, tenant_id).await?;
        }
    }
    Ok(())
}
