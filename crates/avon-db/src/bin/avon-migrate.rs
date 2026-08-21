//! `avon-migrate up` applies the embedded migrations; `avon-migrate status`
//! prints the applied versions. Used by the compose bootstrap service and the
//! Helm migration Job.

use avon_config::{DatabaseArgs, Validate};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "avon-migrate", version)]
struct Cli {
    #[command(flatten)]
    db: DatabaseArgs,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Apply all pending migrations.
    Up,
    /// Show applied migration versions.
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    cli.db.validate()?;
    let pool = avon_db::connect(&cli.db).await?;
    match cli.cmd {
        Cmd::Up => {
            avon_db::migrate(&pool).await?;
            println!("migrations applied");
        }
        Cmd::Status => {
            let rows: Vec<(i64, String)> = sqlx::query_as(
                "SELECT version, description FROM _sqlx_migrations ORDER BY version",
            )
            .fetch_all(&pool)
            .await?;
            for (version, description) in rows {
                println!("{version}\t{description}");
            }
        }
    }
    Ok(())
}
