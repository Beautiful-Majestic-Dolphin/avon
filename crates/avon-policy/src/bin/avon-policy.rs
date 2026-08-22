use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "avon-policy", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Schema,
    Check { file: std::path::PathBuf },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Schema => {
            let v = avon_policy::schema::json_schema();
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Cmd::Check { file } => {
            let data = std::fs::read_to_string(&file)?;
            let spec: avon_policy::spec::PolicySpec = serde_json::from_str(&data)?;
            spec.validate()?;
            println!("ok: {}", file.display());
        }
    }
    Ok(())
}
