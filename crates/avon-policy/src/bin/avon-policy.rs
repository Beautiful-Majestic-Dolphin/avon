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
    Check {
        file: std::path::PathBuf,
    },
    Explain {
        #[arg(long)]
        snapshot: std::path::PathBuf,
        #[arg(long)]
        device: String,
        #[arg(long, alias = "dst-ip")]
        dst_ip: String,
        #[arg(long, default_value = "tcp")]
        protocol: String,
        #[arg(long, default_value = "443")]
        port: u16,
    },
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
        Cmd::Explain {
            snapshot,
            device,
            dst_ip,
            protocol,
            port,
        } => {
            let bytes = std::fs::read(snapshot)?;
            let data = avon_policy::snapshot::decode(&bytes)?;
            let engine = avon_policy::engine::Engine::empty(data.tenant_id);
            engine.load(data, chrono::Utc::now().timestamp())?;
            let dev: uuid::Uuid = device.parse()?;
            let ip: std::net::IpAddr = dst_ip.parse()?;
            let proto = match protocol.to_lowercase().as_str() {
                "tcp" => avon_policy::spec::Protocol::Tcp,
                "udp" => avon_policy::spec::Protocol::Udp,
                "icmp" => avon_policy::spec::Protocol::Icmp,
                _ => avon_policy::spec::Protocol::Any,
            };
            let req = avon_policy::engine::DecisionRequest {
                device: dev,
                destination: avon_policy::engine::Destination::Ip(ip),
                dst_ip: ip,
                protocol: proto,
                dst_port: port,
                admission: false,
            };
            println!("{}", engine.explain(&req));
        }
    }
    Ok(())
}
