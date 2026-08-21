fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "../../proto/avon/v2/common.proto",
        "../../proto/avon/v2/cert.proto",
        "../../proto/avon/v2/tunnel.proto",
        "../../proto/avon/v2/ca.proto",
        "../../proto/avon/v2/agent.proto",
        "../../proto/avon/v2/gateway.proto",
    ];
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&protos, &["../../proto"])?;
    for p in protos {
        println!("cargo:rerun-if-changed={p}");
    }
    Ok(())
}
