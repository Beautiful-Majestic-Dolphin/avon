use std::io::Result;

fn main() -> Result<()> {
    // Tell Cargo to rerun this build script if proto files change
    println!("cargo:rerun-if-changed=../../proto/avon/v1/common.proto");
    println!("cargo:rerun-if-changed=../../proto/avon/v1/control.proto");
    println!("cargo:rerun-if-changed=../../proto/avon/v1/tunnel.proto");
    println!("cargo:rerun-if-changed=../../proto/avon/v1/auth_service.proto");
    println!("cargo:rerun-if-changed=../../proto/avon/v1/ca_service.proto");

    // Use tonic_build to compile all proto files (it includes prost internally)
    // This generates both message types and gRPC service code
    tonic_build::configure()
        .out_dir("src/generated")
        .compile(
            &[
                "../../proto/avon/v1/common.proto",
                "../../proto/avon/v1/control.proto",
                "../../proto/avon/v1/tunnel.proto",
                "../../proto/avon/v1/auth_service.proto",
                "../../proto/avon/v1/ca_service.proto",
            ],
            &["../../proto"],
        )?;

    Ok(())
}
