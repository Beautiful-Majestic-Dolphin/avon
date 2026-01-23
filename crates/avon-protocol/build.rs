use std::io::Result;

fn main() -> Result<()> {
    // Tell Cargo to rerun this build script if proto files change
    println!("cargo:rerun-if-changed=../../proto/avon/v1/common.proto");
    println!("cargo:rerun-if-changed=../../proto/avon/v1/control.proto");
    println!("cargo:rerun-if-changed=../../proto/avon/v1/tunnel.proto");

    // Compile the proto files
    prost_build::Config::new()
        .out_dir("src/generated")
        .compile_protos(
            &[
                "../../proto/avon/v1/common.proto",
                "../../proto/avon/v1/control.proto",
                "../../proto/avon/v1/tunnel.proto",
            ],
            &["../../proto"],
        )?;

    Ok(())
}
