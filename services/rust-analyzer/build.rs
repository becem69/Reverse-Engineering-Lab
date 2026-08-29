fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_path = std::env::var("PROTO_PATH").unwrap_or_else(|_| "../../proto/analyzer.proto".to_string());
    tonic_build::compile_protos(&proto_path)?;
    Ok(())
}
