use std::io::Result;
fn main() -> Result<()> {
    let src_files = &[
        "src/message.proto",
        "src/signature.proto",
        "src/ecdsa-keygen.proto",
        "src/ecdsa-resharing.proto",
        "src/ecdsa-signing.proto",
        "src/eddsa-keygen.proto",
        "src/eddsa-resharing.proto",
        "src/eddsa-signing.proto",
    ];
    prost_build::compile_protos(src_files, &["src/"])?;
    Ok(())
}
