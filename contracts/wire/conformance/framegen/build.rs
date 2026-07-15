//! Generate the wire payload types from the vendored contracts protos (the same frozen
//! `.proto` both consumer repos generate from, so the prost encoding is byte-identical).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // gen/ -> conformance/ -> wire/ -> contracts/ ; the protos live under contracts/proto.
    let proto_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .map(|p| p.join("proto"))
        .expect("contracts/proto is four levels up from gen/");

    let common = proto_root.join("sessionlayer/controlplane/v1/common.proto");
    let wire = proto_root.join("sessionlayer/agent/v1/wire.proto");
    let coord = proto_root.join("sessionlayer/gateway/v1/coordination.proto");
    for p in [&common, &wire, &coord] {
        println!("cargo:rerun-if-changed={}", p.display());
    }

    prost_build::compile_protos(&[common, wire, coord], &[proto_root])?;
    Ok(())
}
