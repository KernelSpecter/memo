fn main() {
    // Export DetourFinishHelperProcess at ordinal 1, as Detours requires for
    // the helper-process handshake.
    let def = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("exports.def");
    println!("cargo:rerun-if-changed={}", def.display());
    println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def.display());
}
