use std::path::PathBuf;

fn main() {
    let vendor: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vendor")
        .join("detours")
        .join("src");

    println!("cargo:rerun-if-changed={}", vendor.display());

    let mut b = cc::Build::new();
    b.cpp(true)
        .include(&vendor)
        // x64-only build: detours.cpp #includes the units it needs
        // (uimports.cpp), and only the x64 offline disassembler is required.
        .file(vendor.join("detours.cpp"))
        .file(vendor.join("modules.cpp"))
        .file(vendor.join("disasm.cpp"))
        .file(vendor.join("image.cpp"))
        .file(vendor.join("creatwth.cpp"))
        .file(vendor.join("disolx64.cpp"))
        .define("WIN32_LEAN_AND_MEAN", None)
        .define("_WIN32_WINNT", "0x0A00")
        .static_crt(true)
        .warnings(false);

    if b.get_compiler().is_like_msvc() {
        b.flag_if_supported("/EHsc");
    }

    b.compile("detours");

    // Detours calls into these system libraries.
    println!("cargo:rustc-link-lib=dylib=kernel32");
    println!("cargo:rustc-link-lib=dylib=user32");
}
