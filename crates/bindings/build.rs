use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is missing");
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let raw = glazier_codegen::generate_winapi_bindings(&out_dir, &workspace.join("phnt"));

    println!("cargo:raw_bindings={}", raw.display());
    println!(
        "cargo:rerun-if-changed={}",
        workspace.join("phnt").display()
    );
}
