use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is missing");
    let raw = env::var("DEP_GLAZIER_BINDINGS_RAW_BINDINGS")
        .expect("bindings crate did not publish its raw declarations");

    glazier_codegen::generate_winapi_hook_bindings(Path::new(&raw), &out_dir);
    println!("cargo:rerun-if-changed={raw}");
}
