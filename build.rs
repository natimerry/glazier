// build.rs
// Place this file in the root of your Rust project

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("teb_asm.rs");

    #[cfg(target_os = "windows")]
    let command = "py.exe";

    let output = Command::new(command)
        .arg("obfuscate_teb.py")
        .arg("--rust-function") // Generate complete Rust function
        .output()
        .expect("Failed to run obfuscator_teb.py");

    if !output.status.success() {
        panic!(
            "Python script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Get the generated Rust code (complete function)
    let rust_code = String::from_utf8(output.stdout).expect("Python output was not valid UTF-8");

    // Write the generated function directly to the output file
    let mut f = File::create(&dest_path).unwrap();
    write!(f, "{}", rust_code).unwrap();

    // Tell Cargo to rerun build.rs if the Python script changes
    println!("cargo:rerun-if-changed=obfuscator_fixed.py");

    // Also rerun if build.rs itself changes
    println!("cargo:rerun-if-changed=build.rs");
}
