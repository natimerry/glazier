
use std::{
    fs::File,
    io::BufReader,
    path::PathBuf,
};

use libwinexploit::pe::PE64;

const SAMPLE_EXE: &str = "app_custom_section_with_imports.exe";
const SAMPLE_C: &str = "tests/samples/app_custom_section_with_imports.c";

fn get_c_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples")
        .join(SAMPLE_EXE)
}

fn load_pe() -> Result<(PE64, BufReader<File>), String> {
    let path = get_c_binary_path();

    if !path.exists() {
        return Err(format!(
            "missing test sample `{}`\n\
             build it with:\n\
             gcc {} -o tests/samples/{}",
            SAMPLE_EXE, SAMPLE_C, SAMPLE_EXE
        ));
    }

    let pe = PE64::from_pe_file(
        path.to_str().ok_or("invalid UTF-8 path")?
    )
        .map_err(|e| format!("failed to parse PE: {e:?}"))?;

    let file = File::open(&path)
        .map_err(|e| format!("failed to open sample binary: {e}"))?;

    Ok((pe, BufReader::new(file)))
}

#[test]
fn test_custom_section_parsing() -> Result<(), String> {
    let (pe, mut reader) = load_pe()?;

    let found = pe.sections.iter().any(|s| {
        s.resolve_section_name(&pe, &mut reader) == ".test_section"
    });

    if !found {
        return Err("custom section `.test_section` not found".into());
    }

    Ok(())
}

#[test]
fn test_imports_messagebox() -> Result<(), String> {
    let (pe, mut reader) = load_pe()?;

    let imports = pe
        .get_parsed_imports(&mut reader)
        .map_err(|e| format!("failed to parse imports: {e:?}"))?;

    let has_user32 = imports.iter().any(|m| {
        m.name.eq_ignore_ascii_case("user32.dll")
    });

    if !has_user32 {
        return Err("User32.dll import not found (MessageBoxA)".into());
    }

    Ok(())
}
