use glazier::PE64Static;
use std::path::PathBuf;

fn get_sample_path(filename: &str) -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests/samples");
    d.push(filename);
    d
}

#[test]
fn test_dos_header() -> Result<(), String> {
    let sample = get_sample_path("app_custom_section_with_imports.exe");

    if !sample.exists() {
        return Err("Sample file does not exist, \
             gcc tests/samples/app_custom_section_with_imports.c \
                 -o tests/samples/app_custom_section_with_imports.exe"
            .parse()
            .unwrap());
    }

    let pe = PE64Static::from_pe_file(sample.to_str().unwrap())
        .map_err(|e| format!("failed to parse PE: {e:?}"))?;

    if pe.image_dos_header.e_magic != 0x5A4D {
        return Err("invalid DOS header magic".into());
    }

    if pe.sections.is_empty() {
        return Err("PE has zero sections".into());
    }

    Ok(())
}

#[test]
fn test_rva_resolution() -> Result<(), String> {
    let filename = "app_custom_section_with_imports.exe";
    let sample = get_sample_path(filename);

    if !sample.exists() {
        return Err(format!(
            "missing test sample `{}`\n\
             build it with:\n\
             gcc tests/samples/app_custom_section_with_imports.c \
                 -o tests/samples/{}",
            filename, filename
        ));
    }

    let pe = PE64Static::from_pe_file(
        sample
            .to_str()
            .ok_or("invalid UTF-8 path for test sample")?,
    )
    .map_err(|e| format!("failed to parse PE: {e:?}"))?;

    let entry_rva = pe.image_nt_headers64.optional_header.address_of_entry_point;
    let offset = pe.rva_to_offset(entry_rva);

    if offset.is_none() {
        return Err("entry point RVA did not resolve to a file offset".into());
    }

    Ok(())
}
