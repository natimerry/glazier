use glazier::pe::pe64_static::PE64Static;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::process;

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path_to_exe>", args[0]);
        process::exit(1);
    }

    let filename = &args[1];
    println!("Parsing file: {}", filename);

    match PE64Static::from_pe_file(filename) {
        Ok(pe) => {
            println!("\n[+] PE64 Header Parsed Successfully");
            println!("========================================");

            // Print Key Info
            println!("DOS Magic:       0x{:04X}", pe.image_dos_header.e_magic);
            println!("PE Signature:    0x{:08X}", pe.image_nt_headers64.signature);
            println!(
                "Machine:         0x{:04X} (AMD64)",
                pe.image_nt_headers64.file_header.machine
            );
            println!(
                "Entry Point:     0x{:08X}",
                pe.image_nt_headers64.optional_header.address_of_entry_point
            );
            println!(
                "Image Base:      0x{:016X}",
                pe.image_nt_headers64.optional_header.image_base
            );
            println!("Sections:        {}", pe.sections.len());

            println!("\n[+] Section Table");
            println!("---------------------------------------------------------------");
            println!(
                "{:<10} | {:<12} | {:<12} | {:<12}",
                "Name", "Virt Size", "Virt Addr", "Raw Offset"
            );
            println!("---------------------------------------------------------------");

            let file = File::open(filename).unwrap();
            let mut reader = BufReader::new(file);

            for section in &pe.sections {
                let name = section.resolve_section_name(&pe, &mut reader);

                println!(
                    "{:<10} | 0x{:<10X} | 0x{:<10X} | 0x{:<10X}",
                    name,
                    section.virtual_size,
                    section.virtual_address,
                    section.pointer_to_raw_data
                );
            }

            let file = File::open(filename).unwrap();
            let mut reader = BufReader::new(file);
            let imports = pe.get_parsed_imports(&mut reader).unwrap();

            for module in imports {
                println!("DLL (IMPORT): {}", module.name);

                for func in module.functions {
                    match &func.name {
                        Some(n) => println!("  - {} (Patch Address: 0x{:X})", n, func.iat_rva),
                        None => println!(
                            "  - Ordinal #{} (Patch Address: 0x{:X})",
                            func.ordinal,
                            pe.rva_to_offset(func.iat_rva).unwrap()
                        ),
                    }
                }
            }

            let exports = pe.get_parsed_exports(&mut reader).unwrap();
            if exports.is_empty() {
                println!("No exports found");
            }
            for export in exports {
                println!("DLL (EXPORT): {}", export.name);
                for func in export.functions {
                    match &func.name {
                        Some(n) => println!(
                            "  - {} (Dyn Patch Address: 0x{:X} | Byte Offset: 0x{:X})",
                            n,
                            func.func_rva,
                            pe.rva_to_offset(func.func_rva as u32).unwrap()
                        ),
                        None => println!(
                            "  - Ordinal #{} (Dyn Patch Address: 0x{:X} Local Patch Address: 0x{:X})",
                            func.ordinal,
                            func.func_rva,
                            pe.rva_to_offset(func.func_rva as u32).unwrap()
                        ),
                    }
                }
            }

            println!(
                "Total Imports: {}",
                pe.get_parsed_imports(&mut reader).unwrap().len()
            );
            println!(
                "Total Exports: {}",
                pe.get_parsed_exports(&mut reader).unwrap().len()
            );
        }
        Err(e) => {
            eprintln!("\n[!] Fatal Error: Failed to parse PE file.");
            eprintln!("    Reason: {:?}", e);
            process::exit(1);
        }
    }
}
