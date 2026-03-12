use libwinexploit::pe::export_address_table::ImageExportDirectory;
use libwinexploit::runtime::memory::MemoryView;
use libwinexploit::runtime::memory::RemoteMemory;
use libwinexploit::runtime::pe64_runtime::PE64Runtime;
use libwinexploit::runtime::process::Process;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;

fn resolve_export(pe: &PE64Runtime<RemoteMemory>, name: &str) -> Option<u64> {
    if pe.export_dir.is_null() {
        return None;
    }

    let memory = &pe.memory;

    // Read export directory from remote
    let export_dir: ImageExportDirectory = memory.read(pe.export_dir as u64).ok()?;

    let base = pe.module_base;
    let count = export_dir.number_of_names as u64;
    let names_rva = export_dir.address_of_names as u64; // RVA to array of RVAs
    let ords_rva = export_dir.address_of_name_ordinals as u64;
    let fns_rva = export_dir.address_of_functions as u64;

    for i in 0..count {
        // Read the RVA of this name string
        let name_rva: u32 = memory.read(base + names_rva + i * 4).ok()?;
        let name_addr = base + name_rva as u64;

        // Read the name byte by byte until null terminator
        let mut export_name = String::new();
        let mut offset = 0u64;
        loop {
            let ch: u8 = memory.read(name_addr + offset).ok()?;
            if ch == 0 {
                break;
            }
            export_name.push(ch as char);
            offset += 1;
            if offset > 256 {
                break;
            } // safety
        }

        if export_name == name {
            // Read ordinal index
            let ordinal: u16 = memory.read(base + ords_rva + i * 2).ok()?;
            // Read function RVA
            let fn_rva: u32 = memory.read(base + fns_rva + ordinal as u64 * 4).ok()?;
            return Some(base + fn_rva as u64);
        }
    }

    None
}

fn analyse_process(proc: &Process) {
    let handle = proc.handle;
    let pe = PE64Runtime::<RemoteMemory>::from_handle(handle).expect("Failed to build PE64Runtime");

    println!("module_base:   {:#x}", pe.module_base);
    println!("image_size:    {:#x}", pe.image_size);
    println!("section_count: {}", pe.section_count);
    println!("has_exports:   {}", pe.has_exports());

    // Dump all sections
    let sections = pe.sections();
    for s in sections {
        let name = core::str::from_utf8(&s.name)
            .unwrap_or("?")
            .trim_end_matches('\0');
        println!(
            "  section: {:8}  VA: {:#010x}  size: {:#x}",
            name, s.virtual_address, s.virtual_size
        );
    }

    // Try resolving a known export
    for sym in &["MessageBoxW", "LoadLibraryW", "GetProcAddress"] {
        match resolve_export(&pe, sym) {
            Some(va) => println!("  export {sym} => {va:#x}"),
            None => println!("  export {sym} => NOT FOUND"),
        }
    }

    unsafe {
        CloseHandle(handle);
    }
}

fn main() {
    let target_proc: String = std::env::args()
        .nth(1)
        .expect("Usage: remote_test <procname>");

    let pids =
        Process::get_from_name(target_proc, PROCESS_ALL_ACCESS).expect("Unable to get process");

    for p in pids {
        analyse_process(&p);
    }
}
