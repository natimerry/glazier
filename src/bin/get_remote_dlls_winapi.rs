use libwinexploit::runtime::NativePeRuntime;
use libwinexploit::runtime::process::Process;

const PROCESS_ALL_ACCESS: u32 = 0x001f_ffff;

fn analyse_process(process: &Process) {
    let pe = NativePeRuntime::from_handle(process.handle).expect("Failed to inspect remote PE");

    println!("architecture:  {:?}", pe.architecture());
    println!("module_base:   {:#x}", pe.module_base());
    println!("image_size:    {:#x}", pe.image_size());
    println!("section_count: {}", pe.sections().len());
    println!("has_exports:   {}", pe.has_exports());

    for section in pe.sections() {
        let name = core::str::from_utf8(&section.name)
            .unwrap_or("?")
            .trim_end_matches('\0');
        println!(
            "  section: {:8}  VA: {:#010x}  size: {:#x}",
            name, section.virtual_address, section.virtual_size
        );
    }

    for symbol in ["MessageBoxW", "LoadLibraryW", "GetProcAddress"] {
        match pe.find_export(symbol) {
            Ok(export) => println!("  export {symbol} => {:#x}", export.func_addr),
            Err(_) => println!("  export {symbol} => NOT FOUND"),
        }
    }
}

fn main() {
    let target_process = std::env::args()
        .nth(1)
        .expect("Usage: get_remote_dlls_winapi <process-name>");

    let processes =
        Process::get_from_name(target_process, PROCESS_ALL_ACCESS).expect("Failed to find process");

    for process in &processes {
        analyse_process(process);
    }
}
