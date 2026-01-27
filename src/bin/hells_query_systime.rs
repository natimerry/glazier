use env_logger::Env;
use env_logger::Target;
use libwinexploit::runtime::pe64_runtime::PE64Runtime;
use libwinexploit::syscall;
use libwinexploit::winapi::LARGE_INTEGER;
use log::error;
use log::info;
use std::io::Write;
pub fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug"))
        // .target(Target::Stdout) // Log to stdout instead of stderr
        // .format(|buf, record| writeln!(buf, "[{}] {}", record.level(), record.args()))
        .init();

    let ntdll = PE64Runtime::from_module("NTDLL.DLL").expect("Failed to find ntdll.dll");

    let target_func = ntdll
        .find_export("NtQuerySystemTime")
        .expect("Failed to find NtQuerySystemTime");

    let ssn = ntdll
        .get_syscall_num(target_func)
        .expect("Failed to get syscall number");

    info!("NtQuerySystemTime SSN: 0x{:04X}", ssn);

    let mut time = unsafe {
        let t = std::mem::MaybeUninit::<LARGE_INTEGER>::zeroed();
        t.assume_init()
    };

    let p_time = &mut time as *mut LARGE_INTEGER;

    info!("Debug: p_time = {:p}", p_time);

    let status = syscall!(
        ssn,
        p_time as usize // Arg1: Ptr to LARGE_INTEGER (Address)
    );

    if status == 0 {
        unsafe {
            info!("Success! System time: {}", time.QuadPart);
            info!("Time represents 100-nanosecond intervals since Jan 1, 1601 UTC");
        }
    } else {
        error!("Failed with NTSTATUS: 0x{:X}", status);
    }
}
