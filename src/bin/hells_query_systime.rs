use libwinexploit::runtime::pe64_runtime::PE64Runtime;
use libwinexploit::syscall;
use libwinexploit::winapi::LARGE_INTEGER;

pub fn main() {
    let ntdll = PE64Runtime::from_module("NTDLL.DLL").expect("Failed to find ntdll.dll");

    let target_func = ntdll
        .find_export("NtQuerySystemTime")
        .expect("Failed to find NtQuerySystemTime");

    let ssn = ntdll
        .get_syscall_num(target_func)
        .expect("Failed to get syscall number");

    println!("NtQuerySystemTime SSN: 0x{:04X}", ssn);

    let mut time = unsafe {
        let t = std::mem::MaybeUninit::<LARGE_INTEGER>::zeroed();
        t.assume_init()
    };

    let p_time = &mut time as *mut LARGE_INTEGER;

    println!("Debug: p_time = {:p}", p_time);

    let status = syscall!(
        ssn,
        p_time as usize // Arg1: Ptr to LARGE_INTEGER (Address)
    );

    if status == 0 {
        unsafe {
            println!("Success! System time: {}", time.QuadPart);
            println!("Time represents 100-nanosecond intervals since Jan 1, 1601 UTC");
        }
    } else {
        println!("Failed with NTSTATUS: 0x{:X}", status);
    }
}
