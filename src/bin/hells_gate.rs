use glazier::runtime::pe64_runtime::PE64Runtime;
use glazier::syscall;

const MEM_COMMIT: usize = 0x1000;
const MEM_RESERVE: usize = 0x2000;
const PAGE_READWRITE: usize = 0x04;

pub fn main() {
    env_logger::builder().default_format().build();

    let ntdll = PE64Runtime::from_module("NTDLL.DLL").expect("Failed to find ntdll.dll");

    let target_func = ntdll
        .find_export("NtAllocateVirtualMemory")
        .expect("Failed to find NtAllocateVirtualMemory");

    let ssn = ntdll
        .get_syscall_num(target_func)
        .expect("Failed to get syscall number");

    println!("NtAllocateVirtualMemory SSN: 0x{:04X}", ssn);

    let process_handle: usize = 0xffffffffffffffff; // Current Process (-1)
    let mut base_address: usize = 0; // The PVOID (init to NULL)
    let mut region_size: usize = 0x1000; // The SIZE_T (4KB)

    let p_base_address = &mut base_address as *mut usize;
    let p_region_size = &mut region_size as *mut usize;

    println!("Debug: p_base_address = {:p}", p_base_address);
    println!("Debug: p_region_size = {:p}", p_region_size);

    let status = syscall!(
        ssn,
        process_handle,           // Arg1: Handle (Value)
        p_base_address as usize,  // Arg2: Ptr to Base Address (Address)
        0,                        // Arg3: ZeroBits (Value)
        p_region_size as usize,   // Arg4: Ptr to Region Size (Address)
        MEM_COMMIT | MEM_RESERVE, // Arg5: AllocationType (Value)
        PAGE_READWRITE            // Arg6: Protect (Value)
    );

    if status == 0 {
        println!("Success! Memory allocated at: 0x{:X}", base_address);

        // Verify we can write to it
        unsafe {
            let ptr = base_address as *mut u8;
            *ptr = 0xCC; // Write a breakpoint or byte
            println!("Wrote 0xCC to allocated memory.");
        }
    } else {
        println!("Failed with NTSTATUS: 0x{:X}", status);
    }
}
