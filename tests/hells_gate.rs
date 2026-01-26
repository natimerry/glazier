#[cfg(all(test, windows))]
mod syscall_tests {
    use super::*;
    use libwinexploit::runtime::pe64_runtime::PE64Runtime;
    use libwinexploit::syscall;

    const MEM_COMMIT: usize = 0x1000;
    const MEM_RESERVE: usize = 0x2000;
    const PAGE_READWRITE: usize = 0x04;

    #[test]
    fn ntallocatevirtualmemory_syscall_resolves() {
        let ntdll = PE64Runtime::from_module("NTDLL.DLL").expect("ntdll.dll not found");

        let export = ntdll
            .find_export("NtAllocateVirtualMemory")
            .expect("NtAllocateVirtualMemory export missing");

        let ssn = ntdll
            .get_syscall_num(export)
            .expect("Failed to extract syscall number");

        assert!(ssn > 0);
    }

    #[test]
    fn ntallocatevirtualmemory_syscall_executes() {
        let ntdll = PE64Runtime::from_module("NTDLL.DLL").expect("ntdll.dll not found");

        let export = ntdll
            .find_export("NtAllocateVirtualMemory")
            .expect("NtAllocateVirtualMemory export missing");

        let ssn = ntdll
            .get_syscall_num(export)
            .expect("Failed to extract syscall number");

        let process_handle: usize = usize::MAX; // (current process)
        let mut base_address: usize = 0;
        let mut region_size: usize = 0x1000;

        let status = syscall!(
            ssn,
            process_handle,
            &mut base_address as *mut _ as usize,
            0usize,
            &mut region_size as *mut _ as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        assert_eq!(status, 0);
        assert_ne!(base_address, 0);

        unsafe {
            let ptr = base_address as *mut u8;
            *ptr = 0x41;
            assert_eq!(*ptr, 0x41);
        }
    }
}

#[cfg(all(test, windows))]
mod hellsgate_tests {
    use libwinexploit::winapi::HANDLE;
    use libwinexploit::winapi::NTSTATUS;
    use libwinexploit::winapi::NtAllocateVirtualMemoryHellsGate;
    use libwinexploit::winapi::PVOID;
    use std::ptr;

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_READWRITE: u32 = 0x04;

    #[test]
    fn hellsgate_ntallocatevirtualmemory_executes() {
        let process_handle: HANDLE = (-1isize) as HANDLE;

        let mut base_address: PVOID = ptr::null_mut();
        let zero_bits: u64 = 0;
        let mut region_size: u64 = 0x1000;

        let status: NTSTATUS = unsafe {
            NtAllocateVirtualMemoryHellsGate(
                process_handle,
                &mut base_address as *mut _,
                zero_bits,
                &mut region_size as *mut _,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        assert_eq!(status, 0);
        assert!(!base_address.is_null());
        assert!(region_size >= 0x1000);

        unsafe {
            let ptr = base_address as *mut u8;
            for i in 0..16 {
                *ptr.add(i) = i as u8;
            }

            for i in 0..16 {
                assert_eq!(*ptr.add(i), i as u8);
            }
        }
    }
}
