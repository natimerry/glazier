#[cfg(all(test, windows))]
mod syscall_tests {
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
    use libwinexploit::syscall;
    use libwinexploit::winapi::GetModuleHandleA;
    use libwinexploit::winapi::GetProcAddress;
    use libwinexploit::winapi::HANDLE;
    use libwinexploit::winapi::LARGE_INTEGER;
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

    #[test]
    fn verify_ntquerysystemtime_ssn() {
        // Call the regular NtQuerySystemTime and trace it
        let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8) };
        let func_ptr =
            unsafe { GetProcAddress(ntdll, b"NtQuerySystemTime\0".as_ptr() as *const i8) };

        println!(
            "NtQuerySystemTime function pointer: {:p}",
            func_ptr.unwrap()
        );

        // Try different SSN values around 0x5B
        for test_ssn in 0x50..=0x65 {
            let mut time = unsafe {
                let mut t = std::mem::MaybeUninit::<libwinexploit::winapi::LARGE_INTEGER>::zeroed();
                t.assume_init()
            };

            let status = syscall!(test_ssn, &mut time as *mut LARGE_INTEGER);

            if status == 0 {
                unsafe {
                    if time.QuadPart > 0 {
                        println!("SSN 0x{:X} works! Time: {}", test_ssn, time.QuadPart);
                    }
                }
            }
        }
    }
}

#[cfg(all(test, windows))]
mod hellsgate_arity_tests {
    use libwinexploit::winapi::*;
    use std::ptr;

    const STATUS_SUCCESS: i32 = 0;
    const STATUS_NO_YIELD_PERFORMED: i32 = 0x40000024_u32 as i32;

    #[test]
    fn hellsgate_0_args_ntyieldexecution() {
        let status = unsafe { NtYieldExecutionHellsGate() };
        // Accept either success or no-yield (both are valid)
        assert!(
            status == STATUS_SUCCESS || status == STATUS_NO_YIELD_PERFORMED,
            "Unexpected status: 0x{:X}",
            status as u32
        );
    }

    #[test]
    fn hellsgate_1_arg_ntclose() {
        let status = unsafe { NtCloseHellsGate(ptr::null_mut()) };
        assert_ne!(status, 0);
    }

    #[test]
    fn hellsgate_1_arg_ntquerydefaultuilanguage() {
        let mut lang_id: u16 = 0;

        let status = unsafe { NtQueryDefaultUILanguageHellsGate(&mut lang_id) };

        assert_eq!(status, STATUS_SUCCESS, "Status: 0x{:X}", status as u32);
        assert_ne!(lang_id, 0, "Language ID should be non-zero");
        println!("Default UI Language: 0x{:X}", lang_id);
    }

    #[test]
    fn hellsgate_1_arg_ntquerysystemtime() {
        let mut time = unsafe {
            let t = std::mem::MaybeUninit::<LARGE_INTEGER>::zeroed();
            t.assume_init()
        };

        let status = unsafe { NtQuerySystemTimeHellsGate(&mut time) };

        assert_eq!(status, STATUS_SUCCESS, "Status: 0x{:X}", status as u32);

        unsafe {
            assert!(time.QuadPart > 0, "Time value should be positive");
            println!("NtQuerySystemTime succeeded! Time: {}", time.QuadPart);
        }
    }

    #[test]
    fn hellsgate_3_args_ntdelayexecution() {
        let mut interval = LARGE_INTEGER { QuadPart: -10_000 };

        let status = unsafe { NtDelayExecutionHellsGate(0, &mut interval as *mut _) };

        assert_eq!(status, STATUS_SUCCESS, "Status: 0x{:X}", status as u32);
    }

    #[test]
    fn hellsgate_4_args_ntqueryperformancecounter() {
        let mut counter = LARGE_INTEGER { QuadPart: 0 };
        let mut freq = LARGE_INTEGER { QuadPart: 0 };

        let status = unsafe {
            NtQueryPerformanceCounterHellsGate(&mut counter as *mut _, &mut freq as *mut _)
        };

        assert_eq!(status, STATUS_SUCCESS, "Status: 0x{:X}", status as u32);
        unsafe {
            assert!(counter.QuadPart > 0);
            assert!(freq.QuadPart > 0);
        }
    }
}
