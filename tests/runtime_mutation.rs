#[cfg(all(test, windows, target_arch = "x86_64"))]
mod tests {
    use glazier::runtime::memory::LocalMemory;
    use glazier::runtime::pe64_runtime::PE64Runtime;
    use glazier::winapi::VirtualAlloc;
    use std::ptr::null_mut;

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_READWRITE: u32 = 0x04;

    struct SizeRestore {
        runtime: *mut PE64Runtime<LocalMemory>,
        original_size: u32,
    }

    impl Drop for SizeRestore {
        fn drop(&mut self) {
            unsafe {
                let _ = (*self.runtime).override_size_of_image(self.original_size);
            }
        }
    }

    #[test]
    fn override_size_of_image_updates_runtime_and_nt_header() {
        let mut runtime =
            PE64Runtime::from_current_module().expect("failed to parse current module");
        let original_size = runtime.image_size;
        let _restore = SizeRestore {
            runtime: &mut runtime,
            original_size,
        };

        let new_size = original_size.saturating_add(0x1000);

        runtime
            .override_size_of_image(new_size)
            .expect("failed to override image size");

        assert_eq!(runtime.image_size, new_size);
        unsafe {
            assert_eq!(
                (*runtime.nt_headers).optional_header.size_of_image,
                new_size
            );
        }
    }

    #[test]
    fn erase_header_zeroes_header_page_and_rejects_second_erase() {
        let module_base =
            unsafe { VirtualAlloc(null_mut(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) }
                as *mut u8;

        assert!(!module_base.is_null(), "VirtualAlloc failed");

        unsafe {
            for i in 0..4096 {
                *module_base.add(i) = 0xA5;
            }
        }

        let mut runtime = PE64Runtime {
            memory: LocalMemory,
            teb: null_mut(),
            module_base: module_base as u64,
            dos_header: module_base as *const _,
            nt_headers: null_mut(),
            section_headers: Vec::new(),
            section_count: 0,
            export_dir: null_mut(),
            image_size: 4096,
            header_erased: false,
        };

        runtime.erase_header().expect("failed to erase header");

        unsafe {
            let erased = std::slice::from_raw_parts(module_base, 4096);
            assert!(erased.iter().all(|byte| *byte == 0));
        }
        assert!(runtime.header_erased);
        assert!(runtime.erase_header().is_err());
    }
}
