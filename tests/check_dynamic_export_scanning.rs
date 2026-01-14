use libwinexploit::runtime::exports::{find_dll_base, find_dll_export};
use windows_sys::w;

type LoadLibraryWFn = unsafe extern "system" fn(*const u16) -> *mut core::ffi::c_void;
type MessageBoxWFn =
    unsafe extern "system" fn(*mut core::ffi::c_void, *const u16, *const u16, u32) -> i32;

fn resolve_load_library() -> LoadLibraryWFn {
    let kernel_32: u64 = find_dll_base("KERNEL32.DLL").unwrap();
    let load_library: u64 = find_dll_export("LoadLibraryW", kernel_32).unwrap();
    let load_library: LoadLibraryWFn = unsafe { core::mem::transmute(load_library) };

    let user32_name = w!("User32.dll");

    let user32_handle = unsafe { load_library(user32_name) };
    assert!(!user32_handle.is_null());
    load_library
}

fn resolve_message_box() -> MessageBoxWFn {
    let user32 = find_dll_base("USER32.DLL").unwrap();
    let addr = find_dll_export("MessageBoxW", user32).unwrap();
    unsafe { core::mem::transmute(addr) }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows_sys::w;

    #[test]
    fn kernel32_is_loaded() {
        let base = find_dll_base("KERNEL32.DLL");
        assert!(base.is_ok());
        assert!(base.unwrap() != 0);
    }

    #[test]
    fn can_resolve_loadlibraryw() {
        let ll = resolve_load_library();
        let name = w!("Kernel32.dll");

        let h = unsafe { ll(name) };
        assert!(!h.is_null());
    }

    #[test]
    fn user32_can_be_loaded_manually() {
        let ll = resolve_load_library();
        let name = w!("User32.dll");

        let h = unsafe { ll(name) };
        assert!(!h.is_null());

        let base = find_dll_base("USER32.DLL");
        assert!(base.is_ok());
    }

    #[test]
    fn can_resolve_messageboxw_symbol() {
        let kl = resolve_load_library(); // we need to call this so that user32 dll is loaded into memory for the test
        let _ = resolve_message_box(); // should not panic
    }
}

#[cfg(all(test, windows))]
#[test]
#[ignore = "spawns UI"]
fn messagebox_smoke_test() {
    let _ = resolve_load_library(); // we need to call this so that user32 dll is loaded into memory for the test

    let msgbox = resolve_message_box();

    let text = w!("Manual MessageBoxW test");
    let caption = w!("PE loader");

    unsafe {
        let ret = msgbox(core::ptr::null_mut(), text, caption, 0);
        assert_eq!(ret, 1);
    }
}
