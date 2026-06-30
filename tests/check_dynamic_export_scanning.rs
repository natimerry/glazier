use libwinexploit::runtime::NativePeRuntime;
use windows_sys::w;
type LoadLibraryWFn = unsafe extern "system" fn(*const u16) -> *mut core::ffi::c_void;
type MessageBoxWFn =
    unsafe extern "system" fn(*mut core::ffi::c_void, *const u16, *const u16, u32) -> i32;

fn resolve_load_library() -> LoadLibraryWFn {
    let kernel32 = NativePeRuntime::from_module("KERNEL32.DLL").expect("kernel32.dll not found");

    let load_library_addr = kernel32
        .find_export("LoadLibraryW")
        .expect("LoadLibraryW not found")
        .func_addr as usize;

    unsafe { core::mem::transmute(load_library_addr) }
}

fn resolve_message_box() -> MessageBoxWFn {
    let user32 = NativePeRuntime::from_module("USER32.DLL").expect("user32.dll not found");

    let message_box_addr = user32
        .find_export("MessageBoxW")
        .expect("MessageBoxW not found")
        .func_addr as usize;

    unsafe { core::mem::transmute(message_box_addr) }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows_sys::w;

    #[test]
    fn kernel32_is_loaded() {
        let kernel32 = NativePeRuntime::from_module("KERNEL32.DLL");
        assert!(kernel32.is_ok());
    }

    #[test]
    fn can_resolve_loadlibraryw() {
        let load_library = resolve_load_library();

        let name = w!("Kernel32.dll");
        let h = unsafe { load_library(name) };

        assert!(!h.is_null());
    }

    #[test]
    fn user32_can_be_loaded_manually() {
        let load_library = resolve_load_library();

        let name = w!("User32.dll");
        let h = unsafe { load_library(name) };
        assert!(!h.is_null());

        let user32 = NativePeRuntime::from_module("USER32.DLL");
        assert!(user32.is_ok());
    }

    #[test]
    fn can_resolve_messageboxw_symbol() {
        // Ensure USER32 is loaded
        let load_library = resolve_load_library();
        unsafe {
            load_library(w!("User32.dll"));
        }

        let _ = resolve_message_box(); // should not panic
    }
}

#[cfg(all(test, windows))]
#[test]
#[ignore = "spawns UI"]
fn messagebox_smoke_test() {
    let load_library = resolve_load_library();
    unsafe {
        load_library(w!("User32.dll"));
    }

    let message_box = resolve_message_box();

    let text = w!("Manual MessageBoxW test");
    let caption = w!("PE loader");

    unsafe {
        let ret = message_box(core::ptr::null_mut(), text, caption, 0);
        assert_eq!(ret, 1);
    }
}
