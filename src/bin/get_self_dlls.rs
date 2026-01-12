use libwinexploit::runtime::exports::{find_dll_base, find_dll_export};
use windows_sys::w;

fn main() {
    type LoadLibraryWFn = unsafe extern "system" fn(
        name: *const u16
    ) -> *mut core::ffi::c_void;


    let kernel32 = find_dll_base("KERNEL32.DLL").unwrap();
    let load_library_addr =
        find_dll_export("LoadLibraryW", kernel32).unwrap();

    let load_library: LoadLibraryWFn =
        unsafe { core::mem::transmute(load_library_addr) };

    let user32_name = w!("User32.dll");

    unsafe {
        load_library(user32_name);
    }


    let dll_base = find_dll_base("USER32.DLL").expect("Failed to retrieve");

    type MessageBoxWFn = unsafe extern "system" fn(
        hwnd: *mut core::ffi::c_void,
        text: *const u16,
        caption: *const u16,
        flags: u32,
    ) -> i32;

    let module_handle = find_dll_export("MessageBoxW", dll_base).expect("Failed to retrieve");

    let message_box: MessageBoxWFn = unsafe { core::mem::transmute(module_handle) };

    let text = w!("Hello from manually resolved MessageBoxW");
    let caption = w!("PE Loader Rust");

    unsafe {
        message_box(
            core::ptr::null_mut(),
            text,
            caption,
            0, // MB_OK
        );
    }
}
