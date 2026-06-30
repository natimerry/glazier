use libwinexploit::runtime::NativePeRuntime;
use windows_sys::w;

fn main() {
    env_logger::init();

    type LoadLibraryWFn = unsafe extern "system" fn(name: *const u16) -> *mut core::ffi::c_void;

    type MessageBoxWFn = unsafe extern "system" fn(
        hwnd: *mut core::ffi::c_void,
        text: *const u16,
        caption: *const u16,
        flags: u32,
    ) -> i32;

    // Load kernel32.dll from PEB and find LoadLibraryW
    let kernel32 =
        NativePeRuntime::from_module("KERNEL32.DLL").expect("Failed to find kernel32.dll");

    let load_library_addr = kernel32
        .find_export("LoadLibraryW")
        .expect("Failed to find LoadLibraryW")
        .func_addr as usize;

    let load_library: LoadLibraryWFn = unsafe { core::mem::transmute(load_library_addr) };

    // Load User32.dll dynamically
    let user32_name = w!("User32.dll");
    unsafe {
        load_library(user32_name);
    }

    // Parse User32.dll from PEB (now that it's loaded)
    let user32 = NativePeRuntime::from_module("USER32.DLL").expect("Failed to find user32.dll");
    //
    let message_box_addr = user32
        .find_export("MessageBoxW")
        .expect("Failed to find MessageBoxW")
        .func_addr as usize;

    let message_box: MessageBoxWFn = unsafe { core::mem::transmute(message_box_addr) };

    // Call MessageBoxW
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
