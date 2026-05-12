use libwinexploit::utils::to_wide;
use libwinexploit::winapi::*;
use windows_sys::Win32::UI::WindowsAndMessaging::MB_OK;
fn main() {
    env_logger::init();

    unsafe {
        let user32_name = to_wide("User32.dll");
        let h_module = LoadLibraryW(user32_name.as_ptr());

        if h_module.is_null() {
            panic!("Failed to load User32.dll");
        }

        let text = to_wide("Hello from generated bindings!");
        let caption = to_wide("PE Loader Rust");

        MessageBoxW(
            std::ptr::null_mut(), // HWND (null)
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK, // Constant from winapi bindings
        );
    }
}
