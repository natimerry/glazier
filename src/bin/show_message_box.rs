use libwinexploit::winapi::MessageBoxW;
use windows_sys::Win32::UI::WindowsAndMessaging::MB_OK;
use windows_sys::w;

fn main() {
    env_logger::init();

    let text = w!("Hello from generated bindings!");
    let caption = w!("PE Loader Rust");

    unsafe {
        MessageBoxW(
            std::ptr::null_mut(), // HWND (null)
            text,
            caption,
            MB_OK, // Constant from winapi bindings
        );
    }
}
