use glazier::utils::to_wide;
use glazier::winapi::MessageBoxW;

const MB_OK: u32 = 0;

fn main() {
    env_logger::init();

    let text = to_wide("Hello from generated bindings!");
    let caption = to_wide("PE Loader Rust");

    unsafe {
        MessageBoxW(
            std::ptr::null_mut(), // HWND (null)
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK, // Constant from winapi bindings
        );
    }
}
