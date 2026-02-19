use libwinexploit::hooking::HookEntry;
use libwinexploit::winapi::GetProcAddress;
use libwinexploit::winapi::LPVOID;
use libwinexploit::winapi::LoadLibraryW;
use libwinexploit::winapi::MessageBoxW;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

// Store the original function pointer so our detour can call through
static ORIGINAL_MESSAGEBOX: AtomicPtr<()> = AtomicPtr::new(null_mut());

// Our detour — same signature as MessageBoxW
unsafe extern "system" fn hooked_message_box(
    hwnd: *mut c_void,
    _text: *const u16,
    _caption: *const u16,
    utype: u32,
) -> i32 {
    println!("In Hook!");
    let original: unsafe extern "system" fn(*mut c_void, *const u16, *const u16, u32) -> i32 =
        std::mem::transmute(ORIGINAL_MESSAGEBOX.load(Ordering::SeqCst));

    let new_text = to_wide("Hooked! Original message intercepted.");
    let new_caption = to_wide("Hook Works!");

    original(hwnd, new_text.as_ptr(), new_caption.as_ptr(), utype)
}
fn to_wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

fn main() {
    env_logger::init();

    unsafe {
        let user32_name = to_wide("User32.dll");
        let h_module = LoadLibraryW(user32_name.as_ptr());
        if h_module.is_null() {
            panic!("Failed to load User32.dll");
        }

        let func_name = b"MessageBoxW\0";
        let target_fn = GetProcAddress(h_module, func_name.as_ptr() as *const i8)
            .expect("Failed to resolve MessageBoxW");

        // Transmute the fn pointer to a raw *mut u8 for the hooking machinery
        let target: *mut u8 = std::mem::transmute(target_fn);

        println!("MessageBoxW address: {:p}", target);
        println!("Detour address:      {:p}", hooked_message_box as *mut u8);

        let mut original: LPVOID = null_mut();
        let mut hook = HookEntry::new(
            target,
            hooked_message_box as *mut u8,
            &mut original as *mut LPVOID,
        )
        .expect("Failed to create hook");

        ORIGINAL_MESSAGEBOX.store(original as *mut (), Ordering::SeqCst);

        println!("Trampoline: {:p}", original);
        let tramp_ptr = original as *const u8;
        print!("Trampoline bytes: ");
        unsafe {
            for i in 0..64 {
                print!("{:02X} ", *tramp_ptr.add(i));
            }
        }
        println!();

        // Also dump the first 16 bytes of MessageBoxW to see what we're disassembling
        let target_ptr = target as *const u8;
        print!("MessageBoxW bytes: ");
        unsafe {
            for i in 0..16 {
                print!("{:02X} ", *target_ptr.add(i));
            }
        }
        println!();
        // Enable
        hook.toggle().expect("Failed to enable hook");
        let text = to_wide("Hello from generated bindings!");
        let caption = to_wide("PE Loader Rust");
        MessageBoxW(null_mut(), text.as_ptr(), caption.as_ptr(), 0u32); // MB_OK = 0

        // Disable
        hook.toggle().expect("Failed to disable hook");
        MessageBoxW(null_mut(), text.as_ptr(), caption.as_ptr(), 0u32);

        // Re-enable
        hook.toggle().expect("Failed to re-enable hook");
        MessageBoxW(null_mut(), text.as_ptr(), caption.as_ptr(), 0u32);
    }
}
