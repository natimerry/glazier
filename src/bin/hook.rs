use libwinexploit::hooking::HookEntry;
use libwinexploit::winapi::GetProcAddress;
use libwinexploit::winapi::LoadLibraryW;
use libwinexploit::winapi::MessageBoxW;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

static ORIGINAL_MESSAGEBOX: AtomicPtr<()> = AtomicPtr::new(null_mut());

#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "system" fn hooked_message_box(
    hwnd: *mut c_void,
    _text: *const u16,
    _caption: *const u16,
    utype: u32,
) -> i32 {
    println!("[Hook] MessageBoxW intercepted!");

    let original: unsafe extern "system" fn(*mut c_void, *const u16, *const u16, u32) -> i32 =
        std::mem::transmute(ORIGINAL_MESSAGEBOX.load(Ordering::SeqCst));

    let new_text = to_wide("Hooked! Original message intercepted.");
    let new_caption = to_wide("Hook Works!");

    original(hwnd, new_text.as_ptr(), new_caption.as_ptr(), utype)
}

fn to_wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

fn call_msgbox(text: &str, caption: &str) {
    let t = to_wide(text);
    let c = to_wide(caption);
    unsafe {
        MessageBoxW(null_mut(), t.as_ptr(), c.as_ptr(), 0);
    }
}

fn dump_bytes(label: &str, ptr: *const u8, len: usize) {
    print!("{}: ", label);
    for i in 0..len {
        print!("{:02X} ", unsafe { *ptr.add(i) });
    }
    println!();
}

fn main() {
    env_logger::init();

    unsafe {
        // Load User32 and resolve MessageBoxW
        let h_module = LoadLibraryW(to_wide("User32.dll").as_ptr());
        assert!(!h_module.is_null(), "Failed to load User32.dll");

        let target_fn = GetProcAddress(h_module, b"MessageBoxW\0".as_ptr() as *const i8) // ← fixed \0
            .expect("Failed to resolve MessageBoxW");

        let target: *mut u8 = std::mem::transmute(target_fn);

        let mut hook = HookEntry::from_winapi_function(
            "MessageBoxW",
            Some("USER32"),
            hooked_message_box as *mut u8,
        )
        .expect("Failed to hook");
        ORIGINAL_MESSAGEBOX.store(hook.original() as *mut (), Ordering::SeqCst);

        dump_bytes("Trampoline bytes (64)", hook.original() as *const u8, 64);
        dump_bytes("MessageBoxW bytes (16)", target as *const u8, 16);

        // Enable → hooked call
        hook.toggle().expect("Failed to enable hook");
        call_msgbox("Hello from Rust!", "PE Loader"); // should show hooked text

        // Disable → original call
        hook.toggle().expect("Failed to disable hook");
        call_msgbox("Hello from Rust!", "PE Loader"); // should show original text

        // Re-enable → hooked again
        hook.toggle().expect("Failed to re-enable hook");
        call_msgbox("Hello from Rust!", "PE Loader");
    }
}
