use libwinexploit::hooking::HookEntry;
use libwinexploit::hooking::pattern::Pattern;
use libwinexploit::hooking::pattern::PatternScanOption;
use libwinexploit::runtime::memory::LocalMemory;
use libwinexploit::winapi::LoadLibraryW;
use libwinexploit::winapi::MessageBoxW;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering; // your scanner

static ORIGINAL_MESSAGEBOX: AtomicPtr<()> = AtomicPtr::new(null_mut());

#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "system" fn hooked_message_box(
    hwnd: *mut c_void,
    _text: *const u16,
    _caption: *const u16,
    utype: u32,
) -> i32 {
    println!("[Hook] Pattern-scanned MessageBoxW intercepted!");

    let original: unsafe extern "system" fn(*mut c_void, *const u16, *const u16, u32) -> i32 =
        std::mem::transmute(ORIGINAL_MESSAGEBOX.load(Ordering::SeqCst));

    let new_text = to_wide("Pattern hook worked.");
    let new_caption = to_wide("Scanner Success");

    original(hwnd, new_text.as_ptr(), new_caption.as_ptr(), utype)
}

fn to_wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

fn main() {
    env_logger::builder().filter_level(log::LevelFilter::Trace).init();
    unsafe {
        // Load user32
        let module = LoadLibraryW(to_wide("user32.dll").as_ptr());
        assert!(!module.is_null());

        // For demo purposes assume 1MB scan window
        let base = module as *const u8;
        let size = 0x100000;

        let mut pattern = Pattern::builder()
            .pattern("48 83 EC 38 45 33 DB 44 39 1D 46 3C 07 00 74 25")
            .unwrap()
            .generate_wildcards().build();
        
        let memory_view = LocalMemory {};

        let results = pattern
            .scan(&memory_view, base, size, PatternScanOption::Begin)
            .expect("Pattern not found");

        let target = results[0] as *mut u8;

        println!("Pattern match at {:p}", target);
        println!("Hooking address...");

        let memory_view = LocalMemory {};

        let mut hook = HookEntry::new(target, hooked_message_box as *mut u8, memory_view)
            .expect("Hook creation failed");

        ORIGINAL_MESSAGEBOX.store(hook.original() as *mut (), Ordering::SeqCst);

        let memory_view = LocalMemory {};

        hook.toggle(&memory_view).unwrap();

        // Test call
        MessageBoxW(
            null_mut(),
            to_wide("Original text").as_ptr(),
            to_wide("Original caption").as_ptr(),
            0,
        );
    }
}
