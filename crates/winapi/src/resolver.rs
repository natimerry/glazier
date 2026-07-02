use libwinexploit_runtime::NativePeRuntime;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

#[inline]
pub(super) unsafe fn resolve(
    slot: &'static AtomicPtr<()>,
    function_name: &str,
    dll: &str,
) -> *mut () {
    let cached = slot.load(Ordering::Acquire);
    if !cached.is_null() {
        return cached;
    }

    if !dll.eq_ignore_ascii_case("KERNEL32.DLL") {
        let dll = dll
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        unsafe {
            super::LoadLibraryW(dll.as_ptr());
        }
    }

    let resolved = NativePeRuntime::from_module(dll)
        .and_then(|module| module.find_export(function_name))
        .map(|export| export.func_addr as *mut ())
        .unwrap_or_else(|_| panic!("Failed to resolve {function_name} from {dll}"));

    match slot.compare_exchange(null_mut(), resolved, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => resolved,
        Err(existing) => existing,
    }
}
