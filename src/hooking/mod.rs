pub mod trampoline;

struct HookEntry {
    address: usize,
    original_bytes: Vec<u8>,
    replacement_bytes: Vec<u8>,
    enabled: bool,
}
