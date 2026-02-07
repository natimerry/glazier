use crate::winapi::LPVOID;

#[repr(C)]
/// Represents a 8 bit jmp
struct JMP_REL_BYTE {
    /// EB xx: JMP +2+xx
    opcode: u8,
    offset: i8,
}

#[repr(C)]
/// Represents a 32 bit jmp
struct JMP_REL_DWORD {
    /// E9 xx xx xx xx: JMP +5+xx
    opcode: u8,
    offset: i32,
}

#[repr(C)]
/// Represents a 64 bit indirect absolute offset jmp
struct JMP_ABS_QWORD {
    opcode_first: u8, // FF25 00000000: JMP [+6]
    opcode_second: u8,
    dummy: u32,
    /// JMP offset
    offset: u64,
}

#[repr(C)]
/// Represents a 64 bit absolute offset indirect call
struct CALL_ABS_QWORD {
    opcode_first: u8, // FF15 00000002: CALL [+6]
    opcode_second: u8,
    dummy: u32,
    dummy2: u8, // EB 08:         JMP +10
    dummy3: u8, // 90:            NOP
    /// CALL offset
    offset: u64,
}

#[repr(C)]
struct JCC_REL_DWORD {
    opcode_first: u8, // 0F8* xx xx xx xx: JCC +6+xx
    opcode_second: u8,
    offset: i32,
}

#[repr(C)]
struct JCC_ABS_QWORD {
    opcode_first: u8, // 75 xx: JCC +2+xx
    dummy: u8,        // EB 08:         JMP +10
    dummy2: u8,       // 90:            NOP
    dummy3: u8,       // 90:            NOP
    dummy4: u8,       // 90:            NOP
    /// JCC offset
    offset: u64,
}

pub struct Trampoline {
    target: LPVOID,
    detour: LPVOID,
    trampoline: LPVOID,
    relay: LPVOID,
    patch_above: bool,
    num_ip: u32,
    old_ip: Vec<u8>,
    new_ip: Vec<u8>,
}
