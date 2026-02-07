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
struct CALL_ABS_QWORD {
    opcode0: u8, // FF
    opcode1: u8, // 15
    disp: u32,   // 2
    jmp0: u8,    // EB
    jmp1: u8,    // 08
    address: u64,
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

impl Trampoline {
    pub fn create_tramp() -> Result<Self, String> {
        let mut ct = Trampoline {
            target: std::ptr::null_mut(),
            detour: std::ptr::null_mut(),
            trampoline: std::ptr::null_mut(),
            relay: std::ptr::null_mut(),
            patch_above: false,
            num_ip: 0,
            old_ip: Vec::new(),
            new_ip: Vec::new(),
        };
        let call = CALL_ABS_QWORD {
            opcode0: 0xFF,
            opcode1: 0x15,
            disp: 2,
            jmp0: 0xEB,
            jmp1: 0x08,
            address: 0x0000000000000000,
        };

        let jmp = JMP_ABS_QWORD {
            opcode_first: 0xFF,
            opcode_second: 0x25,
            dummy: 0x00000000,
            offset: 0x0000000000000000,
        };

        let jcc = JCC_ABS_QWORD {
            opcode_first: 0x75,
            dummy: 0x0E,
            dummy2: 0xFF,
            dummy3: 0x25,
            dummy4: 0x00000000,
            offset: 0x0000000000000000,
        };

        let mut old_pos = 0;
        let mut new_pos = 0;
        let mut jmp_dest: usize = 0; // dest of internal jump

        let mut finished = false;
        let mut instruction_buffer = [0u8; 16];

        ct.patch_above = false;
        todo!()
    }
}
