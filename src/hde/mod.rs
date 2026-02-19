use std::ffi::c_void;

pub const HDE64_TABLE: [u8; 515] = [
    0xa5, 0xaa, 0xa5, 0xb8, 0xa5, 0xaa, 0xa5, 0xaa, 0xa5, 0xb8, 0xa5, 0xb8, 0xa5, 0xb8, 0xa5, 0xb8,
    0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xac, 0xc0, 0xcc, 0xc0, 0xa1, 0xa1, 0xa1, 0xa1,
    0xb1, 0xa5, 0xa5, 0xa6, 0xc0, 0xc0, 0xd7, 0xda, 0xe0, 0xc0, 0xe4, 0xc0, 0xea, 0xea, 0xe0, 0xe0,
    0x98, 0xc8, 0xee, 0xf1, 0xa5, 0xd3, 0xa5, 0xa5, 0xa1, 0xea, 0x9e, 0xc0, 0xc0, 0xc2, 0xc0, 0xe6,
    0x03, 0x7f, 0x11, 0x7f, 0x01, 0x7f, 0x01, 0x3f, 0x01, 0x01, 0xab, 0x8b, 0x90, 0x64, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x92, 0x5b, 0x5b, 0x76, 0x90, 0x92, 0x92, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x6a, 0x73, 0x90, 0x5b, 0x52, 0x52, 0x52, 0x52, 0x5b, 0x5b,
    0x5b, 0x5b, 0x77, 0x7c, 0x77, 0x85, 0x5b, 0x5b, 0x70, 0x5b, 0x7a, 0xaf, 0x76, 0x76, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x86, 0x01, 0x03, 0x01, 0x04, 0x03, 0xd5,
    0x03, 0xd5, 0x03, 0xcc, 0x01, 0xbc, 0x03, 0xf0, 0x03, 0x03, 0x04, 0x00, 0x50, 0x50, 0x50, 0x50,
    0xff, 0x20, 0x20, 0x20, 0x20, 0x01, 0x01, 0x01, 0x01, 0xc4, 0x02, 0x10, 0xff, 0xff, 0xff, 0x01,
    0x00, 0x03, 0x11, 0xff, 0x03, 0xc4, 0xc6, 0xc8, 0x02, 0x10, 0x00, 0xff, 0xcc, 0x01, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x01, 0xff, 0xff, 0xc0, 0xc2, 0x10, 0x11, 0x02, 0x03,
    0x01, 0x01, 0x01, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x10, 0x10, 0x10, 0x10, 0x02, 0x10, 0x00, 0x00, 0xc6, 0xc8, 0x02, 0x02, 0x02, 0x02, 0x06, 0x00,
    0x04, 0x00, 0x02, 0xff, 0x00, 0xc0, 0xc2, 0x01, 0x01, 0x03, 0x03, 0x03, 0xca, 0x40, 0x00, 0x0a,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x33, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xbf, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xbf,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0xff, 0x40, 0x40, 0x40, 0x40,
    0x41, 0x49, 0x40, 0x40, 0x40, 0x40, 0x4c, 0x42, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x4f, 0x44, 0x53, 0x40, 0x40, 0x40, 0x44, 0x57, 0x43, 0x5c, 0x40, 0x60, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x64, 0x66, 0x6e, 0x6b, 0x40, 0x40,
    0x6a, 0x46, 0x40, 0x40, 0x44, 0x46, 0x40, 0x40, 0x5b, 0x44, 0x40, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x06, 0x06, 0x06, 0x01, 0x06, 0x06, 0x02, 0x06, 0x06, 0x00, 0x06, 0x00, 0x0a, 0x0a, 0x00,
    0x00, 0x00, 0x02, 0x07, 0x07, 0x06, 0x02, 0x0d, 0x06, 0x06, 0x06, 0x0e, 0x05, 0x05, 0x02, 0x02,
    0x00, 0x00, 0x04, 0x04, 0x04, 0x04, 0x05, 0x06, 0x06, 0x06, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00,
    0x08, 0x00, 0x10, 0x00, 0x18, 0x00, 0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x80, 0x01, 0x82, 0x01,
    0x86, 0x00, 0xf6, 0xcf, 0xfe, 0x3f, 0xab, 0x00, 0xb0, 0x00, 0xb1, 0x00, 0xb3, 0x00, 0xba, 0xf8,
    0xbb, 0x00, 0xc0, 0x00, 0xc1, 0x00, 0xc7, 0xbf, 0x62, 0xff, 0x00, 0x8d, 0xff, 0x00, 0xc4, 0xff,
    0x00, 0xc5, 0xff, 0x00, 0xff, 0xff, 0xeb, 0x01, 0xff, 0x0e, 0x12, 0x08, 0x00, 0x13, 0x09, 0x00,
    0x16, 0x08, 0x00, 0x17, 0x09, 0x00, 0x2b, 0x09, 0x00, 0xae, 0xff, 0x07, 0xb2, 0xff, 0x00, 0xb4,
    0xff, 0x00, 0,
];

pub const F_MODRM: u32 = 0x00000001;
pub const F_SIB: u32 = 0x00000002;
pub const F_IMM8: u32 = 0x00000004;
pub const F_IMM16: u32 = 0x00000008;
pub const F_IMM32: u32 = 0x00000010;
pub const F_IMM64: u32 = 0x00000020;
pub const F_DISP8: u32 = 0x00000040;
pub const F_DISP16: u32 = 0x00000080;
pub const F_DISP32: u32 = 0x00000100;
pub const F_RELATIVE: u32 = 0x00000200;
pub const F_ERROR: u32 = 0x00001000;
pub const F_ERROR_OPCODE: u32 = 0x00002000;
pub const F_ERROR_LENGTH: u32 = 0x00004000;
pub const F_ERROR_LOCK: u32 = 0x00008000;
pub const F_ERROR_OPERAND: u32 = 0x00010000;
pub const F_PREFIX_REPNZ: u32 = 0x01000000;
pub const F_PREFIX_REPX: u32 = 0x02000000;
pub const F_PREFIX_REP: u32 = 0x03000000;
pub const F_PREFIX_66: u32 = 0x04000000;
pub const F_PREFIX_67: u32 = 0x08000000;
pub const F_PREFIX_LOCK: u32 = 0x10000000;
pub const F_PREFIX_SEG: u32 = 0x20000000;
pub const F_PREFIX_REX: u32 = 0x40000000;
pub const F_PREFIX_ANY: u32 = 0x7f000000;

// Prefix values
//
pub const PREFIX_SEGMENT_CS: u8 = 0x2e;
pub const PREFIX_SEGMENT_SS: u8 = 0x36;
pub const PREFIX_SEGMENT_DS: u8 = 0x3e;
pub const PREFIX_SEGMENT_ES: u8 = 0x26;
pub const PREFIX_SEGMENT_FS: u8 = 0x64;
pub const PREFIX_SEGMENT_GS: u8 = 0x65;
pub const PREFIX_LOCK: u8 = 0xf0;
pub const PREFIX_REPNZ: u8 = 0xf2;
pub const PREFIX_REPX: u8 = 0xf3;
pub const PREFIX_OPERAND_SIZE: u8 = 0x66;
pub const PREFIX_ADDRESS_SIZE: u8 = 0x67;

// Packed unions
//

#[repr(C)]
#[derive(Copy, Clone)]
pub union hde64_imm {
    pub imm8: u8,
    pub imm16: u16,
    pub imm32: u32,
    pub imm64: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union hde64_disp {
    pub disp8: u8,
    pub disp16: u16,
    pub disp32: u32,
}

// Main struct
//

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct hde64s {
    pub len: u8,
    pub p_rep: u8,
    pub p_lock: u8,
    pub p_seg: u8,
    pub p_66: u8,
    pub p_67: u8,
    pub rex: u8,
    pub rex_w: u8,
    pub rex_r: u8,
    pub rex_x: u8,
    pub rex_b: u8,
    pub opcode: u8,
    pub opcode2: u8,
    pub modrm: u8,
    pub modrm_mod: u8,
    pub modrm_reg: u8,
    pub modrm_rm: u8,
    pub sib: u8,
    pub sib_scale: u8,
    pub sib_index: u8,
    pub sib_base: u8,
    pub imm: hde64_imm,
    pub disp: hde64_disp,
    pub flags: u32,
}

// cflags constants
//
pub const C_NONE: u8 = 0x00;
pub const C_MODRM: u8 = 0x01;
pub const C_IMM8: u8 = 0x02;
pub const C_IMM16: u8 = 0x04;
pub const C_IMM_P66: u8 = 0x10;
pub const C_REL8: u8 = 0x20;
pub const C_REL32: u8 = 0x40;
pub const C_GROUP: u8 = 0x80;
pub const C_ERROR: u8 = 0xFF;

// pref constants
//
pub const PRE_NONE: u8 = 0x01;
pub const PRE_F2: u8 = 0x02;
pub const PRE_F3: u8 = 0x04;
pub const PRE_66: u8 = 0x08;
pub const PRE_67: u8 = 0x10;
pub const PRE_LOCK: u8 = 0x20;
pub const PRE_SEG: u8 = 0x40;

// Table delta offsets
//
pub const DELTA_OPCODES: usize = 74;
pub const DELTA_FPU_REG: usize = 253;
pub const DELTA_FPU_MODRM: usize = 260;
pub const DELTA_PREFIXES: usize = 316;
pub const DELTA_OP_LOCK_OK: usize = 430;
pub const DELTA_OP2_LOCK_OK: usize = 454;
pub const DELTA_OP_ONLY_MEM: usize = 472;
pub const DELTA_OP2_ONLY_MEM: usize = 487;

impl Default for hde64s {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

#[inline(always)]
unsafe fn read_u8(p: *const u8) -> u8 { p.read_unaligned() }

#[inline(always)]
unsafe fn read_u16(p: *const u8) -> u16 { (p as *const u16).read_unaligned() }

#[inline(always)]
unsafe fn read_u32(p: *const u8) -> u32 { (p as *const u32).read_unaligned() }

#[inline(always)]
unsafe fn read_u64(p: *const u8) -> u64 { (p as *const u64).read_unaligned() }

/// Disassemble one x86-64 instruction.
pub unsafe fn hde64_disasm(code: *const c_void, hs: &mut hde64s) -> u32 {
    // Zero the output struct
    *hs = hde64s::default();

    // Working pointer into the byte stream
    let mut p: *const u8 = code as *const u8;

    // Local copies of the lookup table as a byte slice

    let ht: &[u8] = HDE64_TABLE.as_slice();

    let mut c: u8 = 0;
    let mut cflags: u8;
    let mut opcode: u8 = 0;
    let mut pref: u8 = 0;
    let mut disp_size: u8 = 0;
    let mut op64: u8 = 0;
    // ht_offset tracks which "base" into the table we are using (mirrors the C
    // pointer arithmetic on `ht`).
    let mut ht_base: usize = 0;
    'prefix: for _ in 0..16 {
        c = read_u8(p);
        p = p.add(1);

        match c {
            0xf3 => {
                hs.p_rep = c;
                pref |= PRE_F3;
            }
            0xf2 => {
                hs.p_rep = c;
                pref |= PRE_F2;
            }
            0xf0 => {
                hs.p_lock = c;
                pref |= PRE_LOCK;
            }
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => {
                hs.p_seg = c;
                pref |= PRE_SEG;
            }
            0x66 => {
                hs.p_66 = c;
                pref |= PRE_66;
            }
            0x67 => {
                hs.p_67 = c;
                pref |= PRE_67;
            }
            _ => break 'prefix,
        }
    }

    // Pack prefix bits into flags field (shifted left 23, matching the C code)
    hs.flags = (pref as u32) << 23;
    if pref == 0 {
        pref |= PRE_NONE;
    }

    // Label used for the "error_opcode" path below.
    // We simulate C's goto with a boolean and early-set cflags.
    let mut error_opcode = false;

    if (c & 0xf0) == 0x40 {
        hs.flags |= F_PREFIX_REX;

        hs.rex_w = (c & 0xf) >> 3;
        if hs.rex_w != 0 && (read_u8(p) & 0xf8) == 0xb8 {
            op64 += 1;
        }

        hs.rex_r = (c & 7) >> 2;
        hs.rex_x = (c & 3) >> 1;
        hs.rex_b = c & 1;

        c = read_u8(p);
        p = p.add(1);

        if (c & 0xf0) == 0x40 {
            // Two consecutive REX bytes → error_opcode
            opcode = c;
            error_opcode = true;
        }
    }

    if !error_opcode {
        hs.opcode = c;

        if c == 0x0f {
            // Two-byte opcode escape
            c = read_u8(p);
            p = p.add(1);
            hs.opcode2 = c;
            ht_base = DELTA_OPCODES;
        } else if c >= 0xa0 && c <= 0xa3 {
            op64 += 1;
            if pref & PRE_67 != 0 {
                pref |= PRE_66;
            } else {
                pref &= !PRE_66;
            }
        }
    }

    opcode = c;
    cflags = ht[ht[ht_base + opcode as usize / 4] as usize + (opcode as usize % 4)];

    if cflags == C_ERROR || error_opcode {
        // error_opcode:
        hs.flags |= F_ERROR | F_ERROR_OPCODE;
        cflags = 0;
        if (opcode as i8 & -3i8) == 0x24i8 {
            cflags += 1;
        }
    }

    // handle C_GROUP: indirection through a 16-bit table entry

    let mut x: u8 = 0;
    if cflags & C_GROUP != 0 {
        let idx = (cflags & 0x7f) as usize;
        let t = read_u16(&ht[idx] as *const u8);
        cflags = t as u8;
        x = (t >> 8) as u8;
    }

    // two-byte opcode prefix compatibility check

    if hs.opcode2 != 0 {
        let pfx_base = DELTA_PREFIXES;
        if ht[pfx_base + ht[pfx_base + opcode as usize / 4] as usize + (opcode as usize % 4)] as u8
            & pref
            != 0
        {
            hs.flags |= F_ERROR | F_ERROR_OPCODE;
        }
    }

    if cflags & C_MODRM != 0 {
        hs.flags |= F_MODRM;
        c = read_u8(p);
        p = p.add(1);
        hs.modrm = c;

        let m_mod = c >> 6;
        let m_rm = c & 7;
        let m_reg = (c & 0x3f) >> 3;

        hs.modrm_mod = m_mod;
        hs.modrm_rm = m_rm;
        hs.modrm_reg = m_reg;

        // Group-opcode validity check
        if x != 0 && ((x << m_reg) & 0x80) != 0 {
            hs.flags |= F_ERROR | F_ERROR_OPCODE;
        }

        // FPU opcode checks (D8–DF range)
        if hs.opcode2 == 0 && opcode >= 0xd9 && opcode <= 0xdf {
            let t_idx = (opcode - 0xd9) as usize;
            if m_mod == 3 {
                let fpu_base = DELTA_FPU_MODRM + t_idx * 8;
                let t = ht[fpu_base + m_reg as usize] << m_rm;
                if t & 0x80 != 0 {
                    hs.flags |= F_ERROR | F_ERROR_OPCODE;
                }
            } else {
                let fpu_base = DELTA_FPU_REG;
                let t = ht[fpu_base + t_idx] << m_reg;
                if t & 0x80 != 0 {
                    hs.flags |= F_ERROR | F_ERROR_OPCODE;
                }
            }
        }

        // LOCK prefix checks
        if pref & PRE_LOCK != 0 {
            if m_mod == 3 {
                hs.flags |= F_ERROR | F_ERROR_LOCK;
            } else {
                let (lock_base, lock_end, mut op): (usize, usize, u8) = if hs.opcode2 != 0 {
                    (
                        DELTA_OP2_LOCK_OK,
                        DELTA_OP2_LOCK_OK + (DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK),
                        opcode,
                    )
                } else {
                    (
                        DELTA_OP_LOCK_OK,
                        DELTA_OP_LOCK_OK + (DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK),
                        opcode & !1u8,
                    ) // op &= -2
                };

                let mut lock_ok = false;
                let mut i = lock_base;
                while i < lock_end {
                    if ht[i] == op {
                        i += 1;
                        if (ht[i] << m_reg) & 0x80 == 0 {
                            lock_ok = true;
                        }
                        break;
                    }
                    i += 2;
                }
                if !lock_ok {
                    hs.flags |= F_ERROR | F_ERROR_LOCK;
                }
            }
        }

        // Special operand checks for 0F-prefixed opcodes
        let mut operand_error = false;
        let mut operand_ok = false;

        if hs.opcode2 != 0 {
            match opcode {
                0x20 | 0x22 => {
                    // m_mod forced to 3; m_reg must not be >4 or ==1
                    let m_mod = 3u8; // local shadow matching C
                    let _ = m_mod;
                    if m_reg > 4 || m_reg == 1 {
                        operand_error = true;
                    } else {
                        operand_ok = true;
                    }
                }
                0x21 | 0x23 => {
                    let m_mod = 3u8;
                    let _ = m_mod;
                    if m_reg == 4 || m_reg == 5 {
                        operand_error = true;
                    } else {
                        operand_ok = true;
                    }
                }
                _ => {}
            }
        } else {
            match opcode {
                0x8c => {
                    if m_reg > 5 {
                        operand_error = true;
                    } else {
                        operand_ok = true;
                    }
                }
                0x8e => {
                    if m_reg == 1 || m_reg > 5 {
                        operand_error = true;
                    } else {
                        operand_ok = true;
                    }
                }
                _ => {}
            }
        }

        // If neither branch fired we still need to run the mem-only checks below.
        if !operand_error && !operand_ok {
            if m_mod == 3 {
                // Check "only-memory" operand tables
                let (only_base, only_end): (usize, usize) = if hs.opcode2 != 0 {
                    (DELTA_OP2_ONLY_MEM, ht.len())
                } else {
                    (DELTA_OP_ONLY_MEM, DELTA_OP2_ONLY_MEM)
                };

                // Each entry in the only-mem table is 3 bytes:
                //   [opcode, pref_mask, reg_mask]
                // The C loop does: ht+=2 per outer step, but `*ht++` inside
                // already consumed 1, so non-matching entries advance by 3.
                let mut i = only_base;
                while i + 2 < only_end {
                    if ht[i] == opcode {
                        // ht[i+1] = pref mask, ht[i+2] = reg mask
                        if (ht[i + 1] & pref) != 0 && (ht[i + 2] << m_reg) & 0x80 == 0 {
                            operand_error = true;
                        }
                        break;
                    }
                    i += 3;
                }
                // fall through to no_error_operand
            } else if hs.opcode2 != 0 {
                match opcode {
                    0x50 | 0xd7 | 0xf7 => {
                        if pref & (PRE_NONE | PRE_66) != 0 {
                            operand_error = true;
                        }
                    }
                    0xd6 => {
                        if pref & (PRE_F2 | PRE_F3) != 0 {
                            operand_error = true;
                        }
                    }
                    0xc5 => {
                        operand_error = true;
                    }
                    _ => {}
                }
            }
        }

        if operand_error {
            hs.flags |= F_ERROR | F_ERROR_OPERAND;
        }

        // Read SIB / displacement
        c = read_u8(p); // SIB candidate (re-read; p not yet advanced past ModRM)

        // Extend cflags for group F6/F7 with reg 0 or 1
        if m_reg <= 1 {
            if opcode == 0xf6 {
                cflags |= C_IMM8;
            } else if opcode == 0xf7 {
                cflags |= C_IMM_P66;
            }
        }

        // Displacement size from m_mod / m_rm
        match m_mod {
            0 => {
                if pref & PRE_67 != 0 {
                    if m_rm == 6 {
                        disp_size = 2;
                    }
                } else {
                    if m_rm == 5 {
                        disp_size = 4;
                    }
                }
            }
            1 => {
                disp_size = 1;
            }
            2 => {
                disp_size = if pref & PRE_67 != 0 { 2 } else { 4 };
            }
            _ => {}
        }

        // SIB byte
        if m_mod != 3 && m_rm == 4 {
            hs.flags |= F_SIB;
            p = p.add(1); // consume the SIB byte
            hs.sib = c;
            hs.sib_scale = c >> 6;
            hs.sib_index = (c & 0x3f) >> 3;
            hs.sib_base = c & 7;
            if hs.sib_base == 5 && (m_mod & 1) == 0 {
                disp_size = 4;
            }
        }

        // Displacement
        match disp_size {
            1 => {
                hs.flags |= F_DISP8;
                hs.disp.disp8 = read_u8(p);
            }
            2 => {
                hs.flags |= F_DISP16;
                hs.disp.disp16 = read_u16(p);
            }
            4 => {
                hs.flags |= F_DISP32;
                hs.disp.disp32 = read_u32(p);
            }
            _ => {}
        }
        p = p.add(disp_size as usize);
    } else if pref & PRE_LOCK != 0 {
        hs.flags |= F_ERROR | F_ERROR_LOCK;
    }

    // ------------------------------------------------------------------
    // Phase 8 – immediates
    // ------------------------------------------------------------------

    if cflags & C_IMM_P66 != 0 {
        if cflags & C_REL32 != 0 {
            if pref & PRE_66 != 0 {
                hs.flags |= F_IMM16 | F_RELATIVE;
                hs.imm.imm16 = read_u16(p);
                p = p.add(2);
                // goto disasm_done
                return finalize(hs, code as *const u8, p);
            }
            // goto rel32_ok  (handled below after this block)
        } else if op64 != 0 {
            hs.flags |= F_IMM64;
            hs.imm.imm64 = read_u64(p);
            p = p.add(8);
        } else if pref & PRE_66 == 0 {
            hs.flags |= F_IMM32;
            hs.imm.imm32 = read_u32(p);
            p = p.add(4);
        } else {
            // imm16_ok
            hs.flags |= F_IMM16;
            hs.imm.imm16 = read_u16(p);
            p = p.add(2);
        }
    }

    if cflags & C_IMM16 != 0 {
        hs.flags |= F_IMM16;
        hs.imm.imm16 = read_u16(p);
        p = p.add(2);
    }

    if cflags & C_IMM8 != 0 {
        hs.flags |= F_IMM8;
        hs.imm.imm8 = read_u8(p);
        p = p.add(1);
    }

    if cflags & C_REL32 != 0 {
        // rel32_ok:
        hs.flags |= F_IMM32 | F_RELATIVE;
        hs.imm.imm32 = read_u32(p);
        p = p.add(4);
    } else if cflags & C_REL8 != 0 {
        hs.flags |= F_IMM8 | F_RELATIVE;
        hs.imm.imm8 = read_u8(p);
        p = p.add(1);
    }

    finalize(hs, code as *const u8, p)
}

#[inline(always)]
unsafe fn finalize(hs: &mut hde64s, start: *const u8, p: *const u8) -> u32 {
    let len = p.offset_from(start) as u8;
    if len > 15 {
        hs.flags |= F_ERROR | F_ERROR_LENGTH;
        hs.len = 15;
    } else {
        hs.len = len;
    }
    hs.len as u32
}
