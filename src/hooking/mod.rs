pub mod pattern;

use crate::ExpError;
use crate::winapi::raw::VirtualAlloc;
use iced_x86::Code;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Encoder;
use iced_x86::Instruction;
use iced_x86::Register;
use std::ffi::c_void;
use thiserror::Error;

pub struct HookEntry {
    target: *mut u8,
    /// Target of the hook
    detour: *mut u8,
    /// Address of function to jmp to
    trampoline: *mut u8,
    /// Address of trampoline
    hot_patch: bool,
    enabled: bool,
    n_ip: u8, // Instruction boundary count
    old_ips: Vec<u8>,
    new_ips: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum HookError {
    #[error("Invalid pointer")]
    InvalidPointer,
    #[error("Invalid instruction")]
    InvalidInstruction,
    #[error("Insufficient size")]
    InsufficientSize,

    #[error("Allocation failed")]
    AllocationFailed,
}

impl HookEntry {
    pub fn new(target: *mut u8, detour: *mut u8) -> Result<Self, HookError> {
        if target.is_null() || detour.is_null() {
            return Err(HookError::InvalidPointer);
        }

        Ok(Self {
            target,
            detour,
            trampoline: std::ptr::null_mut(),
            hot_patch: false,
            enabled: false,
            n_ip: 0,
            old_ips: Vec::new(),
            new_ips: Vec::new(),
        })
    }

    fn check_hot_patch(&self) -> bool {
        unsafe {
            let hot_patch_addr = self.target.sub(5);
            for i in 0..5 {
                if *(hot_patch_addr.add(i)) != 0x90 && *(hot_patch_addr.add(i)) != 0xCC {
                    return false;
                }
            }
            true
        }
    }

    unsafe fn create_trampoline(&self, stolen_len: usize) -> Result<*mut u8, HookError> {
        let trampoline = VirtualAlloc(
            self.target as *mut c_void,
            (stolen_len + 14) as u64,
            0x00001000 | 0x00002000,
            0x40,
        );

        if trampoline.is_null() {
            return Err(HookError::AllocationFailed);
        }

        let tramp = trampoline as *mut u8;

        let mut decoder = Decoder::with_ip(
            64,
            std::slice::from_raw_parts(self.target, stolen_len + 32),
            self.target as u64,
            DecoderOptions::NONE,
        );

        let mut copied_len = 0usize;
        let mut out_ptr = tramp;

        while copied_len < stolen_len {
            let mut encoder = Encoder::new(64);

            let instr = decoder.decode();
            if instr.is_invalid() {
                return Err(HookError::InvalidInstruction);
            }

            let instr_len = instr.len();
            copied_len += instr_len;

            relocate_instruction(&instr, &mut encoder, out_ptr, self.target)?;

            out_ptr = out_ptr.add(encoder.take_buffer().len());
        }
        std::ptr::copy_nonoverlapping(self.target, tramp, stolen_len);

        let return_addr = self.target.add(stolen_len) as u64;

        HookEntry::write_abs_jmp(tramp.add(stolen_len), return_addr);

        Ok(tramp)
    }

    #[inline(always)]
    unsafe fn write_abs_jmp(dst: *mut u8, target: u64) {
        // FF 25 00 00 00 00
        // dq target
        let buf = dst as *mut u8;
        *buf.add(0) = 0xFF;
        *buf.add(1) = 0x25;
        *(buf.add(2) as *mut u32) = 0;
        *(buf.add(6) as *mut u64) = target;
    }

    unsafe fn calculate_stolen_bytes(&self) -> Result<usize, HookError> {
        const MIN_BYTES: usize = 5;
        const MAX_BYTES: usize = 32;

        let bytes = std::slice::from_raw_parts(self.target, MAX_BYTES);
        let mut decoder = Decoder::with_ip(64, bytes, self.target as u64, DecoderOptions::NONE);

        let mut stolen = 0;

        while stolen < MIN_BYTES {
            if !decoder.can_decode() {
                return Err(HookError::InsufficientSize);
            }

            let instr = decoder.decode();
            if instr.is_invalid() {
                return Err(HookError::InvalidInstruction);
            }

            stolen += instr.len();
            if stolen > MAX_BYTES {
                return Err(HookError::InsufficientSize);
            }
        }

        Ok(stolen)
    }

    pub fn install(&mut self) -> Result<*mut u8, ExpError> { todo!() }
}

fn relocate_instruction(
    instr: &Instruction,
    encoder: &mut Encoder,
    out_ptr: *mut u8,
    orig_base: *const u8,
) -> Result<(), &'static str> {
    let mut new = instr.clone();

    // RIP-relative memory operand
    if instr.is_ip_rel_memory_operand() {
        let abs_addr = instr.ip_rel_memory_address();

        // lea reg, [rip+disp]  → mov reg, imm64
        if instr.code() == Code::Lea_r64_m {
            new = Instruction::with2(Code::Mov_r64_imm64, instr.op0_register(), abs_addr).unwrap();
        } else {
            // mov rax, abs
            let tmp = Register::RAX;

            let mov = Instruction::with2(Code::Mov_r64_imm64, tmp, abs_addr).unwrap();

            let mut mem = instr.clone();
            mem.set_memory_base(tmp);
            mem.set_memory_displacement64(0);
            mem.set_memory_index(Register::None);

            encoder.encode(&mov, out_ptr as u64).unwrap();

            let n = encoder.take_buffer().len() as u64;
            encoder.encode(&mem, out_ptr as u64 + n).unwrap();
            return Ok(());
        }
    }

    // RIP-relative call/jmp
    if instr.is_call_near() || instr.is_jmp_short_or_near() {
        let target = instr.near_branch_target();

        let mov = Instruction::with2(Code::Mov_r64_imm64, Register::RAX, target).unwrap();

        let branch = if instr.is_call_near() {
            Instruction::with1(Code::Call_rm64, Register::RAX).unwrap()
        } else {
            Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap()
        };

        encoder.encode(&mov, out_ptr as u64).unwrap();
        encoder.encode(&branch, out_ptr as u64 + 10).unwrap();
        return Ok(());
    }

    encoder.encode(&new, out_ptr as u64).unwrap();
    Ok(())
}
