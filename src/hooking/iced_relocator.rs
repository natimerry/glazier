use super::HookError;
use super::JmpAbs;
use super::JmpRel;
use super::JmpRelShort;
use super::MEMORY_SLOT_SIZE;
use super::Trampoline;
use super::check_address_executable;
use crate::ExpError;
use crate::hooking::trace_instructions::DisasmLayout;
use crate::hooking::trace_instructions::log_disassembly;
use crate::runtime::memory::MemoryView;
use iced_x86::BlockEncoder;
use iced_x86::BlockEncoderOptions;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::FlowControl;
use iced_x86::Instruction;
use iced_x86::InstructionBlock;
use log::trace;
use std::mem::size_of;

impl Trampoline {
    pub unsafe fn new<M: MemoryView>(
        target: *mut u8,
        detour: *mut u8,
        trampoline: *mut u8,
        m: &M,
    ) -> Result<Self, HookError> {
        const MAX_INSTRUCTION_LENGTH: usize = 15;
        const PATCH_SIZE: usize = size_of::<JmpRel>();

        let mut instructions = Vec::new();
        let mut original_bytes = Vec::new();
        let mut old_len = 0usize;
        let mut ends_in_branch = false;

        while old_len < PATCH_SIZE && !ends_in_branch {
            if instructions.len() >= 8 {
                return Err(HookError::TrampolineError);
            }

            let instruction_address = target.add(old_len) as u64;
            let (instruction, decode_bytes) =
                decode_instruction(m, instruction_address, MAX_INSTRUCTION_LENGTH)?;

            let length = instruction.len();
            original_bytes.push(decode_bytes[..length].to_vec());
            old_len += length;
            ends_in_branch = ends_relocated_block(&instruction, target as u64, PATCH_SIZE as u64);
            instructions.push(instruction);
        }

        let encoded = BlockEncoder::encode(
            64,
            InstructionBlock::new(&instructions, trampoline as u64),
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )
        .map_err(|error| {
            trace!("iced-x86 could not relocate the trampoline: {error}");
            HookError::TrampolineError
        })?;

        let needs_jump_back = !ends_in_branch;
        let reserved = size_of::<JmpAbs>()
            + if needs_jump_back {
                size_of::<JmpAbs>()
            } else {
                0
            };
        if encoded.code_buffer.len() + reserved > MEMORY_SLOT_SIZE {
            return Err(HookError::TrampolineError);
        }

        log_disassembly(
            "Writing Trampoline Instruction",
            &encoded.code_buffer,
            64,
            trampoline as u64,
            DisasmLayout::MultiLine,
            log::Level::Debug,
            true,
        );

        m.write_bytes(trampoline as u64, &encoded.code_buffer)?;

        let mut new_pos = encoded.code_buffer.len();
        if needs_jump_back {
            let jump_back = JmpAbs {
                opcode0: 0xFF,
                opcode1: 0x25,
                dummy: 0,
                address: target.add(old_len) as u64,
            };

            m.copy_non_overlapping(
                &jump_back as *const _ as u64,
                trampoline.add(new_pos) as u64,
                size_of::<JmpAbs>(),
            )?;

            new_pos += size_of::<JmpAbs>();
        }

        let relay = trampoline.add(new_pos);
        let relay_jump = JmpAbs {
            opcode0: 0xFF,
            opcode1: 0x25,
            dummy: 0,
            address: detour as u64,
        };
        m.copy_non_overlapping(
            &relay_jump as *const _ as u64,
            relay as u64,
            size_of::<JmpAbs>(),
        )?;

        let mut result = Self {
            target,
            detour,
            trampoline,
            relay,
            patch_above: false,
            num_ips: instructions.len() as u8,
            old_ips: [0; 8],
            new_ips: [0; 8],
        };

        let mut old_offset = 0usize;
        let mut last_new_offset = 0u8;
        for (index, instruction) in instructions.iter().enumerate() {
            result.old_ips[index] = old_offset as u8;
            let offset = encoded.new_instruction_offsets[index];
            if offset != u32::MAX {
                last_new_offset = offset as u8;
            }
            result.new_ips[index] = last_new_offset;
            old_offset += instruction.len();
        }

        if old_len < PATCH_SIZE
            && !Self::is_code_padding(m, target.add(old_len) as u64, (PATCH_SIZE - old_len) as u64)?
        {
            let short_jump_size = size_of::<JmpRelShort>();
            if old_len < short_jump_size
                && !Self::is_code_padding(
                    m,
                    target.add(old_len) as u64,
                    (short_jump_size - old_len) as u64,
                )?
            {
                return Err(HookError::TrampolineError);
            }

            if !check_address_executable(target.sub(PATCH_SIZE), m.get_handle())
                || !Self::is_code_padding(m, target.sub(PATCH_SIZE) as u64, PATCH_SIZE as u64)?
            {
                return Err(HookError::TrampolineError);
            }

            result.patch_above = true;
        }

        Ok(result)
    }

    fn is_code_padding<M: MemoryView>(m: &M, inst: u64, size: u64) -> Result<bool, ExpError> {
        let first = m.read::<u8>(inst)?;

        if first != 0x00 && first != 0x90 && first != 0xCC {
            return Ok(false);
        }

        for offset in 1..size {
            if m.read::<u8>(inst + offset)? != first {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

fn decode_instruction<M: MemoryView>(
    memory: &M,
    address: u64,
    max_length: usize,
) -> Result<(Instruction, Vec<u8>), HookError> {
    let mut bytes = Vec::with_capacity(max_length);

    for offset in 0..max_length {
        bytes.push(memory.read::<u8>(address + offset as u64)?);
        let instruction = decode_one(&bytes, address);
        if !instruction.is_invalid() && instruction.len() == bytes.len() {
            return Ok((instruction, bytes));
        }
    }

    trace!("iced-x86 failed to decode an instruction at {address:#x}");
    Err(HookError::DisassemblyError)
}

fn ends_relocated_block(instruction: &Instruction, target: u64, patch_size: u64) -> bool {
    match instruction.flow_control() {
        FlowControl::Return | FlowControl::IndirectBranch => true,
        FlowControl::UnconditionalBranch => {
            let destination = instruction.near_branch_target();
            destination < target || destination >= target + patch_size
        }
        _ => false,
    }
}

fn decode_one(bytes: &[u8], ip: u64) -> Instruction {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    decoder.decode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incrementally_decodes_without_reading_past_the_instruction() {
        let memory = crate::runtime::memory::LocalMemory;
        let bytes = [0xC3, 0xCC];
        let (instruction, read) =
            decode_instruction(&memory, bytes.as_ptr() as u64, bytes.len()).unwrap();

        assert_eq!(instruction.len(), 1);
        assert_eq!(read, [0xC3]);
    }
}
