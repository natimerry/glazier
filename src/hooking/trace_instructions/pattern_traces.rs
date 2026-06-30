use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use log::Level;

use crate::hooking::trace_instructions::{AnsiFormatterOutput, DisasmLayout, color_label};


pub fn format_pattern_bytes(bytes: &[Option<u8>]) -> String {
    bytes
        .iter()
        .map(|byte| match byte {
            Some(byte) => format!("{byte:02X}"),
            None => "??".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn format_pattern_compact(bytes: &[Option<u8>]) -> String {
    bytes
        .iter()
        .map(|byte| match byte {
            Some(byte) => format!("{byte:02X}"),
            None => "??".to_owned(),
        })
        .collect::<String>()
}
#[derive(Debug, Clone)]
struct PatternDisasmLine {
    ip: u64,
    bytes: Vec<Option<u8>>,
    text: String,
}

pub fn log_pattern(
    label: &str,
    bytes: &[Option<u8>],
    bitness: u32,
    ip: u64,
    layout: DisasmLayout,
    level: Level,
) {
    let wildcard_count = bytes.iter().filter(|byte| byte.is_none()).count();
    let fixed_count = bytes.len() - wildcard_count;

    let lines = disassemble_pattern(bytes, bitness, ip);
    let listing = format_pattern_disassembly(&lines, layout);

    match layout {
        DisasmLayout::OneLine => {
            log::log!(
                level,
                "{}: [{}] ({}-bit, {} bytes, {} fixed, {} wildcards) {}",
                color_label(label),
                format_pattern_bytes(bytes),
                bitness,
                bytes.len(),
                fixed_count,
                wildcard_count,
                listing,
            );
        }

        DisasmLayout::MultiLine => {
            log::log!(
                level,
                "{}: [{}] ({}-bit, {} bytes, {} fixed, {} wildcards)\n{}",
                color_label(label),
                format_pattern_bytes(bytes),
                bitness,
                bytes.len(),
                fixed_count,
                wildcard_count,
                listing,
            );
        }
    }
}

fn format_pattern_instruction(
    instruction: &Instruction,
    pattern: &[Option<u8>],
) -> String {
    let has_unknown_constant = pattern.iter().any(Option::is_none);

    let colors = std::env::var_os("NO_COLOR").is_none();

    let mut formatter = IntelFormatter::new();
    let mut output = AnsiFormatterOutput::with_masked_literals(
        colors,
        has_unknown_constant,
    );

    formatter.format(instruction, &mut output);
    output.finish()
}

fn disassemble_pattern(
    pattern: &[Option<u8>],
    bitness: u32,
    ip: u64,
) -> Vec<PatternDisasmLine> {
    // Safe only if wildcards are in displacement/immediate fields.
    // Zero is just a decoder placeholder; it never gets printed.
    let decode_bytes = pattern
        .iter()
        .map(|byte| byte.unwrap_or(0))
        .collect::<Vec<_>>();

    let mut decoder = Decoder::with_ip(
        bitness,
        &decode_bytes,
        ip,
        DecoderOptions::NONE,
    );

    let mut lines = Vec::new();

    while decoder.can_decode() {
        let start = decoder.position();
        let instruction = decoder.decode();
        let end = decoder.position();

        if instruction.is_invalid()
            || end <= start
            || end > pattern.len()
        {
            lines.push(PatternDisasmLine {
                ip: ip + start as u64,
                bytes: pattern[start..].to_vec(),
                text: "<unknown instruction>".to_owned(),
            });
            break;
        }

        let instruction_pattern = &pattern[start..end];
        let offsets = decoder.get_constant_offsets(&instruction);

        // If an unknown byte touches the opcode/prefix/ModRM/SIB,
        // the instruction layout itself is not trustworthy.
        let wildcard_touches_encoding = instruction_pattern
            .iter()
            .enumerate()
            .any(|(index, byte)| {
                byte.is_none() && !is_constant_byte(index, &offsets)
            });

        if wildcard_touches_encoding {
            lines.push(PatternDisasmLine {
                ip: instruction.ip(),
                bytes: pattern[start..].to_vec(),
                text: "<unknown instruction: wildcard in opcode/prefix/ModRM/SIB>"
                    .to_owned(),
            });

            // Cannot trust the decoded length after this point.
            break;
        }

        lines.push(PatternDisasmLine {
            ip: instruction.ip(),
            bytes: instruction_pattern.to_vec(),
            text: format_pattern_instruction(
                &instruction,
                instruction_pattern,
            ),
        });
    }

    lines
}

fn is_constant_byte(
    index: usize,
    offsets: &iced_x86::ConstantOffsets,
) -> bool {
    in_range(
        index,
        offsets.displacement_offset(),
        offsets.displacement_size(),
        offsets.has_displacement(),
    ) || in_range(
        index,
        offsets.immediate_offset(),
        offsets.immediate_size(),
        offsets.has_immediate(),
    ) || in_range(
        index,
        offsets.immediate_offset2(),
        offsets.immediate_size2(),
        offsets.has_immediate2(),
    )
}

fn in_range(
    index: usize,
    offset: usize,
    size: usize,
    present: bool,
) -> bool {
    present
        && size != 0
        && index >= offset
        && index < offset + size
}


fn format_pattern_disassembly(
    lines: &[PatternDisasmLine],
    layout: DisasmLayout,
) -> String {
    if lines.is_empty() {
        return "<no decodable instructions>".to_owned();
    }

    match layout {
        DisasmLayout::OneLine => lines
            .iter()
            .map(|line| {
                format!(
                    "{:016X} [{}] {}",
                    line.ip,
                    format_pattern_compact(&line.bytes),
                    line.text,
                )
            })
            .collect::<Vec<_>>()
            .join(" ; "),

        DisasmLayout::MultiLine => {
            const BYTE_COLUMN_WIDTH: usize = 47;

            lines
                .iter()
                .map(|line| {
                    format!(
                        "{:016X}  {:<BYTE_COLUMN_WIDTH$}  {}",
                        line.ip,
                        format_pattern_bytes(&line.bytes),
                        line.text,
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    }
}