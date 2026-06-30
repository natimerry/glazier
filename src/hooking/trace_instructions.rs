pub mod pattern_traces;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, FormatterOutput, FormatterTextKind, Instruction, IntelFormatter,
};
use log::Level;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisasmLayout {
    OneLine,
    MultiLine,
}

#[derive(Debug, Clone)]
pub struct DisasmLine {
    pub ip: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

pub fn parse_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();

    for raw_token in input.split(|c: char| {
        c.is_whitespace() || matches!(c, ',' | ';' | '[' | ']' | '(' | ')')
    }) {
        let raw_token = raw_token.trim();

        if raw_token.is_empty() {
            continue;
        }

        let token = raw_token
            .strip_prefix("0x")
            .or_else(|| raw_token.strip_prefix("0X"))
            .unwrap_or(raw_token);

        let token = token
            .strip_suffix('h')
            .or_else(|| token.strip_suffix('H'))
            .unwrap_or(token);

        if token.is_empty() {
            return Err(format!("empty hex token in `{raw_token}`"));
        }

        if token.len() % 2 != 0 {
            return Err(format!(
                "hex token `{raw_token}` has an odd number of digits"
            ));
        }

        for pair in token.as_bytes().chunks_exact(2) {
            let pair = std::str::from_utf8(pair)
                .map_err(|_| format!("invalid UTF-8 in `{raw_token}`"))?;

            let byte = u8::from_str_radix(pair, 16)
                .map_err(|_| format!("invalid hex byte `{pair}` in `{raw_token}`"))?;

            bytes.push(byte);
        }
    }

    Ok(bytes)
}

pub fn decode_instruction_sequence(
    bytes: &[u8],
    bitness: u32,
    ip: u64,
    stop_at_terminal: bool,
) -> Vec<Instruction> {
    let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
    let mut instructions = Vec::new();

    while decoder.can_decode() {
        let instruction = decoder.decode();

        if instruction.is_invalid() {
            break;
        }

        let terminal = matches!(
            instruction.flow_control(),
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
        );

        instructions.push(instruction);

        if stop_at_terminal && terminal {
            break;
        }
    }

    instructions
}

pub fn disassemble_bytes(
    bytes: &[u8],
    bitness: u32,
    ip: u64,
    stop_at_terminal: bool,
) -> Vec<DisasmLine> {
    let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
    let mut offset = 0usize;
    let mut lines = Vec::new();

    while decoder.can_decode() && offset < bytes.len() {
        let instruction = decoder.decode();
        let instruction_len = instruction.len();

        // Do not pretend invalid / truncated bytes are valid assembly.
        // Preserve them as raw data instead.
        if instruction.is_invalid()
            || instruction_len == 0
            || offset + instruction_len > bytes.len()
        {
            let remaining = &bytes[offset..];

            lines.push(DisasmLine {
                ip: ip + offset as u64,
                bytes: remaining.to_vec(),
                text: format!(
                    "db {} ; invalid or truncated bytes",
                    format_db_bytes(remaining),
                ),
            });

            break;
        }

        let end = offset + instruction_len;
        let instruction_bytes = bytes[offset..end].to_vec();

        let terminal = matches!(
            instruction.flow_control(),
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
        );

        lines.push(DisasmLine {
            ip: instruction.ip(),
            bytes: instruction_bytes,
            text: format_instruction(&instruction),
        });

        offset = end;

        if stop_at_terminal && terminal {
            break;
        }
    }

    lines
}

pub fn format_disassembly(lines: &[DisasmLine], layout: DisasmLayout) -> String {
    if lines.is_empty() {
        return "<empty>".to_owned();
    }

    match layout {
        DisasmLayout::OneLine => lines
            .iter()
            .map(|line| {
                format!(
                    "{:016X} [{}] {}",
                    line.ip,
                    format_hex_compact(&line.bytes),
                    line.text,
                )
            })
            .collect::<Vec<_>>()
            .join(" ; "),

        DisasmLayout::MultiLine => {
            const BYTE_COLUMN_WIDTH: usize = 47; // 15 bytes: "AA BB ..."

            lines
                .iter()
                .map(|line| {
                    format!(
                        "{:016X}  {:<BYTE_COLUMN_WIDTH$}  {}",
                        line.ip,
                        format_hex_bytes(&line.bytes),
                        line.text,
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    }
}


pub fn log_disassembly(
    label: &str,
    bytes: &[u8],
    bitness: u32,
    ip: u64,
    layout: DisasmLayout,
    level: Level,
    stop_at_terminal: bool,
) {
    let lines = disassemble_bytes(bytes, bitness, ip, stop_at_terminal);
    let listing = format_disassembly(&lines, layout);


    match layout {
        DisasmLayout::OneLine => {
            log::log!(level,"{}: {}", color_label(label), listing);
        }

        DisasmLayout::MultiLine => {
            log::log!(level,"{}:\n{}", color_label(label), listing);
        }
    }
}

pub fn format_instruction(instruction: &Instruction) -> String {
    let colors = std::env::var_os("NO_COLOR").is_none();

    let mut formatter = IntelFormatter::new();
    let mut output = AnsiFormatterOutput::new(colors);

    formatter.format(instruction, &mut output);
    output.finish()
}

// Keep this so your existing relocation logger still works unchanged.
pub fn format_instruction_sequence(instructions: &[Instruction]) -> String {
    let separator = if std::env::var_os("NO_COLOR").is_some() {
        "; "
    } else {
        " \x1b[2m;\x1b[0m "
    };

    instructions
        .iter()
        .map(format_instruction)
        .collect::<Vec<_>>()
        .join(separator)
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_hex_compact(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>()
}

fn format_db_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("0x{byte:02X}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn color_label(label: &str) -> String {
    if std::env::var_os("NO_COLOR").is_some() {
        label.to_owned()
    } else {
        format!("\x1b[1;35m{label}\x1b[0m")
    }
}

struct AnsiFormatterOutput {
    text: String,
    colors: bool,
    mask_literals: bool,
}

impl AnsiFormatterOutput {
    fn new(colors: bool) -> Self {
        Self {
            text: String::new(),
            colors,
            mask_literals: false,
        }
    }

    fn with_masked_literals(
        colors: bool,
        mask_literals: bool,
    ) -> Self {
        Self {
            text: String::new(),
            colors,
            mask_literals,
        }
    }

    fn finish(self) -> String {
        self.text
    }
}
use colored::{Color, Colorize};


impl FormatterOutput for AnsiFormatterOutput {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let is_literal_value = matches!(
            kind,
            FormatterTextKind::Number
                | FormatterTextKind::LabelAddress
                | FormatterTextKind::FunctionAddress
                | FormatterTextKind::SelectorValue
        );

        if !self.colors {
            self.text.push_str(if self.mask_literals && is_literal_value {
                "<disp>"
            } else {
                text
            });
            return;
        }

        if self.mask_literals && is_literal_value {
            self.text.push_str(
                &"<disp>"
                    .bright_white()
                    .on_bright_red()
                    .to_string(),
            );
            return;
        }

        let color = match kind {
            FormatterTextKind::Mnemonic | FormatterTextKind::Prefix => Color::BrightYellow,
            FormatterTextKind::Register => Color::BrightCyan,

            FormatterTextKind::Number
            | FormatterTextKind::LabelAddress
            | FormatterTextKind::FunctionAddress
            | FormatterTextKind::SelectorValue => Color::BrightGreen,

            FormatterTextKind::Keyword | FormatterTextKind::Decorator => Color::BrightBlue,

            FormatterTextKind::Operator | FormatterTextKind::Punctuation => Color::White,

            _ => Color::White,
        };

        if color == Color::White {
            self.text.push_str(text);
        } else {
            self.text.push_str(&text.color(color).to_string());
        }
    }
}