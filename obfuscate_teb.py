import random

MASK64 = (1 << 64) - 1


def rand64():
    return random.getrandbits(64) & MASK64


def make_numeric_label():
    """Generate a numeric label suitable for Rust inline assembly."""
    s = "1"
    while s[0] == "1":
        s = str(random.randint(2, 99))
    return s


def emit_simple_xor_obfuscated(a_reg, b_val, dest_reg="rax"):
    """
    Obfuscate XOR using the identity: a XOR b = (a OR b) - (a AND b)
    This is mathematically correct and simpler than MBA
    """
    asm = []
    temp1 = "r8"
    temp2 = "r9"
    temp3 = "r10"

    # Load b into temp1
    asm.append(f"mov {temp1}, 0x{b_val:016x}")

    if a_reg != dest_reg:
        asm.append(f"mov {dest_reg}, {a_reg}")

    # temp2 = a OR b
    asm.append(f"mov {temp2}, {dest_reg}")
    asm.append(f"or {temp2}, {temp1}")

    # temp3 = a AND b
    asm.append(f"mov {temp3}, {dest_reg}")
    asm.append(f"and {temp3}, {temp1}")

    # dest = (a OR b) - (a AND b) = a XOR b
    asm.append(f"mov {dest_reg}, {temp2}")
    asm.append(f"sub {dest_reg}, {temp3}")

    return asm


def emit_control_flow_junk(depth=2):
    """Generate some control flow obfuscation"""
    asm = []
    label = make_numeric_label()

    for i in range(depth):
        asm.append(f"{label}:")
        if random.choice([True, False]):
            asm.append(f"cmp rax, rax")
            asm.append(f"je {label}f")
        else:
            fake_label = make_numeric_label()
            asm.append(f"test rcx, 0x{random.randint(1, 0xFFFF):x}")
            asm.append(f"jnz {fake_label}f")
            asm.append(f"jmp {label}f")
            asm.append(f"{fake_label}:")
            asm.append(f"nop")
            asm.append(f"jmp {label}f")

    asm.append(f"{label}:")
    return asm


def emit_dummy_moves(count=5):
    """Generate dummy register moves"""
    asm = []
    dummy_regs = ["r13", "r14", "rsi", "rdi", "rdx"]
    for _ in range(count):
        reg = random.choice(dummy_regs)
        val = rand64()
        asm.append(f"mov {reg}, 0x{val:016x}")
    return asm


def emit_dispatcher_block(blocks, state_reg="r15"):
    """Generate a state machine dispatcher"""
    DISPATCHER_LOOP = make_numeric_label()
    DISPATCHER_END = make_numeric_label()

    asm = []
    asm.append(f"mov {state_reg}, 0")
    asm.append(f"{DISPATCHER_LOOP}:")

    block_labels = [make_numeric_label() for _ in range(len(blocks))]

    # Dispatcher comparisons
    for i in range(len(blocks)):
        asm.append(f"cmp {state_reg}, {i}")
        asm.append(f"je {block_labels[i]}f")

    asm.append(f"jmp {DISPATCHER_END}f")

    # Generate blocks
    for i, (_, block_asm, next_state) in enumerate(blocks):
        asm.append(f"{block_labels[i]}:")
        asm.extend(block_asm)
        if next_state == -1:
            asm.append(f"jmp {DISPATCHER_END}f")
        else:
            asm.append(f"mov {state_reg}, {next_state}")
            asm.append(f"jmp {DISPATCHER_LOOP}b")

    asm.append(f"{DISPATCHER_END}:")
    asm.extend(emit_dummy_moves(random.randint(3, 14)))
    return asm


def emit_teb_reader():
    """
    Generate obfuscated code that computes 0x30 and reads from gs:[0x30]
    TEB offset 0x30 contains the ProcessEnvironmentBlock pointer on x64 Windows
    """
    target = 0x30

    # Block 0: Compute 0x30 using obfuscated XOR
    block0 = []
    a = rand64()
    b = a ^ target  # b XOR a = target
    block0.append(f"mov rax, 0x{a:016x}")
    block0.extend(emit_simple_xor_obfuscated("rax", b, "rax"))
    block0.extend(emit_control_flow_junk(depth=5))

    # Block 1: Identity operation (XOR with random value twice)
    block1 = []
    k1 = rand64()
    block1.append(f"mov r8, 0x{k1:016x}")
    # XOR twice = identity
    block1.extend(emit_simple_xor_obfuscated("rax", k1, "rax"))
    block1.extend(emit_simple_xor_obfuscated("rax", k1, "rax"))
    block1.extend(emit_control_flow_junk(depth=5))

    # Block 2: Identity operation (add then subtract)
    block2 = []
    k2 = rand64()
    block2.append(f"mov r13, 0x{k2:016x}")
    block2.append(f"add rax, r13")
    block2.append(f"sub rax, r13")
    block2.extend(emit_control_flow_junk(depth=14))

    # Block 3: Read from GS:[RAX] (RAX should be 0x30)
    block3 = []
    block3.append(f"mov {{out}}, gs:[rax]")
    block3.extend(emit_dummy_moves(random.randint(40, 500)))

    blocks = [
        ("", block0, 1),
        ("", block1, 2),
        ("", block2, 3),
        ("", block3, -1),
    ]

    return emit_dispatcher_block(blocks)


if __name__ == "__main__":
    import io
    import sys

    if sys.platform == "win32":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")

    random.seed()
    output = emit_teb_reader()

    generate_full_function = "--rust-function" in sys.argv

    if generate_full_function:
        # Generate complete Rust function
        print("// Auto-generated - do not edit")
        print('#[cfg(target_arch = "x86_64")]')
        print("#[inline(never)]")
        print("pub unsafe fn get_teb() -> *mut TEB { unsafe {")
        print("    let teb: *mut TEB;")
        print("    core::arch::asm!(")

        # Print assembly lines
        for line in output:
            if not line.strip().startswith(";"):
                print(f'        "{line}",')

        print("        out=out(reg) teb,")
        print("        options(nostack, volatile)")
        print("    );")
        print('assert!(teb as usize != 0, "TEB pointer xis null");')
        print("    teb")
        print("}}")
    else:
        # Just output assembly lines for manual copying
        for line in output:
            if not line.strip().startswith(";"):
                print(f'"{line}",')

        print("Total INSTRUCTIONS:", len(output))
