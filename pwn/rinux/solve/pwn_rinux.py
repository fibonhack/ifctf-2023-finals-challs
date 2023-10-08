#!/usr/bin/env python3
from pwn import remote, log, logging
from argparse import ArgumentParser
from pathlib import Path


logging.disable()


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


def trying(hostname: str, port: int):
    io = remote(hostname, port)
    do_pow(io)
    rootfs = Path(__file__).parent / "rootfs.cpio"

    with open(str(rootfs), "rb") as infile:
        content = infile.read()

    io.sendlineafter(
        b"only 'GABIBBOGABIBBOGABIBBOGABIBBO'",
        content.hex().encode(),
    )
    io.sendline(b"GABIBBOGABIBBOGABIBBOGABIBBO")

    io.recvuntil(b"Entering syscall Write")
    flag = io.recvlines(3)
    for line in flag:
        if b"ifctf" in line:
            line = line.replace(b"\x00", b"").decode()
            log.success(f"{line = :}")
            print("OK - Flag found")
            exit(0)
    io.close()


def main(hostname, port):
    for _ in range(1):
        trying(hostname, port)
    print("ERROR - could not retrieve the flag")
    exit(2)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('--hostname', type=str, default="localhost")
    parser.add_argument('--port', type=int, default=10001)
    args = parser.parse_args()

    main(args.hostname, args.port)
