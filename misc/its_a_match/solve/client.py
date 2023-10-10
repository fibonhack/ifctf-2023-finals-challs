#!/usr/bin/env python3
import zlib
from base64 import b64encode
import argparse
import time

from pathlib import Path
from pwn import process, remote, context

context.log_level = 'debug'


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
    re = open(Path(__file__).parent / "tha_regex.txt", "r").read()

    io.recvuntil(b'good luck!')
    io.sendline(b64encode(zlib.compress(re.encode())))
    io.interactive()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--hostname')
    parser.add_argument('--port')
    args = parser.parse_args()

    hostname = args.hostname or 'localhost'
    port = int(args.port) if args.port is not None else 10001

    main(hostname, port)
