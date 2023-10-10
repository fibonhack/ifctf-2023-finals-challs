#!/usr/bin/env python3
from pwn import process, remote, logging, context
from base64 import b64decode
import argparse
from pathlib import Path

logging.disable()
# context.log_level = 'debug'

PROGRAM_PATH = "/tmp/program.compiled"


def main(hostname, port):
    io = remote(hostname, port)
    io.recvuntil(b'parameters: ')
    n, g = map(int, io.recvline().strip().split(b', '))
    io.sendline(b'')
    io.recvuntil(b'...')
    program = io.recvline()

    program = b64decode(program).decode()
    # print('program length:', len(program))

    with open(PROGRAM_PATH, 'w') as f:
        f.write(program)

    # print(f"{n=}")
    # print(f"{g=}")

    vm = process([str(Path(__file__).parent.parent / 'src' / 'vm' / 'vm'), PROGRAM_PATH, str(n), str(g)])
    l = vm.recvall()
    result = int(l.split(b'\n')[0].split(b' ')[-1].decode())

    io.sendlineafter(b'result:', str(result).encode())
    output = io.recvall()
    if b'That is correct' in output:
        print('OK - service works')
        exit(0)
    print('ERR - Does not work')
    exit(2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--hostname')
    parser.add_argument('--port')
    args = parser.parse_args()

    hostname = args.hostname or 'localhost'
    port = int(args.port) if args.port is not None else 10001

    main(hostname, port)
