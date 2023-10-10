#!/usr/bin/env python3
import argparse
from pwn import remote, logging
import string

logging.disable()

leak_count = 0
LEAK_LIMIT = 217


def main(hostname, port):
    try:
        io = remote(hostname, port)
        io.recvuntil(b'Public point =')
        l = io.recvline()
        #print(f'pub = Point({l.decode().strip()})')
        io.recvuntil(b'IV =')
        l = io.recvline()
        #print(f'iv = \'{l.decode().strip()}\'')
        io.recvuntil(b'Encrypted flag =')
        l = io.recvline()
        #print(f'encrypted_flag = \'{l.decode().strip()}\'')

        padding_string = 'A' * 32
        def padding(i, c):
            return padding_string[:32-i-1] + c + padding_string[32-i:]


        ALPHABET = string.ascii_letters + '0123456789'
        def oracle_geq(a):
            assert len(a) == 256 // 8
            assert all([x in ALPHABET for x in a])

            io.sendlineafter(b'> ', a.encode())
            l = io.recvline()
            global leak_count
            leak_count += 1
            return  b'>=' in l

        bits = [-1] * 8 * 32


        io.sendlineafter(b'> ', b'A'*32)


        for i in range(32):
            is_geq = oracle_geq(padding(i, 'a'))
            bits[5 + 8*i] = 0 if is_geq else 1
            is_geq = oracle_geq(padding(i, 'q'))
            bits[4 + 8*i] = 0 if is_geq else 1
            is_geq = oracle_geq(padding(i, 's'))
            bits[1 + 8*i] = 0 if is_geq else 1
            is_geq = oracle_geq(padding(i, 'w'))
            bits[2 + 8*i] = 0 if is_geq else 1

            padding_string = padding_string[:32-i-1] + 'w' + padding_string[32-i:]

        io.sendlineafter(b'> ', b'0'*32)
        l = io.recvline()
        global leak_count
        leak_count += 1

        padding_string = '0' * 32

        sequence = []
        for i in range(32):
            sequence.extend([i, 32-i-1])
        sequence = sequence[:32]

        guess_string = ''.join([str(x) if x >= 0 else '?' for x in  bits[::-1]])

        for i in sequence:
            is_geq = oracle_geq(padding(i, '8'))
            bits[3 + 8*i] = 0 if is_geq else 1
            if leak_count >= LEAK_LIMIT: break

            is_geq = oracle_geq(padding(i, '9'))
            bits[0 + 8*i] = 0 if is_geq else 1
            if leak_count >= LEAK_LIMIT: break

            is_geq = oracle_geq(padding(i, 'y'))
            bits[6 + 8*i] = 0 if is_geq else 1
            if leak_count >= LEAK_LIMIT: break

            padding_string = padding_string[:32-i-1] + 'y' + padding_string[32-i:]

        guess_string = ''.join([str(x) if x >= 0 else '?' for x in  bits[::-1]])

        # pls Orsobruno non mi togliere questi 2 numeri
        # mi serve come controllo a occhio che stia leakando bene
        # potrei scrivere un check apposito ma onestamente zero voglia
        print(f'OK - Service works {guess_string.count("0")}/{guess_string.count("1")}')
        exit(0)

    except Exception as e:
        print(e)
        print('ERROR - could no leak from server')
        exit(2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--hostname')
    parser.add_argument('--port')
    args = parser.parse_args()

    hostname = args.hostname or 'localhost'
    port = int(args.port) if args.port is not None else 5000

    main(hostname, port)