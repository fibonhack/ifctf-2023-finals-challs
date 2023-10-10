#!/usr/bin/sage -python

from pwn import remote, logging
from sage.all import GF, vector, Matrix
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
import argparse

logging.disable()

def generate_random_palindromic(nbit=256):
    val = 0
    while val.bit_length() != nbit:
        x = random.randint(0, 2**(nbit//2))
        val = int(str(x) + str(x)[::-1])
    return val

rank = 0
while rank != 254:
    vectors = []
    leak_values = []
    for i in range(256):
        x = generate_random_palindromic()
        v = vector(GF(2), [int(b) for b in bin(x)[2:].rjust(256, '0')])
        vectors.append(v)
        leak_values.append(x)

    M = Matrix(GF(2), vectors)
    rank = M.rank()

def decrypt_flag(solution, encrypted_flag, iv):
    key = sha256(hex(solution).encode()).digest()
    iv_b = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv_b)
    flag = cipher.decrypt(bytes.fromhex(encrypted_flag))
    return flag

def main(hostname, port):
    io = remote(hostname, port)
    io.recvuntil(b'Public point =')
    l = io.recvline()
    io.recvuntil(b'IV =')
    l = io.recvline()
    iv = l.decode().strip()
    io.recvuntil(b'Encrypted flag =')
    l = io.recvline()
    encrypted_flag = l.decode().strip()

    def oracle(a):
        assert a.bit_length() == 256
        assert str(a) == str(a)[::-1]

        io.sendlineafter(b'> ', str(a).encode())
        l = io.recvline()
        return 1 if (b'1' in l) else 0

    B = []
    for v in leak_values:
        b = oracle(v)
        B.append(b)

    B = vector(GF(2), B)

    x0 = M.solve_right(B)
    assert M * x0 == B
    K = M.right_kernel()
    k0, k1 = K.basis()

    # compute all solutions to system of linear equations
    for b0 in range(2):
        for b1 in range(2):
            x = x0 + b0*k0 + b1*k1
            x_bin = ''.join([str(int(bit)) for bit in x])
            x_int = int(x_bin, 2)
            candidate = decrypt_flag(x_int, encrypted_flag, iv)
            if b'ifctf{' in candidate:
                flag = (unpad(candidate, 16).decode())
                if flag == 'ifctf{Just_4_l1ttle_bit_of_l1ne4r_4lg3bra_n0th1ng_t00_str4ng3}':
                    print('OK - read flag from service')
                    exit(0)
    
    print('ERROR - could not get flag')
    exit(2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--hostname')
    parser.add_argument('--port')
    args = parser.parse_args()

    hostname = args.hostname or 'localhost'
    port = int(args.port) if args.port is not None else 10001

    main(hostname, port)
