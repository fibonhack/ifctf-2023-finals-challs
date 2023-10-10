#!/usr/local/bin/python3

from fastecdsa.curve import P256
from fastecdsa.keys import gen_keypair
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha256
import os
import string

from secret import FLAG

d, pub = gen_keypair(P256)
assert len(long_to_bytes(d)) == 256 // 8, "Private key too short"

key = sha256(hex(d).encode()).digest()
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
enc_flag = cipher.encrypt(pad(FLAG.encode(), 16))

print(f'Public point = {hex(pub.x)}, {hex(pub.y)}')
print(f'IV = {iv.hex()}')
print(f'Encrypted flag = {enc_flag.hex()}')


ALPHABET = string.ascii_letters + '0123456789'
def craft_leak(data):
    assert len(data) == 256 // 8
    assert all([x in ALPHABET for x in data])

    result = bytes([c&b for c, b in zip(data.encode(), long_to_bytes(d))])
    return bin(bytes_to_long(result)).count('1')

prev_data = input('> ')
for _ in range(217):
    data = input('> ')
    a = craft_leak(prev_data)
    b = craft_leak(data)
    print('A < B' if a < b else 'A >= B')
    prev_data = data
