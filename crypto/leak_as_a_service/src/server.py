#!/usr/local/bin/python3

from fastecdsa.curve import P256
from fastecdsa.keys import gen_keypair
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha256
import os
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


def craft_leak(value):
    assert value.bit_length() == 256
    assert str(value) == str(value)[::-1]
    
    result = bytes([c&b for c, b in zip(long_to_bytes(value), long_to_bytes(d))])
    return bin(bytes_to_long(result)).count('1') % 2

for _ in range(256):
    data = int(input('> '))
    print('Your leak is:', craft_leak(data))
