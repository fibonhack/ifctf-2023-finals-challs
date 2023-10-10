from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa.keys import gen_keypair
from Crypto.Random import random
from tqdm import tqdm
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

# leaked from server

pub = Point(0xe2586c8c4ea8044ed2e423444cf3be3aec41bc56114b00c43774b41e6a717ad4, 0xbe7596642b7598dc4783b728f0ae9eb91871007442df2eb715fd1a9ef1d590fb)
iv = '32d16a9e573b97f621425fb431f385c6'
encrypted_flag = 'e44827fabfdc48cfb2f01355cfa60afd04f9bac39da3a9e2ef26494c73a923b012692a466313afd021d13e34ffcf936e88c3147e948bb63ba62be200fea7a62b'
# Bruteforce 40 bits
leak = '?0011110?0110100?0011101?0001000?0011100?0010111?1001001?0111000?0001000?0110001?1101000?0111000?0111110?0101101??11111???11?11???00?00??0110111?0011011?1100110?0011101?0000110?0010011?0101101?1101010?1110100?0111001?0110001?0101001?1111010?0101110?1111001'

print(leak)
half_len = len(leak) // 2 - 1 # -1 is to balance 40 unknown bits to be 20 and 20 for the two steps

low_part = leak[half_len:]
print('low part', low_part)
unknown_bits_low = low_part.count('?')

unknown_bits_pos = []
for i in range(len(low_part)):
    if low_part[i] == '?':
        unknown_bits_pos.append(len(low_part) - i - 1)

base = int(low_part.replace('?', '0'), 2)

m = 2**len(low_part)

table = {}
# baby step
for i in tqdm(range(2**unknown_bits_low)):
    bin_i = bin(i)[2:].rjust(unknown_bits_low, '0')
    val = base
    for i, value in zip(unknown_bits_pos, bin_i):
        #print(i, value)
        if value == '1':
            val += 1 << i
    table[(val * P256.G).x] = val

high_part = leak[:half_len]
print('high part', high_part)
unknown_bits_high = high_part.count('?')

unknown_bits_pos = []
for i in range(len(high_part)):
    if high_part[i] == '?':
        unknown_bits_pos.append(len(high_part) - i - 1)

base = int(high_part.replace('?', '0'), 2)

# giant step
alpha = (-m) * P256.G
for i in tqdm(range(2**unknown_bits_high)):
    bin_i = bin(i)[2:].rjust(unknown_bits_high, '0')
    val = base
    for i, value in zip(unknown_bits_pos, bin_i):
        if value == '1':
            val += 1 << i
    
    gamma = pub + alpha * val
    
    if gamma.x in table:
        solution = val * m + table[gamma.x]
        print('found!', solution)
        break

assert solution * P256.G == pub


key = sha256(hex(solution).encode()).digest()
iv = bytes.fromhex(iv)
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = cipher.decrypt(bytes.fromhex(encrypted_flag))
print(unpad(flag, 16).decode())
