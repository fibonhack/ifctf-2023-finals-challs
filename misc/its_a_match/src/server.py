#!/usr/local/bin/python3 -u

import re
import random
from secret import FLAG
import zlib
from base64 import b64decode
import sys

HEADER = """

    .___  __ /\                                 __         .__   ._.
    |   |/  |)/ ______ _____      _____ _____ _/  |_  ____ |  |__| |
    |   \   __\/  ___/ \__  \    /     \\\\__  \\\\   __\/ ___\|  |  \ |
    |   ||  |  \___ \   / __ \_ |  Y Y  \/ __ \|  | \  \___|   Y  \|
    |___||__| /____  > (____  / |__|_|  (____  /__|  \___  >___|  /_
                   \/       \/        \/     \/          \/     \/\/


Please send me a regular expressions that matches strings of the form "x*y+z=t",
where x, y, z and t are arbitrarily long binary numbers, and the regular expression
matches if and only if x*y + z = t mod 7 holds.

For example:
- "100*1111+101=1001" should match because 4*15 + 5 = 9 (mod 7)
- "100*1111+101=100" should not match because 4*15 + 5 != 4 (mod 7)

Timeout is 120 seconds for all the tests, good luck!
"""
print(HEADER)

try:
    r = zlib.decompress(b64decode(input('> '))).decode()
except:
    print('An error occurred')
    exit(0)

if '(?' in r:
    print('Please, do not use extensions! Only *regular* expressions are allowed.')
    exit(0)

print('Compiling...')
r = re.compile(r)

p = 7
TEST_SIZES = [4, 4, 6, 6, 8, 8, 12, 12, 16, 16, 32, 32, 64, 64]
for i, test_bits in enumerate(TEST_SIZES):
    x = random.randint(0, 2**test_bits)
    y = random.randint(0, 2**test_bits)
    z = random.randint(0, 2**test_bits)

    if i%2 == 0:
        # test matching
        t = random.randint(0, 2**test_bits) * p + ((x*y + z) % p)
        assert (x*y + z) % p == t % p
        expected_matches = True
    else:
        # test non matching
        t = random.randint(0, 2**test_bits) * p + ((x*y + z) % p) + random.randint(1, p-1)
        assert (x*y + z) % p != t % p
        expected_matches = False

    s = f'{bin(x)[2:]}*{bin(y)[2:]}+{bin(z)[2:]}={bin(t)[2:]}'

    print(f'[{i+1}/{len(TEST_SIZES)}] Testing the input "{s}"')
    
    matches = r.fullmatch(s) is not None
    if matches != expected_matches:
        print('Sorry, you need to match harder!')
        exit(0)

print('Congratulations! Here is the flag:', FLAG)

