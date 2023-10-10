import z3
from pwn import remote
import string


io = remote('localhost', 1234)
io.recvuntil(b'Public point =')
l = io.recvline()
print(f'pub = Point({l.decode().strip()})')
io.recvuntil(b'IV =')
l = io.recvline()
print(f'iv = \'{l.decode().strip()}\'')
io.recvuntil(b'Encrypted flag =')
l = io.recvline()
print(f'encrypted_flag = \'{l.decode().strip()}\'')

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

leak_count = 0
LEAK_LIMIT = 217
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
print(f'# Bruteforce {guess_string.count("?")} bits')
print('leak = \'' + guess_string + '\'')


"""
The idea is:
leak 4 bits (1, 2, 4, 5) with chain Aaqsw
in total 32 * 4 = 128 bits are leaked, this takes exactly 128 leaks.

   vv vv
0b1000001 A
0b1100001 a -> 5
0b1110001 q -> 4
0b1110011 s -> 1
0b1110111 w -> 2

Reset all bytes to 0, +1 leak, discard.

Then we need to leak 3 more bits (0, 3, 6)
  v  v  v
0b0110000 0
0b0111000 8
0b0111001 9
0b1111001 y

this process in 217 leaves 40 bit unknown, which can be bruteforced with a modified version
of baby-step giant-step.

These sequences can be found by the code below:

max_length = 0
max_length_list = []
bits_leaked_max = []

def find_recursive_paths(value, curr_path=[], bits_leaked=[]):
    for i in range(1, 8):
        if value & (1 << i) == 0:
            new_value = value | (1 << i)
            # print(bin(new_value))
            if chr(new_value) in ALPHABET:
                find_recursive_paths(new_value, curr_path=curr_path+[new_value], bits_leaked=bits_leaked+[i])
    
    # print(curr_path)
    global max_length, max_length_list, bits_leaked_max
    
    if len(curr_path)== 4:
        print('--------------------------------------')
        print(curr_path)
        print(bits_leaked)
        for x in curr_path:
            print(bin(x), chr(x))

        max_length = len(curr_path)
        max_length_list = curr_path[::]
        bits_leaked_max = bits_leaked[::]

for c in ALPHABET:
    find_recursive_paths(ord(c), [ord(c)])

print('--------------------------------------')
print(max_length)
print(max_length_list)
print([chr(x) for x in max_length_list])
for x in max_length_list:
    print(bin(x), chr(x))
print(bits_leaked_max)
exit()

"""


