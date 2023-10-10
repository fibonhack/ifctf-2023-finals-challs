# Leak as a service revenge

## TL;DR

It is possible to craft a sequence of inputs to the server to leak all but 40 known bits of the private key.
We can then compute the ecdlog in a few minutes using a meet-in-the-middle approach.

## Differences with Leak as a service

The only differences are that now the inputs are bytes, and all the bytes must be in the alphabet
```py
ALPHABET = string.ascii_letters + '0123456789'
```

and the leak is not given directly, but it is a boolean value: it computes the count of ones in the bitwise and between the private key and the data provided, and compares it to the previous count.

```py
data = input('> ')
a = craft_leak(prev_data)
b = craft_leak(data)
print('A < B' if a < b else 'A >= B')
```

## Leaking strategy

The basic observation is that we can leak deterministically one bit only if the difference between the previous input and the current input is one bit that has flipped from 0 to 1.
We need to find some sequences in the alphabet with that property, and we can use some code like

```py
max_length = 0
max_length_list = []
bits_leaked_max = []

def find_recursive_paths(value, curr_path=[], bits_leaked=[]):
    for i in range(1, 8):
        if value & (1 << i) == 0:
            new_value = value | (1 << i)
            if chr(new_value) in ALPHABET:
                find_recursive_paths(new_value, curr_path=curr_path+[new_value], bits_leaked=bits_leaked+[i])
    
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
```

After some fiddling around, we can find two sequences that leak 4 and 3 complementary bits:

```
   vv vv
0b1000001 A
0b1100001 a
0b1110001 q
0b1110011 s
0b1110111 w

  v  v  v
0b0110000 0
0b0111000 8
0b0111001 9
0b1111001 y
```

So the idea is:
- set the initial state to all `'A'`
- leak byte by byte 4 bits using the first chain
- reset the internal state to all `'0'` by loosing one leak
- leak the other 3 bits using the second chain

## Taking the dlog

At this point we have some private key where 40 bits are missing, like so

```py
leak = '?0011110?0110100?0011101?0001000?0011100?0010111?1001001?0111000?0001000?0110001?1101000?0111000?0111110?0101101??11111???11?11???00?00??0110111?0011011?1100110?0011101?0000110?0010011?0101101?1101010?1110100?0111001?0110001?0101001?1111010?0101110?1111001'
```

We can implement a modified version of baby-step giant-step to deal with missing bits across the private key. It is essentially equal to the original algorithm, but the private key is split in half for the two steps, and $m$ is taken to be something like $2^{128}$.
