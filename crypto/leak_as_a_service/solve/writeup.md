# Leak as a service

## TL;DR

It is possible to construct a set of vector over $GF(2)$ such that their base-10 representation is palindromic, and have rank 254.
It is then possible to find the private key by iterating on the four possible solutions of the linear system of equations constructed using the leaks from the server.

## The challenge

in the challenge we can request 256 leaks, we need to send an integer and the following checks are made
```py
assert value.bit_length() == 256
assert str(value) == str(value)[::-1]
```

so the integer must have 256 bit exactly and its base-10 representation must be palindromic.
The leak is constructed as

```py
result = bytes([c&b for c, b in zip(long_to_bytes(value), long_to_bytes(d))])
return bin(bytes_to_long(result)).count('1') % 2
```

and we can see that this is basically a dot product of the private key with the provided integer, with the bits seen as elements of $GF(2)$.
Our objective is to construct a basis of this vector space and then solve the linear system of equations.

Luckily we can generate randomly vectors such that the integer representation is palindromic, and quickly we can find a set of vectors of rank 254
```py
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
```

Then we send those values to the server, save the results, solve the linear system, iterate over the four possible solutions and check if we found the flag.