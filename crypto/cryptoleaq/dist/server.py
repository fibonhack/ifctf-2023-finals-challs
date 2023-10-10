#!/usr/local/bin/python3

from secret.compiler import CryptoleqCompiler
from Crypto.Util.number import bytes_to_long, long_to_bytes
from base64 import b64encode
import random
from Crypto.Util.number import getStrongPrime
from math import gcd

from secret.flag import FLAG
assert len(FLAG) == 32

class Pailler:
    def __init__(self, bit_length_primes):
        self._p = getStrongPrime(bit_length_primes)
        self._q = getStrongPrime(bit_length_primes)
        self.n = self._p * self._q
        
        self.g = 1 + self.n
        self.n_square = self.n * self.n
        
        self._phi = (self._p - 1) * (self._q - 1)
        self._mu = pow(self._phi, -1, self.n)
    
    def get_pub(self):
        return (self.n, self.g)
    
    def encrypt(self, m):
        assert m < self.n

        r = random.randint(1, self.n-1)
        while gcd(r, self.n) != 1:
            r = random.randint(1, self.n-1)

        return (pow(self.g, m, self.n_square) * pow(r, self.n, self.n_square)) % self.n_square

    def decrypt(self, c):
        m = (pow(c, self._phi, self.n_square) - 1) // self.n
        return (m * self._mu) % self.n


def main():
    cipher = Pailler(512)

    flag_blocks = [FLAG[i:i+8] for i in range(0, len(FLAG), 8)]

    flag_ns = [bytes_to_long(x.encode()) for x in flag_blocks]
    retrieve_index = random.randint(0, len(flag_ns)-1)

    # generate inputs suitable to homomorphically compute flag_ns[retrieve_index]
    retrieve_vector = [cipher.n-i-1 for i in range(len(flag_ns))]
    retrieve_vector[retrieve_index] = 1

    for block in flag_ns:
        assert block < cipher.n

    encs_flag = [cipher.encrypt(block) for block in flag_ns]
    enc_indexes = [cipher.encrypt(x) for x in retrieve_vector]

    # compile the program
    comp = CryptoleqCompiler(*cipher.get_pub())

    # the compiler needs it to implement G
    comp.set_private_param((cipher._phi * cipher._mu) % cipher.n_square)

    with open('program.subleq') as f:
        program = f.read()

    # compile the program, embedding the input values
    compiled = comp.compile(program, {
        'flag0': encs_flag[0],
        'flag1': encs_flag[1],
        'flag2': encs_flag[2],
        'flag3': encs_flag[3],
        'idx0': enc_indexes[0],
        'idx1': enc_indexes[1],
        'idx2': enc_indexes[2],
        'idx3': enc_indexes[3],
    })

    print('Dear untrusted user, could you please execute this program for me?')
    print('You will retrieve a piece of the flag, but I will not tell you which one!')
    print('In fact, both the items and the index to retrieve are encrypted, so you can\'t know which one you are retrieving!')
    print('Isn\'t that cool?')
    print(f'Here are the public parameters: {cipher.get_pub()[0]}, {cipher.get_pub()[1]}')

    input('Press enter to continue...')
    print(b64encode(compiled.encode()).decode())

    user_result = int(input('Please enter the result: '))
    result = cipher.decrypt(user_result)

    if result == flag_ns[retrieve_index]:
        print('That is correct, thank you for giving me the answer!')
        print('What? You want the flag? I don\'t know what you are talking about...')
    else:
        print('That is not correct, I knew I shouldn\'t trust you!')

if __name__ == '__main__':
    main()