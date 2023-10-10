from Crypto.Util.number import isPrime
import random
from sage.all import factor

rand = random.SystemRandom()

def get_next_prime(n):
    while True:
        n += 1
        if isPrime(n):
            return n

def generate_smooth_prime(bits):
    # using the first primes in sequence to generate a smooth prime
    s = 200
    primes = []
    bits_obt = 0
    while bits_obt < int(bits/4):
        s = get_next_prime(s)
        primes.append(s)
        bits_obt += s.bit_length()

    p=1
    # select a random subset of primes to multiply to get a p with the desired bit length
    while p.bit_length() != bits:
        p = 2
        # selected = []
        already_used = set()
        while p.bit_length() < bits:
            s = rand.choice(primes)
            while s in already_used:
                s = rand.choice(primes)
            p *= s
            # already_used.add(s)
            # selected.append(s)
        p = p+1
        if not isPrime(p):
            p = 1
            continue
        
    return p

def get_g(n, phi, phi_fact):
    for g in range(2,10000):
        for (f,e) in phi_fact:
            if pow(g, phi//f, n) == 1:
                break
        else:
            return g
    else:
        raise Exception("no g found")


n = generate_smooth_prime(1024)
phi = n-1
phi_fact = factor(phi)
g = get_g(n, phi, phi_fact)

# generate until we get suitable parameters

# n = 112342157362030661625451381477943769703920310909613461265945018454079128130272126671887377675187527897989307201597065257898023493898453514665847255328223468902411201380480377953140160543715352538701530618677076422209538558032942269050554760335192020050191035641977065491034725417594789267193731406476074779047
# phi = n-1
# phi_fact = [(2, 1), (211, 5), (223, 9), (227, 4), (229, 2), (233, 2), (239, 2), (241, 4), (251, 4), (257, 3), (263, 3), (269, 7), (271, 6), (277, 3), (281, 6), (283, 4), (293, 3), (307, 7), (311, 7), (313, 3), (317, 3), (331, 4), (337, 3), (347, 5), (349, 5), (353, 3), (359, 2), (367, 2), (373, 5), (379, 2), (383, 7)]
