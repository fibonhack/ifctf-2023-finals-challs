import random
import re

p = 7

with open("tha_regex.txt", "r") as f:
    r = f.read()

r = re.compile(str(r))

for i in range(5):
    # test matching
    x = random.randint(0, 2**64)
    y = random.randint(0, 2**64)
    z = random.randint(0, 2**64)
    t = random.randint(0, 2**64) * p + ((x * y + z) % p)

    assert (x * y + z) % p == t % p

    s = f"{bin(x)[2:]}*{bin(y)[2:]}+{bin(z)[2:]}={bin(t)[2:]}"
    print(f"testing {s}")
    matches = r.fullmatch(s) is not None

    assert matches

    # test non matching
    x = random.randint(0, 2**64)
    y = random.randint(0, 2**64)
    z = random.randint(0, 2**64)
    t = random.randint(0, 2**64) * p + ((x * y + z) % p) + random.randint(1, p - 1)

    assert (x * y + z) % p != t % p

    s = f"{bin(x)[2:]}*{bin(y)[2:]}+{bin(z)[2:]}={bin(t)[2:]}"
    print(f"testing {s}")
    matches = r.fullmatch(s) is not None

    assert not matches
