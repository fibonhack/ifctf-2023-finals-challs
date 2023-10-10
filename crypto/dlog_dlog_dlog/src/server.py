#!/usr/local/bin/python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
import hashlib

from secret import FLAG

assert FLAG.startswith(b"ifctf{")
assert FLAG.endswith(b"}")
assert len(FLAG) == 53

n = 112342157362030661625451381477943769703920310909613461265945018454079128130272126671887377675187527897989307201597065257898023493898453514665847255328223468902411201380480377953140160543715352538701530618677076422209538558032942269050554760335192020050191035641977065491034725417594789267193731406476074779047
g = 5

FLAG = bytes_to_long(FLAG)
def handle():
    print(f"{n = }")
    print(f"{g = }")    
    glag = pow(g, FLAG, n)
    i = 1
    while True:
        e = int(input("Enter e:"))
        k = pow(glag, e, n)
        h = hashlib.sha256(long_to_bytes(k)).hexdigest()
        i+=1
        print(h[:2])

if __name__ == "__main__":
    handle()