#!/usr/bin/sage -python

from pwn import remote, logging

from sage.all import crt, lcm, prod
from Crypto.Util.number import long_to_bytes, bytes_to_long
import hashlib
import itertools
import argparse

logging.disable()


n = 112342157362030661625451381477943769703920310909613461265945018454079128130272126671887377675187527897989307201597065257898023493898453514665847255328223468902411201380480377953140160543715352538701530618677076422209538558032942269050554760335192020050191035641977065491034725417594789267193731406476074779047
phi = n-1
phi_fact = [(2, 1), (211, 5), (223, 9), (227, 4), (229, 2), (233, 2), (239, 2), (241, 4), (251, 4), (257, 3), (263, 3), (269, 7), (271, 6), (277, 3), (281, 6), (283, 4), (293, 3), (307, 7), (311, 7), (313, 3), (317, 3), (331, 4), (337, 3), (347, 5), (349, 5), (353, 3), (359, 2), (367, 2), (373, 5), (379, 2), (383, 7)]

io = None

def req(e):
    io.sendlineafter(b'Enter e:', str(e).encode())
    line = io.recvline().strip().decode()
    return bytes.fromhex(line)

def fun(g):
    return bytes.fromhex(hashlib.sha256(long_to_bytes(g)).hexdigest()[:2])

def search(g, h, n, f, ex = lambda x: x):
    sol = []
    for i in range(f):
        # print("check", i, ex(pow(g,i,n)))
        if fun(ex(pow(g,i,n))) == h:
            # print("found", ex(pow(g,i,n)))
            sol.append(i)
    return sol


def pohlig_hellman_pp(g, n, phi, p, e):
    mod = phi // pow(p,e)
    xs = [0]
    y = pow(g, pow(p, e-1, phi), n)
    #print(pow(g, 1, n))
    #print(f"{y = }")
    for k in range(e):
        # hk = pow(h * pow(g,-x,n) % n, pow(p, e-k-1, phi), n)
        # y^dk = (h * g^(-x))^ex
        # y^dk = h^ex * g^(-x*ex)
        # y^dk * g^(x*ex) = h^ex
        xss = []
        for x in xs:
            ex = pow(p, e-k-1, phi)
            hk = req(ex*mod % phi)
            exx = pow(g, x*ex, n)
            # yy = y * pow(pow(g,-x,n), -ex, n) % n
            # print(f"bsgs {y}**dk == {hk} mod n, f={p}")
            dk = search(y, hk, n, p, lambda x: ( x*exx ) % n)
            # print(dk)
            if len(dk) == 0:
                continue
            for d in dk:
                xss.append(int((x+d*pow(p, k)) % phi))
        if xss == []:
            return None
        xs = xss
        # print(f"{dk = }")
    return xs

def pohlig_hellman(g, n, phi, factors_phi):
    rs = []
    ms = []
    h = req(1)
    # print(f"Pohlig Hellman: {g}**x = {h} mod {n}")
    # print(f"{phi = }")
    for i, (p,e) in enumerate(factors_phi):
        p = int(p)
        e = int(e)
        gamma = pow(g, phi // p, n)
        while gamma == 1:
            phi = phi // p
            e = e-1
            if e == 0:
                # print(gamma)
                # print("fail -----")
                break
            gamma = pow(g, phi // p, n)
        factors_phi[i] = (p,e)

    for f in factors_phi:
        p = int(f[0])
        e = int(f[1])
        xi = None
        # print(p,e)
        # print("y = ",pow(g, pow(p, e-1, phi), n))
        f = pow(p,e)
        # print(f"factor: {p}^{e} = {f}")
        mod = phi // f
        gi = pow(g, mod, n)
        hi = req(mod) # pow(h, mod, n)
        # print(f"{gi}**xi = {hi} mod {n}")
        xi = pohlig_hellman_pp(gi, n, phi, p, e)
        if xi is None:
            #print("fail")
            return None
        else:
            if xi is not None:
                rs.append(xi)
                ms.append(f)
                # print(f"{xi = }")
                # print(pow(gi,xi[0],n) == hi)
                # print()

    vals = []
    for r,m in zip(rs, ms):
        vals.append((len(r),r,m))
    
    vals.sort(key=lambda x: x[0])
    
    # print(vals[:5])

    rs = []
    ms = []
    placeholder = b"ifctf{"+b"\xff"*46+b"}"
    for i in range(len(vals)-1):
        r = vals[i][1]
        m = vals[i][2]
        rs.append(r)
        ms.append(m)
        if prod(ms) > bytes_to_long(placeholder):
            break
        

    # print(prod([len(r) for r in rs]).bit_length())
    # print(rs)
    # print(ms)

    d_rs = []
    d_ms = []
    t_rs = []
    for r,m in zip(rs, ms):
        if len(r) == 1:
            d_rs.append(int(r[0]))
            d_ms.append(int(m))
        else:
            t_rs.append([(rr,m) for rr in r])
    
    # print(d_rs)
    # print(d_ms)

    if len(d_rs) == 1:
        rs = d_rs[0]
        ms = d_ms[0]
    elif len(d_rs) > 1:
        rs = int(crt(d_rs, d_ms))
        ms = int(lcm(d_ms))
    else:
        rs = []
        ms = []

    sol = []
    i = 0
    for r in itertools.product(*t_rs):
        rr = [rr[0] for rr in r]
        mm = [rr[1] for rr in r]
        rr.append(rs)
        mm.append(ms)
        r = int(crt(rr, mm))
        sol.append(r)
        i+=1
        if b"ifctf{" in long_to_bytes(r):
            flag = long_to_bytes(r)

            if flag == b'ifctf{WTF?_Th1s_sh0uld_b3_c4ll3d_fkin_Brut3f0rc3_CTF}':
                print('OK - service works') 
                exit(0)
    print('ERROR - service does not work')
    exit(2)


def main(hostname, port):
    global io
    io = remote(hostname, port)
    io.recvuntil(b'g = ')
    g = int(io.recvline().strip())
    pohlig_hellman(g, n, phi, phi_fact)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--hostname')
    parser.add_argument('--port')
    args = parser.parse_args()

    hostname = args.hostname or 'localhost'
    port = int(args.port) if args.port is not None else 10001

    main(hostname, port)
