import functools

from greenery import fsm, lego

p = 7


@functools.cache
def gen_fsm(n, a=1):
    # match only if the two numbers are n mod p
    print(f"generating regex for {n=}")
    maps = {}
    for x in range(p):
        maps[f"a{x}"] = {}

    for x in range(p):
        if x == n:
            maps[f"a{x}"] = {
                "1": f"a{(2*x + a) % p}",
                "0": f"a{(2*x) % p}",
            }
        else:
            maps[f"a{x}"] = {
                "1": f"a{(2*x + a) % p}",
                "0": f"a{(2*x) % p}",
            }

    # create the FSM
    machine = fsm.fsm(
        alphabet={"0", "1"},
        states=set(maps.keys()),
        initial="a0",
        finals={f"a{n}"},
        map=maps,
    )

    # convert it to regex
    rex = lego.from_fsm(machine)
    return rex


def gen_equation(x, y, z, t):
    assert x < p
    assert y < p
    assert z < p
    assert t < p
    assert (x * y + z) % p == t % p
    return (
        gen_fsm(x)
        .concatenate(lego.parse("\*"))
        .concatenate(gen_fsm(y))
        .concatenate(lego.parse("\+"))
        .concatenate(gen_fsm(z))
        .concatenate(lego.parse("="))
        .concatenate(gen_fsm(t))
    )


r = lego.parse("")
for x in range(p):
    for y in range(p):
        for z in range(p):
            for t in range(p):
                if (x * y + z) % p == t % p:
                    print(f"{x}*{y}+{z}={t}")
                    r = r.union(gen_equation(x, y, z, t))

with open("tha_regex.txt", "w") as f:
    f.write(str(r))
