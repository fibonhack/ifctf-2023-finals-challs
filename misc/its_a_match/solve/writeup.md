# Its a match!

## TL;DR

We can construct a regular expression to match a binary number being some fixed value modulo 7 using a construction on deterministic finite automatons (DFA) and using an algorithm to convert DFAs to regular expressions.
We can then combine those regular expressions using the concatenation and union operators to solve the overall matching problem.

## Matching a number being some chosen value modulo 7

The task we are trying to solve is: how can we match a binary number being some $t mod 7$?
Well, a regex is in reality one of the [many ways](https://en.wikipedia.org/wiki/Regular_language#Equivalent_formalisms) to express a regular language, so we may try to express this condition as a Deterministic Finite Automaton.
The intuition is that we may have a DFA with seven states, one for each residue class.
The initial state is the `0` state.
When we read a `0`, we go to state `2*curr_state mod 7`, and when we read a `1` we go to `2*curr_state + 1 mod 7`.
The final (accepting) state is the one we have chosen to match.
This DFA can be turned into a regular expression for example using the Brzozowski algebraic method.

Using the python package [Greenery](https://github.com/qntm/greenery) to work with DFA and regexes.
Greenery has a nice `from_fsm` [method](https://github.com/qntm/greenery/blob/10223e69236f04ee6fd9dfe99262046f0333bda1/greenery/rxelems.py#L260) which can convert some DFA to a regex.


We can generate a regular expression matching a binary number being some value mod 7 with this function
```py
p = 7

@functools.cache
def gen_fsm(n):
    print(f"generating regex for {n=}")
    maps = {}
    for x in range(p):
        maps[f"{x}"] = {}

    for x in range(p):
        if x == n:
            maps[f"{x}"] = {
                "1": f"{(2*x + 1) % p}",
                "0": f"{(2*x) % p}",
            }
        else:
            maps[f"{x}"] = {
                "1": f"{(2*x + 1) % p}",
                "0": f"{(2*x) % p}",
            }

    # create the FSM
    machine = fsm.fsm(
        alphabet={"0", "1"},
        states=set(maps.keys()),
        initial="0",
        finals={f"{n}"},
        map=maps,
    )

    # convert it to regex
    rex = lego.from_fsm(machine)
    return rex
```

## Matching the whole thing

In theory it is possible to construct a DFA to match the strings, here is the idea:
- match the first binary number as before
- construct $7^2$ states for the second matching, where each state keeps the information `(prev_state, curr_parsing_state)`, and reading `0` jumps to `(prev_state, curr_parsing_state*2 mod 7)` and reading `1` jumps to `(prev_state, curr_parsing_state*2 + 1 mod 7)`
- construct other $7^2$ sates for `c` and other $7^2$ for `d`.

This is theoretically possible (and hopefully correct), but the complexity of the transformation from DFAs to regexes is [kinda bad](https://stackoverflow.com/questions/16095230/dfa-to-regular-expression-time-complexity), so it is not really feasible.

But we can employ this trick by realizing that regexes have some operations that are easily computed.
Given some regexes `R1` and `R2` that match some languages, we can match

- the concatenation of the languages with `R1R2`
- the union of the langiages with `R1|R2`

and those regexes can be computed efficiently (just string concatenation).
Let's call `M(i)` the regex that matches a binary number being `i` modulo 7.
We can match the equation `0*0+0=0` by matching `M(0)\*M(0)\+M(0)=M(0)`, and then we can match `M(0)\*M(0)\+M(1)=M(1)`, and so on, enumerating all possible true statements (which are around 500).
The final regex is just the union of all those intermediate regexes, here is the (very ugly) code that generates it

```py
def gen_equation(x, y, z, t):
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
```


