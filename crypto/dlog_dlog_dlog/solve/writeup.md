# DlogDlogDlog

## TL;DR

The order of the group $\phi(n) = n-1$ is very smooth, and this allows and implementation of Pohlig-Hellman algorithm to take the discrete logarithm, even after the hashing function.
There can be collisions, and multiple solution values for each step of the Pohlig-Hellman algorithm are possible, but those are only a few, and can be checked in less than a minute.


## The challenge

The challenge lets you compute, provided $e$

$$
(g^{\text{flag}})^{e} \mod n
$$

and we notice that the order of the group $\phi(n) = n-1$ is very smooth, in fact its factorization is
```py
phi_fact = [(2, 1), (211, 5), (223, 9), (227, 4), (229, 2), (233, 2), (239, 2), (241, 4), (251, 4), (257, 3), (263, 3), (269, 7), (271, 6), (277, 3), (281, 6), (283, 4), (293, 3), (307, 7), (311, 7), (313, 3), (317, 3), (331, 4), (337, 3), (347, 5), (349, 5), (353, 3), (359, 2), (367, 2), (373, 5), (379, 2), (383, 7)]
```


If we take a look at the [wikipedia page for Pohlig-Hellman](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) we notice that to compute the dlog we need to compute at each iteration

$$
g_i = g^{n / p_i^{e_i}}
$$

which we can compute, and 

$$
h_i = h^{n / p_i^{e_i}}
$$

where $h = g^{\text{flag}}$ in our case, which we cannot compute directly, but sending $n / p_i^{e_i}$ to the server we can get a part of the hash of that value.
We can now try all possible $g_i^x$, taking the hash and checking against the leaked value from the server.

The actual solve makes use of the prime-power Pohlig-Hellman algorithm, for which a similar strategy is used.

## Collision handling

Since there will be collisions in the check for matching partial hashes, in the last CRT step we need to try all possible values until we find the flag. Indeed, in the last step we cannot rely on some sort of backtracking, since every possible set of candidate values will have a valid solution.

While computing the steps of Pohlig-Hellman in the prime powers variant, however, each step will produce a set of possible values, but in the next step it may happen that only some of these possible values correspond to valid outputs, reducing the final search space.

Also, we can notice that the flag is small compared to $\varphi$, so we actually can compute only a partial solution to the system of modular equations if we find a partial solution modulo some value greater than the flag value.
To reduce the search space we adopt this strategy: given a set of equations and candidate solutions in the form of

```
flag = x_0 or  x_1 or ... or x_m (mod m)
```

we take into considerations only the equations that have the least number of candidates, such that the product of the corresponding moduli is greater than the flag value.
In this way we are sure that we need to try the minimum number of candidate solutions that still result in obtaining the flag, and the whole computation can be performed in less than a minute.