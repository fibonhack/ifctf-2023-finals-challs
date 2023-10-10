# Cryptole(a)q

## TL;DR

The challenge is a straightforward implementation of [Cryptoleq](https://ieeexplore.ieee.org/document/7469876) without any "externally introduced" bugs.
Due to the way this homomorphic computation system achieves full homomorphism over the integers, it is possible to recover the private parameter by reverse engineering the program, and decrypt the flag.

## How Cryptoleq can be broken

Cryptoleq aims at being a language that operates both on encrypted an unencrypted data in an homomorphic way.
Citing the abstract:

> The program operands are protected using the Paillier partially homomorphic cryptosystem, which supports addition on the encrypted domain.Full homomorphism over addition and multiplication, which is necessary for enabling general-purpose computation, is achieved by inventing a heuristically obfuscated software re-encryption module written using Cryptoleq instructions and blended into the executing program.

It turns out that the core of this re-encryption is a special function named $G$, that basically needs to decrypt one of the arguments.
In the paper they say that

> In Cryptoleq, if an encrypted value is raised to exponent $\varphi (k \varphi)^{-1} N$, it actually decrypts into an open representation

and

> Cryptoleq programs do not have to retain a copy of $\varphi (k \varphi)^{-1} N$ , as its obfuscated bit expansion is sufficient to define the sequence of multiplications in calculating the result of function G; this sequence can be statically generated during program compilation.

so Cryptoleq programs needs to retain the sequence of square and multiply necessary to decrypt any value, so implicitly they retain the sequence of bits of the private parameter!!!

## The challenge

In this challenge the server sends the client a program to be executed by the client.
This program contains encrypted values of four parts of the flag, and encrypted values of four indices.
One of the index is the encrypted value of $1$, while the other are encrypted negative values.
The program calculates homomorphically

$$
G(\text{idx}_0, \text{flag}_0) + G(\text{idx}_1, \text{flag}_1) + G(\text{idx}_2, \text{flag}_2) + G(\text{idx}_3, \text{flag}_3)
$$

which, by the way $G$ is defined, results in the re-encrypted value of $\text{flag}_i$ at the index where $\text{idx}_i$ is $1$.
So this is a way to secretly select one piece of information without revealing the information nor the selected index, which is in a way an [oblivious transfer](https://en.wikipedia.org/wiki/Oblivious_transfer) implementation.

The encrypted flag chunks are written in the program, and can be extracted easily.
At this point, we need to extract $\varphi (k \varphi)^{-1} N$ and elevating the flag chunks to that value we can decrypt them.

One possible strategy is to reverse the program and find the pattern of square and multiply used, and extract the private key.
Actually, a simpler approach, that is implemented in `solve.py` can be used: identify where the $G$ function is implemented and just reuse the routine to decrypt one of the arguments.