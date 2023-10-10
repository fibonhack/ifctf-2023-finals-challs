# Cryptole(a)q

This is my implementation of cryptoleq (https://ieeexplore.ieee.org/document/7469876)


## subleq custom assembly and macros

Since the compiler is not released, here is most of what you need to know:
- this is based on subleq: https://esolangs.org/wiki/Subleq
- `.label name` gives a name to the location of the beginning of the next instruction.
- `.def name arg1 arg2 ...` defines a macro. The macro definition ends with `.end`.
- `.call name arg1 arg2 ...` instantiate a macro by substitution.
- `?` stands for "the location of the beginning of this instruction".
- `?+x` stands for `?` plus some offset `x`
- `~x` transforms the number `x` it into its open representation.
- `builtins.G` is the builtin G function, it takes `x`, `y` and one random value used for re-encryption.
- `.input identifier` defines a label of name `identifier` and contains the corresponding input value passed to the compiler at compilation time.
- `.random` tells the compiler to put an open representation of a random value in `[0, n-1]`, different each compilation.

If you have questions on how the program is compiled dm me.

## Example compilation

```
.def goto location
    Z Z location
.end

.call goto entrypoint

.label Z
    ~0 ~0 0

.def halt
    Z Z -1
.end

.label entrypoint
.call halt
```

compiles to 

```
; goto entrypoint, entrypoint is the sixth program memory cell.
; Z is the third memory cell
3 3 6

; Z, initialized with ~0 = 1
1 1 0

;entrypoint
; halt, jump to -1
3 3 -1
```

## VM execution

To run a cryptoleq program with the provided vm, save the cryptoleq compiled program as a text file and run
```
./vm <program_file> <n> <g>
```
