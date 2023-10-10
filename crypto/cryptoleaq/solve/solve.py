#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes

# modified vm to act as a decryption oracle, reusing the G function


class CryptoleqVM:
    def __init__(self, n, g):
        self.n = n
        self.g = g
        self.n_square = n * n
        self.neg_tresh = n//2

    def execute(self, program):
        memory = program[::]

        assert len(memory) % 3 == 0
        assert len(memory) >= 3

        ip = 0
        while ip >= 0 and ip + 2 < len(memory):
            # print(ip)
            a = memory[ip]
            b = memory[ip+1]
            c = memory[ip+2]

            # subtract a from b and store in b
            memory[b] = self.sub(memory[b], memory[a])

            # if b < 0, jump to c
            if self.leq(memory[b]):
                ip = c
            else:
                ip += 3

            # if ip > 9100 * 3:
            #     try:
            #         print(i, long_to_bytes(self.from_open_repr(memory[12])))
            #     except:
            #         pass

        # return content of register R0
        return long_to_bytes(self.from_open_repr(memory[12]))

    def sub(self, a, b):
        return (a * pow(b, -1, self.n_square)) % self.n_square

    def leq(self, x):
        return (x - 1) // self.n > self.neg_tresh or (x - 1) // self.n == 0

    def open_repr(self, x):
        return 1 + x * self.n

    def from_open_repr(self, x):
        val = (x - 1) // self.n
        if val > self.neg_tresh:
            val -= self.n
        return val


def read_compiled_program(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    program = []
    for l in lines:
        program.extend([int(x) for x in l.split(' ')])
    return program


program = read_compiled_program('program.compiled.saved')

# cut off to first G invocation
program = program[:9303 * 3]

# parameters sent from the server for this compiled instance
n = 145104955885181846605767204663327882199333841001404210652989190073450375623737346606478626437061266580352419417541453067662932488521675838822114351138999192887054451930995759225658874495739208868299823800084457158657053558146764774820859461912673383297225463782714017804255332653151624711624836771358594999903
g = 145104955885181846605767204663327882199333841001404210652989190073450375623737346606478626437061266580352419417541453067662932488521675838822114351138999192887054451930995759225658874495739208868299823800084457158657053558146764774820859461912673383297225463782714017804255332653151624711624836771358594999904

vm = CryptoleqVM(n, g)

flag_parts = []
for i in range(4):
    program[12*3] = program[(8 + i)*3]
    flag_part = vm.execute(program)
    print('recovered:', flag_part.decode())
    flag_parts.append(flag_part.decode())


print(''.join(flag_parts))
