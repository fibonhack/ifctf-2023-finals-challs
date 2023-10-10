import random

debug = False
def dbgprint(*x):
    if debug:
        print(*x)

class CryptoleqCompiler:
    def __init__(self, n, g):
        self.n = n
        self.g = g
        self.n_square = n * n

        self.neg_tresh = n//2

    def open_repr(self, x):
        return 1 + x * self.n

    def from_open_repr(self, x):
        val = (x - 1) // self.n
        if val > self.neg_tresh:
            val -= self.n
        return val
    
    def strip_program(self, program):
        stripped_program = []
        for l in program.split('\n'):
            l = l.strip()
            if l == '':
                continue
            if l.startswith(';'):
                continue
            stripped_program.append(l)
        return '\n'.join(stripped_program)

    def compile_symbol(self, symbol, labels):
        # dbgprint('compile_symbol', symbol)
        if symbol.startswith('~'):
            return self.open_repr(int(symbol[1:]))
        elif symbol[0] in '0123456789-':
            return int(symbol)
        elif symbol in labels:
            return labels[symbol]
        elif symbol[0] == '?':
            return eval(symbol.replace('?', str(self.address)))
        else:
            if self.to_be_resolved.get(symbol) is None:
                self.to_be_resolved[symbol] = []
            self.to_be_resolved[symbol].append(self.address//3)
            return symbol

    def compile(self, program, inputs={}):
        program = self.strip_program(program)
        # dbgprint(program)
        self.compiled = []

        self.address = 0
        if self.builtins is not None:
            self.macros = self.builtins.copy()
        else:
            self.macros = {}
        self.to_be_resolved = {}
        self.inputs = inputs
        self.encryption_index = 0

        labels = {}
        self.compile_rec(program, labels)
        
        dbgprint(self.compiled)
        dbgprint(labels)
        #dbgprint(self.macros)

        if self.to_be_resolved != {}:
            raise Exception(f"Unresolved symbols: {self.to_be_resolved}")

        compiled = ''
        for line in self.compiled:
            compiled += ' '.join(map(str, line)) + '\n'
        
        return compiled



    def compile_rec(self, program, labels):
        while program != '':
            assert self.address == len(self.compiled) * 3

            instruction = program.split('\n', 1)[0]
            if instruction == '':
                program = program.split('\n', 1)[1]
                continue

            if instruction.startswith('.label'):
                name = instruction.split(' ')[1]
                if name in labels:
                    raise Exception(f"Label {name} already defined")
                labels[name] = self.address

                # resolve previous references
                if name in self.to_be_resolved:
                    for addr in self.to_be_resolved[name]:
                        dbgprint('resolve', name, addr)
                        dbgprint(self.compiled[addr])
                        for i in range(3):
                            if self.compiled[addr][i] == name:
                                self.compiled[addr][i] = self.compile_symbol(self.compiled[addr][i], labels)
                    del self.to_be_resolved[name]

                try:
                    program = program.split('\n', 1)[1]
                except IndexError:
                    program = ''
            elif instruction.startswith('.input'):
                name = instruction.split(' ')[1]
                if name not in self.inputs:
                    raise Exception(f"Input {name} not defined")
                self.compiled.append([self.inputs[name], 0, 0])

                if name in labels:
                    raise Exception(f"Label {name} already defined")
                labels[name] = self.address

                # resolve previous references
                if name in self.to_be_resolved:
                    for addr in self.to_be_resolved[name]:
                        dbgprint('resolve', name, addr)
                        dbgprint(self.compiled[addr])
                        for i in range(3):
                            if self.compiled[addr][i] == name:
                                self.compiled[addr][i] = self.compile_symbol(self.compiled[addr][i], labels)
                    del self.to_be_resolved[name]


                self.address += 3
                try:
                    program = program.split('\n', 1)[1]
                except IndexError:
                    program = ''

            elif instruction.startswith('.def'):
                name = instruction.split(' ')[1]
                if name in self.macros:
                    raise Exception(f"Macro {name} already defined")
                self.macros[name] = program.split('.end', 1)[0]
                try:
                    program = program.split('.end', 1)[1]
                except IndexError:
                    program = ''
                # dbgprint(self.macros)
            
            elif instruction.startswith('.call'):
                fun_name = instruction.split(' ')[1]

                if fun_name not in self.macros:
                    raise Exception(f"Macro {fun_name} not defined")
                args = instruction.split(' ')[2:]
                dbgprint('call', fun_name, args)
                signature, body = self.macros[fun_name].split('\n', 1)
                signature_args = signature.split(' ')[2:]

                dbgprint('signature', signature)
                dbgprint('signature_args', signature_args)

                new_labels = labels.copy()
                for name, value in zip(signature_args, args):
                    dbgprint('name', name, 'value', value)
                    new_labels[name] = self.compile_symbol(value, labels)
                
                dbgprint('new_labels', new_labels)

                self.compile_rec(body, new_labels)
                try:
                    program = program.split('\n', 1)[1]
                except IndexError:
                    program = ''
            elif instruction.startswith('.random'):
                r = random.randint(1, self.n-1)
                coeff = pow(r, self.n, self.n_square)
                self.compiled.append([coeff, 0, 0])
                self.address += 3
                try:
                    program = program.split('\n', 1)[1]
                except IndexError:
                    program = ''

            else:
                dbgprint('compile', instruction)
                ops = instruction.split(' ')
                out = []
                for op in ops:
                    out.append(self.compile_symbol(op, labels))
                    
                self.address += 3
                try:
                    program = program.split('\n', 1)[1]
                except IndexError:
                    program = ''
                self.compiled.append(out)
    
    def set_private_param(self, param):
        self.builtins = {}
        decrypt = '.def builtins.decrypt ct\n'
        decrypt += '.call mov Z R1\n'
        decrypt += '.call mov ct R2\n'
        for bit in bin(param)[2:][::-1]:
            if bit == '1':
                # multiply
                decrypt += '.call add R2 R1\n'
            decrypt += '.call add R2 R2\n'
        decrypt += '.call mov R1 ct\n'

        self.builtins['builtins.decrypt'] = decrypt
        
        g = '\n'.join(map(lambda x: x.strip(), '''.def G x y rand_input
            .call mov x R0
            .call builtins.decrypt R0
            R2 R2 ?+3
            .call add rand_input R2
            Z R0 exit
            .call add y R2
            .label exit
            .call mov R2 y
            Z Z ?+3
        '''.split('\n')))
        self.builtins['builtins.G'] = g
