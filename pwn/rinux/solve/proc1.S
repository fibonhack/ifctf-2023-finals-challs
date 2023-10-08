        .intel_syntax noprefix
        .text

        .global _start

_start:
        // fork
        mov rax, 0x39
        syscall

        cmp rax, 0
        je child

parent:
        // wait4
        mov rdi, rax
        mov rsi, rsp
        mov rax, 0x3d
        syscall

        // trigger shellcode
exception_start:
        mov rax, 0x3c
        mov rdi, 0
        syscall
        ud2


child:

        // execve(new proc)
        push 0x632f
        mov rax, 0x3b
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        syscall
        ud2
