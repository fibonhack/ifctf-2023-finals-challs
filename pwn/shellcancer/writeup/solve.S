

        .intel_syntax noprefix
        .global openat, open, exit, read, write, syscall, close, strlen

strlen:
        xor rax, rax
        dec rax
_loop:
        inc rax
        cmp byte ptr [rdi + rax], 0x0
        jne _loop
        ret


openat:
        mov rax, 0x101
        syscall
        ret

open:
        mov rax, 0x2
        syscall
        ret

close:
        mov rax, 0x3
        syscall
        ret

exit:
        mov rax, 0x3c
        syscall
        ret

read:
        mov rax, 0x0
        syscall
        ret

write:
        mov rax, 0x1
        syscall
        ret


syscall:
        mov rax, rdi
        mov rdi, rsi
        mov rsi, rdx
        mov rdx, rcx
        mov r10, r8
        mov r8, r9
        syscall
        ret
