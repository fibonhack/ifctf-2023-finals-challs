

        .intel_syntax noprefix


        .global enter_shellcode, shellcode_end

enter_shellcode:
        add rdi, 0x8
        jmp rdi


        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop

        mov rsp, rsi
        push rdi
        push rsi
        push rdx

        mov r15, qword ptr [rsp]

loop:
        mov r14, qword ptr [r15]
        cmp r14, 0
        je _quit
        mov rdi, r14
        mov rsi, qword ptr [r15 + 0x8]
        mov rax, 0xb
        syscall
        add r15, 0x10
        jmp loop

_quit:
        pop rdx
        pop rsi
        pop rdi

        // zero region
        xor r8, r8
loop2:
        mov qword ptr [rdx+r8], 0x0
        add r8, 8
        cmp r8, 0x200
        jle loop2
jail_start:
        xor rax, rax
        xor rbx, rbx
        xor rcx, rcx
        xor rdx, rdx
        xor rdi, rdi
        xor rsi, rsi
        xor rbp, rbp

        xor r8, r8
        xor r9, r9
        xor r10, r10
        xor r11, r11
        xor r12, r12
        xor r13, r13
        xor r14, r14
        xor r15, r15

        sub rsp, 0x40


shellcode_end:
        nop
