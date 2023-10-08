# Rinux

## Introduction
This is a rust minimal clone of the Linux kernel. It has almost zero functionalities, but boots, reads an initrd and execs the init file.
Only a very few syscalls are implemented.

In the challenge setup, a python scripts receives a cpio file from the user and writes it to disk, and then runs qemu. The flag is not added to the cpio, that will be the initrd of the kernel, but is instead mounted as an hard disk, as says the flag `-hda /tmp/flag.txt`.

Several protections are added, the kernel is ran with smap and smep enabled (they are not only qemu flags, they really are implemented in the kernel code), but kaslr is disabled. The kernel stack is randomized.

## Spot the vuln
Being written in rust is not a synonim of safety, at all. In several places there are unsafe blocks, and there also are some integer overflows. However, the kernel is compiled with integer check at runtime also in release mode, so these will be not easy to exploit.

In order to obtain the flag we must read the first of the disks, hda. However there is no code at all that can read the disk in the kernel. We need to gain code execution in ring0 and add some extra code.

The easiest vulnerability to use, in my opinion, is in the function `src/syscall/exec.rs:load_user_elf`. This function takes a file from memory (no interaction with hdd exists in this kernel, all files have to be in the initrd at the beginning of the execution), and does a part of what `execve` should do:

- load it in memory, with correct permissions
- load extra sections, like stack
- prepare the stack
- return to userland

This function calls `elf.memory_load` under the hood, that accepts bot PIE and executables with fixed loading address. It is very interesting to notice that no validation at all is performed on the address that the elf wants to be loaded at. :eyes:

Seems reasonable to try to craft a custom elf with a section loaded at an address that contains kernel code in order to overwrite it. However, `load_user_elf` runs the function `MemoryManagement.copy_to_mem` with always the `PTEFlags::USER` active, meaning that this will be a problem: when the kernel runs this code, smep will prevent it.

Actually this is not a problem in this kernel because of an interesting feature of the page tables: in order to have a flag on a leaf of the page table tree, this flag has to be set in all of the entries of that leaf of the tree. In this kernel, the root page has the USER bit set only for the addresses that start with the first bit set to zero. In this case, even if this function adds the USER flag, the page will be mapped as kernel.


## Strategy

We can overwrite some kernel code. We can try to do some minor damage in order to not break this fragile kernel:

- overwrite code that has not been reached: we overwrite an entire page with a copy of it, overwriting an unused function with our shellcode
- we can choose as an unused function some of the interrupt handlers. most of them panic, so they have not been called yet.
- in order to write a small shellcode in kernel and gain space, we can write a shellcode that disables SMAP and SMEP and then jump to a userland address


The plan is:
- Craft a custom elf: normal section as .text and an extra section loaded at the address of an interrupt handler, for example the breakpoint handler
- Craft in this custom section a shellcode that disables smap, smep and jumps to userland. The rest of the section should be equal to the original page
- prepare the userland shellcode. We need to read from disk and then print it somehow. We can copy-paste the instructions from [osdev](https://wiki.osdev.org/ATA_read/write_sectors), namely the function `ata_chs_read`. We need to read one sector from the first cylinder, head and sector of the first disk of our system, and we need to copy to userland somewhere, the userland stack will be fine. Watch out, not all of the former indexes are zero, one of them is one.

- trigger int3 while in userland to trigger our shellcode
- use the normal syscall `write` to print to the user the content of the buffer obtained
- leave the kernel to crash horribly and go have some drinks
