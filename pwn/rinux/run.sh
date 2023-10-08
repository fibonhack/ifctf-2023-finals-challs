#!/bin/sh

python3 server.py && \
    qemu-system-x86_64 \
        -hda /tmp/flag.txt \
        -net none \
        -no-reboot \
        -nographic \
        -monitor /dev/null \
        -kernel bootloader \
        -initrd 'kernel,/tmp/rootfs.cpio' \
        -m 256 \
        -append 'nokaslr' \
        -cpu qemu64,+smap,+smep
