
.DEFAULT_GOAL = rootfs.cpio
.PHONY = debug

tmp:
	mkdir -p $@


tmp/rinux: tmp
	rm -rf $@
	mkdir -p $@

tmp/rinux/src/target/x86_64-unknown-none/release/kernel: tmp/rinux
	cp ../dist/rinux.zip tmp/rinux
	cd tmp/rinux && unzip -o rinux.zip


tmp/kernel_shellcode.bin: root root/c tmp/rinux/src/target/x86_64-unknown-none/release/kernel
	./extract_page.py

tmp/kek_elf: proc2.S tmp
	gcc -nostdlib $< -c -o $@

tmp/kek_elf_enhan: tmp/kek_elf tmp/kernel_shellcode.bin
	objcopy --add-section .kcode=tmp/kernel_shellcode.bin --set-section-flags .kcode=code,readonly,load,alloc $< $@
# 	objcopy --add-section .kdata=kernel_data.bin --set-section-flags .kdata=data,load,alloc /tmp/cusumano $@

root:
	mkdir -p $@

root/c: tmp/kek_elf_enhan root tmp/rinux/src/target/x86_64-unknown-none/release/kernel
	nm tmp/rinux/src/target/x86_64-unknown-none/release/kernel | grep breakpoint_hand | cut -d ' ' -f1 | tr -d '\n' | tr '[:lower:]' '[:upper:]' > tmp/addr_handler
	echo -n "obase=16; ibase=16; (" > tmp/primo
	echo " / 1000) * 1000 + FFFFFFFF81000000" > tmp/secondo
	gcc -nostdlib -o $@ -Xlinker --section-start=.kcode=0x$(shell cat tmp/primo tmp/addr_handler tmp/secondo | bc) $<

root/init: proc1.S root
	gcc -nostdlib -o $@ $<


rootfs.cpio: root/c root/init
	rm -f $@
	cd root && find . -print0 | cpio --null -oH newc --owner=root > ../$@


clean:
	rm -rf tmp/ rootfs.cpio root/c root/init


debug: tmp/rinux/src/target/x86_64-unknown-none/release/kernel rootfs.cpio
	qemu-system-x86_64 \
               -hda ../flag.txt \
               -net none -no-reboot \
               -snapshot -nographic -kernel tmp/rinux/src/target/stage0/release/bootloader \
               -initrd 'tmp/rinux/src/target/x86_64-unknown-none/release/kernel,rootfs.cpio' \
               -m 256 \
               -append 'nokaslr' \
               -cpu qemu64,+smap,+smep \
               -s -S
