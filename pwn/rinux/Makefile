
BOOTLOADER = target/stage0/release/bootloader
KERNEL = target/x86_64-unknown-none/release/kernel
KDIR = src
.DEFAULT_GOAL = dist/rinux.zip
.PHONY: $(KDIR)/$(BOOTLOADER) $(KDIR)/$(KERNEL)


$(KDIR)/$(BOOTLOADER):
	cd $(KDIR) && MODE=release make $(BOOTLOADER)

$(KDIR)/$(KERNEL):
	cd $(KDIR) && MODE=release make $(KERNEL)

dist:
	mkdir -p $@

dist/rinux.zip: dist $(KDIR)/$(BOOTLOADER) $(KDIR)/$(KERNEL)
	rm -f $@
	cd $(KDIR) && git archive --format=zip --output repo.zip vettocon
	zip -r $@ $(KDIR)/$(BOOTLOADER) $(KDIR)/$(KERNEL) $(KDIR)/repo.zip run.sh server.py example.py Dockerfile
	rm -f $(KDIR)/repo.zip
