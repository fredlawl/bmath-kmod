KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)
KIMG ?= /boot/vmlinuz-$(KVER)
KDIR_BUILD = $(KDIR)
ifeq ($(KDIR),/lib/modules/$(KVER))
KDIR_BUILD = $(KDIR)/build
endif
SOURCES := $(shell find . -iname '*.c' -o -iname '*.h' 2>/dev/null)
CPUS := $(shell nproc --ignore=1)

.PHONY: all
all: bmath.ko firmware

.PHONY: clean
clean:
	rm -rf src/dl/symbols.h libbmath.so System.map
	$(MAKE) -j$(CPUS) -C $(KDIR_BUILD) M=$(PWD) clean

bmath.ko: $(SOURCES) src/dl/symbols.h
	bear -- $(MAKE) -j$(CPUS) -C $(KDIR_BUILD) M=$(PWD)

src/dl/symbols.h: src/dl/symbols.h.in System.map
	python3 replace-symbols.py System.map src/dl/symbols.h.in > $@

# Assume we're compiling on same kernel we're running this one
System.map:
	-sudo cp /boot/System.map-$(KVER) $@
	-sudo cp $(KDIR)/System.map $@

.PHONY: firmware
firmware: libbmath.so

libbmath.so:
	# common search paths. Prefer copying over manually installed builds
	-sudo install /usr/lib/x86_64-linux-gnu/libbmath.so.1 /usr/lib/firmware/$@
	-sudo install /usr/lib/lib64/libbmath.so.1 /usr/lib/firmware/$@
	-sudo install /usr/local/lib/x86_64-linux-gnu/libbmath.so.1 /usr/lib/firmware/$@
	-sudo install /usr/local/lib64/libbmath.so.1 /usr/lib/firmware/$@
	# for easier readelf purposes
	cp /usr/lib/firmware/libbmath.so $@

.PHONY: run
run: all
	vng \
		-m 6G \
		--cpus $(CPUS) \
		--run $(KIMG) \
		--user root \
		--rwdir=$(PWD) \
		--append "module.sig_enforce=0 kaslr"

.PHONY: debug
debug: all
	vng \
		--debug \
		-m 6G \
		--cpus $(CPUS) \
		--run $(KIMG) \
		--user root \
		--rwdir=$(PWD) \
		--append "kasan_multi_shot module.sig_enforce=0 nokaslr debug loglevel=8 kmemleak=on"

.PHONY: test
test: all
	vng \
		-m 6G \
		--cpus $(CPUS) \
		--run $(KIMG) \
		--user root \
		--rwdir=$(PWD) \
		--append "oops=panic module.sig_enforce=0 kaslr kmemleak=on"  \
		-- /bin/sh test-runner.sh

.PHONY: probe
probe: all
	-rmmod bmath
	-insmod bmath.ko bmath.dyndbg=+p

