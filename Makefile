KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)

obj-m := src/bmath.o
src/bmath-objs := src/init.o src/fw.o src/libtest_reloc.o

ccflags-y += -DDEBUG -g -I/src
#ldflags-y += -T src/bmath.lds --verbose

.PHONY: all
all: src/bmath.ko

.PHONY: clean
clean:
	rm -f compile_commands.json *.so* src/symbols.h
	$(MAKE) -j$(shell nproc) -C $(KDIR)/build M=$(PWD) clean

src/bmath.ko: src/init.c src/fw.c src/symbols.h src/bmath.h libtest.so src/bmath.lds src/libtest_reloc.c
	bear -- $(MAKE) -j$(shell nproc) -C $(KDIR)/build M=$(PWD)

src/symbols.h: src/symbols.h.in System.map
	python3 replace-symbols.py System.map src/symbols.h.in > $@

# Assume we're compiling on same kernel we're running this one
System.map:
	sudo cp /boot/System.map-$(shell uname -r) $@

#src/libbmath.so.0.0.1:
#	-cp /usr/local/lib64/libbmath.so.0.0.1 .
#	-cp /usr/lib/x86_64-linux-gnu/libbmath.so.0.0.1 .

libtest.so: test.c
	$(CC) -g -o $@ -fPIC --shared $< -Wl,-Map=libtest.so.map,--hash-style=both
	objcopy -S $@ $@

/usr/lib/firmware/libtest.so: libtest.so
#	sudo install $< $@
	install $< $@

.PHONY: run
run:
	virtme-ng \
		-m 6G \
		--cpus 12 \
		--run \
		--user root \
		--rwdir=$(PWD) \
		--append "module.sig_enforce=0 kaslr debug loglevel=7"

.PHONY: probe
probe: src/bmath.ko /usr/lib/firmware/libtest.so
	-rmmod bmath
	-insmod src/bmath.ko
