KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)
obj-m := src/bmath.o
ldflags-y += -T ./src/bmath.lds --verbose
ccflags-y += -DDEBUG

.PHONY: all
all: src/bmath.ko

.PHONY: clean
clean:
	rm -f compile_commands.json
	$(MAKE) -j$(shell nproc) -C $(KDIR)/build M=$(PWD) clean

src/bmath.ko: src/bmath.c src/libbmath.so.0.0.1
	bear -- $(MAKE) -j$(shell nproc) -C $(KDIR)/build M=$(PWD)

src/libbmath.so.0.0.1:
	-cp /usr/local/lib64/libbmath.so.0.0.1 .
	-cp /usr/lib/x86_64-linux-gnu/libbmath.so.0.0.1 .

test.so: test.c
	$(CC) -o $@ --shared $<

/usr/lib/firmware/test.so: test.so
	sudo install $< $@

.PHONY: run
run:
	virtme-ng \
		--debug \
		-m 6G \
		--cpus 12 \
		--run \
		--user root \
		--rwdir=$(PWD) \
		--append "module.sig_enforce=0 nokaslr debug loglevel=7"

.PHONY: probe
probe:
	-rmmod bmath
	-insmod src/bmath.ko
