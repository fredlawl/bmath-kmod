obj-$(CONFIG_BMATH) := bmath.o
bmath-y += src/init.o \
	src/dl/loader.o \
	src/libbmath/stubs.o \
	src/libc/stubs.o \
	src/libiconv/stubs.o \
	src/libc/api.o

bmath-$(CONFIG_X86_64) += src/arch/x86_64.o

ccflags-y += -I/src
ccflags-$(CONFIG_DYNAMIC_DEBUG_CORE) += -DDYNAMIC_DEBUG_MODULE
