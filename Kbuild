obj-m := bmath.o
bmath-y += src/init.o src/dl/loader.o
bmath-$(CONFIG_X86_64) += src/arch/x86_64.o
bmath-y += src/libbmath/stubs.o src/libc/stubs.o src/libiconv/stubs.o
bmath-y += src/libc/api.o

ccflags-y += -I/src
# ccflags-y += -DDEBUG # To quickly test bmath api
ccflags-$(CONFIG_DYNAMIC_DEBUG_CORE) += -DDYNAMIC_DEBUG_MODULE

