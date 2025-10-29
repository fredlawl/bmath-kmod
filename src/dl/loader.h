#ifndef _BMATH_LOADER_H_
#define _BMATH_LOADER_H_

#include <linux/elf.h>
#include <linux/firmware.h>
#include <linux/types.h>

#include "symbols.h"

#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif // DT_GNU_HASH

struct relocate_sym {
	const unsigned char *name;
	size_t nlen;
	uintptr_t addr;
};

struct exe;

ptrdiff_t kaslr(void);

struct exe *exe_alloc(const struct firmware *fw,
		      const struct relocate_sym **rlsyms);
void exec_release(const struct exe *exe);
int exe_find_header(const struct exe *exe, const unsigned char *name,
		    Elf64_Shdr *hdr);
int exe_find_symbol(const struct exe *exe, const unsigned char *name,
		    Elf64_Sym *sym);

static __always_inline int kaslr_request_firmware(const struct firmware **fw,
						  const char *name,
						  struct device *dev)
{
	return ((request_firmware_t)__request_firmware + kaslr())(fw, name,
								  dev);
}

static __always_inline int kaslr_set_memory_ro(unsigned long addr, int numpages)
{
	return ((set_memory_t)__set_memory_ro + kaslr())(addr, numpages);
}

static __always_inline int kaslr_set_memory_rw(unsigned long addr, int numpages)
{
	return ((set_memory_t)__set_memory_rw + kaslr())(addr, numpages);
}

static __always_inline int kaslr_set_memory_x(unsigned long addr, int numpages)
{
	return ((set_memory_t)__set_memory_x + kaslr())(addr, numpages);
}

static __always_inline int kaslr_set_memory_nx(unsigned long addr, int numpages)
{
	return ((set_memory_t)__set_memory_nx + kaslr())(addr, numpages);
}

#endif // _BMATH_LOADER_H_
