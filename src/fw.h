#ifndef _BMATH_FW_H_
#define _BMATH_FW_H_

#include <linux/elf.h>
#include <linux/firmware.h>
#include <linux/types.h>

#include "symbols.h"

#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif // !DT_GNU_HASH

struct relocate_sym {
	const unsigned char *name;
	uintptr_t addr;
};

struct fw_parse_ctx;

inline ptrdiff_t kaslr(void);

struct fw_parse_ctx *alloc_fw_parse_ctx(const struct firmware *,
					const struct relocate_sym **);
void release_fw_parse_ctx(const struct fw_parse_ctx *);
int fw_find_header(const struct fw_parse_ctx *, const unsigned char *,
		   Elf64_Shdr *);
int fw_find_symbol(const struct fw_parse_ctx *, const unsigned char *,
		   Elf64_Sym *);

static inline int set_memory_ro(unsigned long addr, int numpages)
{
	return ((set_memory_t)__set_memory_ro + kaslr())(addr, numpages);
}

static inline int set_memory_rw(unsigned long addr, int numpages)
{
	return ((set_memory_t)__set_memory_rw + kaslr())(addr, numpages);
}

static inline int set_memory_x(unsigned long addr, int numpages)
{
	return ((set_memory_t)__set_memory_x + kaslr())(addr, numpages);
}

static inline int set_memory_nx(unsigned long addr, int numpages)
{
	return ((set_memory_t)__set_memory_nx + kaslr())(addr, numpages);
}

#endif
