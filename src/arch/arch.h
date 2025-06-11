#ifndef _BMATH_ARCH_ARCH_H_
#define _BMATH_ARCH_ARCH_H_

#include <linux/types.h>

uintptr_t arch_set_reg_fs(uintptr_t addr);
uintptr_t arch_get_reg_fs(void);

void *tls_alloc(void);
void tls_free(const void *tls);

#endif // _BMATH_ARCH_ARCH_H_
