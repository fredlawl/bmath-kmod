#include <linux/printk.h>

#include "../dl/loader.h"
#include "../libc/stubs.h"
#include "../libiconv/stubs.h"

#define R_STUB(n) \
	((struct relocate_sym){ .name = #n, .addr = (uintptr_t) & _stub__##n })

const struct relocate_sym *rlsyms[] = {
	// libc
	&R_STUB(__assert_fail), &R_STUB(__cxa_atexit),
	&R_STUB(__errno_location), &R_STUB(__fprintf_chk),
	&R_STUB(__stack_chk_fail), &R_STUB(stdout), &R_STUB(stderr),
	&R_STUB(fprintf), &R_STUB(fputc), &R_STUB(free), &R_STUB(fwrite),
	&R_STUB(malloc), &R_STUB(memset), &R_STUB(printf), &R_STUB(putc),
	&R_STUB(putchar), &R_STUB(puts), &R_STUB(strlen),

	// iconv
	&R_STUB(iconv), &R_STUB(iconv_open), &R_STUB(iconv_close),
	(struct relocate_sym *)0
};
