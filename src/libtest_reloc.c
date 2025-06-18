#define pr_fmt(fmt) "%s relocation: " fmt, KBUILD_MODNAME

#include <linux/printk.h>

#include "libtest_reloc.h"

int printf(const char *fmt, ...)
{
	// todo: sprintf() basically
	return pr_info("%s %s\n", __FUNCTION__, fmt);
}

int __cxa_finalize(void *data)
{
	pr_debug("%s\n", __FUNCTION__);
	return 0;
}
