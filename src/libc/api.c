#define pr_fmt(fmt) KBUILD_MODNAME " libc: " fmt

#include <linux/string.h>
#include <linux/list.h>

#include "api.h"

// glibc-2.36/libio/stdio.h
#define EOF (-1)

struct atexit {
	struct list_head list;
	void (*func)(void *);
};

static LIST_HEAD(atexit_queue);
static DEFINE_MUTEX(libcmux);

int libc_write(FILE *dest, const char *src, size_t len)
{
	if (dest->len + len > LIBC_IO_BUF_SIZE) {
		return EOF;
	}

	memcpy(dest->buf + dest->len, src, len);
	dest->len += len;
	return len;
}

int libc_writechar(FILE *dest, const char c)
{
	if (dest->len + 1 > LIBC_IO_BUF_SIZE) {
		return EOF;
	}

	memset(dest->buf + dest->len, c, 1);
	dest->len += 1;
	return 1;
}

void libc_flush(FILE *stream)
{
	memset(stream->buf, 0, stream->len);
	stream->len = 0;
}

int libc_cpy_flush(void *dest, size_t len, FILE *src)
{
	if (len > src->len) {
		return -EINVAL;
	}

	memcpy(dest, src->buf, len);
	libc_flush(src);
	return 0;
}

int libc_queue_atexit(void (*func)(void *))
{
	struct atexit *atexit;
	pr_debug("%s: function 0x%lx queued\n", __FUNCTION__, (uintptr_t)func);
	if (list_empty(&atexit_queue)) {
		INIT_LIST_HEAD(&atexit_queue);
	}

	atexit = kzalloc(sizeof(*atexit), GFP_ATOMIC);
	if (!atexit) {
		return -ENOMEM;
	}

	atexit->func = func;
	mutex_lock(&libcmux);
	list_add_tail(&atexit->list, &atexit_queue);
	mutex_unlock(&libcmux);
	return 0;
}

void libc_execute_atexit_queue(void)
{
	struct atexit *entry, *it = NULL;
	pr_debug("%s: executing queued atexit functions\n", __FUNCTION__);

	mutex_lock(&libcmux);
	list_for_each_entry_safe(entry, it, &atexit_queue, list) {
		pr_debug("%s: executing 0x%lx\n", __FUNCTION__,
			 (uintptr_t)entry->func);
		entry->func(NULL);
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&libcmux);
}
