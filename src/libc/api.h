#ifndef _BMATH_LIBC_API_H_
#define _BMATH_LIBC_API_H_

#include <linux/err.h>
#include <linux/slab.h>
#include <linux/types.h>

#define LIBC_IO_BUF_SIZE 1024

typedef struct libc_file {
	char buf[LIBC_IO_BUF_SIZE];
	size_t len;
} FILE;

static __always_inline FILE *libc_stream_alloc(void)
{
	FILE *s = kzalloc(sizeof(*s), GFP_ATOMIC);
	if (!s) {
		return ERR_PTR(-ENOMEM);
	}

	return s;
}

static __always_inline void libc_stream_release(FILE *stream)
{
	kfree(stream);
}

int libc_write(FILE *dest, const char *src, size_t len);
int libc_writechar(FILE *dest, const char c);
void libc_flush(FILE *stream);
int libc_cpy_flush(void *dest, size_t len, FILE *src);
int libc_queue_atexit(void (*func)(void *));
void libc_execute_atexit_queue(void);

#endif // _BMATH_LIBC_API_H_
