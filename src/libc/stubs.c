#define pr_fmt(fmt) KBUILD_MODNAME " libc: " fmt

#include <linux/bug.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sprintf.h>

#include "api.h"
#include "stubs.h"

uintptr_t _stub___ITM_deregisterTMCloneTable = 0;
uintptr_t _stub___ITM_registerTMCloneTable = 0;
FILE *_stub__stdout = &(FILE){ 0 };
FILE *_stub__stderr = &(FILE){ 0 };
int _stub__errno = 0;
int *errno_loc = &_stub__errno;

// https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/baselib---assert-fail-1.html
void _stub____assert_fail(const char *assertion, const char *file,
			  unsigned int line, const char *function)
{
	WARN(1, KBUILD_MODNAME ": assert %s failed. %s:%u (%s)\n", assertion,
	     file, line, function);
}

// https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/baselib---cxa-atexit.html
int _stub____cxa_atexit(void (*func)(void *), void *arg, void *dso_handle)
{
	// TODO: Only works with atexit() api's. Therefore args arn't retained to pass to function
	return libc_queue_atexit(func);
}

// https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/baselib---errno-location.html
int *_stub____errno_location(void)
{
	pr_debug("%s\n", __FUNCTION__);
	return errno_loc;
}

// https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/baselib---cxa-finalize.html
void _stub____cxa_finalize(void *d)
{
	// See: libc_execute_atexit_queue
}

// https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/baselib---fprintf-chk-1.html
// https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/sysdeps/ieee754/ldbl-opt/nldbl-fprintf_chk.c#L5
int _stub____fprintf_chk(FILE *stream, int flag, const char *format, ...)
{
	int ret;
	va_list args;

	va_start(args, format);
	ret = vsprintf(stream->buf + stream->len, format, args);
	va_end(args);
	stream->len += ret;
	return ret;
}

// https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/baselib---stack-chk-fail-1.html
void _stub____stack_chk_fail(void)
{
	WARN(1, KBUILD_MODNAME ": stack check failure\n");
}

void *_stub__calloc(size_t nmemb, size_t size)
{
	return kzalloc(size * nmemb, GFP_ATOMIC);
}

int _stub__fprintf(FILE *stream, const char *fmt, ...)
{
	int ret;
	va_list args;

	va_start(args, fmt);
	ret = vsprintf(stream->buf + stream->len, fmt, args);
	va_end(args);
	stream->len += ret;
	return ret;
}

int _stub__fputc(int c, FILE *stream)
{
	return libc_writechar(stream, c);
}

void _stub__free(void *ptr)
{
	kfree(ptr);
}

size_t _stub__fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t b;
	size_t len = size * nmemb;

	if (len == 0) {
		return 0;
	}

	b = libc_write(stream, ptr, len);
	if (len == b) {
		return b;
	}

	return b / size;
}

void *_stub__malloc(size_t size)
{
	return kzalloc(size, GFP_ATOMIC);
}

void *_stub__memcpy(void *dest, const void *src, size_t n)
{
	return __builtin_memcpy(dest, src, n);
}

void _stub__memset(void *s, int c, size_t n)
{
	memset(s, c, n);
}

int _stub__printf(const char *format, ...)
{
	int ret;
	va_list args;
	FILE *stream = _stub__stdout;

	va_start(args, format);
	ret = vsprintf(stream->buf + stream->len, format, args);
	va_end(args);
	stream->len += ret;
	return ret;
}

int _stub__putc(int c, FILE *stream)
{
	return _stub__fputc(c, stream);
}

int _stub__putchar(int c)
{
	return _stub__fputc(c, _stub__stdout);
}

int _stub__puts(const char *s)
{
	int b;
	b = libc_write(_stub__stdout, s, strlen(s));
	b += libc_writechar(_stub__stdout, '\n');
	return b;
}

int _stub__snprintf(char *str, size_t size, const char *format, ...)
{
	int ret;
	va_list args;

	va_start(args, format);
	ret = vsnprintf(str, size, format, args);
	va_end(args);
	return ret;
}

size_t _stub__strlen(const char *s)
{
	return __builtin_strlen(s);
}

int _stub__strncmp(const char *s1, const char *s2, size_t n)
{
	return __builtin_strncmp(s1, s2, n);
}
