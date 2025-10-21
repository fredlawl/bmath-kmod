#ifndef _BMATH_LIBC_STUBS_H_
#define _BMATH_LIBC_STUBS_H_

#include <linux/types.h>

#include "api.h"

extern uintptr_t _stub___ITM_deregisterTMCloneTable;
extern uintptr_t _stub___ITM_registerTMCloneTable;

extern FILE *_stub__stderr;
extern FILE *_stub__stdout;
extern int *errno_loc;

// TODO: get this into the libc api .c file.
// Well... this is going to be a challenge.
// I need to test this functionality to see if the
// bmath_read lock is good enough to keep other
// file handles out of here
static __always_inline void libc_set_errno(int err)
{
	*errno_loc = err;
	if (*errno_loc < 0) {
		*errno_loc *= -1;
	}
}

void _stub____assert_fail(const char *assertion, const char *file,
			  unsigned int line, const char *function);
int _stub____cxa_atexit(void (*func)(void *), void *arg, void *dso_handle);
int *_stub____errno_location(void);
void _stub____cxa_finalize(void *d);
int _stub____fprintf_chk(FILE *stream, int flag, const char *format, ...);
void _stub____stack_chk_fail(void);

void *_stub__calloc(size_t nmemb, size_t size);
int _stub__fprintf(FILE *stream, const char *fmt, ...);
int _stub__fputc(int c, FILE *stream);
void _stub__free(void *ptr);
size_t _stub__fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
void *_stub__malloc(size_t size);
void *_stub__memcpy(void *dest, const void *src, size_t n);
void _stub__memset(void *s, int c, size_t n);
int _stub__printf(const char *format, ...);
int _stub__putc(int c, FILE *stream);
int _stub__putchar(int c);
int _stub__puts(const char *s);
size_t _stub__strlen(const char *s);
int _stub__snprintf(char *str, size_t size, const char *format, ...);
size_t _stub__strlen(const char *s);
int _stub__strncmp(const char *s1, const char *s2, size_t n);
#endif // _BMATH_LIBC_STUBS_H_
