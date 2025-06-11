#ifndef _BMATH_LIBICONV_STUBS_H_
#define _BMATH_LIBICONV_STUBS_H_

#include <linux/types.h>
#include <linux/unicode.h>

typedef struct iv *iconv_t;

#define ICONV_ERR ((iconv_t) - 1)
#define ICONV_CONV_ERR ((size_t) - 1)

size_t _stub__iconv(iconv_t cd, char **inbuf, size_t *inbytesleft,
		    char **outbuf, size_t *outbytesleft);
iconv_t _stub__iconv_open(const char *tocode, const char *fromcode);
int _stub__iconv_close(iconv_t cd);

#endif // _BMATH_LIBICONV_STUBS_H_
