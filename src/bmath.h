#ifndef _BMATH_H_
#define _BMATH_H_

#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/mutex.h>

#include "libbmath/api.h"

#define DEV_NAME "bmath"

#define BMATH_MAX_INPUT_LEN 512
#define BMATH_MAX_PARSE_LEN BMATH_MAX_INPUT_LEN - 12

#define BMATH_IOCTL_TYPE 0xb3

#define BMATH_SET_FORMAT _IOW(BMATH_IOCTL_TYPE, 1, u32)
#define BMATH_FMT_DEFAULT 0
#define BMATH_FMT_UPPERCASE (1 << 0)

#define BMATH_SET_ENCODING _IOW(BMATH_IOCTL_TYPE, 2, u32)
#define BMATH_ENC_NONE 0
#define BMATH_ENC_ASCII (1 << 0)
#define BMATH_ENC_UTF8 (1 << 1)
#define BMATH_ENC_UTF16 (1 << 2)
#define BMATH_ENC_UTF32 (1 << 3)
#define BMATH_ENC_BINARY (1 << 4)
#define BMATH_ENC_DEFAULT (1 << 5)

struct bmath_dev {
	struct cdev cdev;
	struct class *class;
	struct exe *exe;
	struct mutex mutex;
};

struct bmath_data {
	char input[BMATH_MAX_INPUT_LEN];
	size_t len_input;
	size_t len_output;
	u64 format;
	u64 encoding;
	char *output;
	struct parser_context *pctx;
	FILE *stream;
	void *tls;
};

struct parse_fmt {
	int encoding;
	bool uppercase;
	bool binary;
};

static __always_inline struct parse_fmt
bmath_parse_fmt(const struct bmath_data *data)
{
	u32 enc = (data->encoding & ~(BMATH_ENC_BINARY)) & 0xffffffff;
	return (struct parse_fmt){
		.encoding = (enc & BMATH_ENC_DEFAULT) ? BMATH_ENC_ASCII : enc,
		.uppercase = (data->format & BMATH_FMT_UPPERCASE),
		.binary = (data->encoding & BMATH_ENC_BINARY)
	};
}

#endif // _BMATH_H_
