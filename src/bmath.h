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
#define BMATH_FMT_NONE 0
#define BMATH_FMT_UPPERCASE (1 << 0)
#define BMATH_FMT_JUSTIFY (1 << 1)
#define BMATH_FMT_HUMAN (1 << 2)
#define BMATH_FMT_DEFAULT BMATH_FMT_NONE

#define BMATH_SET_ENCODING _IOW(BMATH_IOCTL_TYPE, 2, u32)
#define BMATH_ENC_NONE 0
#define BMATH_ENC_ASCII (1 << 0)
#define BMATH_ENC_BINARY (1 << 1)
#define BMATH_ENC_HEX (1 << 2)
#define BMATH_ENC_HEX16 (1 << 3)
#define BMATH_ENC_HEX32 (1 << 4)
#define BMATH_ENC_HEX64 (1 << 5)
#define BMATH_ENC_INT (1 << 6)
#define BMATH_ENC_UINT (1 << 7)
#define BMATH_ENC_OCTAL (1 << 8)
#define BMATH_ENC_UNICODE (1 << 9)
#define BMATH_ENC_UTF8 (1 << 10)
#define BMATH_ENC_UTF16 (1 << 11)
#define BMATH_ENC_UTF32 (1 << 12)

#define BMATH_ENC_DEFAULT (~0L)

#define BMATH_ENC_ALL                                                          \
	(BMATH_ENC_ASCII | BMATH_ENC_BINARY | BMATH_ENC_HEX |                  \
	 BMATH_ENC_HEX16 | BMATH_ENC_HEX32 | BMATH_ENC_HEX64 | BMATH_ENC_INT | \
	 BMATH_ENC_UINT | BMATH_ENC_OCTAL | BMATH_ENC_UNICODE |                \
	 BMATH_ENC_UTF8 | BMATH_ENC_UTF16 | BMATH_ENC_UTF32)

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
	enum encoding_t encodings[ENC_LENGTH];
	size_t encodings_len;
	enum format_t format;
	enum output_format_t out_format;
};

static __always_inline struct parse_fmt
bmath_parse_fmt(const struct bmath_data *data)
{
	struct parse_fmt fmt = { 0 };
	u64 enc;
	u64 format;

	if (!data) {
		format = BMATH_FMT_DEFAULT;
		enc = BMATH_ENC_DEFAULT;
	} else {
		format = data->format;
		enc = data->encoding;
	}

	if (enc == BMATH_ENC_DEFAULT) {
		enc = BMATH_ENC_UINT;
	}

	if (enc & BMATH_ENC_ASCII) {
		fmt.encodings[fmt.encodings_len++] = ENC_ASCII;
	}

	if (enc & BMATH_ENC_BINARY) {
		fmt.encodings[fmt.encodings_len++] = ENC_BINARY;
	}

	if (enc & BMATH_ENC_HEX) {
		fmt.encodings[fmt.encodings_len++] = ENC_HEX;
	}

	if (enc & BMATH_ENC_HEX16) {
		fmt.encodings[fmt.encodings_len++] = ENC_HEX16;
	}

	if (enc & BMATH_ENC_HEX32) {
		fmt.encodings[fmt.encodings_len++] = ENC_HEX32;
	}

	if (enc & BMATH_ENC_HEX64) {
		fmt.encodings[fmt.encodings_len++] = ENC_HEX64;
	}

	if (enc & BMATH_ENC_INT) {
		fmt.encodings[fmt.encodings_len++] = ENC_INT;
	}

	if (enc & BMATH_ENC_UINT) {
		fmt.encodings[fmt.encodings_len++] = ENC_UINT;
	}

	if (enc & BMATH_ENC_OCTAL) {
		fmt.encodings[fmt.encodings_len++] = ENC_OCTAL;
	}

	if (enc & BMATH_ENC_UNICODE) {
		fmt.encodings[fmt.encodings_len++] = ENC_UNICODE;
	}

	if (enc & BMATH_ENC_UTF8) {
		fmt.encodings[fmt.encodings_len++] = ENC_UTF8;
	}

	if (enc & BMATH_ENC_UTF16) {
		fmt.encodings[fmt.encodings_len++] = ENC_UTF16;
	}

	if (enc & BMATH_ENC_UTF32) {
		fmt.encodings[fmt.encodings_len++] = ENC_UTF32;
	}

	if (format == BMATH_FMT_DEFAULT) {
		fmt.out_format = OUT_FMT_NONE;
		fmt.format = FMT_NONE;
	} else {
		u64 of = format & (~BMATH_FMT_HUMAN | ~BMATH_FMT_UPPERCASE);
		u64 f = format & ~BMATH_FMT_JUSTIFY;

		if (of & BMATH_FMT_JUSTIFY)
			fmt.out_format |= OUT_FMT_JUSTIFY;

		if (f & BMATH_FMT_HUMAN)
			fmt.format |= FMT_HUMAN;

		if (f & BMATH_FMT_UPPERCASE)
			fmt.format |= FMT_UPPERCASE;
	}

	return fmt;
}

#endif // _BMATH_H_
