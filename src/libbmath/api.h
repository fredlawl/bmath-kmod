#ifndef _BMATH_LIBBMATH_API_H_
#define _BMATH_LIBBMATH_API_H_

#include <linux/types.h>

#include "../libc/api.h"

// https://github.com/fredlawl/bmath/blob/master/src/parser.h
#define PE_EXPRESSION_TOO_LONG 1
#define PE_PARSE_ERROR 2
#define PE_NOTHING_TO_PARSE 3

#define PE_EXPRESSION_TOO_LONG_MSG "Expression too long.\n"
#define PE_PARSE_ERROR_MSG "Parse error ocurred.\n"
#define PE_NOTHING_TO_PARSE_MSG "Nothing to parse.\n"
#define PE_UKNOWN_MSG "Nothing to parse.\n"

struct parser_context;
struct parser_settings {
	int max_parse_len;
	FILE *err_stream;
};

enum encoding_t {
	ENC_NONE = 0,
	ENC_ASCII,
	ENC_BINARY,
	ENC_HEX,
	ENC_HEX16,
	ENC_HEX32,
	ENC_HEX64,
	ENC_INT,
	ENC_UINT,
	ENC_OCTAL,
	ENC_UNICODE,
	ENC_UTF8,
	ENC_UTF16,
	ENC_UTF32,
};

#define ENC_LENGTH ENC_UTF32

enum bits_t {
	BITS_MINIMAL = 0,
	BITS_8,
	BITS_16,
	BITS_32,
	BITS_64,
};

enum format_t {
	FMT_NONE = 0,
	FMT_HUMAN = 1 << 0,
	FMT_UPPERCASE = 1 << 1,
};

enum output_format_t {
	OUT_FMT_NONE = 0,
	OUT_FMT_JUSTIFY = 1 << 0,
};

struct parser_context *(*parser_new)(struct parser_settings *settings);
int (*parser_free)(struct parser_context *parser_ctx);
int (*parse)(struct parser_context *parser_ctx, const char *input,
	     ssize_t input_len, u64 *out);
ssize_t (*print_all)(FILE *stream, uint64_t num,
		     const enum encoding_t encode_order[],
		     size_t encode_order_len, enum format_t fmt,
		     enum output_format_t output_fmt);

#endif // _BMATH_LIBBMATH_API_H_
