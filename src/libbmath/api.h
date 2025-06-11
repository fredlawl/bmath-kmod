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

struct parser_context *(*parser_new)(struct parser_settings *settings);
int (*parser_free)(struct parser_context *parser_ctx);
int (*parse)(struct parser_context *parser_ctx, const char *input,
	     ssize_t input_len, u64 *out);
int (*print_number)(u64 val, bool uppercase, int encoding);
int (*print_binary)(u64 val);
int (*print_set_stream)(FILE *stream);

#endif // _BMATH_LIBBMATH_API_H_
