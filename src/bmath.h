#ifndef _BMATH_H_
#define _BMATH_H_

#include <linux/types.h>
#include <linux/cdev.h>

#define DEV_NAME "bmath"
// /usr/lib/firmware/DEV_FW_PATH
#define DEV_FW_PATH "libtest.so"

#define BMATH_MAX_INPUT_LEN 512

#define BMATH_FMT_UPPERCASE (1 << 1)

#define BMATH_ENC_ASCII (1 << 0)
#define BMATH_ENC_UTF8 (1 << 1)
#define BMATH_ENC_UTF16 (1 << 2)
#define BMATH_ENC_UTF32 (1 << 3)
#define BMATH_ENC_BINARY (1 << 4)

#define BMATH_IOCTL_TYPE 0xb3
#define BMATH_SET_FORMAT _IOW(BMATH_IOCTL_TYPE, 1, u32)
#define BMATH_SET_ENCODING _IOW(BMATH_IOCTL_TYPE, 2, u32)

struct bmath_dev {
	struct cdev cdev;
	struct class *class;
	void *vm;
};

struct bmath_data {
	u32 format;
	u32 encoding;
	size_t len_input;
	char input[BMATH_MAX_INPUT_LEN];
	size_t len_output;
	char *output;
};

#endif
