#!/usr/bin/env python3
import fcntl

BMATH_SET_FORMAT = 0x4004B301
BMATH_FMT_DEFAULTS = 0
BMATH_FMT_UPPERCASE = 1 << 0

BMATH_SET_ENC = 0x4004B302
BMATH_ENC_NONE = 0
BMATH_ENC_ASCII = 1 << 0
BMATH_ENC_UTF8 = 1 << 1
BMATH_ENC_UTF16 = 1 << 2
BMATH_ENC_UTF32 = 1 << 3
BMATH_ENC_BINARY = 1 << 4


input = "1" * 501
# input = "0x21"
fp = open("/dev/bmath", "r+")
fcntl.ioctl(
    fp.fileno(),
    BMATH_SET_ENC,
    BMATH_ENC_UTF32,
)
b = fp.write(input)
print(b, fp.read())
fp.close()
