#!/usr/bin/env python3
import os
import fcntl
import ioctl

BMATH_SET_FORMAT = ioctl.IOW(0xB3, 1, 4)
BMATH_SET_ENC = ioctl.IOW(0xB3, 2, 4)

BMATH_ENC_ASCII = 1 << 0
BMATH_ENC_UTF8 = 1 << 1
BMATH_ENC_UTF16 = 1 << 2
BMATH_ENC_UTF32 = 1 << 3

fp = open("/dev/bmath", "w+")
fp2 = open("/dev/bmath", "w+")
fp.write("0xff\n")
fp2.write("0xBADBEEF")
print("1", fp.read())
fcntl.ioctl(fp.fileno(), BMATH_SET_ENC, BMATH_ENC_ASCII | BMATH_ENC_UTF16)
print("2", fp2.read())
print("1", fp.read())
print("1", fp.read())
fp.write("1 << 0")
print("1", fp.read())
print("1", fp.read())
print("1", fp.read())
fp.close()
fp2.close()
