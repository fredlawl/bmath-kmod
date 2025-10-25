import ctypes
import errno
import os
from ctypes import (
    POINTER,
    Structure,
    c_bool,
    c_char,
    c_char_p,
    c_int,
    c_int64,
    c_size_t,
    c_ssize_t,
    c_uint64,
)
from enum import IntEnum, IntFlag, auto


class BmathIoctlOption:
    SET_FORMAT = 0x4004B301
    SET_ENC = 0x4004B302


class BmathIoctlEcoding(IntFlag):
    NONE = 0
    ASCII = 1 << 0
    BINARY = 1 << 1
    HEX = 1 << 2
    HEX16 = 1 << 3
    HEX32 = 1 << 4
    HEX64 = 1 << 5
    INT = 1 << 6
    UINT = 1 << 7
    OCTAL = 1 << 8
    UNICODE = 1 << 9
    UTF8 = 1 << 10
    UTF16 = 1 << 11
    UTF32 = 1 << 12

    DEFAULT = 0xFFFFFFFFFFFFFFFF
    ALL = (
        ASCII
        | BINARY
        | HEX
        | HEX16
        | HEX32
        | HEX64
        | INT
        | UINT
        | OCTAL
        | UNICODE
        | UTF8
        | UTF16
        | UTF32
    )


class BmathIoctlFormat(IntFlag):
    NONE = 0
    UPPERCASE = 1 << 0
    JUSTIFY = 1 << 1
    HUMAN = 1 << 2
    DEFAULT = NONE


class Encoding(IntEnum):
    NONE = 0
    ASCII = auto()
    BINARY = auto()
    HEX = auto()
    HEX16 = auto()
    HEX32 = auto()
    HEX64 = auto()
    INT = auto()
    UINT = auto()
    OCTAL = auto()
    UNICODE = auto()
    UTF8 = auto()
    UTF16 = auto()
    UTF32 = auto()


class Bits(IntEnum):
    MINIMAL = 0
    BITS_8 = auto()
    BITS_16 = auto()
    BITS_32 = auto()
    BITS_64 = auto()


class Format(IntFlag):
    NONE = 0
    HUMAN = 1 << 0
    UPPERCASE = 1 << 1


class OutputFormat(IntFlag):
    NONE = 0
    JUSTIFY = 1 << 0


class File(Structure):
    pass


class BmathFailedEncoding(Exception):
    """Raised when a specific custom condition occurs."""

    def __init__(self, message, code):
        super().__init__(f"{message}: {
            os.strerror(code)} ({errno.errorcode[code]})")


libbmath = ctypes.CDLL("./libbmath.so")
libc = ctypes.CDLL(None)

# ssize_t print_all(FILE *stream, uint64_t num, enum encoding_t encode_order[],
# size_t encode_order_len, enum format_t fmt,
# enum output_format_t output_fmt);
c_FILE_p = POINTER(File)
libbmath.print_all.argtypes = (
    c_FILE_p,
    c_uint64,
    POINTER(c_int),
    c_size_t,
    c_uint64,
    c_int,
)
libbmath.print_all.restype = c_ssize_t

libc.fdopen.argtypes = (c_int, c_char_p)
libc.fdopen.restype = c_FILE_p

libc.fseek.argtypes = [c_FILE_p, c_int64, c_int]
libc.fseek.restype = c_int


# Pythons fnctl doesn't take unsigned 64 bit integers for some reason
def ioctl(fd, op, arg):
    libc.ioctl(fd, op, arg)


def print_all_str(num, encodings, fmt, outfmt):
    written = -1
    out = ""
    fd = os.memfd_create("print_all_file")
    EncodingsArray = ctypes.c_int * len(encodings)
    arr = EncodingsArray(*encodings)

    f = libc.fdopen(fd, "w+".encode("ascii"))
    written = libbmath.print_all(
        f, num, arr, len(encodings), c_uint64(fmt), int(outfmt)
    )
    if written < 0:
        os.close(fd)
        raise BmathFailedEncoding("failed to write print_all()", -written)

    libc.fseek(f, 0, os.SEEK_SET)
    out = os.read(fd, written)
    os.close(fd)
    return out.decode("utf-8")


def print_all_encodings_str(num, fmt, outfmt):
    return print_all_str(
        num,
        [
            Encoding.ASCII,
            Encoding.BINARY,
            Encoding.HEX,
            Encoding.HEX16,
            Encoding.HEX32,
            Encoding.HEX64,
            Encoding.INT,
            Encoding.UINT,
            Encoding.OCTAL,
            Encoding.UNICODE,
            Encoding.UTF8,
            Encoding.UTF16,
            Encoding.UTF32,
        ],
        fmt,
        outfmt,
    )


# ssize_t binary_str(char *dest, size_t dest_len, uint64_t number,
# enum format_t fmt);
libbmath.binary_str.argtypes = (POINTER(c_char), c_size_t, c_uint64, c_int)
libbmath.binary_str.restype = c_ssize_t


def binary_str(num):
    buf = ctypes.create_string_buffer(74)
    written = libbmath.binary_str(buf, len(buf), num, 0)
    if written < 0:
        raise BmathFailedEncoding("failed to write binary_str()", -written)
    return buf.value.decode()


# ssize_t ascii_str(char *dest, size_t dest_len, uint64_t number,
# enum format_t fmt);
libbmath.ascii_str.argtypes = (POINTER(c_char), c_size_t, c_uint64, c_int)
libbmath.ascii_str.restype = c_ssize_t


def ascii_str(num, fmt):
    buf = ctypes.create_string_buffer(32)
    written = libbmath.ascii_str(buf, len(buf), num, int(fmt))
    if written < 0:
        raise BmathFailedEncoding("failed to write ascii_str()", -written)
    return buf.value.decode()


# ssize_t hex_str(char *dest, size_t dest_len, uint64_t number, enum bits_t bits,
# enum format_t fmt);
libbmath.hex_str.argtypes = (POINTER(c_char), c_size_t, c_uint64, c_int, c_int)
libbmath.hex_str.restype = c_ssize_t


def hex_str(num, bits, fmt):
    buf = ctypes.create_string_buffer(32)
    written = libbmath.hex_str(buf, len(buf), num, int(bits), int(fmt))
    if written < 0:
        raise BmathFailedEncoding("failed to write hex_str()", -written)
    return buf.value.decode()


# ssize_t int_str(char *dest, size_t dest_len, uint64_t number, bool is_unsigned,
# enum format_t fmt);
libbmath.int_str.argtypes = (
    POINTER(c_char), c_size_t, c_uint64, c_bool, c_int)
libbmath.int_str.restype = c_ssize_t


def int_str(num, unsigned, fmt):
    buf = ctypes.create_string_buffer(32)
    written = libbmath.int_str(buf, len(buf), num, unsigned, int(fmt))
    if written < 0:
        raise BmathFailedEncoding("failed to write int_str()", -written)
    return buf.value.decode()


def default_str(num):
    return int_str(num, True, Format.NONE)


# ssize_t oct_str(char *dest, size_t dest_len, uint64_t number,
# enum format_t fmt);
libbmath.oct_str.argtypes = (POINTER(c_char), c_size_t, c_uint64, c_int)
libbmath.oct_str.restype = c_ssize_t


def oct_str(num, fmt):
    buf = ctypes.create_string_buffer(32)
    written = libbmath.oct_str(buf, len(buf), num, int(fmt))
    if written < 0:
        raise BmathFailedEncoding("failed to write oct_str()", -written)
    return buf.value.decode()


# ssize_t unicode_str(char *dest, size_t dest_len, uint64_t number,
# enum format_t fmt);
libbmath.unicode_str.argtypes = (POINTER(c_char), c_size_t, c_uint64, c_int)
libbmath.unicode_str.restype = c_ssize_t


def unicode_str(num, fmt):
    buf = ctypes.create_string_buffer(32)
    written = libbmath.unicode_str(buf, len(buf), num, int(fmt))
    if written < 0:
        raise BmathFailedEncoding("failed to write unicode_str()", -written)
    return buf.value.decode()


# ssize_t utf_str(char *dest, size_t dest_len, uint64_t number, enum bits_t bits,
# enum format_t fmt);
libbmath.utf_str.argtypes = (POINTER(c_char), c_size_t, c_uint64, c_int, c_int)
libbmath.utf_str.restype = c_ssize_t


def utf_str(num, bits, fmt):
    buf = ctypes.create_string_buffer(32)
    written = libbmath.utf_str(buf, len(buf), num, int(bits), int(fmt))
    if written < 0:
        raise BmathFailedEncoding("failed to write utf_str()", -written)
    return buf.value.decode()


# if __name__ == "__main__":
#     print(binary_str(0xA))
#     print(ascii_str(0xA, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0x00, Bits.MINIMAL, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0x0A, Bits.MINIMAL, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0xAB, Bits.MINIMAL, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0xABCD, Bits.MINIMAL, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0x00, Bits.BITS_8, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0x0A, Bits.BITS_8, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0xAB, Bits.BITS_8, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0xABCD, Bits.BITS_8, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0x0000, Bits.BITS_16, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0xABCD, Bits.BITS_16, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0x00000000, Bits.BITS_32, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0xABCD, Bits.BITS_32, Format.HUMAN | Format.UPPERCASE))
#     print(hex_str(0xABCD, Bits.BITS_64, Format.HUMAN | Format.UPPERCASE))
#     print(int_str(0xABCD, True, Format.HUMAN | Format.UPPERCASE))
#     print(int_str(0xABCD, False, Format.HUMAN | Format.UPPERCASE))
#     print(oct_str(0xABCD, Format.HUMAN | Format.UPPERCASE))
#     print(unicode_str(0xABCD, Format.HUMAN | Format.UPPERCASE))
#     print(utf_str(0xABCD, Bits.MINIMAL, Format.HUMAN | Format.UPPERCASE))
#     print(utf_str(0xABCD, Bits.BITS_8, Format.HUMAN | Format.UPPERCASE))
#     print(utf_str(0xABCD, Bits.BITS_16, Format.HUMAN | Format.UPPERCASE))
#     print(utf_str(0xABCD, Bits.BITS_32, Format.HUMAN | Format.UPPERCASE))
#     print(
#         print_all_encodings_str(
#             0xABCD, Format.HUMAN | Format.UPPERCASE, OutputFormat.JUSTIFY
#         )
#     )
