import pytest
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
BMATH_ENC_DEFAULT = 1 << 5


@pytest.mark.parametrize(
    "input, expected, req, arg",
    [
        pytest.param(
            "0xAB",
            """   u64: 171
    i8: -85
  char: Exceeded
   Hex: 0xAB
 Hex16: 0x00AB
 Hex32: 0x000000AB
 Hex64: 0x00000000000000AB
""",
            BMATH_SET_FORMAT,
            BMATH_FMT_UPPERCASE,
            id="fmt uppercase",
        ),
        pytest.param(
            "0xAB",
            """   u64: 171
    i8: -85
  char: Exceeded
   Hex: 0xab
 Hex16: 0x00ab
 Hex32: 0x000000ab
 Hex64: 0x00000000000000ab
""",
            BMATH_SET_FORMAT,
            BMATH_FMT_DEFAULTS,
            id="fmt default",
        ),
        pytest.param(
            "0x21",
            "",
            BMATH_SET_ENC,
            BMATH_ENC_NONE,
            id="enc none",
        ),
        pytest.param(
            "0x21",
            """   u64: 33
    i8: 33
  char: !
   Hex: 0x21
 Hex16: 0x0021
 Hex32: 0x00000021
 Hex64: 0x0000000000000021
""",
            BMATH_SET_ENC,
            BMATH_ENC_DEFAULT,
            id="enc default",
        ),
        pytest.param(
            "0x21",
            """   u64: 33
    i8: 33
  char: !
   Hex: 0x21
 Hex16: 0x0021
 Hex32: 0x00000021
 Hex64: 0x0000000000000021
""",
            BMATH_SET_ENC,
            BMATH_ENC_ASCII,
            id="enc ascii",
        ),
        pytest.param(
            "0x21",
            """   u64: 33
    i8: 33
 UTF-8: ! (0x21)
   Hex: 0x21
 Hex16: 0x0021
 Hex32: 0x00000021
 Hex64: 0x0000000000000021
""",
            BMATH_SET_ENC,
            BMATH_ENC_UTF8,
            id="enc utf-8",
        ),
        pytest.param(
            "0x7d71",
            """   u64: 32113
   i16: 32113
 UTF-8: q} (0x717d)
   Hex: 0x7d71
 Hex16: 0x7d71
 Hex32: 0x00007d71
 Hex64: 0x0000000000007d71
""",
            BMATH_SET_ENC,
            BMATH_ENC_UTF8,
            id="enc utf-8 (chinese 統)",
        ),
        pytest.param(
            "0x1f0a0",
            """   u64: 127136
   i32: 127136
 UTF-8: <invalid> <invalid>
   Hex: 0x1f0a0
 Hex16: Exceeded
 Hex32: 0x0001f0a0
 Hex64: 0x000000000001f0a0
""",
            BMATH_SET_ENC,
            BMATH_ENC_UTF8,
            id="enc utf-8 (card 🂠 )",
        ),
        pytest.param(
            "0x21",
            """   u64: 33
    i8: 33
UTF-16: ! <invalid>
   Hex: 0x21
 Hex16: 0x0021
 Hex32: 0x00000021
 Hex64: 0x0000000000000021
""",
            BMATH_SET_ENC,
            BMATH_ENC_UTF16,
            id="enc utf-16",
        ),
        pytest.param(
            "0x21",
            """   u64: 33
    i8: 33
UTF-32: ! <invalid>
   Hex: 0x21
 Hex16: 0x0021
 Hex32: 0x00000021
 Hex64: 0x0000000000000021
""",
            BMATH_SET_ENC,
            BMATH_ENC_UTF32,
            id="enc utf-32",
        ),
        pytest.param(
            "0x21",
            """00000000 00000000 00000000 00000000
00000000 00000000 00000000 00100001\n\x00""",
            BMATH_SET_ENC,
            BMATH_ENC_BINARY,
            id="enc binary",
        ),
    ],
)
def test_ioctl(input, expected, req, arg):
    with open("/dev/bmath", "r+", encoding="utf-8") as f:
        # with open("/dev/bmath", "r+") as f:
        fcntl.ioctl(f.fileno(), req, arg)
        f.write(input)
        actual = f.read()
        assert expected == actual


def test_ioctl_overtakes():
    with open("/dev/bmath", "r+") as f:
        fcntl.ioctl(f.fileno(), BMATH_SET_ENC, BMATH_ENC_BINARY)
        f.write("0x21")
        fcntl.ioctl(f.fileno(), BMATH_SET_ENC, BMATH_ENC_NONE)
        actual = f.read()
        assert "" == actual


def test_ioctl_after_read_has_no_effect():
    with open("/dev/bmath", "r+") as f:
        f.write("0x21")
        f.read()
        fcntl.ioctl(f.fileno(), BMATH_SET_ENC, BMATH_ENC_NONE)
        actual = f.read()
        assert "" != actual
