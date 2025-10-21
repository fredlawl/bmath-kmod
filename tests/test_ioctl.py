import pytest
from util import (
    Bits,
    BmathIoctlEcoding,
    BmathIoctlFormat,
    BmathIoctlOption,
    Encoding,
    Format,
    OutputFormat,
    ascii_str,
    binary_str,
    hex_str,
    int_str,
    ioctl,
    oct_str,
    print_all_str,
    unicode_str,
)


@pytest.mark.parametrize(
    "input, expected, enc, fmt",
    [
        pytest.param(
            "0xAB",
            int_str(0xAB, True, Format.NONE),
            BmathIoctlEcoding.DEFAULT,
            BmathIoctlFormat.DEFAULT,
            id="fmt default",
        ),
        pytest.param(
            "0x21",
            print_all_str(0x21, [], Format.NONE, OutputFormat.NONE),
            BmathIoctlEcoding.NONE,
            BmathIoctlFormat.NONE,
            id="enc none",
        ),
        pytest.param(
            "0x21",
            print_all_str(0x21, [], Format.NONE, OutputFormat.NONE),
            BmathIoctlEcoding.NONE,
            BmathIoctlFormat.HUMAN,
            id="enc none; fmt human",
        ),
        pytest.param(
            "0x21",
            ascii_str(0x21, Format.NONE),
            BmathIoctlEcoding.ASCII,
            BmathIoctlFormat.NONE,
            id="enc ascii",
        ),
        pytest.param(
            "0x21",
            ascii_str(0x21, Format.HUMAN),
            BmathIoctlEcoding.ASCII,
            BmathIoctlFormat.HUMAN,
            id="enc ascii; fmt human",
        ),
        pytest.param(
            "0x21",
            binary_str(0x21),
            BmathIoctlEcoding.BINARY,
            BmathIoctlFormat.NONE,
            id="enc binary",
        ),
        pytest.param(
            "0x21",
            binary_str(0x21),
            BmathIoctlEcoding.BINARY,
            BmathIoctlFormat.HUMAN,
            id="enc binary; fmt human",
        ),
        pytest.param(
            "0x21",
            hex_str(0x21, Bits.MINIMAL, Format.NONE),
            BmathIoctlEcoding.HEX,
            BmathIoctlFormat.NONE,
            id="enc hex",
        ),
        pytest.param(
            "0x21",
            hex_str(0x21, Bits.MINIMAL, Format.HUMAN),
            BmathIoctlEcoding.HEX,
            BmathIoctlFormat.HUMAN,
            id="enc hex; fmt human",
        ),
        pytest.param(
            "0x21",
            hex_str(0x21, Bits.BITS_16, Format.NONE),
            BmathIoctlEcoding.HEX16,
            BmathIoctlFormat.NONE,
            id="enc hex16",
        ),
        pytest.param(
            "0x21",
            hex_str(0x21, Bits.BITS_16, Format.HUMAN),
            BmathIoctlEcoding.HEX16,
            BmathIoctlFormat.HUMAN,
            id="enc hex16; fmt human",
        ),
        pytest.param(
            "0x21",
            hex_str(0x21, Bits.BITS_32, Format.NONE),
            BmathIoctlEcoding.HEX32,
            BmathIoctlFormat.NONE,
            id="enc hex32",
        ),
        pytest.param(
            "0x21",
            hex_str(0x21, Bits.BITS_32, Format.HUMAN),
            BmathIoctlEcoding.HEX32,
            BmathIoctlFormat.HUMAN,
            id="enc hex32; fmt human",
        ),
        pytest.param(
            "0x21",
            hex_str(0x21, Bits.BITS_64, Format.NONE),
            BmathIoctlEcoding.HEX64,
            BmathIoctlFormat.NONE,
            id="enc hex64",
        ),
        pytest.param(
            "0x21",
            hex_str(0x21, Bits.BITS_64, Format.HUMAN),
            BmathIoctlEcoding.HEX64,
            BmathIoctlFormat.HUMAN,
            id="enc hex64; fmt human",
        ),
        pytest.param(
            "0xAB",
            print_all_str(
                0xAB,
                [
                    Encoding.HEX,
                    Encoding.HEX16,
                    Encoding.HEX32,
                    Encoding.HEX64,
                ],
                Format.UPPERCASE,
                OutputFormat.NONE,
            ),
            BmathIoctlEcoding.HEX
            | BmathIoctlEcoding.HEX16
            | BmathIoctlEcoding.HEX32
            | BmathIoctlEcoding.HEX64,
            BmathIoctlFormat.UPPERCASE,
            id="fmt uppercase",
        ),
        pytest.param(
            "0xAB",
            print_all_str(
                0xAB,
                [
                    Encoding.HEX,
                    Encoding.HEX16,
                    Encoding.HEX32,
                    Encoding.HEX64,
                ],
                Format.UPPERCASE | Format.HUMAN,
                OutputFormat.NONE,
            ),
            BmathIoctlEcoding.HEX
            | BmathIoctlEcoding.HEX16
            | BmathIoctlEcoding.HEX32
            | BmathIoctlEcoding.HEX64,
            BmathIoctlFormat.UPPERCASE | BmathIoctlFormat.HUMAN,
            id="fmt uppercase; fmt human",
        ),
        pytest.param(
            "0x21",
            int_str(0x21, False, Format.NONE),
            BmathIoctlEcoding.INT,
            BmathIoctlFormat.NONE,
            id="enc int",
        ),
        pytest.param(
            "0x21",
            int_str(0x21, False, Format.HUMAN),
            BmathIoctlEcoding.INT,
            BmathIoctlFormat.HUMAN,
            id="enc int; fmt human",
        ),
        pytest.param(
            "0x21",
            int_str(0x21, True, Format.NONE),
            BmathIoctlEcoding.UINT,
            BmathIoctlFormat.NONE,
            id="enc uint",
        ),
        pytest.param(
            "0x21",
            int_str(0x21, True, Format.HUMAN),
            BmathIoctlEcoding.UINT,
            BmathIoctlFormat.HUMAN,
            id="enc uint; fmt human",
        ),
        pytest.param(
            "0x21",
            oct_str(0x21, Format.NONE),
            BmathIoctlEcoding.OCTAL,
            BmathIoctlFormat.NONE,
            id="enc octal",
        ),
        pytest.param(
            "0x21",
            oct_str(0x21, Format.HUMAN),
            BmathIoctlEcoding.OCTAL,
            BmathIoctlFormat.HUMAN,
            id="enc octal; fmt human",
        ),
        pytest.param(
            "0x21",
            unicode_str(0x21, Format.NONE),
            BmathIoctlEcoding.UNICODE,
            BmathIoctlFormat.NONE,
            id="enc unicode",
        ),
        pytest.param(
            "0x21",
            unicode_str(0x21, Format.HUMAN),
            BmathIoctlEcoding.UNICODE,
            BmathIoctlFormat.HUMAN,
            id="enc unicode; fmt human",
        ),
        pytest.param(
            "0x21",
            "0x21",
            BmathIoctlEcoding.UTF8,
            BmathIoctlFormat.NONE,
            id="enc utf8",
        ),
        pytest.param(
            "0x21",
            "UTF-8BE: 0x21",
            BmathIoctlEcoding.UTF8,
            BmathIoctlFormat.HUMAN,
            id="enc utf8; fmt human",
        ),
        pytest.param(
            "0x21",
            "<invalid>",
            BmathIoctlEcoding.UTF16,
            BmathIoctlFormat.NONE,
            id="enc utf16",
        ),
        pytest.param(
            "0x21",
            "UTF-16BE: <invalid>",
            BmathIoctlEcoding.UTF16,
            BmathIoctlFormat.HUMAN,
            id="enc utf16; fmt human",
        ),
        pytest.param(
            "0x21",
            "<invalid>",
            BmathIoctlEcoding.UTF32,
            BmathIoctlFormat.NONE,
            id="enc utf32",
        ),
        pytest.param(
            "0x21",
            "UTF-32BE: <invalid>",
            BmathIoctlEcoding.UTF32,
            BmathIoctlFormat.HUMAN,
            id="enc utf32; fmt human",
        ),
    ],
)
def test_ioctl(input, expected, enc, fmt):
    with open("/dev/bmath", "r+") as f:
        ioctl(f.fileno(), BmathIoctlOption.SET_ENC, enc)
        ioctl(f.fileno(), BmathIoctlOption.SET_FORMAT, fmt)
        f.write(input)
        actual = f.read()
        assert expected == actual


def test_ioctl_overtakes():
    with open("/dev/bmath", "r+") as f:
        ioctl(f.fileno(), BmathIoctlOption.SET_ENC, BmathIoctlEcoding.BINARY)
        f.write("0x21")
        ioctl(f.fileno(), BmathIoctlOption.SET_ENC, BmathIoctlEcoding.NONE)
        actual = f.read()
        assert "" == actual


def test_ioctl_after_read_has_no_effect():
    with open("/dev/bmath", "r+") as f:
        f.write("0x21")
        f.read()
        ioctl(f.fileno(), BmathIoctlOption.SET_ENC, BmathIoctlEcoding.NONE)
        actual = f.read()
        assert "" != actual
