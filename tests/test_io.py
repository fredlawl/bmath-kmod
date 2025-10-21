from io import SEEK_CUR, SEEK_END, SEEK_SET, UnsupportedOperation

import pytest
from util import default_str


def test_open_close():
    fp = open("/dev/bmath", "r+")
    fp.close()
    assert True


def test_rw():
    with open("/dev/bmath", "r+") as f:
        data = f.read()
        assert len(data) == 0, "first read before write yields no data"

    with open("/dev/bmath", "r+") as f:
        f.write("")
        assert True, "no error for empty write"

    with open("/dev/bmath", "r+") as f:
        f.write("0xab")
        data = f.read()
        assert len(data) > 0, "first read after write yeilds data"

    with open("/dev/bmath", "r+") as f:
        f.write("0xab")
        data1 = f.read()
        data2 = f.read()
        assert data1 == data2, "reads after write are cached"

    with open("/dev/bmath", "r+") as f:
        f.write("0x1")
        data1 = f.read()
        f.write("0x2")
        data2 = f.read()
        assert data1 != data2, "writes resets read"

    # The module assumes that writes arn't done until first read.
    # The input effectivley becomes 0x10x2
    with open("/dev/bmath", "r+") as f:
        f.write("0x1")
        f.write("0x2")
        data = f.read()
        assert "Parse error" in data, "second write concats to first"

    with open("/dev/bmath", "r+") as f:
        f.write("0x1\n")  # newline terminator is bmath behavior, hence test passes
        f.write("0x2")
        data = f.read()
        assert default_str(0x1) in data, "second write doesn't reset first"


def test_read():
    with open("/dev/bmath", "r+") as f:
        b = f.read()
        assert b == "", "empty read should be empty"


@pytest.mark.parametrize(
    "cookie, whence, supported",
    [
        pytest.param(10, SEEK_SET, True, id="set"),
        pytest.param(10, SEEK_CUR, False, id="cur"),
        # SEEK_END is testing python behavior more than anything else
        pytest.param(0, SEEK_END, True, id="end"),
        pytest.param(-1, SEEK_END, False, id="end relative"),
    ],
)
def test_seek(cookie, whence, supported):
    with open("/dev/bmath", "r+") as f:
        if not supported:
            with pytest.raises(UnsupportedOperation):
                f.write("0xab")
                data1 = f.read()
                f.seek(cookie, whence)
                data2 = f.read()
            assert True
            return

        f.write("0xab")
        data1 = f.read()
        f.seek(cookie, whence)
        data2 = f.read()
        assert data1 == data2


def test_maximum_input():
    with open("/dev/bmath", "r+") as f:
        len = 501
        input = "1" * len
        b = f.write(input)
        data = f.read()
        assert (
            "Expression too long.\n\x00" == data and b == len
        ), "bmath calculation limit not met"

    # tests that the EFBIG is not raised for subsequent write after read
    with open("/dev/bmath", "r+") as f:
        len = 501
        input = "1" * len
        b = f.write(input)
        data = f.read()
        b = f.write(input)
        assert (
            "Expression too long.\n\x00" == data and b == len
        ), "bmath calculation limit not met"

    with pytest.raises(OSError):
        input = "1" * 513  # module buffer limit
        with open("/dev/bmath", "r+") as f:
            f.write(input)
