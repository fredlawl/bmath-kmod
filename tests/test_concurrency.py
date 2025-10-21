import concurrent.futures

from util import (
    BmathIoctlEcoding,
    BmathIoctlFormat,
    BmathIoctlOption,
    Encoding,
    Format,
    OutputFormat,
    default_str,
    ioctl,
    print_all_str,
)


# This proves that we have multiple handles open, and there's no problem
def test_synchronous_writes():
    with open("/dev/bmath", "r+") as f1, open("/dev/bmath", "r+") as f2:
        f1.write("0x1")
        f2.write("0x2")
        data1 = f1.read()
        data2 = f2.read()
        assert default_str(1) == data1, "data1 must equal"
        assert default_str(2) == data2, "data2 must equal"


# Test can be flaky, but this gives somewhat consistent results without the lock
# in the first read() workloads
def test_async_writes():
    encodings = [
        Encoding.ASCII,
        Encoding.BINARY,
        Encoding.HEX,
        Encoding.HEX16,
        Encoding.HEX32,
        Encoding.HEX64,
        Encoding.INT,
        Encoding.UINT,
        Encoding.OCTAL,
    ]

    def _rw(fp, input, expected, loops):
        result = ""
        for i in range(0, loops):
            fp.write(input)
            result = fp.read()
            # don't give this test an opportunity to accedenlty pass on a later loop iteration
            if result != expected:
                break
        return (fp, input, result, expected)

    cases = [
        ("0x1", print_all_str(1, encodings, Format.HUMAN, OutputFormat.JUSTIFY), 50),
        ("0x2", print_all_str(2, encodings, Format.HUMAN, OutputFormat.JUSTIFY), 60),
        ("0x3", print_all_str(3, encodings, Format.HUMAN, OutputFormat.JUSTIFY), 40),
        ("0x4", print_all_str(4, encodings, Format.HUMAN, OutputFormat.JUSTIFY), 30),
        ("0x5", print_all_str(5, encodings, Format.HUMAN, OutputFormat.JUSTIFY), 90),
        ("0x6", print_all_str(6, encodings, Format.HUMAN, OutputFormat.JUSTIFY), 10),
        ("0x7", print_all_str(7, encodings, Format.HUMAN, OutputFormat.JUSTIFY), 70),
    ]

    futures = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        for case in cases:
            input, template, loops = case
            fp = open("/dev/bmath", "r+")
            ioctl(
                fp.fileno(),
                BmathIoctlOption.SET_ENC,
                BmathIoctlEcoding.ASCII
                | BmathIoctlEcoding.BINARY
                | BmathIoctlEcoding.HEX
                | BmathIoctlEcoding.HEX16
                | BmathIoctlEcoding.HEX32
                | BmathIoctlEcoding.HEX64
                | BmathIoctlEcoding.INT
                | BmathIoctlEcoding.UINT
                | BmathIoctlEcoding.OCTAL,
            )
            ioctl(
                fp.fileno(),
                BmathIoctlOption.SET_FORMAT,
                BmathIoctlFormat.HUMAN | BmathIoctlFormat.JUSTIFY,
            )
            futures.append(executor.submit(_rw, fp, input, template, loops))

        done, waiting = concurrent.futures.wait(
            futures, return_when=concurrent.futures.ALL_COMPLETED
        )

        assert len(waiting) == 0, "hung tasks?"

        for future in done:
            fp, input, result, expected = future.result()
            fp.close()
            assert result == expected, f"input: {input} has mismatching data"
