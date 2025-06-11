import concurrent.futures
from util import _fill_template


# This proves that we have multiple handles open, and there's no problem
def test_synchronous_writes():
    with open("/dev/bmath", "r+") as f1, open("/dev/bmath", "r+") as f2:
        f1.write("0x1")
        f2.write("0x2")
        data1 = f1.read()
        data2 = f2.read()
        assert data1 == _fill_template("1"), "data1 must equal"
        assert data2 == _fill_template("2"), "data2 must equal"


# Test can be flaky, but this gives somewhat consistent results without the lock
# in the first read() workloads
def test_async_writes():
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
        ("0x1", _fill_template("1"), 50),
        ("0x2", _fill_template("2"), 60),
        ("0x3", _fill_template("3"), 40),
        ("0x4", _fill_template("4"), 30),
        ("0x5", _fill_template("5"), 90),
        ("0x6", _fill_template("6"), 10),
        ("0x7", _fill_template("7"), 70),
    ]

    futures = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        for case in cases:
            input, template, loops = case
            fp = open("/dev/bmath", "r+")
            futures.append(executor.submit(_rw, fp, input, template, loops))

        done, waiting = concurrent.futures.wait(
            futures, return_when=concurrent.futures.ALL_COMPLETED
        )

        assert len(waiting) == 0, "hung tasks?"

        for future in done:
            fp, input, result, expected = future.result()
            fp.close()
            assert result == expected, f"input: {input} has mismatching data"
