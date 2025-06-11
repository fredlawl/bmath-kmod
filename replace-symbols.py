# Usage: python3 replace-symbols.py /path/to/symbols/file /path/to/template/file
# Replacement pattern: <symbol name> (<> included)
import re
import sys


def main(symbols_file, template_file):
    sym_pattern_template = r"^([a-fA-F0-9]+)\s+([a-zA-Z])\s+:symbol:$"
    lookup_pattern = r"<(.*)>"

    symf = open(symbols_file, "r")
    tf = open(template_file, "r")
    symbols_buf = symf.read()
    template_buf = tf.read()
    symf.close()
    tf.close()

    lookup_symbols = re.findall(lookup_pattern, template_buf)
    for sym in lookup_symbols:
        sym_pattern = sym_pattern_template.replace(":symbol:", sym, 1)
        sym_pattern = re.compile(sym_pattern, re.MULTILINE)
        match = re.search(
            sym_pattern,
            symbols_buf,
        )
        assert match is not None, str(sym_pattern)

        # print("0", match.group(0), "1", match.group(1), "2", match.group(2))
        address = match.group(1)
        # TODO: Do some validation?
        # sym_type = match.group(2)

        template_buf = template_buf.replace(f"<{sym}>", f"0x{address}")

    print(template_buf)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
