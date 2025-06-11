test_data_template = """   u64: {val}
    i8: {val}
  char: <special>
   Hex: 0x{val}
 Hex16: 0x000{val}
 Hex32: 0x0000000{val}
 Hex64: 0x000000000000000{val}
"""


def _fill_template(val):
    return test_data_template.format(val=val)
