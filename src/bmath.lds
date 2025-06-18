SECTIONS {
  .fred : {
    . = ALIGN(8);
    *(.fred);
    add = .;
    summation = .;
  }
} INSERT AFTER .text
