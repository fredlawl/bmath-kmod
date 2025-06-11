MEMORY {
  sneaky (wxa) : ORIGIN = 0, LENGTH = 256K
}

SECTIONS {
  .fred : 
  {
    *(.fred);
  } > sneaky
}


