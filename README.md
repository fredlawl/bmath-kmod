# bmath-kmod

Linux kernel implementation of [bmath](https://github.com/fredlawl/bmath)
with a twist. Instead of reimplementing bmath as a kernel module, this is an
exercise in loading libbmath.so into the kernel and expose functionality
via the character device: `/dev/bmath`.

> WARNING: Do not use this code in production! This is for educational
> purposes only! There are clear an obvious security implications
> loading executing shared libraries in kernel space.

## Basic usage

Calculations are performed on first read() after write(). Subsequent reads
contain cached data from the first read() calculation. This behavior exists
so that there's no definitive "ending" character that users need to be
concerned with, such as a newline.

Users are welcome to add a newline in a write(). Subsequent write() data is
ignored by read(). Newline behavior is not module behavior, that's
bmath behavior.

Unlike normal files, every first read() after write() truncates the file.
Seeking has no effect.

Users can have multiple handles open to the `/dev/bmath` device.

See `tests/*.py` to exhaustively understand the behavior.

Trivial example:

```py
with open("/dev/bmath", "r+") as f:
  f.write("0x1")
  print(f.read())

```

### IOCTL

[ioctl()](https://man7.org/linux/man-pages/man2/ioctl.2.html) needs to be
called before the first read() after write(). Calling before write() is OK.
Calling `ioctl` after the first read() after write() doesn't mutate the
output because the calculation has already been performed & cached.

Format:

```c
// op
#define BMATH_SET_FORMAT 0x4004b301

// arg
#define BMATH_FMT_NONE 0
#define BMATH_FMT_UPPERCASE (1 << 0)
#define BMATH_FMT_JUSTIFY (1 << 1)
#define BMATH_FMT_HUMAN (1 << 2)
#define BMATH_FMT_DEFAULT BMATH_FMT_NONE
```

Encoding:

```c
// op
#define BMATH_SET_ENC 0x4004b302

// arg
#define BMATH_ENC_NONE 0
#define BMATH_ENC_ASCII (1 << 0)
#define BMATH_ENC_BINARY (1 << 1)
#define BMATH_ENC_HEX (1 << 2)
#define BMATH_ENC_HEX16 (1 << 3)
#define BMATH_ENC_HEX32 (1 << 4)
#define BMATH_ENC_HEX64 (1 << 5)
#define BMATH_ENC_INT (1 << 6)
#define BMATH_ENC_UINT (1 << 7)
#define BMATH_ENC_OCTAL (1 << 8)
#define BMATH_ENC_UNICODE (1 << 9)
#define BMATH_ENC_UTF8 (1 << 10)
#define BMATH_ENC_UTF16 (1 << 11)
#define BMATH_ENC_UTF32 (1 << 12)

#define BMATH_ENC_DEFAULT (~0L)

#define BMATH_ENC_ALL                                                          \
 (BMATH_ENC_ASCII | BMATH_ENC_BINARY | BMATH_ENC_HEX |                  \
  BMATH_ENC_HEX16 | BMATH_ENC_HEX32 | BMATH_ENC_HEX64 | BMATH_ENC_INT | \
  BMATH_ENC_UINT | BMATH_ENC_OCTAL | BMATH_ENC_UNICODE |                \
  BMATH_ENC_UTF8 | BMATH_ENC_UTF16 | BMATH_ENC_UTF32)
```

Currently `BMATH_ENC_UTF16` and `BMATH_ENC_UTF32` are not supported.
`BMATH_ENC_UNICODE` and `BMATH_ENC_UTF8` only has normalization supported.
The kernel doesn't have an implementation to convert to these encodings.
So this will only display normalization in the UTF-8 case. Making that conversion
myself is a project on it's own.

All of that said, given the bmath unicode encoding options, the UTF-8
normalization appears in all of them. The byte representation
will just be `<invalid>` in any case other than UTF-8. If normalization
fails, then everything is `<invalid>`.

The reason the normalization appears for all unicode options is because
of an bmath implementation detail where it'll display the character
for each encoding as UTF-8 in output for consistency, but the byte
representation differs per-encoding.

## Build & Run

Tested on kernel 6.12.z (kasan + kmemleak) and 6.15.y

### Dependencies

Kernel:

- CONFIG_UNICODE=y

Build:

- [bmath](https://github.com/fredlawl/bmath)
- [Build EAR](https://github.com/rizsotto/Bear)
- gcc
- linux-headers
- make

```sh
make
make probe
```

> Running `make probe` will likely not work if you're on a machine that
> requires signed modules. Best to stick to the test workflows.

### Dev Dependencies

Kernel:

- CONFIG_DYNAMIC_DEBUG=y
- CONFIG_KASAN=y
- CONFIG_KASAN_VMALLOC=y
- CONFIG_DEBUG_KMEMLEAK=y
- CONFIG_DEBUG_KMEMLEAK_DEFAULT_OFF=y
- CONFIG_DEBUG_KMEMLEAK_AUTO_SCAN=n

Virtme-ng will setup the rest of the options that are needed:

```sh
cd /path/to/kernel/source; vng --kconfig
# - or -
cd /path/to/kernel/source; vng --build
```

Test:

- python3-pytest
- [virtme-ng](https://github.com/arighi/virtme-ng)

Test:

```sh
make clean
make test
# or for custom kernel
make clean
KDIR=/path/to/kernel/source KIMG=/path/to/kernel/source/image make test
```

## Wishlist

- kunit tests
