#ifndef _BMATH_SYMBOLS_H_
#define _BMATH_SYMBOLS_H_

struct firmware;
struct device;
typedef int (*request_firmware_t)(const struct firmware **, const char *,
				  struct device *);
typedef int (*set_memory_t)(unsigned long, int);

static request_firmware_t __request_firmware =
	(request_firmware_t)0xffffffff818ce0b0;

static set_memory_t __set_memory_ro = (set_memory_t)0xffffffff810a72c0;
static set_memory_t __set_memory_rw = (set_memory_t)0xffffffff810a7360;
static set_memory_t __set_memory_x = (set_memory_t)0xffffffff810a7220;
static set_memory_t __set_memory_nx = (set_memory_t)0xffffffff810a7270;

#endif // _BMATH_SYMBOLS_H_

