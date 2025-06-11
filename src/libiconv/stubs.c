#define pr_fmt(fmt) KBUILD_MODNAME " libiconv: " fmt

#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/dcache.h>

#include "../libc/stubs.h"
#include "stubs.h"

#ifndef UTF8_LATEST
#define UTF8_LATEST UNICODE_AGE(12, 1, 0)
#endif

enum encoding { UNSUPPORTED, UTF8 };

struct iv {
	enum encoding to;
	struct unicode_map *unicode;
};

// iconv API is master class in how to not design a function
size_t _stub__iconv(iconv_t cd, char **inbuf, size_t *inbytesleft,
		    char **outbuf, size_t *outbytesleft)
{
	int ret;
	struct qstr in;

	if (cd->to == UNSUPPORTED) {
		libc_set_errno(EINVAL);
		return ICONV_CONV_ERR;
	}

	// iconv doesn't describe what happens here...
	// TODO: Test this against iconv to know what happens for this case...
	if (!inbytesleft || (inbytesleft && *inbytesleft <= 0) ||
	    !outbytesleft || (outbytesleft && *outbytesleft <= 0)) {
		libc_set_errno(EINVAL);
		return ICONV_CONV_ERR;
	}

	// Case: No input, has output
	// This case is supposed to put some shift squence (w/e that is) into the
	// outbuf or return an E2BIG if outbuf isn't big enough.
	// Since I don't know what that shift sequence is, I'm just going
	// to pretend I wrote something to outbuf.
	// No point in setting E2BIG becuase of make-believe
	if ((!inbuf || (inbuf && !*inbuf)) && outbuf && *outbuf) {
		ret = *outbytesleft;
		outbuf += ret;
		*outbytesleft = 0;
		return ret;
	}

	// Case: No input, no output
	// Handles third case that's a reset sequence that we don't need
	if ((!inbuf || (inbuf && !*inbuf)) &&
	    (!outbuf || (outbuf && !*outbuf))) {
		return 0;
	}

	// Case: Has input, but no output
	if (inbuf && *inbuf && (!outbuf || (outbuf && !*outbuf))) {
		libc_set_errno(E2BIG);
		return ICONV_CONV_ERR;
	}

	in = (struct qstr)QSTR_INIT(*inbuf, *inbytesleft);

	// TODO: Implement conversion?
	// The kernel doens't have converstion functionality (AFAIK), so we're
	// stuck with next best thing, show the normalization.
	ret = utf8_normalize(cd->unicode, &in, *outbuf, *outbytesleft);

	// The kernel implementation doesn't provide enough information to return
	// back anything other than EINVAL. Sry callers. You should be dealing
	// with EINVAL over the others at the very least anyway.
	if (ret < 0) {
		if (ret != -EINVAL)
			ret = EINVAL;
		libc_set_errno(ret);
		return ICONV_CONV_ERR;
	}

	*outbytesleft = *outbytesleft - ret - 1;
	*inbytesleft = 0;

	return ret;
}

iconv_t _stub__iconv_open(const char *tocode, const char *fromcode)
{
	iconv_t cd;

	cd = kzalloc(sizeof(*cd), GFP_ATOMIC);
	if (!cd) {
		*errno_loc = ENOMEM;
		return ICONV_ERR;
	}

	/*
   * iconv --list
   * Has an extremely large amount of encodings that it supports. We're
   * not messing with any of that here... Better to load iconv itself
   * alongside binaries that use it 😎
   *
   * For now, since we're dealing with just libbmath, only match on
   * the most likely selection, and for all others return cd, but
   * make _stub__iconv() return (size_t)-1
   *
   * Because Linux only has utf8 currently, only support that.
   */
	cd->to = UNSUPPORTED;
	cd->unicode = NULL;
	if (strlen("UTF-8") == strlen(tocode) && !strcmp("UTF-8", tocode)) {
		cd->to = UTF8;
	}

	if (cd->to == UNSUPPORTED) {
		return cd;
	}

	cd->unicode = utf8_load(UTF8_LATEST);
	if (IS_ERR(cd->unicode)) {
		libc_set_errno(PTR_ERR(cd->unicode));
		goto err;
	}

	return cd;

err:
	utf8_unload(cd->unicode);
	kfree(cd);
	return ICONV_ERR;
}

int _stub__iconv_close(iconv_t cd)
{
	utf8_unload(cd->unicode);
	kfree(cd);
	return 0;
}
