#include <asm/fsgsbase.h>
#include <linux/slab.h>

#include "arch.h"

// https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/sysdeps/unix/sysv/linux/bits/pthread_stack_min.h
#define PTHREAD_STACK_MIN 16384

// https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/sysdeps/generic/dl-dtv.h
struct dtv_pointer {
	void *val; /* Pointer to data, or TLS_DTV_UNALLOCATED.  */
	void *to_free; /* Unaligned pointer, for deallocation.  */
};

typedef union dtv {
	size_t counter;
	struct dtv_pointer pointer;
} dtv_t;

// https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/sysdeps/x86_64/nptl/tls.h
typedef struct {
	void *tcb; /* Pointer to the TCB.  Not necessarily the
			   thread descriptor used by libpthread.  */
	dtv_t *dtv;
	void *self; /* Pointer to the thread descriptor.  */
	int multiple_threads;
	int gscope_flag;
	uintptr_t sysinfo;
	uintptr_t stack_guard;
	uintptr_t pointer_guard;
	unsigned long int unused_vgetcpu_cache[2];
	/* Bit 0: X86_FEATURE_1_IBT.
     Bit 1: X86_FEATURE_1_SHSTK.
   */
	unsigned int feature_1;
	int __glibc_unused1;
	/* Reservation of some values for the TM ABI.  */
	void *__private_tm[4];
	/* GCC split stack support.  */
	void *__private_ss;
	/* The marker for the current shadow stack.  */
	unsigned long long int ssp_base;
} tcbhead_t;

__always_inline uintptr_t arch_set_reg_fs(uintptr_t addr)
{
	uintptr_t out = x86_fsbase_read_cpu();
	x86_fsbase_write_cpu(addr);
	return out;
}

__always_inline uintptr_t arch_get_reg_fs(void)
{
	return x86_fsbase_read_cpu();
}

void *tls_alloc(void)
{
	tcbhead_t *head;
	tcbhead_t tcbhead = { 0 };
	uintptr_t stack_guard;

	// Size is really difficult to calculate without a more complete glibc implementation
	void *tls = kzalloc(sizeof(*head) + PTHREAD_STACK_MIN, GFP_ATOMIC);
	if (!tls) {
		return ERR_PTR(-ENOMEM);
	}

	memcpy(tls, &tcbhead, sizeof(tcbhead));
	head = tls;

	// https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/sysdeps/generic/dl-osinfo.h
	stack_guard = get_random_u64() & ~(uintptr_t)0xff; // x86_64 is LE
	head->stack_guard = stack_guard;
	head->pointer_guard = head->stack_guard;

	return tls;
}

void tls_free(const void *tls)
{
	kfree(tls);
}
