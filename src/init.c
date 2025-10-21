#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/device/class.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/firmware.h>
#include <linux/fs.h>
#include <linux/gfp_types.h>
#include <linux/init.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/random.h>

#include "bmath.h"
#include "dl/loader.h"
#include "dl/symbols.h"
#include "libbmath/api.h"
#include "arch/arch.h"

#define DEV_FW_PATH "libbmath.so"

extern const struct relocate_sym *rlsyms[];
static struct bmath_dev *b_dev;

#define UNUSED(x) (void)(x)

/*
 * Preemption could break the loaded code by potentionally clobbering
 * the stack.
 *
 * Userspace code may rely on a 16-byte aligned stack for SIMD instruction,
 * so we need to ensure that the stack pointer ends on that boundary.
 *
 * Given compiler options such as -fstack-protector, the loaded code relies
 * on thread local storage. In x84_64, the FS regiter's value should 
 * be the address of the storage location.
 */
#define GUARD(FS)                                        \
	({                                               \
		volatile char x __aligned(16) = 0;       \
		UNUSED(x);                               \
		local_irq_disable();                     \
		uintptr_t fs_prev = arch_set_reg_fs(FS); \
		fs_prev;                                 \
	})

/*
 * Resets the CPU to allow the kernel to
 * continue to preempt.
 */
#define END_GUARD(FS)                \
	({                           \
		arch_set_reg_fs(FS); \
		local_irq_enable();  \
	})

/*
 * Call guards are a convinent way to wrap loaded code calls to setup the
 * CPU, align kernel stak, etc...
 *
 * 7-paramater functions arn't currently supported.
 *
 * @param FUNC: function to call
 * @param FS: uintptr_t address to thread-local-storage
 * @param A...: function param in order
 * @return: the result of the calling function
 */
#define GUARD_CALL_1(FUNC, FS, A)             \
	({                                    \
		uintptr_t old_fs = GUARD(FS); \
		__auto_type ret = FUNC(A);    \
		END_GUARD(old_fs);            \
		ret;                          \
	})

#define GUARD_CALL_2(FUNC, FS, A, B)          \
	({                                    \
		uintptr_t old_fs = GUARD(FS); \
		__auto_type ret = FUNC(A, B); \
		END_GUARD(old_fs);            \
		ret;                          \
	})

#define GUARD_CALL_3(FUNC, FS, A, B, C)          \
	({                                       \
		uintptr_t old_fs = GUARD(FS);    \
		__auto_type ret = FUNC(A, B, C); \
		END_GUARD(old_fs);               \
		ret;                             \
	})

#define GUARD_CALL_4(FUNC, FS, A, B, C, D)          \
	({                                          \
		uintptr_t old_fs = GUARD(FS);       \
		__auto_type ret = FUNC(A, B, C, D); \
		END_GUARD(old_fs);                  \
		ret;                                \
	})

#define GUARD_CALL_5(FUNC, FS, A, B, C, D, E)          \
	({                                             \
		uintptr_t old_fs = GUARD(FS);          \
		__auto_type ret = FUNC(A, B, C, D, E); \
		END_GUARD(old_fs);                     \
		ret;                                   \
	})

#define GUARD_CALL_6(FUNC, FS, A, B, C, D, E, G)          \
	({                                                \
		uintptr_t old_fs = GUARD(FS);             \
		__auto_type ret = FUNC(A, B, C, D, E, G); \
		END_GUARD(old_fs);                        \
		ret;                                      \
	})

static int evaluate(void *tls, FILE *stream, struct parser_context *pctx,
		    const char *input, size_t len, const struct parse_fmt *fmt)
{
	u64 val;
	int err = 0;

	// TODO: We need a way to reset the error stream for the parse context as well
	// Also add the ability to get it as well.

	err = GUARD_CALL_4(parse, (uintptr_t)tls, pctx, input, len, &val);
	if (err) {
		// parse error, not kernel error. error output should be in stream for output
		switch (err) {
		case PE_EXPRESSION_TOO_LONG:
			libc_write(stream, PE_EXPRESSION_TOO_LONG_MSG,
				   sizeof(PE_EXPRESSION_TOO_LONG_MSG));
			break;
		case PE_PARSE_ERROR:
			libc_write(stream, PE_PARSE_ERROR_MSG,
				   sizeof(PE_PARSE_ERROR_MSG));
			break;
		case PE_NOTHING_TO_PARSE:
			libc_write(stream, PE_NOTHING_TO_PARSE_MSG,
				   sizeof(PE_NOTHING_TO_PARSE_MSG));
			break;
		default:
			libc_write(stream, PE_UKNOWN_MSG,
				   sizeof(PE_UKNOWN_MSG));
			break;
		}

		// set error to zero because these are not read errors
		err = 0;
		goto err;
	}

	GUARD_CALL_6(print_all, (uintptr_t)tls, stream, val, fmt->encodings,
		     fmt->encodings_len, fmt->format, fmt->out_format);

err:
	return err;
}

#ifndef DEBUG
static __always_inline int api_test(void)
{
	return 0;
}
#else
#include "libc/stubs.h"
static int api_test(void)
{
#define TEST_EXPR "0xab"
	FILE *stream = _stub__stdout;
	int err = 0;
	void *tls;
	struct parser_context *pctx;
	struct parse_fmt fmt = { .uppercase = true,
				 .encoding = BMATH_ENC_ASCII,
				 .binary = true };
	struct parser_settings *psettings =
		&(struct parser_settings){ .max_parse_len = BMATH_MAX_PARSE_LEN,
					   .err_stream = stream };

	tls = tls_alloc();
	if (IS_ERR(tls)) {
		err = PTR_ERR(tls);
	}

	pctx = GUARD_CALL_1(parser_new, (uintptr_t)tls, psettings);
	if (!pctx) {
		pr_err("couldn't allocate pctx\n");
		err = -EINVAL;
		goto err;
	}

	err = evaluate(tls, _stub__stdout, pctx, TEST_EXPR, sizeof(TEST_EXPR),
		       &fmt);
	if (err) {
		goto err;
	}

	pr_info("\n%s\n", _stub__stdout->buf);
	libc_flush(stream);

err:
	if (pctx) {
		GUARD_CALL_1(parser_free, (uintptr_t)tls, pctx);
	}
	tls_free(tls);
	return err;
}
#endif

#define REGISTER_BMATH_FUNC(exe, func, stub, err_label)               \
	do {                                                          \
		Elf64_Sym sym;                                        \
		if (!exe_find_symbol(exe, func, &sym)) {              \
			pr_err("couldn't find symbol: %s\n", func);   \
			goto err_label;                               \
		}                                                     \
		stub = (void *)sym.st_value;                          \
		pr_debug("sym: %s -> %s; addr: 0x%lx\n", func, #stub, \
			 (uintptr_t)sym.st_value);                    \
	} while (0)

static int init_bmath(struct bmath_dev *dev, const struct firmware *fw)
{
	int err = -EINVAL;

	struct exe *exe = exe_alloc(fw, rlsyms);
	if (IS_ERR(exe)) {
		return PTR_ERR(exe);
	}

	REGISTER_BMATH_FUNC(exe, "parser_new", parser_new, err);
	REGISTER_BMATH_FUNC(exe, "parser_free", parser_free, err);
	REGISTER_BMATH_FUNC(exe, "parse", parse, err);
	REGISTER_BMATH_FUNC(exe, "print_all", print_all, err);

	dev->exe = exe;

	return api_test();

err:
	exec_release(exe);
	return err;
}

static int bmath_open(struct inode *inode, struct file *file)
{
	struct bmath_data *data;
	struct parser_context *pctx;
	struct parser_settings psettings;
	FILE *stream;

	int err = 0;

	stream = libc_stream_alloc();
	if (IS_ERR(stream)) {
		return PTR_ERR(stream);
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		err = -ENOMEM;
		goto err;
	}

	data->tls = tls_alloc();
	if (IS_ERR(data->tls)) {
		err = PTR_ERR(data->tls);
		goto err;
	}

	psettings.max_parse_len = BMATH_MAX_PARSE_LEN;
	psettings.err_stream = stream;

	pctx = GUARD_CALL_1(parser_new, (uintptr_t)data->tls, &psettings);
	if (!pctx) {
		err = -ENOMEM;
		goto err;
	}

	data->pctx = pctx;
	data->format = BMATH_FMT_DEFAULT;
	data->encoding = BMATH_ENC_DEFAULT;
	data->stream = stream;
	data->output = NULL;
	file->private_data = data;
	return 0;

err:
	tls_free(data->tls);
	kfree(data);
	libc_stream_release(stream);
	return err;
}

static int bmath_release(struct inode *inode, struct file *file)
{
	// BUG: Need to put a lock here so that the driver isn't removed until current references are drained etc...
	struct bmath_data *data = (struct bmath_data *)file->private_data;
	libc_stream_release(data->stream);
	GUARD_CALL_1(parser_free, (uintptr_t)data->tls, data->pctx);
	kfree(data->output);
	tls_free(data->tls);
	kfree(file->private_data);
	return 0;
}

static loff_t bmath_seek(struct file *file, loff_t offsest, int point)
{
	return file->f_pos = 0;
}

static ssize_t bmath_write(struct file *file, const char *user_buff,
			   size_t size, loff_t *offset)
{
	struct bmath_data *data = (struct bmath_data *)file->private_data;
	ssize_t len;

	if (size >= BMATH_MAX_INPUT_LEN) {
		return -EFBIG;
	}

	/*
   * The offset is moved along and not really reset at seek. When 0,
	 * we're at first write. Ensure we start at the start of the file.
   */
	if (!data->len_input) {
		*offset = 0;
	}

	len = min((long long)sizeof(data->input) - *offset, (long long)size);

	if (len <= 0) {
		return 0;
	}

	if (copy_from_user(data->input + *offset, user_buff, len))
		return -EFAULT;

	data->len_input = *offset += len;
	return len;
}

static ssize_t bmath_read(struct file *file, char *user_buff, size_t size,
			  loff_t *offset)
{
	int err;
	ssize_t len;
	struct bmath_data *data = (struct bmath_data *)file->private_data;
	struct cdev *cdev = file->f_inode->i_cdev;
	struct bmath_dev *dev = container_of(cdev, struct bmath_dev, cdev);
	struct parse_fmt fmt;

	if (data->len_input) {
		kfree(data->output);
		data->output = NULL;

		/*
     * Multiple users may have a file open to the device, and all
     * users will share the same executable. Since the executable
     * isn't thread-safe, we need to lock out users from sharing
     * execution.
     */
		mutex_lock(&dev->mutex);
		fmt = bmath_parse_fmt(data);
		err = evaluate(data->tls, data->stream, data->pctx, data->input,
			       data->len_input, &fmt);
		if (err) {
			pr_err("module error: %d\n", err);
			mutex_unlock(&dev->mutex);
			return err;
		}

		data->len_output = data->stream->len;
		data->output = kzalloc(data->len_output, GFP_KERNEL);
		if (!data->output) {
			libc_flush(data->stream);
			mutex_unlock(&dev->mutex);
			pr_err("module error: unable to allocate output buffer\n");
			return -ENOMEM;
		}

		libc_cpy_flush(data->output, data->len_output, data->stream);
		mutex_unlock(&dev->mutex);

		// New write after read is a new evalution. Clear buffer.
		memset(data->input, 0, data->len_input);
		data->len_input = 0;

		// Put position into start for next reads
		bmath_seek(file, 0, SEEK_SET);
	}

	len = min((long long)data->len_output - *offset, (long long)size);

	if (len <= 0) {
		return 0;
	}

	if (copy_to_user(user_buff, data->output + *offset, len))
		return -EFAULT;

	*offset += len;
	return len;
}

static long bmath_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct bmath_data *data = (struct bmath_data *)file->private_data;
	if (_IOC_TYPE(cmd) != BMATH_IOCTL_TYPE)
		return -EINVAL;

	switch (cmd) {
	case BMATH_SET_FORMAT:
		data->format = arg;
		break;
	case BMATH_SET_ENCODING:
		data->encoding = arg;
		break;
	default:
		return -ENOTTY;
	}
	return 0;
}

static const struct file_operations fops = { .owner = THIS_MODULE,
					     .read = bmath_read,
					     .write = bmath_write,
					     .open = bmath_open,
					     .unlocked_ioctl = bmath_ioctl,
					     .llseek = bmath_seek,
					     .release = bmath_release };

static int __init bmath_init(void)
{
	const struct firmware *fw;
	struct device *dev;
	dev_t dev_number;
	int err;
	int ret;

	b_dev = kzalloc(sizeof(*b_dev), GFP_KERNEL);
	if (!b_dev) {
		return -ENOMEM;
	}

	// -----------------
	// TEST KMEMLEAK --
	// Need to do more test tweaking
	// to get more consistent results.
	//volatile char *test_leak = kzalloc(36, GFP_KERNEL);
	//if (!test_leak) {
	//	return -ENOMEM;
	//}

	//memset((void *)test_leak, 'a', 35);
	//pr_debug("%s\n", test_leak);
	//test_leak = NULL;
	// -----------------

	mutex_init(&b_dev->mutex);

	ret = alloc_chrdev_region(&dev_number, 0, 1, DEV_NAME);
	if (ret < 0) {
		pr_err("error registering: %d\n", ret);
		return ret;
	}

	cdev_init(&b_dev->cdev, &fops);

	b_dev->class = class_create(DEV_NAME);
	if (IS_ERR(b_dev->class)) {
		pr_err("can't create device class\n");
		err = PTR_ERR(b_dev->class);
		goto err_region;
	}

	dev = device_create(b_dev->class, NULL, dev_number, NULL, DEV_NAME);
	if (IS_ERR(dev)) {
		pr_err("can't create device /dev/%s\n", DEV_NAME);
		err = PTR_ERR(dev);
		goto err_class;
	}

	err = cdev_add(&b_dev->cdev, dev_number, 1);
	if (err) {
		pr_err("unable to cdev_add()\n");
		goto err_dev;
	}

	// KASLR early test
	err = kaslr_request_firmware(&fw, DEV_FW_PATH, dev);
	if (err) {
		pr_err("unable to load FW %s\n", DEV_FW_PATH);
		err = -EINVAL;
		goto err_dev;
	}

	err = init_bmath(b_dev, fw);
	release_firmware(fw);
	if (err) {
		pr_err("unable to init bmath\n");
		goto err_dev;
	}

	pr_info("dev init (%d, %d)\n", MAJOR(dev_number), MINOR(dev_number));

	return 0;

err_dev:
	device_destroy(b_dev->class, dev_number);

err_class:
	class_destroy(b_dev->class);

err_region:
	unregister_chrdev_region(dev_number, 1);
	mutex_destroy(&b_dev->mutex);
	kfree(b_dev);
	pr_err("module not loaded\n");
	return err;
}

static void __exit bmath_exit(void)
{
	dev_t dev_number = b_dev->cdev.dev;

	libc_execute_atexit_queue();
	exec_release(b_dev->exe);
	cdev_del(&b_dev->cdev);
	device_destroy(b_dev->class, dev_number);
	class_destroy(b_dev->class);
	unregister_chrdev_region(dev_number, 1);
	mutex_destroy(&b_dev->mutex);
	kfree(b_dev);
	pr_info("unregistered\n");
}

module_init(bmath_init);
module_exit(bmath_exit);

MODULE_AUTHOR("Frederick Lawler <me@fred.software>");
MODULE_DESCRIPTION("Kernel module implementation of bmath");
MODULE_LICENSE("GPL");
