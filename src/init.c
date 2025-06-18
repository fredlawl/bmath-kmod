#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

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

#include "bmath.h"
#include "fw.h"
#include "symbols.h"
#include "libtest_reloc.h"

MODULE_AUTHOR("Frederick Lawler <me@fred.software>");
MODULE_DESCRIPTION("Kernel module implementation of bmath");
MODULE_LICENSE("GPL");

static struct bmath_dev *b_dev;

static int init_bmath(struct bmath_dev *dev, const struct firmware *fw)
{
	Elf64_Sym addsym;
	Elf64_Sym summationsym;
	Elf64_Sym show_summationsym;
	int (*add)(int, int);
	int (*summation)(void);
	void (*show_summation)(void);

	int err = -EINVAL;

	pr_debug("fw start: %p\n", fw->data);

	const struct relocate_sym *rlsyms[] = {
		&(const struct relocate_sym){ .name = "printf",
					      .addr = (uintptr_t)printf },
		&(const struct relocate_sym){
			.name = "__cxa_finalize",
			.addr = (uintptr_t)__cxa_finalize },
		NULL
	};

	struct fw_parse_ctx *ctx = alloc_fw_parse_ctx(fw, rlsyms);
	if (IS_ERR(ctx)) {
		return PTR_ERR(ctx);
	}

	if (!fw_find_symbol(ctx, "add", &addsym)) {
		pr_debug("add symbol not found\n");
		goto err;
	}
	add = (void *)addsym.st_value;

	if (!fw_find_symbol(ctx, "summation", &summationsym)) {
		pr_debug("summation symbol not found\n");
		goto err;
	}
	summation = (void *)summationsym.st_value;

	if (!fw_find_symbol(ctx, "show_summation", &show_summationsym)) {
		pr_debug("show_summation symbol not found\n");
		goto err;
	}
	show_summation = (void *)show_summationsym.st_value;

	int result = add(1, 1);
	pr_debug("add(): %d!!\n", result);

	// the problem with stripped binary now, is that we're missing the commulative global variable location
	add(3, 3);
	result = summation();
	pr_debug("summation(): %d!!\n", result);

	show_summation();

	err = 0;

err:
	release_fw_parse_ctx(ctx);
	return err;
}

static int bmath_open(struct inode *inode, struct file *file)
{
	struct bmath_data *data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		return -ENOMEM;
	}

	data->format = 0;
	data->encoding = BMATH_ENC_ASCII;
	file->private_data = data;
	return 0;
}

static int bmath_release(struct inode *inode, struct file *file)
{
	struct bmath_data *data = (struct bmath_data *)file->private_data;
	kfree(data->output);
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
	ssize_t len =
		min((long long)sizeof(data->input) - *offset, (long long)size);

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
	struct bmath_data *data = (struct bmath_data *)file->private_data;
	if (data->len_input && data->input[data->len_input - 1] == '\n') {
		data->input[data->len_input - 1] = '\0';
		data->len_input -= 1;
	}

	// Only evaluate at read time.
	// Print out evaluated/cached answer until next write.
	// The problem with evalulate on write is we don't know when users
	// are done writing. Write can be called multiple times.

	// Start off making an evalution
	if (data->len_input) {
		kfree(data->output);

		// TODO: Do evaulation
		// u64 answer = evaluate(data->input, data->len_input);
		// pr_debug("answer: %llu\n", answer);

		// -- tmp just copy input to output
		data->output = kzalloc(data->len_input, GFP_KERNEL);
		if (!data->output) {
			return -ENOMEM;
		}
		data->len_output = data->len_input;
		memcpy(data->output, data->input, data->len_input);
		// --

		// New write after read is a new evalution. Clear buffer.
		memset(data->input, 0, data->len_input);
		data->len_input = 0;
		// Force offset reset
		bmath_seek(file, 0, SEEK_SET);
	}

	ssize_t len =
		min((long long)data->len_output - *offset, (long long)size);

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

	// KASLR test
	ptrdiff_t kaslr_offset = kaslr();
	__request_firmware =
		(request_firmware_t)(kaslr_offset +
				     (uintptr_t)__request_firmware);

	err = __request_firmware(&fw, DEV_FW_PATH, dev);
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

	pr_err("module not loaded\n");
	return err;
}

static void __exit bmath_exit(void)
{
	dev_t dev_number = b_dev->cdev.dev;
	vfree(b_dev->vm);
	cdev_del(&b_dev->cdev);
	device_destroy(b_dev->class, dev_number);
	class_destroy(b_dev->class);
	unregister_chrdev_region(dev_number, 1);
	kfree(b_dev);
	pr_info("unregistered\n");
}

module_init(bmath_init);
module_exit(bmath_exit);
