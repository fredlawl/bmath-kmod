#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/device/class.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/firmware.h>
#include <linux/gfp_types.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>

MODULE_AUTHOR("Frederick Lawler <me@fred.software>");
MODULE_DESCRIPTION("Kernel module implementation of bmath");
MODULE_LICENSE("GPL");

#define DEV_NAME "bmath"
// /usr/lib/firmware/DEV_FW_PATH
#define DEV_FW_PATH "test.so"

#define BMATH_MAX_INPUT_LEN 512

#define BMATH_FMT_UPPERCASE (1 << 1)

#define BMATH_ENC_ASCII (1 << 0)
#define BMATH_ENC_UTF8 (1 << 1)
#define BMATH_ENC_UTF16 (1 << 2)
#define BMATH_ENC_UTF32 (1 << 3)
#define BMATH_ENC_BINARY (1 << 4)

#define BMATH_IOCTL_TYPE 0xb3
#define BMATH_SET_FORMAT _IOW(BMATH_IOCTL_TYPE, 1, u32)
#define BMATH_SET_ENCODING _IOW(BMATH_IOCTL_TYPE, 2, u32)

struct bmath_dev {
	struct cdev cdev;
	struct class *class;
	//	const struct firmware *fw;
	void *vm;

	// for practice
	int (*add)(int a, int b);
};

static struct bmath_dev *b_dev;

struct bmath_data {
	u32 format;
	u32 encoding;
	size_t len_input;
	char input[BMATH_MAX_INPUT_LEN];
	size_t len_output;
	char *output;
};

static int init_bmath(struct bmath_dev *dev)
{
	struct elf64_hdr hdr = { 0 };
	struct elf64_shdr symtab = { 0 };
	struct elf64_shdr shdrstrtab = { 0 };
	struct elf64_shdr strtab = { 0 };
	struct elf64_shdr dynstrtab = { 0 };
	struct elf64_shdr text = { 0 };
	u64 symtab_offset = 0;
	void *fw = dev->vm;

	memcpy(&hdr, fw, sizeof(hdr));
	pr_debug(
		"elf header:\nentry point: %llx\nsection headers offset: %llx\n",
		hdr.e_entry, hdr.e_shoff);

	memcpy(&shdrstrtab,
	       fw + hdr.e_shoff + (hdr.e_shstrndx * hdr.e_shentsize),
	       hdr.e_shentsize);

	for (Elf64_Half i = 0; i < hdr.e_shnum; i++) {
		struct elf64_shdr shdr = { 0 };
		char *hdr_name;

		memcpy(&shdr, fw + (i * hdr.e_shentsize) + hdr.e_shoff,
		       hdr.e_shentsize);

		hdr_name = (char *)fw + shdrstrtab.sh_offset + shdr.sh_name;

		pr_debug("shdr hit: %s; index: %d offset: %llx\n", hdr_name, i,
			 shdr.sh_offset);

		switch (shdr.sh_type) {
		case SHT_SYMTAB:
			if (!strncmp(".symtab", hdr_name, sizeof(".symtab"))) {
				symtab = shdr;
			}
			break;
		case SHT_STRTAB:
			if (i != hdr.e_shstrndx) {
				if (!strncmp(".dynstr", hdr_name,
					     sizeof(".dynstr"))) {
					dynstrtab = shdr;
				}

				if (!strncmp(".strtab", hdr_name,
					     sizeof(".strtab"))) {
					strtab = shdr;
				}
			}
			break;
		case SHT_PROGBITS:
			if (!strncmp(".text", hdr_name, sizeof(".text"))) {
				text = shdr;
			}
			break;
		default:
			continue;
		}

		// TODO: Need to figure out how to get the callable functions into a exetuable page
		// Areas that can be executed
		//if (shdr.sh_type == SHT_PROGBITS && shdr.sh_flags & SHF_EXECINSTR) {
		//	struct vm_struct *vms =
		//		find_vm_area((const void*)fw + shdr.sh_offset);
		//	void *mmapd = vmap(vms->pages, vms->nr_pages, VM_MAP,
		//			   PAGE_KERNEL_EXEC);
		//	pr_debug("mmapd: %p\n", mmapd);
		//}
	}

	if (!symtab.sh_type) {
		pr_err("fw missing .symtab\n");
		return -EINVAL;
	}

	if (!strtab.sh_type) {
		pr_err("fw missing .strtab\n");
		return -EINVAL;
	}

	// Loops through symbol table
	const u8 *strtab_start = fw + strtab.sh_offset;
	symtab_offset = symtab.sh_offset;
	do {
		struct elf64_sym sym = { 0 };
		char *sym_name;
		memcpy(&sym, fw + symtab_offset, sizeof(sym));

		symtab_offset += sizeof(sym);
		if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) {
			continue;
		}

		unsigned long addr = (unsigned long)fw + sym.st_value;
		set_memory_rox(addr, 1);

		sym_name = (char *)strtab_start + sym.st_name;

		pr_debug("sym: %s; val: %llx; addr: %lx; idx: %hu\n", sym_name,
			 sym.st_value, addr, sym.st_shndx);

		if (!strncmp("add", sym_name, sizeof("add"))) {
			dev->add = (int (*)(int, int))addr;
		}

	} while (symtab_offset < (symtab.sh_offset + symtab.sh_size));

	return 0;
}

static u64 evaluate(const char *input, ssize_t len)
{
	return b_dev->add(1, 1);
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
		u64 answer = evaluate(data->input, data->len_input);
		pr_debug("answer: %llu\n", answer);

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

	const struct firmware *fw;
	err = request_firmware(&fw, DEV_FW_PATH, dev);
	if (err) {
		pr_err("unable to load FW %s\n", DEV_FW_PATH);
		err = -EINVAL;
		goto err_dev;
	}

	b_dev->vm = vmalloc(fw->size);
	if (!b_dev->vm) {
		pr_err("unable to vmalloc(%lu)\n", fw->size);
		err = -ENOMEM;
		goto err_fw;
	}

	memcpy(b_dev->vm, fw->data, fw->size);
	release_firmware(fw);

	err = init_bmath(b_dev);
	if (err) {
		pr_err("unable to init bmath\n");
		goto err_vm;
	}

	pr_info("dev init (%d, %d)\n", MAJOR(dev_number), MINOR(dev_number));

	return 0;

err_vm:
	vfree(b_dev->vm);

err_fw:
	release_firmware(fw);

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
