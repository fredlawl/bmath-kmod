#define pr_fmt(fmt) KBUILD_MODNAME " loader: " fmt

#include "asm/page_types.h"
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/firmware.h>
#include <linux/gfp_types.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "loader.h"
#include "symbols.h"

__always_inline ptrdiff_t kaslr(void)
{
	return (uintptr_t)request_firmware - (uintptr_t)__request_firmware;
}

struct symtbl {
	uintptr_t entry;
	Elf64_Xword ent_size;
};

struct strtbl {
	uintptr_t entry;
	Elf64_Xword size;
};

struct jmpreltbl {
	uintptr_t entry;
	Elf64_Xword size;
	Elf64_Xword ent_size;
	Elf64_Xword type;
};

struct relocationtbl {
	uintptr_t entry;
	Elf64_Xword size;
	Elf64_Xword ent_size;
};

struct hashtbl {
	uintptr_t entry;
	Elf64_Sxword type;
};

struct exe {
	const void *blob;
	size_t size;
	Elf64_Ehdr hdr;
	Elf64_Shdr shstrtab;
	struct strtbl strtbl;
	struct symtbl symtbl;
	struct jmpreltbl jmpreltbl;
	struct relocationtbl relocationtbl;
	struct hashtbl hashtbl;
};

static int protect_section(const struct exe *exe, Elf64_Phdr *seghdr)
{
	int err;
	int numpages;
	uintptr_t addr;
	Elf64_Word flags;

	numpages = ALIGN(seghdr->p_memsz, PAGE_SIZE) >> PAGE_SHIFT;
	addr = ALIGN_DOWN((uintptr_t)exe->blob + seghdr->p_vaddr, PAGE_SIZE);
	flags = seghdr->p_flags;

	pr_debug("num pages: %d\n", numpages);

	if ((flags & (PF_W | PF_R)) == (PF_W | PF_R)) {
		pr_debug("set access: PF_R | PF_W\n");
		err = kaslr_set_memory_rw(addr, numpages);
		if (err) {
			goto err;
		}
		flags &= ~(PF_R | PF_W);
	}

	if (flags & PF_R) {
		pr_debug("set access: PF_R\n");
		err = kaslr_set_memory_ro(addr, numpages);
		if (err) {
			goto err;
		}
		flags &= ~PF_R;
	}

	if (flags & PF_X) {
		pr_debug("set access: PF_X\n");
		err = kaslr_set_memory_x(addr, numpages);
		if (err) {
			goto err;
		}
		flags &= ~PF_X;
	}

	return 0;

err:
	pr_debug("unable to set access: %d\n", err);
	return err;
}

static int handle_dynamic_section(struct exe *exe, const struct firmware *fw,
				  Elf64_Phdr *seghdr)
{
	Elf64_Dyn *dy;
	Elf64_Xword val;
	Elf64_Addr ptr;
	int i = 0;

	const void *blob = fw->data;

	do {
		dy = (Elf64_Dyn *)(blob + seghdr->p_offset) + i;
		val = dy->d_un.d_val;
		ptr = dy->d_un.d_ptr;

		switch (dy->d_tag) {
		case DT_NULL:
			// Don't warn it's not handled
			break;
		case DT_SYMTAB:
			exe->symtbl.entry = ptr + (uintptr_t)blob;
			break;
		case DT_SYMENT:
			exe->symtbl.ent_size = val;
			break;
		case DT_STRTAB:
			exe->strtbl.entry = ptr + (uintptr_t)blob;
			break;
		case DT_STRSZ:
			exe->strtbl.size = val;
			break;
		case DT_JMPREL:
			exe->jmpreltbl.entry = ptr + (uintptr_t)blob;
			break;
		case DT_PLTRELSZ:
			exe->jmpreltbl.size = val;
			break;
		case DT_PLTREL:
			exe->jmpreltbl.type = val;
			if (val == DT_RELA) {
				exe->jmpreltbl.ent_size = sizeof(Elf64_Rela);
			} else {
				exe->jmpreltbl.ent_size = sizeof(Elf64_Rel);
			}
			break;
		case DT_RELA:
			exe->relocationtbl.entry = ptr + (uintptr_t)blob;
			break;
		case DT_RELAENT:
			exe->relocationtbl.ent_size = val;
			break;
		case DT_RELASZ:
			exe->relocationtbl.size = val;
			break;
		case DT_HASH:
			// Prefer DT_GNU_HASH if that exists
			if (!exe->hashtbl.entry) {
				exe->hashtbl.entry = ptr + (uintptr_t)blob;
				exe->hashtbl.type = dy->d_tag;
			}
			break;
		case DT_GNU_HASH:
			exe->hashtbl.entry = ptr + (uintptr_t)blob;
			exe->hashtbl.type = dy->d_tag;
			break;
		default:
			pr_debug("unhandled .dynamic entry: %lld\n", dy->d_tag);
			break;
		}

		i++;
	} while (dy->d_tag != DT_NULL);

	pr_debug("strtab addr: 0x%lx; size: %lld\n", exe->strtbl.entry,
		 exe->strtbl.size);

	pr_debug("symtbl addr: 0x%lx; ent_size: %lld\n", exe->symtbl.entry,
		 exe->symtbl.ent_size);

	pr_debug("jmpreltbl addr: 0x%lx\n", exe->jmpreltbl.entry);

	pr_debug("hashtbl addr: 0x%lx; type: %lld\n", exe->hashtbl.entry,
		 exe->hashtbl.type);

	pr_debug("relocationtbl addr: 0x%lx; ent_size: %lld; size: %llu\n",
		 exe->relocationtbl.entry, exe->relocationtbl.ent_size,
		 exe->relocationtbl.size);

	// TODO: Return error if we don't have the symtbl, strtab, and jumreltbl1

	return 0;
}

static __always_inline const unsigned char *__sym_name(const struct exe *exe,
						       const Elf64_Sym *sym)
{
	return (const unsigned char *)(exe->strtbl.entry) + sym->st_name;
}

static __always_inline const Elf64_Sym *__sym_index(const struct exe *exe,
						    u32 sym_idx)
{
	return (Elf64_Sym *)(exe->symtbl.entry) + sym_idx;
}

static void internal_relocation(const struct exe *exe, u64 type,
				const Elf64_Rela *entry, const Elf64_Sym *sym,
				Elf64_Addr *addr)
{
	const char *sym_name;
	ssize_t sym_namelen;

	sym_name = __sym_name(exe, sym);
	sym_namelen = strlen(sym_name);

	pr_debug(
		"sym: %s; info: 0x%x; size: %llu; hdridx: %d; val: 0x%llx; other: 0x%hhx\n",
		sym_name, sym->st_info, sym->st_size, sym->st_shndx,
		sym->st_value, sym->st_other);

	if (sym->st_shndx != SHT_NULL) {
		*addr = (uintptr_t)exe->blob + sym->st_value +
			((type == R_X86_64_64) ? entry->r_addend : 0);
		pr_debug("internally relocating sym: %s; addr: 0x%lx\n",
			 sym_name, (uintptr_t)addr);
	}
}

static void relocate_stubs(const struct exe *exe, u64 type,
			   const Elf64_Rela *entry, const Elf64_Sym *sym,
			   Elf64_Addr *addr, const struct relocate_sym *rsyms[])
{
	const char *sym_name;
	const struct relocate_sym *rsym;
	ssize_t sym_namelen;

	sym_name = __sym_name(exe, sym);
	sym_namelen = strlen(sym_name);

	internal_relocation(exe, type, entry, sym, addr);

	while ((rsym = *rsyms++) != NULL) {
		// Only match symbols we want to relocate
		if (rsym->nlen != sym_namelen || strcmp(rsym->name, sym_name)) {
			continue;
		}

		pr_debug("relocating sym: %s; addr: 0x%lx\n", sym_name,
			 rsym->addr);

		*addr = rsym->addr;
	}
}

// https://www.ucw.cz/~hubicka/papers/abi/node19.html
static void do_relocation(const struct exe *exe, const Elf64_Rela *entry,
			  const struct relocate_sym *rsyms[])
{
	Elf64_Addr *addr;
	u64 type;
	u32 sym_idx;
	const Elf64_Sym *sym;

	sym_idx = ELF64_R_SYM(entry->r_info);
	type = ELF64_R_TYPE(entry->r_info);
	addr = (Elf64_Addr *)(exe->blob + entry->r_offset);

	switch (type) {
	case R_X86_64_NONE:
		break;
	case R_X86_64_RELATIVE:
		*addr = (uintptr_t)exe->blob + entry->r_addend;
		break;
	case R_X86_64_64:
		sym = __sym_index(exe, sym_idx);
		internal_relocation(exe, type, entry, sym, addr);
		break;
	case R_X86_64_GLOB_DAT:
	case R_X86_64_JUMP_SLOT:
		sym = __sym_index(exe, sym_idx);
		relocate_stubs(exe, type, entry, sym, addr, rsyms);
		break;
	default:
		pr_debug("%s: unhandled type %llu\n", __FUNCTION__, type);
		break;
	}
}

/*
 * Handles relocation table
 */
static int relocate_dyn(const struct exe *exe,
			const struct relocate_sym *rsyms[])
{
	Elf64_Rela *entry;
	Elf64_Xword i;

	for (i = 0; i < exe->relocationtbl.size / exe->relocationtbl.ent_size;
	     i++) {
		// TODO: this could be REL and not RELA
		entry = (Elf64_Rela *)(exe->relocationtbl.entry) + i;
		do_relocation(exe, entry, rsyms);
	}

	return 0;
}

/*
 * Handles plt table
 */
static int relocate_plt(const struct exe *exe,
			const struct relocate_sym *rsyms[])
{
	Elf64_Rela *entry;
	Elf64_Xword i;

	for (i = 0; i < exe->jmpreltbl.size / exe->jmpreltbl.ent_size; i++) {
		// TODO: this could be REL and not RELA
		entry = (Elf64_Rela *)(exe->jmpreltbl.entry) + i;
		do_relocation(exe, entry, rsyms);
	}

	return 0;
}

static int load_program_sections(struct exe *exe, const struct firmware *fw,
				 const struct relocate_sym *rlsyms[])
{
	Elf64_Phdr *seghdr;
	int err = 0;
	u64 size = 0;
	u64 total_size = 0;
	const void *fw_blob = fw->data;

	for (Elf64_Half i = 0; i < exe->hdr.e_phnum; i++) {
		seghdr = (Elf64_Phdr *)(fw_blob + exe->hdr.e_phoff) + i;
		if (seghdr->p_type != PT_LOAD) {
			continue;
		}

		if (seghdr->p_align != PAGE_SIZE) {
			pr_err("system page size (0x%lx) does not match alginment (0x%llx). Was the FW built for this system?\n",
			       PAGE_SIZE, seghdr->p_align);
			return -EINVAL;
		}

		if ((seghdr->p_offset % seghdr->p_align) !=
		    (seghdr->p_vaddr % seghdr->p_align)) {
			pr_err("segment %d: (p_offset (0x%llx) mod p_algin (0x%llx)) must equal to (p_vaddr (0x%llx) mod p_align (0x%llx))\n",
			       i, seghdr->p_offset, seghdr->p_align,
			       seghdr->p_vaddr, seghdr->p_align);
			return -EINVAL;
		}

		size = ALIGN(seghdr->p_vaddr + seghdr->p_memsz,
			     seghdr->p_align);
		if (size > total_size) {
			total_size = size;
		}
	}

	pr_debug("allocating size %llu at %llu pages\n", total_size,
		 total_size >> PAGE_SHIFT);

	exe->blob = vzalloc(total_size);
	if (!exe->blob) {
		return -ENOMEM;
	}
	exe->size = total_size;

	pr_debug("addr: 0x%lx; align addr: 0x%lx; nr: %llu",
		 (uintptr_t)exe->blob,
		 ALIGN_DOWN((uintptr_t)exe->blob, PAGE_SIZE),
		 total_size >> PAGE_SHIFT);

	for (Elf64_Half i = 0; i < exe->hdr.e_phnum; i++) {
		seghdr = (Elf64_Phdr *)(fw_blob + exe->hdr.e_phoff) + i;

		pr_debug(
			"loading segment %d; vaddr: 0x%llx; aligned addr: 0x%llx; actual addr: 0x%llx\n",
			seghdr->p_type, seghdr->p_vaddr,
			ALIGN_DOWN((uintptr_t)exe->blob + seghdr->p_vaddr,
				   PAGE_SIZE),
			(uintptr_t)exe->blob + seghdr->p_vaddr);

		switch (seghdr->p_type) {
		case PT_LOAD:
			memcpy((void *)exe->blob + seghdr->p_vaddr,
			       fw_blob + seghdr->p_offset, seghdr->p_filesz);
			err = protect_section(exe, seghdr);
			if (err) {
				return err;
			}
			break;
		case PT_DYNAMIC:
			err = handle_dynamic_section(exe, fw, seghdr);
			if (relocate_dyn(exe, rlsyms)) {
				return -EINVAL;
			}

			if (relocate_plt(exe, rlsyms)) {
				return -EINVAL;
			}
			break;
		case PT_GNU_RELRO:
			err = protect_section(exe, seghdr);
			if (err) {
				return err;
			}
			break;
		default:
			pr_debug("skipping...\n");
			break;
		}
	}

	return 0;
}

/**
 * exe_alloc() - fw is not owned this context.
 * @fw: Pointer to struct firmware
 * @rlsyms: Null-terminated list of symbols to relocate
 * Returns: Pointer to a context used by parser. May return ERR_PTR(-error)
 */
struct exe *exe_alloc(const struct firmware *fw,
		      const struct relocate_sym *rlsyms[])
{
	struct exe *exe;
	int err;

	exe = kzalloc(sizeof(*exe), GFP_KERNEL);
	if (!exe) {
		return ERR_PTR(-ENOMEM);
	}

	memcpy(&exe->hdr, fw->data, sizeof(exe->hdr));

	// Blob must have program headers
	if (exe->hdr.e_phnum == 0) {
		err = -EINVAL;
		goto err;
	}

	// Copy the section header of the section header string table
	// This table contains all the strings for section header names
	memcpy(&exe->shstrtab,
	       fw->data + exe->hdr.e_shoff +
		       (exe->hdr.e_shentsize * exe->hdr.e_shstrndx),
	       sizeof(exe->hdr));

	if (load_program_sections(exe, fw, rlsyms)) {
		err = -EINVAL;
		goto err;
	}

	return exe;
err:
	kfree(exe);
	return ERR_PTR(err);
}

void exec_release(const struct exe *exe)
{
	if (exe) {
		// Kernel needs everything RW for free
		kaslr_set_memory_rw((uintptr_t)exe->blob,
				    exe->size >> PAGE_SHIFT);
		vfree(exe->blob);
	}
	kfree(exe);
}

/**
 * exe_find_header() - Find a section given section name. The sh_addr will be
 * actual kernel address.
 * @exe: Executable
 * @name: Name of section header
 * @hdr: Will be filled with data from the found header
 * Returns: 1 if found, 0 if not
 */
int exe_find_header(const struct exe *exe, const unsigned char *name,
		    Elf64_Shdr *hdr)
{
	char *hdr_name;
	size_t namelen = strlen(name);

	for (Elf64_SHalf i = 0; i < exe->hdr.e_shnum; i++) {
		memcpy(hdr,
		       exe->blob + exe->hdr.e_shoff + i * exe->hdr.e_shentsize,
		       exe->hdr.e_shentsize);

		hdr_name = (unsigned char *)exe->blob +
			   exe->shstrtab.sh_offset + hdr->sh_name;

		if (strlen(hdr_name) == namelen && !strcmp(name, hdr_name)) {
			hdr->sh_addr += (uintptr_t)exe->blob;
			return 1;
		}
	}

	return 0;
}

/*
 * Hashing function (DT_HASH)
 * https://refspecs.linuxbase.org/elf/gabi4+/ch5.dynamic.html#hash
 */
static unsigned long elf_hash(const unsigned char *name)
{
	unsigned long h = 0, g;
	while (*name) {
		h = (h << 4) + *name++;
		if ((g = h & 0xf0000000))
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

/*
 * https://flapenguin.me/elf-dt-hash
 */
static const Elf64_Sym *
dt_hash_lookup(const struct exe *exe, const unsigned char *name, size_t namelen)
{
	const Elf64_Sym *fsym;
	const char *sym_name;
	Elf32_Word *tbl = (Elf32_Word *)exe->hashtbl.entry;
	Elf32_Word nbucket = tbl[0];
	Elf32_Word *bucket = &tbl[2];
	Elf32_Word *chain = &tbl[2 + nbucket];
	Elf32_Word hash = elf_hash(name);

	for (Elf32_Word i = bucket[hash % nbucket]; i; i = chain[i]) {
		fsym = __sym_index(exe, i);
		sym_name = __sym_name(exe, fsym);
		if (!strncmp(name, sym_name, namelen)) {
			return fsym;
		}
	}

	return NULL;
}

/*
 * Hashing function (DT_GNU_HASH)
 * https://flapenguin.me/elf-dt-gnu-hash
 */
static Elf32_Word gnu_elf_hash(const unsigned char *name)
{
	Elf32_Word h = 5381;
	for (; *name; name++) {
		h = (h << 5) + h + *name;
	}
	return h;
}

/*
 * https://flapenguin.me/elf-dt-gnu-hash
 */
static const Elf64_Sym *dt_gnu_hash_lookup(const struct exe *exe,
					   const unsigned char *name,
					   size_t namelen)
{
#define bloom_el_t u64
#define ELFCLASS_BITS 64

	const Elf64_Sym *fsym;
	const char *sym_name;
	Elf32_Word *tbl = (Elf32_Word *)exe->hashtbl.entry;

	Elf32_Word namehash = gnu_elf_hash(name);
	Elf32_Word nbuckets = tbl[0];
	Elf32_Word symoffset = tbl[1];
	Elf32_Word bloom_size = tbl[2];
	Elf32_Word bloom_shift = tbl[3];
	bloom_el_t *bloom = (void *)&tbl[4];
	Elf32_Word *buckets = (void *)&bloom[bloom_size];
	Elf32_Word *chain = &buckets[nbuckets];

	bloom_el_t word = bloom[(namehash / ELFCLASS_BITS) % bloom_size];
	bloom_el_t mask =
		0 | (bloom_el_t)1 << (namehash % ELFCLASS_BITS) |
		(bloom_el_t)1 << ((namehash >> bloom_shift) % ELFCLASS_BITS);

	/* If at least one bit is not set, a symbol is surely missing. */
	if ((word & mask) != mask) {
		return NULL;
	}

	uint32_t symix = buckets[namehash % nbuckets];
	if (symix < symoffset) {
		return NULL;
	}

	/* Loop through the chain. */
	while (true) {
		fsym = __sym_index(exe, symix);
		sym_name = __sym_name(exe, fsym);
		const uint32_t hash = chain[symix - symoffset];

		if ((namehash | 1) == (hash | 1) &&
		    !strncmp(name, sym_name, namelen)) {
			return fsym;
		}

		/* Chain ends with an element with the lowest bit set to 1. */
		if (hash & 1) {
			break;
		}

		symix++;
	}

	return NULL;
}

/**
 * exe_find_symbol() - Find a symbol given a name. The st_value will be actual
 * kernel address.
 * @exe: Executable
 * @sym_name: Name of symbol
 * @sym: Will be filled with symbol data
 * Returns: 1 if found, 0 if not
 */
int exe_find_symbol(const struct exe *exe, const unsigned char *name,
		    Elf64_Sym *sym)
{
	const Elf64_Sym *fsym;
	size_t namelen = strlen(name);
	const char *sym_name;

	if (exe->hashtbl.entry && exe->hashtbl.type == DT_GNU_HASH) {
		fsym = dt_gnu_hash_lookup(exe, name, namelen);
		if (fsym) {
			memcpy(sym, fsym, sizeof(*sym));
			sym->st_value += (uintptr_t)exe->blob;
			return 1;
		}
		return 0;
	}

	if (exe->hashtbl.entry && exe->hashtbl.type == DT_HASH) {
		fsym = dt_hash_lookup(exe, name, namelen);
		if (fsym) {
			memcpy(sym, fsym, sizeof(*sym));
			sym->st_value += (uintptr_t)exe->blob;
			return 1;
		}
		return 0;
	}

	// Fallback to linear search if there's no faster way provided
	fsym = __sym_index(exe, 0);
	do {
		sym_name = __sym_name(exe, fsym);
		if (strlen(sym_name) == namelen && !strcmp(name, sym_name)) {
			memcpy(sym, fsym, sizeof(*sym));
			sym->st_value += (uintptr_t)exe->blob;
			return 1;
		}
		fsym++;
	} while (fsym);

	return 0;
}
