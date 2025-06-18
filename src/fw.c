#define pr_fmt(fmt) "%s fw: " fmt, KBUILD_MODNAME

#include <linux/elf.h>
#include <linux/err.h>
#include <linux/firmware.h>
#include <linux/gfp_types.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "fw.h"
#include "symbols.h"

inline ptrdiff_t kaslr(void)
{
	return (uintptr_t)request_firmware - (uintptr_t)__request_firmware;
}

struct symtbl {
	uintptr_t entry;
	Elf64_Xword size;
};

struct strtbl {
	uintptr_t entry;
	Elf64_Xword size;
};

struct jmpreltbl {
	uintptr_t entry;
	Elf64_Xword len;
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

struct fw_parse_ctx {
	const void *blob;
	Elf64_Ehdr hdr;
	Elf64_Shdr shstrtab;
	struct strtbl strtbl;
	struct symtbl symtbl;
	struct jmpreltbl jmpreltbl;
	struct relocationtbl relocationtbl;
	struct hashtbl hashtbl;
	uintptr_t pltgot;
};

static int protect_section(const struct fw_parse_ctx *ctx, Elf64_Phdr *seghdr,
			   Elf32_Half index)
{
	uintptr_t addr;
	int numpages;

	numpages = (int)(seghdr->p_memsz / seghdr->p_align) + 1;
	addr = (uintptr_t)ctx->blob + index * seghdr->p_align;

	if (seghdr->p_flags & PF_X) {
		if (set_memory_x(addr, numpages)) {
			pr_debug(
				"addr: %lx unable to set loadable header to E\n",
				addr);
			return -EINVAL;
		}
	}

	if (seghdr->p_flags & PF_W) {
		if (set_memory_rw(addr, numpages)) {
			pr_debug(
				"addr: %lx unable to set loadable header to RW\n",
				addr);
			return -EINVAL;
		}
	}
	return 0;
}

static int handle_dynamic_section(struct fw_parse_ctx *ctx,
				  const struct firmware *fw, Elf64_Phdr *seghdr)
{
	Elf64_Dyn *dy;
	int i = 0;
	const void *blob = fw->data;

	do {
		dy = (Elf64_Dyn *)(blob + seghdr->p_offset) + i;

		switch (dy->d_tag) {
		case DT_SYMTAB:
			ctx->symtbl.entry = dy->d_un.d_ptr + (uintptr_t)blob;
			break;
		case DT_SYMENT:
			ctx->symtbl.size = dy->d_un.d_ptr;
			break;
		case DT_STRTAB:
			ctx->strtbl.entry = dy->d_un.d_ptr + (uintptr_t)blob;
			break;
		case DT_STRSZ:
			ctx->strtbl.size = dy->d_un.d_val;
			break;
		case DT_JMPREL:
			// TODO: Need to account for DT_PLTREL for Rela vs Rel in future
			ctx->jmpreltbl.entry = dy->d_un.d_ptr + (uintptr_t)blob;
			break;
		case DT_RELACOUNT:
			ctx->jmpreltbl.len = dy->d_un.d_val;
			break;
		case DT_PLTGOT:
			ctx->pltgot = dy->d_un.d_ptr + (uintptr_t)blob;
			break;
		case DT_RELA:
			ctx->relocationtbl.entry =
				dy->d_un.d_ptr + (uintptr_t)blob;
			break;
		case DT_RELAENT:
			ctx->relocationtbl.ent_size = dy->d_un.d_val;
			break;
		case DT_RELASZ:
			ctx->relocationtbl.size = dy->d_un.d_val;
			break;
		case DT_HASH:
			// Prefer DT_GNU_HASH if that exists
			if (!ctx->hashtbl.entry) {
				ctx->hashtbl.entry =
					dy->d_un.d_ptr + (uintptr_t)blob;
				ctx->hashtbl.type = dy->d_tag;
			}
			break;
		case DT_GNU_HASH:
			ctx->hashtbl.entry = dy->d_un.d_ptr + (uintptr_t)blob;
			ctx->hashtbl.type = dy->d_tag;
			break;
		case DT_NULL:
			// Skip
			break;
		default:
			pr_debug("%s: unhandled .dynamic entry: %lld\n",
				 __FUNCTION__, dy->d_tag);
		}

		i++;
	} while (dy->d_tag != DT_NULL);

	pr_debug("strtab addr: %lu; size: %lld\n", ctx->strtbl.entry,
		 ctx->strtbl.size);

	pr_debug("symtbl addr: %lu; size: %lld\n", ctx->symtbl.entry,
		 ctx->symtbl.size);

	pr_debug("jmpreltbl addr: %lu; len: %lld\n", ctx->jmpreltbl.entry,
		 ctx->jmpreltbl.len);

	pr_debug("hashtbl addr: %lu; type: %lld\n", ctx->hashtbl.entry,
		 ctx->hashtbl.type);
	return 0;
}

static int load_program_sections(struct fw_parse_ctx *ctx,
				 const struct firmware *fw)
{
	Elf64_Phdr *seghdr;
	int err;
	int pgsize;
	int numpages = 0;
	const void *fw_blob = fw->data;

	for (Elf64_Half i = 0; i < ctx->hdr.e_phnum; i++) {
		seghdr = (Elf64_Phdr *)(fw_blob + ctx->hdr.e_phoff) + i;
		if (seghdr->p_type != PT_LOAD) {
			continue;
		}

		numpages += seghdr->p_memsz / seghdr->p_align + 1;
		pgsize = seghdr->p_align;
	}
	numpages++;

	pr_debug("allocating %d pages at size %d\n", numpages, pgsize);
	void *blob = vmalloc(numpages * pgsize);
	if (!blob) {
		return -ENOMEM;
	}
	ctx->blob = blob;

	for (Elf64_Half i = 0; i < ctx->hdr.e_phnum; i++) {
		seghdr = (Elf64_Phdr *)(fw_blob + ctx->hdr.e_phoff) + i;

		pr_debug("loading segment %d; vaddr: %llx; actual addr: %llx\n",
			 seghdr->p_type, seghdr->p_vaddr,
			 (uintptr_t)ctx->blob + seghdr->p_vaddr);
		memcpy((void *)ctx->blob + seghdr->p_vaddr,
		       fw_blob + seghdr->p_offset, seghdr->p_filesz);

		switch (seghdr->p_type) {
		case PT_LOAD:
			err = protect_section(ctx, seghdr, i);
			break;
		case PT_DYNAMIC:
			err = handle_dynamic_section(ctx, fw, seghdr);
			break;
		default:
			pr_debug("unhandled segment %d\n", seghdr->p_type);
		}
	}

	return 0;
}

static inline const unsigned char *__sym_name(const struct fw_parse_ctx *ctx,
					      const Elf64_Sym *sym)
{
	return (const unsigned char *)(ctx->strtbl.entry) + sym->st_name;
}

static inline const Elf64_Sym *__sym_index(const struct fw_parse_ctx *ctx,
					   u32 sym_idx)
{
	return (Elf64_Sym *)(ctx->symtbl.entry) + sym_idx;
}

/*
 * This function basically rewrites addresses in the .got.plt table
 */
static int relocate_functions(const struct fw_parse_ctx *ctx,
			      const struct relocate_sym *rsyms[])
{
	Elf64_Rela *entry;
	Elf64_Xword i;
	u32 symbol_idx;
	u64 type;
	const Elf64_Sym *sym;
	Elf64_Addr *addr;
	const char *sym_name;
	const struct relocate_sym *rsym;
	const struct relocate_sym **rsyms_start;

	for (i = 0; i < ctx->jmpreltbl.len; i++) {
		rsyms_start = rsyms;
		entry = (Elf64_Rela *)(ctx->jmpreltbl.entry) + i;

		symbol_idx = ELF64_R_SYM(entry->r_info);
		type = ELF64_R_TYPE(entry->r_info);

		addr = (Elf64_Addr *)(ctx->blob + entry->r_offset);
		sym = __sym_index(ctx, symbol_idx);
		sym_name = __sym_name(ctx, sym);

		pr_debug("sym: %s; idx: %d, type: %d; bind: %d; size: %llu\n",
			 sym_name, sym->st_shndx, ELF64_ST_TYPE(sym->st_info),
			 ELF64_ST_BIND(sym->st_info), sym->st_size);

		if (type == R_X86_64_JUMP_SLOT) {
			if (sym->st_shndx != 0) {
				pr_debug("relocating sym: %s internally\n",
					 sym_name);
				*addr = (uintptr_t)ctx->blob + sym->st_value;
				continue;
			}

			// Loop through our provided symbols to manually relocate.
			while ((rsym = *rsyms_start++) != NULL) {
				// Only match symbols we want to relocate
				if (strncmp(rsym->name, sym_name,
					    strlen(rsym->name))) {
					continue;
				}

				pr_debug(
					"relocating sym: %s; off: %llx; addr: %llx; info: %llx; idx: %d, type: %llu; addend: %lld",
					sym_name, entry->r_offset,
					(uintptr_t)ctx->blob - +entry->r_offset,
					entry->r_info, symbol_idx, type,
					entry->r_addend);
				pr_cont(" val: %llx\n", *addr);

				*addr = rsym->addr;
			}
		}
	}
	return 0;
}

/**
 * alloc_fw_parse_ctx() - fw is not owned this context.
 * @fw: Pointer to struct firmware
 * @rlsyms: Null-terminated list of symbols to relocate
 * Returns: Pointer to a context used by parser. May return ERR_PTR(-error)
 */
struct fw_parse_ctx *alloc_fw_parse_ctx(const struct firmware *fw,
					const struct relocate_sym *rlsyms[])
{
	struct fw_parse_ctx *ctx;
	int err;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		return ERR_PTR(-ENOMEM);
	}

	memcpy(&ctx->hdr, fw->data, sizeof(ctx->hdr));

	// Blob must have program headers
	if (ctx->hdr.e_phnum == 0) {
		err = -EINVAL;
		goto err;
	}

	// Copy the section header of the section header string table
	// This table contains all the strings for section header names
	memcpy(&ctx->shstrtab,
	       fw->data + ctx->hdr.e_shoff +
		       (ctx->hdr.e_shentsize * ctx->hdr.e_shstrndx),
	       sizeof(ctx->hdr));

	if (load_program_sections(ctx, fw)) {
		err = -EINVAL;
		goto err;
	}

	if (relocate_functions(ctx, rlsyms)) {
		err = -EINVAL;
		goto err;
	}

	return ctx;
err:
	kfree(ctx);
	return ERR_PTR(err);
}

void release_fw_parse_ctx(const struct fw_parse_ctx *ctx)
{
	vfree(ctx->blob);
	kfree(ctx);
}

/**
 * fw_find_header() - Find a section given section name. The sh_addr will be
 * actual kernel address.
 * @ctx:
 * @hdr_name: Name of section header
 * @hdr: Will be filled with data from the found header
 * Returns: 1 if found, 0 if not
 */
int fw_find_header(const struct fw_parse_ctx *ctx,
		   const unsigned char *hdr_name, Elf64_Shdr *hdr)
{
	char *name;
	__kernel_size_t hdr_namelen = strlen(hdr_name);

	for (Elf64_SHalf i = 0; i < ctx->hdr.e_shnum; i++) {
		memcpy(hdr,
		       ctx->blob + ctx->hdr.e_shoff + i * ctx->hdr.e_shentsize,
		       ctx->hdr.e_shentsize);

		name = (unsigned char *)ctx->blob + ctx->shstrtab.sh_offset +
		       hdr->sh_name;

		if (!strncmp(name, hdr_name, hdr_namelen)) {
			hdr->sh_addr += (uintptr_t)ctx->blob;
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
static const Elf64_Sym *dt_hash_lookup(const struct fw_parse_ctx *ctx,
				       const unsigned char *name,
				       __kernel_size_t namelen)
{
	const Elf64_Sym *fsym;
	const char *sym_name;
	Elf32_Word *tbl = (Elf32_Word *)ctx->hashtbl.entry;
	Elf32_Word nbucket = tbl[0];
	Elf32_Word *bucket = &tbl[2];
	Elf32_Word *chain = &tbl[2 + nbucket];
	Elf32_Word hash = elf_hash(name);

	for (Elf32_Word i = bucket[hash % nbucket]; i; i = chain[i]) {
		fsym = __sym_index(ctx, i);
		sym_name = __sym_name(ctx, fsym);
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
static const Elf64_Sym *dt_gnu_hash_lookup(const struct fw_parse_ctx *ctx,
					   const unsigned char *name,
					   __kernel_size_t namelen)
{
#define bloom_el_t u64
#define ELFCLASS_BITS 64

	const Elf64_Sym *fsym;
	const char *sym_name;
	Elf32_Word *tbl = (Elf32_Word *)ctx->hashtbl.entry;

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
		fsym = __sym_index(ctx, symix);
		sym_name = __sym_name(ctx, fsym);
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
 * fw_find_symbol() - Find a symbol given a name. The st_value will be actual
 * kernel address.
 * @ctx:
 * @sym_name: Name of symbol
 * @sym: Will be filled with symbol data
 * Returns: 1 if found, 0 if not
 */
int fw_find_symbol(const struct fw_parse_ctx *ctx, const unsigned char *name,
		   Elf64_Sym *sym)
{
	const Elf64_Sym *fsym;
	__kernel_size_t namelen = strlen(name);
	const char *sym_name;

	if (ctx->hashtbl.entry && ctx->hashtbl.type == DT_GNU_HASH) {
		fsym = dt_gnu_hash_lookup(ctx, name, namelen);
		if (fsym) {
			memcpy(sym, fsym, sizeof(*sym));
			sym->st_value += (uintptr_t)ctx->blob;
			return 1;
		}
	}

	if (ctx->hashtbl.entry && ctx->hashtbl.type == DT_HASH) {
		fsym = dt_hash_lookup(ctx, name, namelen);
		if (fsym) {
			memcpy(sym, fsym, sizeof(*sym));
			sym->st_value += (uintptr_t)ctx->blob;
			return 1;
		}
	}

	// Fallback to linear search if nothing provided
	fsym = __sym_index(ctx, 0);
	while ((uintptr_t)fsym < (uintptr_t)ctx->blob + ctx->symtbl.size) {
		sym_name = __sym_name(ctx, fsym);
		if (!strncmp(name, sym_name, namelen)) {
			memcpy(sym, fsym, sizeof(*sym));
			sym->st_value += (uintptr_t)ctx->blob;
			return 1;
		}
		fsym++;
	}

	return 0;
}
