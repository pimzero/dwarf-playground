#include <dwarf.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define arrsze(X) (sizeof(X) / sizeof(*(X)))

static int print_disass = 0;
static int print_lines = 0;

static int printf_on_condition(int cond, const char* format, ...) {
	if (!cond)
		return 0;

	va_list ap;
	va_start(ap, format);
	int ret = vprintf(format, ap);
	va_end(ap);

	return ret;
}

#define pr_disass(...) printf_on_condition(print_disass, __VA_ARGS__)
#define pr_lines(...) printf_on_condition(print_lines, __VA_ARGS__)

static void fail(const char* s) {
	perror(s);
	exit(1);
}

static void usage_and_quit(char* progname) {
	fprintf(stderr, "Usage: %s [-d] [-l] path/to/file\n", progname);
	exit(1);
}

static char* shstrtab(Elf64_Ehdr* ehdr) {
	Elf64_Shdr* shdr = (void*)(((char*)ehdr) + ehdr->e_shoff);

	return ((char*)ehdr) + shdr[ehdr->e_shstrndx].sh_offset;
}

static uint64_t leb128u(uint8_t** s) {
	uint64_t result = 0, shift = 0;

	while(1) {
		uint8_t byte = **s;
		(*s)++;
		result |= (byte & 0x7f) << shift;
		if ((byte & 0x80) == 0)
			break;
		shift += 7;

		if (shift >= (sizeof(result) * CHAR_BIT)) {
			fprintf(stderr, "Value too big\n");
			exit(1);
		}
	}

	return result;
}

static int64_t leb128s(uint8_t** s) {
	int64_t result = 0;
	uint64_t shift = 0;

	uint8_t byte;
	do{
		byte = **s;
		(*s)++;
		result |= (byte & 0x7f) << shift;
		shift += 7;
	}while(byte & 0x80);

	/* sign bit of byte is second high order bit (0x40) */
	if (0x40 & byte)
		result |= ((uint64_t)~0 << shift); /* sign extend */

	return result;
}

static uint16_t uhalf(uint8_t** s) {
	uint16_t out;

	memcpy(&out, *s, sizeof(out));
	*s += sizeof(out);

	return out;
}

struct sm {
	uint64_t address;
	uint64_t op_index;
	uint64_t file;
	uint64_t line;
	uint64_t column;
	uint64_t isa;
	uint64_t discriminator;
	bool is_stmt;
	bool basic_block;
	bool end_sequence;
	bool prologue_end;
	bool epilogue_begin;
};

typedef struct __attribute__((packed)) {
	uint32_t length;
	uint16_t version;
	uint32_t header_length;
	uint8_t min_instruction_length;
	uint8_t default_is_stmt;
	int8_t line_base;
	uint8_t line_range;
	uint8_t opcode_base;
	uint8_t std_opcode_lengths[12];
} DebugLineHeader;

typedef struct {
	DebugLineHeader* hdr;
	char** directories;
	char** files;
} metainfo;

static struct sm init_sm(DebugLineHeader* hdr) {
	struct sm sm = { 0 };

	sm.file = 1;
	sm.line = 1;

	sm.is_stmt = hdr->default_is_stmt;

	return sm;
}

static metainfo init_metainfo(DebugLineHeader* hdr) {
	metainfo out = { .hdr = hdr };

	char* directories = (void*)(hdr + 1);
	size_t dir_count = 0;

	size_t i;

	for (i = 0; directories[i]; i += strlen(directories + i) + 1)
		dir_count++;

	out.directories = calloc(dir_count + 1, sizeof(*out.directories));
	if (!out.directories)
		fail("calloc");

	size_t pos = 0;
	for (i = 0; directories[i]; i += strlen(directories + i) + 1)
		out.directories[pos++] = directories + i;

	char* files = directories + i + 1;
	size_t file_count = 0;

	for (i = 0; files[i]; i += strlen(files + i) + 4)
		file_count++;

	out.files = calloc(file_count + 1, sizeof(*out.files));
	if (!out.files)
		fail("calloc");

	pos = 0;
	for (i = 0; files[i]; i += strlen(files + i) + 4)
		out.files[pos++] = files + i;

	return out;
}

struct fileinfo {
	uint8_t dir, time, size;
};

static void print_files_and_dirs(metainfo* mi) {
	printf("Directories:\n");
	for (size_t i = 0; mi->directories[i]; i++)
		printf(" %s\n", mi->directories[i]);

	printf("Files:\n");
	printf(" Dir\tTime\tSize\tName\n");
	for (size_t i = 0; mi->files[i]; i++) {
		struct fileinfo* info = (void*)(mi->files[i] +
						strlen(mi->files[i]) + 1);
		printf(" %u\t%u\t%u\t%s\n", info->dir,
		       info->time, info->size, mi->files[i]);
	}
}

static void append_row(struct sm* sm, metainfo* mi) {
	char* file = mi->files[sm->file - 1];

	struct fileinfo* fi = (void*)(file + strlen(file) + 1);
	if (fi->dir)
		pr_lines("%s/", mi->directories[fi->dir - 1]);

	pr_lines("%s:%zu\t%#zx\n", file, sm->line, sm->address);
}

/* Special Opcodes (6.2.5.1) */

static void handle_special_opcode(struct sm* sm, metainfo* mi,
				  uint8_t** opptr) {
	DebugLineHeader* hdr = mi->hdr;
	uint8_t op = (*opptr)[0];

	pr_disass("<%u>\n", op - hdr->opcode_base);

	uint8_t adjusted_opcode = op - hdr->opcode_base;
	sm->line += hdr->line_base + (adjusted_opcode % hdr->line_range);

	uint8_t operation_advance = adjusted_opcode / hdr->line_range;
	sm->address += hdr->min_instruction_length * operation_advance;

	append_row(sm, mi);

	sm->basic_block = false;
	sm->prologue_end = false;
	sm->epilogue_begin = false;

	sm->discriminator = 0;
}

/* Standard Opcodes (6.2.5.2) */

static void handle_std_op_copy(struct sm* sm, metainfo* mi,
			       uint8_t** opptr) {
	pr_disass("\n");

	append_row(sm, mi);

	sm->discriminator = 0;

	sm->basic_block = false;
	sm->prologue_end = false;
	sm->epilogue_begin = false;
}

static void handle_std_op_advance_pc(struct sm* sm, metainfo* mi,
				     uint8_t** opptr) {
	uint64_t arg = leb128u(opptr);
	pr_disass(" %zu\n", arg);

	sm->address += arg;
}

static void handle_std_op_advance_line(struct sm* sm, metainfo* mi,
				       uint8_t** opptr) {
	int64_t arg = leb128s(opptr);
	pr_disass(" %zd\n", arg);

	sm->line += arg;
}

static void handle_std_op_set_file(struct sm* sm, metainfo* mi,
				   uint8_t** opptr) {
	uint64_t arg = leb128u(opptr);
	pr_disass(" %zu\n", arg);

	sm->file = arg;
}

static void handle_std_op_set_column(struct sm* sm, metainfo* mi,
				     uint8_t** opptr) {
	uint64_t arg = leb128u(opptr);
	pr_disass(" %zu\n", arg);

	sm->column = arg;
}

static void handle_std_op_negate_stmt(struct sm* sm, metainfo* mi,
				      uint8_t** opptr) {
	pr_disass("\n");

	sm->is_stmt = !sm->is_stmt;
}

static void handle_std_op_set_basic_block(struct sm* sm, metainfo* mi,
					  uint8_t** opptr) {
	pr_disass("\n");

	sm->basic_block = true;
}

static void handle_std_op_const_add_pc(struct sm* sm, metainfo* mi,
				       uint8_t** opptr) {
	pr_disass("\n");

	uint64_t adjusted_opcode = 255 - mi->hdr->opcode_base;
	uint64_t operation_advance = adjusted_opcode / mi->hdr->line_range;
	sm->address += mi->hdr->min_instruction_length * operation_advance;
}

static void handle_std_op_fixed_advance_pc(struct sm* sm, metainfo* mi,
					   uint8_t** opptr) {
	uint16_t arg = uhalf(opptr);
	pr_disass(" %u\n", arg);

	sm->address += arg;
}

static void handle_std_op_set_prologue_end(struct sm* sm, metainfo* mi,
					   uint8_t** opptr) {
	pr_disass("\n");

	sm->prologue_end = true;
}

static void handle_std_op_set_epilogue_begin(struct sm* sm,
					     metainfo* mi,
					     uint8_t** opptr) {
	pr_disass("\n");

	sm->epilogue_begin = true;
}

static void handle_std_op_set_isa(struct sm* sm, metainfo* mi,
				  uint8_t** opptr) {
	uint64_t arg = leb128u(opptr);
	pr_disass("%zu\n", arg);

	sm->isa = arg;
}

static struct {
	const char* str;
	void (*f)(struct sm*, metainfo*, uint8_t**);
} standard_op[] = {
#define X(X) [DW_LNS_##X] = { .str = #X, .f = handle_std_op_##X }
	X(copy),
	X(advance_pc),
	X(advance_line),
	X(set_file),
	X(set_column),
	X(negate_stmt),
	X(set_basic_block),
	X(const_add_pc),
	X(fixed_advance_pc),
	X(set_prologue_end),
	X(set_epilogue_begin),
	X(set_isa),
#undef X
};

static void handle_standard_opcode(struct sm* sm, metainfo* mi,
				   uint8_t** opptr) {
	void (*func)(struct sm*, metainfo*, uint8_t**) = NULL;
	uint8_t* op = *opptr;

	if (*op >= arrsze(standard_op) || !standard_op[*op].str) {
		fprintf(stderr, "Invalid opcode\n");
		exit(1);
	}

	pr_disass("%s", standard_op[*op].str);
	func = standard_op[*op].f;
	op++;
	func(sm, mi, &op);

	*opptr = op - 1;
}

/* Extended Opcodes (6.2.5.3) */

static void handle_ext_end_sequence(struct sm* sm, metainfo* mi,
				    uint8_t* args, size_t size) {
	pr_disass("\n");

	sm->end_sequence = true;

	append_row(sm, mi);

	*sm = init_sm(mi->hdr);
}

static void handle_ext_set_address(struct sm* sm, metainfo* mi,
				   uint8_t* arg, size_t size) {
	uint64_t addr;
	if (size != sizeof(addr)) {
		fprintf(stderr, "set_address: Invalid address size\n");
		exit(1);
	}
	memcpy(&addr, arg, size);

	pr_disass("set address to %#lx\n", addr);

	sm->address = addr;
}

static void handle_ext_define_file(struct sm* sm, metainfo* mi,
				   uint8_t* args, size_t size) {
	pr_disass("\n");
}

static void handle_ext_set_discriminator(struct sm* sm,
					 metainfo* mi,
					 uint8_t* args, size_t size) {
	uint64_t discriminator = leb128u(&args);

	pr_disass("%" PRIu64 "\n", discriminator);

	sm->discriminator = discriminator;
}

static struct {
	const char* str;
	void (*f)(struct sm*, metainfo*, uint8_t*, size_t);
} extended[] = {
#define X(Name) [DW_LNE_##Name] = { .f = handle_ext_##Name, .str = #Name }
	X(end_sequence),
	X(set_address),
	X(define_file),
	X(set_discriminator),
#undef X
};

static void handle_extended_opcode(struct sm* sm, metainfo* mi,
				   uint8_t** opptr) {
	uint8_t* op = *opptr + 1;
	uint64_t size = leb128u(&op);

	if (*op < arrsze(extended) && extended[*op].f) {
		pr_disass("Extended %u: %s: ", *op, extended[*op].str);
		extended[*op].f(sm, mi, op + 1, size - 1);
	} else {
		pr_disass("<Extended %u>: ???: ", *op);
		for (size_t j = 1; j < size; j++)
			pr_disass(" %x", op[j]);
		pr_disass("\n");
	}
	*opptr = op + size - 1;
}

static enum {
	OP_standard,
	OP_extended,
	OP_special,
} get_opcode_type(DebugLineHeader* hdr, uint8_t op) {
	if (!op)
		return OP_extended;

	if (op < hdr->opcode_base)
		return OP_standard;

	return OP_special;
}

static void do_debug_line(void* mem, size_t size, Elf64_Shdr* shdr) {
	DebugLineHeader* hdr = (void*)((char*)mem + shdr->sh_offset);

#define X(Attr, Pr) printf(#Attr ": %" Pr "\n", hdr->Attr)
	X(length, PRIu32);
	X(version, PRIu16);
	X(header_length, PRIu32);
	X(min_instruction_length, PRIu8);
	X(default_is_stmt, PRIu8);
	X(line_base, PRIi8);
	X(line_range, PRIu8);
	X(opcode_base, PRIu8);
#undef X

#define ADD_LEN(F) (offsetof(DebugLineHeader, F) + sizeof(hdr->F) + hdr->F)

	if (ADD_LEN(length) > size) {
		fprintf(stderr, "Corrupted \".debug_line\" section\n");
		return;
	}

	if (hdr->version != 2) {
		fprintf(stderr, "Invalid version\n");
		return;
	}

	printf("Opcodes:\n");
	for (size_t i = 0; i < arrsze(hdr->std_opcode_lengths); i++)
		printf(" [%zu]: %u args\n", i, hdr->std_opcode_lengths[i]);

	metainfo mi = init_metainfo(hdr);
	struct sm sm = init_sm(hdr);

	print_files_and_dirs(&mi);

	uint8_t* hdr_addr = (uint8_t*)hdr;
	uint8_t* op = hdr_addr + ADD_LEN(header_length);
	for (; op < hdr_addr + ADD_LEN(length); op++) {
		pr_disass("  %#lx: ", op - hdr_addr);
		switch (get_opcode_type(hdr, *op)) {
		case OP_special:
			handle_special_opcode(&sm, &mi, &op);
			break;
		case OP_extended:
			handle_extended_opcode(&sm, &mi, &op);
			break;
		case OP_standard:
			handle_standard_opcode(&sm, &mi, &op);
			break;
		}
	}
}

static int is_valid_elf(Elf64_Ehdr* ehdr, size_t size) {
#define MAGCHK(Hdr, Mag) ((Hdr)->e_ident[EI_MAG##Mag] == ELFMAG##Mag)
	return MAGCHK(ehdr, 0) &&
	       MAGCHK(ehdr, 1) &&
	       MAGCHK(ehdr, 2) &&
	       MAGCHK(ehdr, 3) &&
#undef MAGCHK
	       ((ehdr->e_shoff + ehdr->e_shnum * ehdr->e_shentsize) <= size);
}

int main(int argc, char** argv) {
	int opt;
	while ((opt = getopt(argc, argv, "dl")) != -1) {
		switch (opt) {
		case 'd':
			print_disass = !print_disass;
			break;
		case 'l':
			print_lines = !print_lines;
			break;
		default:
			usage_and_quit(argv[1]);
		}
	}

	if (!argv[optind])
		usage_and_quit(argv[0]);

	int fd = open(argv[optind], O_RDONLY);
	if (fd < 0)
		fail("open");

	struct stat st;
	if (fstat(fd, &st) < 0)
		fail("fstat");

	char* mem = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED)
		fail("mmap");

	Elf64_Ehdr* ehdr = (void*)mem;
	if (!is_valid_elf(ehdr, st.st_size)) {
		fprintf(stderr, "Invalid ELF file\n");
		return 1;
	}

	Elf64_Shdr* shdr = (void*)(mem + ehdr->e_shoff);

	for (size_t i = 0; i < ehdr->e_shnum; i++) {
		char* shname = shstrtab(ehdr) + shdr[i].sh_name;
		size_t maxlen = st.st_size - (shname - mem);

		if (shname > mem + st.st_size ||
		    shdr[i].sh_offset > (size_t)st.st_size ||
		    shdr[i].sh_offset + shdr[i].sh_size > (size_t)st.st_size) {
			fprintf(stderr, "Corrupted ELF file\n");
			return 1;
		}

		if (!strncmp(".debug_line", shname, maxlen)) {
			do_debug_line(mem, st.st_size, shdr + i);
			return 0;
		}
	}

	fprintf(stderr, "Section \".debug_line\" not found\n");
	return 1;
}
