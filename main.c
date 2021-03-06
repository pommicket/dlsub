/*
Anyone is free to modify/distribute/use/sell/etc
this software for any purpose by any means.
Any copyright protections are relinquished by the author(s).
This software is provided "as is", without any warranty.
The author(s) shall not be held liable in connection with this software.
*/

#define VERSION "0.0"

#if __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

#if __unix__
	#define _POSIX_C_SOURCE 200809L
	#include <sys/stat.h>
	#include <sys/wait.h>
	#include <sys/mman.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <fcntl.h>
	#include <limits.h>
	#include <ctype.h>
	#include <assert.h>
	#define C_PREPROCESSOR_DEFAULT "/usr/bin/tcc"

	static int file_is_readable(const char *name) {
		return access(name, R_OK) == 0;
	}

	#if __GNUC__
		#pragma GCC diagnostic push
		#pragma GCC diagnostic error "-Wpadded"
	#endif
	typedef struct {
		unsigned magic;
		unsigned char class;
		unsigned char endianness;
		unsigned char version;
		unsigned char abi;
		unsigned char abi_version;
		char _pad1[7];
		unsigned short type;
		unsigned short architecture;
		unsigned version2;
		size_t entry;
		size_t phoff;
		size_t shoff;
		unsigned flags;
		unsigned short ehsize;
		unsigned short phentsize;
		unsigned short phnum;
		unsigned short shentsize;
		unsigned short shnum;
		unsigned short shstrndx;
	} ELFHeader;

	typedef struct {
		unsigned name;
		unsigned type;
		size_t flags;
		size_t addr;
		size_t offset;
		size_t size;
		unsigned link;
		unsigned info;
		size_t addralign;
		size_t entsize;
	} ELFSectionHeader;

	#if LONG_MAX == 0x7fffffff
	/* 32-bit struct */
	typedef struct {
		unsigned name;
		size_t value;
		size_t size;
		unsigned char info;
		unsigned char other;
		unsigned short shndx;
	} ELFSym;
	#else
	/* 64-bit struct */
	typedef struct {
		unsigned name;
		unsigned char info;
		unsigned char other;
		unsigned short shndx;
		size_t value;
		size_t size;
	} ELFSym;
	#endif

	#if __GNUC__
		#pragma GCC diagnostic pop
	#endif

#elif _WIN32
	#define C_PREPROCESSOR_DEFAULT "cl.exe /nologo /P"
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <limits.h>
	#include <ctype.h>
	#include <assert.h>
	#include <windows.h>

	#if _WIN64
	#define fseek _fseeki64
	#define ftell _ftelli64
	typedef __int64 fseek_t;
	#else
	typedef long fseek_t;
	#endif

	typedef struct {
		unsigned signature;
		unsigned short machine;
		unsigned short n_sections;
		unsigned time_date_stamp;
		unsigned ptr_symbol_table;
		unsigned n_symbols;
		unsigned short size_of_optional_header;
		unsigned short characteristics;
	} PEHeader;

	typedef struct {
		char name[8];
		unsigned virtual_size;
		unsigned virtual_address;
		unsigned size_of_raw_data;
		unsigned ptr_to_raw_data;
		unsigned ptr_to_relocations;
		unsigned ptr_to_line_numbers;
		unsigned short number_of_relocations;
		unsigned short number_of_linenumbers;
		unsigned characteristics;
	} PESectionHeader;

	typedef struct {
		unsigned flags;
		unsigned time_date_stamp;
		unsigned short major_version;
		unsigned short minor_version;
		unsigned name_rva;
		unsigned ordinal_base;
		unsigned address_table_entries;
		unsigned n_name_pointers;
		unsigned export_address_table_rva;
		unsigned name_pointer_rva;
		unsigned ordinal_table_rva;
	} PEExportDirectoryTable;
	
	static char PEHeader__static_assertion[2 * (sizeof(PEHeader) == 24) - 1];
	static char PESectionHeader__static_assertion[2 * (sizeof(PESectionHeader) == 40) - 1];
	static char PEExportDirectoryTable__static_assertion[2 * (sizeof(PEExportDirectoryTable) == 40) - 1];

	static int file_is_readable(const char *filename) {
		FILE *f = fopen(filename, "rb");
		if (f) {
			fclose(f);
			return 1;
		}
		return 0;
	}
#else
	#error "Unsupported operating system."
#endif


#define VERSION_TEXT "dlsub version " VERSION "\n"



static void show_help_text_and_exit(const char *program_name) {
	printf(VERSION_TEXT
		"\n");
	printf(
		"Usage: %s -i <header file> -l <dynamic library file> ...\n",
		program_name);
	printf(
		"Options:\n"
		"\t-i <header file>         Add a header file to be processed.\n"
		"\t-I <include directory>   Add an include directory when preprocessing header files.\n"
		"\t-l <dynamic library>     Set the dynamic library file you want to replace.\n"
		"\t-o <output name>         Set the output file name.\n"
		"\t-C <argument>            Add an argument for the C preprocessor.\n"
	);
	printf(
		"\t--no-warn                Disable warnings if a function isn't found in a header file.\n"
		"\t--help                   Show this help text and exit.\n"
		"\t--version                Show version number and exit.\n"
		"Environment variables:\n"
		"\tC_PREPROCESSOR - Program to be used for C preprocessing (default: '" C_PREPROCESSOR_DEFAULT "')\n"
	);
	exit(0);
}

/* can `c' appear in a C identifier? */
static int is_ident(int c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

static unsigned long str_hash(const char *str) {
    unsigned long hash = 5381;
	const unsigned char *p;

    for (p = (const unsigned char *)str; *p; ++p)
        hash = ((hash << 5) + hash) + *p;

    return hash;
}


typedef struct {
	unsigned char declared; /* have we found this in a header file */
	char symbol[1];
} SymbolHashEntry;

typedef struct {
	size_t n_entries;
	size_t n_present_entries;
	SymbolHashEntry **entries;
} SymbolHashTable;

static void symbol_hash_table_grow(SymbolHashTable *table) {
	size_t i, new_n_entries = 2*table->n_entries + 55;
	SymbolHashEntry **new_entries = calloc(new_n_entries, sizeof *new_entries);
	if (!new_entries) {
		fprintf(stderr, "Out of memory.\n");
		exit(2);
	}
	
	for (i = 0; i < table->n_entries; ++i) {
		SymbolHashEntry *entry = table->entries[i];
		size_t p;
		if (!entry) continue;
		p = str_hash(entry->symbol) % new_n_entries;
		while (new_entries[p]) {
			++p;
			if (p >= new_n_entries) p -= new_n_entries;
		}
		new_entries[p] = entry;
	}

	free(table->entries);
	table->entries = new_entries;
	table->n_entries = new_n_entries;
}

static void symbol_hash_table_insert(SymbolHashTable *table, const char *sym_name) {
	size_t p;
	SymbolHashEntry *entry;
	if (table->n_present_entries * 2 >= table->n_entries) {
		symbol_hash_table_grow(table);
	}

	p = str_hash(sym_name) % table->n_entries;
	while ((entry = table->entries[p])) {
		if (strcmp(entry->symbol, sym_name) == 0)
			return; /* already exists */

		++p;
		if (p >= table->n_entries) p -= table->n_entries;
	}
	entry = calloc(1, sizeof *entry + strlen(sym_name) + 1);
	if (!entry) {
		fprintf(stderr, "Out of memory.\n");
		exit(2);
	}
	strcpy(entry->symbol, sym_name);
	++table->n_present_entries;
	table->entries[p] = entry;
}

static SymbolHashEntry *symbol_hash_table_get(SymbolHashTable *table, const char *name) {
	size_t p = str_hash(name) % table->n_entries;
	SymbolHashEntry *entry;
	while ((entry = table->entries[p])) {
		if (strcmp(entry->symbol, name) == 0)
			return entry;
		++p;
		if (p >= table->n_entries) p -= table->n_entries;
	}
	return 0;
}

static void symbol_hash_table_free(SymbolHashTable *table) {
	size_t i;
	for (i = 0; i < table->n_entries; ++i)
		free(table->entries[i]);
	free(table->entries);
	memset(table, 0, sizeof *table);
}

int main(int argc, char **argv) {
	char *preprocessed_headers;
	size_t preprocessed_headers_len = 0;
	const char *preprocessor_program = C_PREPROCESSOR_DEFAULT;
	const char *output_name = NULL;
	const char *input_filename = NULL;
	int no_warn = 0;

	SymbolHashTable all_symbols = {0}; /* all symbols in all provided libraries */

	int i;

	{
		char *p = getenv("C_PREPROCESSOR");
		if (p)
			preprocessor_program = p;
	}
	
	{
		/* parse arguments */
		for (i = 1; i < argc; ++i) {
			if (argv[i][0] == '-') {
				switch (argv[i][1]) {
				case 'i':
					if (i < argc-1) {
						++i;
					} else {
						fprintf(stderr, "-i must be followed by a file name.\n");
						exit(-1);
					}
					break;
				case 'l':
					if (i < argc-1) {
						input_filename = argv[i+1];
						++i;
					} else {
						fprintf(stderr, "-l must be followed by a file name.\n");
						exit(-1);
					}
					break;
				case 'I':
					if (i < argc-1) {
						++i;
					} else {
						fprintf(stderr, "-I must be followed by a directory name.\n");
						exit(-1);
					}
					break;
				case 'C':
					if (i < argc-1) {
						++i;
					} else {
						fprintf(stderr, "-I must be followed by a directory name.\n");
						exit(-1);
					}
					break;
				case 'o':
					if (output_name) {
						fprintf(stderr, "-o specified twice.\n");
						exit(-1);
					} else if (i < argc-1) {
						output_name = argv[i+1];
						++i;
					} else {
						fprintf(stderr, "-o must be followed by a file name.\n");
						exit(-1);
					}
					break;
				case '-':
					if (strcmp(argv[i], "--help") == 0) {
						show_help_text_and_exit(argv[0]);
					} else if (strcmp(argv[i], "--version") == 0) {
						printf(VERSION_TEXT);
						exit(0);
					} else if (strcmp(argv[i], "--no-warn") == 0) {
						no_warn = 1;
					} else goto unrecognized;
					break;
				default:
				unrecognized:
					fprintf(stderr, "Unrecognized flag: '%s'.\n", argv[i]);
					break;
				}
			} else {
				fprintf(stderr, "Stray argument (#%d): '%s'.\n", i, argv[i]);
				exit(-1);
			}
		}
		if (!input_filename) {
			show_help_text_and_exit(argv[0]);
		}
	}

	if (!output_name) {
		output_name = "out";
	}


	if (!file_is_readable(input_filename)) {
		fprintf(stderr, "Can't open provided dynamic library file: '%s'.\n", input_filename);
		exit(1);
	}

	/* read library */
	{
		const char *libname = input_filename;
		FILE *fp = fopen(libname, "rb");

		if (!fp) {
			char prefix[128];
			sprintf(prefix, "Couldn't open %.100s.\n", libname);
			perror(prefix);
			exit(1);
		}

	#if __unix__	
		{
			ELFHeader elf_header = {0};
			int any_dynsym = 0;
			size_t dynstr_offset = 0;
			unsigned shidx;

			fread(&elf_header, sizeof elf_header, 1, fp);

			if (elf_header.magic != 0x464c457f || elf_header.type != 3) {
				fprintf(stderr, "%s is not an ELF dynamic library.\n", libname);
				exit(2);
			}
			if (elf_header.endianness != 1
				|| elf_header.shentsize < (sizeof(size_t) == 4 ? 0x28 : 0x40)
				|| elf_header.class * 4 != sizeof(size_t)
				|| elf_header.shoff > LONG_MAX) {
				fprintf(stderr, "%s has an unsupported or invalid ELF format.\n", libname);
				exit(2);
			}

			{
				ELFSectionHeader strtab_header = {0}, section_header = {0};

				fseek(fp, (long)elf_header.shoff + (long)elf_header.shentsize * elf_header.shstrndx, SEEK_SET);
				fread(&strtab_header, sizeof strtab_header, 1, fp);

				for (shidx = 0; shidx < elf_header.shnum; ++shidx) {
					char secname[32] = {0};
					fseek(fp, (long)(elf_header.shoff + shidx * elf_header.shentsize), SEEK_SET);
				
					fread(&section_header, sizeof section_header, 1, fp);
					fseek(fp, (long)strtab_header.offset + (long)section_header.name, SEEK_SET);
					fread(secname, 1, sizeof secname-1, fp);
					if (strcmp(secname, ".dynstr") == 0) {
						dynstr_offset = section_header.offset;
					}
				}
			}

			if (dynstr_offset == 0) {
				fprintf(stderr, "%s has no .dynstr section.\n", libname);
				exit(2);
			}

			
			{
				ELFSectionHeader section_header = {0};
				
				for (shidx = 0; shidx < elf_header.shnum; ++shidx) {
					fseek(fp, (long)(elf_header.shoff + shidx * elf_header.shentsize), SEEK_SET);
					fread(&section_header, sizeof section_header, 1, fp);
					if (section_header.type == 0xB /* SHT_DYNSYM */) {
						ELFSym sym = {0};
						size_t nsyms, sym_idx;
						char sym_name[256] = {0};

						any_dynsym = 1;
						
						if (section_header.entsize < sizeof(ELFSym) || section_header.offset > LONG_MAX) {
							fprintf(stderr, "%s has an unsupported or invalid ELF format.\n", libname);
							exit(2);
						}

						nsyms = section_header.size / section_header.entsize;
						
						for (sym_idx = 0; sym_idx < nsyms; ++sym_idx) {

							fseek(fp, (long)(section_header.offset + sym_idx * section_header.entsize), SEEK_SET);
							fread(&sym, sizeof sym, 1, fp);
							if (sym.other == 2 || sym.other == 6 /* check visibility */
								|| (sym.info & 0xf) != 2 /* check if is function */
								|| (sym.info >> 4) != 1 /* make sure "bind" is global */
								|| sym.value == 0 /* make sure this function is actually *from* this library */) {
								/* this symbol isn't a function exported by the dynamic library. it's something else */
							} else {
								fseek(fp, (long)(dynstr_offset + sym.name), SEEK_SET);
								fread(sym_name, 1, sizeof sym_name - 1, fp);
								/*printf("%02x %02x %08lx %08lx %s\n",sym.other,sym.info,sym.value,sym.size,sym_name);*/
								symbol_hash_table_insert(&all_symbols, sym_name);
							}
						}
					}
				}
			}
			
			if (!any_dynsym) {
				fprintf(stderr, "%s does not have a symbol table.\n", libname);
				exit(2);
			}
		}
	#else
		{
			PEHeader pe_header = {0};

			{ /* check if this is an actual DLL, find offset to PE header */
				unsigned short signature1 = 0;
				unsigned pe_header_offset = 0;

				fread(&signature1, sizeof signature1, 1, fp);
				if (signature1 != 0x5a4d) {
					fprintf(stderr, "%s is not a DLL file.\n", libname);
					exit(2);
				}

				fseek(fp, 0x3c, SEEK_SET);
				fread(&pe_header_offset, sizeof pe_header_offset, 1, fp);
				fseek(fp, (fseek_t)pe_header_offset, SEEK_SET);
			}
			
			fread(&pe_header, sizeof pe_header, 1, fp);
			
			if (pe_header.signature != 0x00004550 || (pe_header.characteristics & 0x2000) == 0) {
				fprintf(stderr, "%s is not a DLL file.\n", libname);
				exit(2);
			}
			
			fseek(fp, (fseek_t)pe_header.size_of_optional_header, SEEK_CUR);

			{
				unsigned section;
				PESectionHeader section_header = {0};
				for (section = 1; section <= pe_header.n_sections; ++section) {
					fread(&section_header, sizeof section_header, 1, fp);
					if (strncmp(section_header.name, ".edata", 8) == 0) {
						/* offset for all "RVA" pointers */
						fseek_t rva_offset = (fseek_t)section_header.ptr_to_raw_data - (fseek_t)section_header.virtual_address;

						PEExportDirectoryTable edt = {0};
						unsigned s;
						unsigned name_ptr = 0;
						char name[256];

						fseek(fp, (fseek_t)section_header.ptr_to_raw_data, SEEK_SET);
						fread(&edt, sizeof edt, 1, fp);
					
						for (s = 0; s < edt.n_name_pointers; ++s) {
							fseek(fp, rva_offset + (fseek_t)edt.name_pointer_rva + s * 4, SEEK_SET);
							fread(&name_ptr, sizeof name_ptr, 1, fp);
							fseek(fp, rva_offset + (fseek_t)name_ptr, SEEK_SET);
							fread(name, 1, sizeof name, fp);
							symbol_hash_table_insert(&all_symbols, name);
							/* printf("%s\n",name); */
						}
						break;
					}
				}
			}
			
		}
	#endif
		
		fclose(fp);
	}

	/* preprocess headers */
#if __unix__
	{
		int preprocessed_headers_fd = fileno(tmpfile());
		pid_t compiler_process;
		int pipefd[2];

		if (preprocessed_headers_fd == -1) {
			perror("Couldn't create temporary preprocessing output file");
			exit(2);
		}
		
		if (pipe(pipefd) == -1) {
			perror("Couldn't create pipe");
			exit(2);
		}

		compiler_process = fork();

		switch (compiler_process) {
		case -1:
			perror("Couldn't create compiler process");
			exit(2);
		case 0: {
		#define MAX_CC_ARGV 4000
			static char *cc_argv[MAX_CC_ARGV+1];
			int a = 0;
			/* child */
			close(pipefd[1]); /* don't need write end of pipe */
			if (dup2(pipefd[0], 0) == -1) {
				perror("Couldn't redirect pipe to C compiler's stdin");
				exit(2);
			}
			if (dup2(preprocessed_headers_fd, 1) == -1) {
				perror("Couldn't redirect C compiler's stdout to file");
				exit(2);
			}

			cc_argv[a++] = (char *)preprocessor_program;
			cc_argv[a++] = "-E";
			cc_argv[a++] = "-";
			for (i = 1; i < argc-1; ++i) {
				if (strcmp(argv[i], "-I") == 0) {
					if (a + 2 > MAX_CC_ARGV) {
						fprintf(stderr, "Too many compiler arguments.\n");
						exit(-1);
					}
					cc_argv[a++] = "-I";
					cc_argv[a++] = argv[i+1];
				} else if (strcmp(argv[i], "-C") == 0) {
					if (a + 1 > MAX_CC_ARGV) {
						fprintf(stderr, "Too many compiler arguments.\n");
						exit(-1);
					}
					cc_argv[a++] = argv[i+1];
				}
				if (argv[i][0] == '-' && argv[i][1] != '-') ++i;
			}
			cc_argv[a++] = NULL;
			if (execv(preprocessor_program, cc_argv) == -1) {
				perror("Couldn't start C compiler");
				exit(2);
			}
		} break;
		default:
			break;
		}

		/* parent */
		close(pipefd[0]); /* don't need read end of pipe */
		for (i = 1; i < argc-1; ++i) {
			if (strcmp(argv[i], "-i") == 0) {
				const char *header = argv[i+1];
				int fd = open(header, O_RDONLY);
				char buf[4096];
				ssize_t bytes_read;

				if (fd == -1) {
					/* check include directories */
					char path[520];
					int j;
					for (j = 1; j < argc-1; ++j) {
						if (strcmp(argv[j], "-I") == 0) {
							const char *dir = argv[j+1];
							sprintf(path, "%.256s/%.256s", dir, header);
							fd = open(path, O_RDONLY);
							if (fd != -1) break;
						}
						if (argv[j][0] == '-' && argv[j][1] != '-') ++j;
					}
				
					if (fd == -1) {
						fprintf(stderr, "Couldn't find %.100s\n", header);
						kill(SIGKILL, compiler_process);
						exit(2);
					}
				}
				
				while ((bytes_read = read(fd, buf, sizeof buf)) > 0) {
					write(pipefd[1], buf, (size_t)bytes_read);
				}

				if (bytes_read < 0) {
					char prefix[128];
					sprintf(prefix, "Error reading %.100s", header);
					perror(prefix);
					kill(SIGKILL, compiler_process);
					exit(2);
				}

				close(fd);
			}
			if (argv[i][0] == '-' && argv[i][1] != '-') ++i;
		}
	
		close(pipefd[1]);

		/* wait for compiler to finish */
		while (1) {
			int status = 0;
			wait(&status);
			if (WIFEXITED(status)) {
				int exit_status = WEXITSTATUS(status);
				if (exit_status == 0) {
					break;
				} else {
					fprintf(stderr, "C preprocessor failed with exit code %d\n", exit_status);
					exit(exit_status);
				}
			} else if (WIFSIGNALED(status)) {
				int sig = WTERMSIG(status);
				fprintf(stderr, "C preprocessor terminated with signal %s (#%d)\n", strsignal(sig), sig);
				exit(2);
			}
		}

		{
			struct stat statbuf = {0};
			fstat(preprocessed_headers_fd, &statbuf);
			preprocessed_headers_len = (size_t)statbuf.st_size;
			preprocessed_headers = mmap(NULL, preprocessed_headers_len, PROT_READ, MAP_PRIVATE,
				preprocessed_headers_fd, 0);
			if (preprocessed_headers == MAP_FAILED) {
				perror("Couldn't map preprocessed headers file into memory");
				exit(2);
			}
		}
		
	}
#else
	{
		const char *in_headers_name = "_dlsub_temp";
		const char *out_headers_name = "_dlsub_temp.i";
		FILE *in_headers;

		in_headers = fopen(in_headers_name, "wb");
		if (!in_headers) {
			perror("Couldn't create temporary file");
			exit(2);
		}

		for (i = 1; i < argc-1; ++i) {
			if (strcmp(argv[i], "-i") == 0) {
				const char *header_name = argv[i+1];
				FILE *header_fp = fopen(header_name, "rb");
				char buf[4096];
				size_t bytes_read;

				if (!header_fp) {
					/* check include directories */
					char path[520];
					int j;
					for (j = 1; j < argc-1; ++j) {
						if (strcmp(argv[j], "-I") == 0) {
							const char *dir = argv[j+1];
							sprintf(path, "%.256s\\%.256s", dir, header_name);
							header_fp = fopen(path, "rb");
							if (header_fp) break;
						}
						if (argv[j][0] == '-' && argv[j][1] != '-') ++j;
					}
				
					if (!header_fp) {
						fprintf(stderr, "Couldn't find %.100s.\n", header_name);
						exit(2);
					}
				}
				
				while ((bytes_read = fread(buf, 1, sizeof buf, header_fp))) {
					fwrite(buf, 1, bytes_read, in_headers);
				}

			}
			if (argv[i][0] == '-' && argv[i][1] != '-') ++i;
		}

		fclose(in_headers);
		
		{
			static char command[L_tmpnam + 50000] = {0};
			size_t p = 0;
			sprintf(&command[p], "%.300s %.1000s ", preprocessor_program, in_headers_name);
			p += strlen(&command[p]);
			for (i = 1; i < argc-1; ++i) {
				if (strcmp(argv[i], "-I") == 0) {
					const char *inc = argv[i+1];
					if (p + strlen(inc) + 10 > sizeof command) {
						fprintf(stderr, "Too many arguments to C preprocessor.\n");
						exit(-1);
					}
					sprintf(&command[p], "/I %s ", inc);
					p += strlen(&command[p]);
				} else if (strcmp(argv[i], "-C") == 0) {
					const char *arg = argv[i+1];
					if (p + strlen(arg) + 10 > sizeof command) {
						fprintf(stderr, "Too many arguments to C preprocessor.\n");
						exit(-1);
					}
					sprintf(&command[p], "%s ", arg);
					p += strlen(&command[p]);
				}
				if (argv[i][0] == '-' && argv[i][1] != '-') ++i;
			}

			system(command);
			if (!file_is_readable(out_headers_name)) {
				fprintf(stderr, "C header preprocessing failed.\n");
				exit(2);
			}
		}

		{
			HANDLE output_file = CreateFileA(out_headers_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			HANDLE mapping;
			
			if (output_file == INVALID_HANDLE_VALUE) {
				fprintf(stderr, "Couldn't open %s (Windows error code %u).\n", out_headers_name, GetLastError());
				exit(2);
			}

			mapping = CreateFileMappingA(output_file, NULL, PAGE_READONLY, 0, 0, NULL);
			if (mapping == INVALID_HANDLE_VALUE) {
				fprintf(stderr, "Couldn't create mapping for %s (Windows error code %u).\n", out_headers_name, GetLastError());
				exit(2);
			}
			
			/* lets hope nobody's preprocessed headers are >4GB in size ... */
			preprocessed_headers_len = GetFileSize(output_file, NULL);
			preprocessed_headers = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, preprocessed_headers_len);
			if (!preprocessed_headers) {
				fprintf(stderr, "Couldn't map file %s into memory (Windows error code %u).\n", out_headers_name, GetLastError());
				exit(2);
			}
		}


	}
#endif

	/* figure out functions! */


	{
		FILE *c_output;
		FILE *nasm_output; 
		size_t c = 0;
		const char *semicolon;
		

		{
			char filename[1024];
			
			sprintf(filename, "%.1000s.c", output_name);
			c_output = fopen(filename, "w");
			if (!c_output) {
				perror("Couldn't open C output file");
				exit(1);
			}
			
			sprintf(filename, "%.1000s.asm", output_name);
			nasm_output = fopen(filename, "w");
			if (!nasm_output) {
				perror("Couldn't open nasm output file");
				exit(1);
			}
		}

		for (i = 1; i < argc-1; ++i) {
			if (strcmp(argv[i], "-i") == 0) {
				fprintf(c_output, "#include <%s>\n", argv[i+1]);
			}
			if (argv[i][0] == '-' && argv[i][1] != '-') ++i;
		}

		#if __unix__
		fprintf(c_output, "#if __unix__\n");
		#else
		fprintf(c_output, "#if _WIN32\n");
		#endif
		fprintf(c_output, "#define DLSUB_REAL_DL_NAME \"");
		{
			const char *p;
			for (p = input_filename; *p; ++p) {
				switch (*p) {
				case '\\':
					fputs("\\\\", c_output);
					break;
				case '"':
					fputs("\\\"", c_output);
					break;
				default:
					putc(*p, c_output);
					break;
				}
			}
		}
		fprintf(c_output, "\"\n");
		fprintf(c_output,
			"#else\n"
			"#error \"Please define DLSUB_REAL_DLNAME here.\"\n"
			"#endif\n");

		fprintf(c_output,
			"static void dlsub_init(void);\n"
			"\n"
			"#if __unix__\n"
			"#include <dlfcn.h>\n"
			"#define DLSUB_GET_DLHANDLE(filename) dlopen(filename, RTLD_LAZY)\n"
			"#define DLSUB_GET_SYM(handle, name) ((void(*)(void))dlsym(handle, name))\n"
			"#define DLSUB_EXPORT\n"
			"#define DLSUB_CALL\n"
			"static void __attribute__((constructor)) dlsub_constructor(void) {\n"
			"\tdlsub_init();\n"
			"}\n"
		);
		fprintf(c_output,
			"#elif _WIN32\n"
			"typedef struct HINSTANCE__ *HMODULE;\n"
			"__declspec(dllimport) HMODULE __stdcall LoadLibraryA(const char *);\n"
			"__declspec(dllimport) __int64 (*__stdcall GetProcAddress(HMODULE, const char *))();\n"
			"#define DLSUB_GET_DLHANDLE LoadLibraryA\n"
			"#define DLSUB_GET_SYM GetProcAddress\n"
			"#define DLSUB_CALL\n"
			"#define DLSUB_EXPORT __declspec(dllexport)\n"
		);
		fprintf(c_output,
			"unsigned __stdcall DllMain(void *instDLL, unsigned reason, void *_reserved) {\n"
			"\t(void)instDLL; (void)_reserved;\n"
			"\tswitch (reason) {\n"
			"\tcase 1: /* DLL loaded */\n"
			"\t\tdlsub_init();\n"
			"\t\tbreak;\n"
			"\tcase 0: /* DLL unloaded */\n"
			"\t\tbreak;\n"
			"\t}\n"
			"\treturn 1;\n"
			"}\n"
		);
		fprintf(c_output,
			"#else\n"
			"#error \"Unrecognized OS.\"\n"
			"#endif\n"
		);

		fprintf(c_output, "\n\n");

		while ((semicolon = memchr(preprocessed_headers + c, ';', preprocessed_headers_len - c))) {
			char statement_data[1024], *statement = statement_data;

			{

				int in_line_directive = 0;

				/* get rid of whitespace + line directives before actual statements */
				for (; c < preprocessed_headers_len; ++c) {
					switch (preprocessed_headers[c]) {
					case '\n':
						if (in_line_directive)
							in_line_directive = 0;
						break;
					case '\r':
					case '\t':
					case ' ':
					case '\v':
						break;
					case '#':
						in_line_directive = 1;
						break;
					default:
						if (!in_line_directive)
							goto brk;
						break;
					}
				}
			brk:
				{
					size_t l = (size_t)(semicolon - &preprocessed_headers[c]);
					if (l > sizeof statement_data - 5)
						l = sizeof statement_data - 5;
					memcpy(statement, &preprocessed_headers[c], l);
					statement[l] = 0;
				}
			}

			{
				char *p;
				char *in, *out;
			
				/* remove line directives */
				while ((p = strchr(statement, '#'))) {
					char *end = strchr(p, '\n');
					if (end) {
						memmove(p, end + 1, (size_t)((statement + strlen(statement) + 1) - (end + 1)));
					} else {
						*p = '\0';
					}
				}

				/* normalize whitespace */
				for (p = statement; *p; ++p) {
					if (isspace(*p)) *p = ' ';
				}
				
				/* remove duplicate/unnecessary whitespace */
				for (in = statement, out = statement; *in; ++in) {
					if (in[0] == ' ' && strchr(" (){}*,", in[1])) {
						continue;
					} else if (strchr(" (){}*,", in[0]) && in[1] == ' ') {
						*out++ = *in;
						while (in[1] == ' ') ++in;
					} else {
						*out++ = *in;
					}
				}
				*out = 0;
				
				/* remove leading whitespace */
				if (*statement == ' ')
					++statement;
				/* remove trailing whitespace */
				if (*statement && statement[strlen(statement)-1] == ' ') {
					statement[strlen(statement)-1] = '\0';
				}

				while (statement[0] == '}') {
					/* this can happen with inline functions */
					++statement;
				}

				/* remove "extern" at beginning */
				if (strncmp(statement, "extern ", 7) == 0) {
					statement += 7;
				}

				{
					/* remove GCC's __attribute__ s */
					char *attr;
					while ((attr = strstr(statement, "__attribute__(("))) {
						int paren_level = 2;

						p = attr;

						p += 15;
						for (; *p; ++p) {
							if (paren_level == 0) break;
							switch (*p) {
							case '(': ++paren_level; break;
							case ')': --paren_level; break;
							}
						}
						if (*p == ' ') ++p;
						memmove(attr, p, (size_t)(statement + strlen(statement) + 1 - p));
					}
				}
				{
					/* remove MSVC calling conventions */
					char *cc = strstr(statement, "__cdecl");
					if (cc)
						memmove(cc, cc + 7, (size_t)(statement + strlen(statement) + 1 - (cc+7)));
					cc = strstr(statement, "__stdcall");
					if (cc)
						memmove(cc, cc + 9, (size_t)(statement + strlen(statement) + 1 - (cc+9)));
					cc = strstr(statement, "__fastcall");
					if (cc)
						memmove(cc, cc + 10, (size_t)(statement + strlen(statement) + 1 - (cc+10)));
				}
			}

			if (
				/* these conditions aren't airtight but practically speaking they're good */
				   strlen(statement) < 5 /* shortest possible function declaration is A f(); */
				|| strchr(statement, '(') == NULL
				|| strchr(statement, ')') == NULL
				|| strchr(statement, '{') != NULL
				|| strchr(statement, '}') != NULL
				|| (strncmp(statement, "struct ",  6) == 0)
				|| (strncmp(statement, "enum ",    5) == 0)
				|| (strncmp(statement, "union ",   6) == 0)
				|| (strncmp(statement, "static ",  7) == 0)
				|| (strncmp(statement, "typedef ", 8) == 0)
				) {
				/* not a function declaration */
			} else {
				/* possibly a function declaration */
				char *func_name = statement, *func_name_end = 0;
				if (strncmp(func_name, "const ", 6) == 0) func_name += 6;
				while (is_ident(*func_name)) ++func_name;
				if (*func_name == ' ') ++func_name;
				if (strncmp(func_name, "const ", 6) == 0) func_name += 6;
				
				while (*func_name) {
					if (is_ident(*func_name) && func_name[1] == '(') {
						/* we got it! */
						func_name_end = func_name + 1;
						while (is_ident(*func_name))
							--func_name;
						++func_name;
						break;
					}
					++func_name;
				}

				if (*func_name) {
					SymbolHashEntry *entry;

					*func_name_end = '\0';
					entry = symbol_hash_table_get(&all_symbols, func_name);
					*func_name_end = '(';

					if (!entry) {
						/* ignore this function; it's not part of one of the libraries we're concerned with */
					} else if (entry->declared) {
						/* already processed this function */
					} else {
						entry->declared = 1;
						fprintf(c_output,
							"typedef %.*s (*DLSUB_CALL PTR_%.*s)%.*s;\n"
							"PTR_%.*s REAL_%.*s;\n",
							(int)(func_name - statement),
							statement,
							(int)(func_name_end - func_name),
							func_name,
							(int)(statement + strlen(statement) - func_name_end),
							func_name_end,

							(int)(func_name_end - func_name),
							func_name,
							(int)(func_name_end - func_name),
							func_name
							);
					}
				}

			}
			c = (size_t)(semicolon - preprocessed_headers);
			++c;
		}
		
		{
			size_t s;
			const SymbolHashEntry *entry;
			const char *symbol;
			
			fputs("default rel\n"
				"%ifidn __OUTPUT_FORMAT__, elf64\n"
				"\t%define FUNCPTR(p) [p wrt ..gotpc]\n"
				"\t%macro GLOBAL 1\n"
				"\t\tglobal %1 %+ :function\n"
				"\t%endmacro\n"
				"%else\n"
				"\t%define FUNCPTR(p) p\n"
				"\t%macro GLOBAL 1\n"
				"\t\tglobal %1\n"
				"\t\texport %1\n"
				"\t%endmacro\n"
				"%endif\n",
			nasm_output);
			

			for (s = 0; s < all_symbols.n_entries; ++s) {
				entry = all_symbols.entries[s];
				if (!entry) continue;
				symbol = entry->symbol;
				fprintf(nasm_output, "extern REAL_%s\n", symbol);
				if (!entry->declared) {
					fprintf(c_output, "void (*REAL_%s)(void);\n", symbol);
					if (!no_warn)
						fprintf(stderr, "Warning: Function '%s' declared in library, not found in any header file. It will not be usable from C.\n", symbol);
				}
			}

			fprintf(nasm_output, "section .text\n");
			fprintf(c_output, "static void dlsub_init(void) {\n"
				"\tvoid *handle = DLSUB_GET_DLHANDLE(DLSUB_REAL_DL_NAME);\n");

			for (s = 0; s < all_symbols.n_entries; ++s) {
				entry = all_symbols.entries[s];
				if (!entry) continue;
				symbol = entry->symbol;
				fprintf(c_output, "\tREAL_%s = (%s%s)DLSUB_GET_SYM(handle, \"%s\");\n", symbol,
					entry->declared ? "PTR_" : "void (*)(void)", entry->declared ? symbol : "", symbol);
				fprintf(nasm_output, "GLOBAL %s\n", symbol);
			}

		
			for (s = 0; s < all_symbols.n_entries; ++s) {
				entry = all_symbols.entries[s];
				if (!entry) continue;
				symbol = entry->symbol;
				fprintf(nasm_output, "%s: mov r11, FUNCPTR(REAL_%s)\njmp [r11]\n", symbol, symbol);
			}
		}

		fprintf(c_output, "}\n");


		fclose(c_output);
		fclose(nasm_output);
	}

	symbol_hash_table_free(&all_symbols);

	return 0;
}
