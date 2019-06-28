#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <cassert>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <vector>
#include <utility>
#include <capstone/capstone.h>
#include <sys/stat.h> 
#include <fcntl.h>
#include "elftool.h"

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

unsigned char permission, status = 0; // 0: not loaded ; 1 : loaded ; 2 : runnung
long long entry, addr, offset, size, vaddr, base, daddr, saddr;
struct user_regs_struct regs;
std::vector <std::pair<unsigned long, unsigned long>> breakpoint;
csh handle;
cs_insn * insn = NULL;
int count;
unsigned char buffer[10000];

void error_msg(char * string)
{
	std::fprintf(stderr, "Error : %s.\n", string);
	exit(-1);
}
void load(char * file)
{
	elf_handle_t * eh = NULL;
	elf_strtab_t * tab = NULL;

	elf_init();
	eh = elf_open(file);
	elf_load_all(eh);
	entry = eh->entrypoint;
	for(tab = eh->strtab; tab != NULL; tab = tab->next) if(tab->id == eh->shstrndx) break;
	for(int i = 0; i < eh->shnum; i++) 
		if(!std::strcmp(&tab->data[eh->shdr[i].name], ".text"))
		{
			addr = eh->shdr[i].addr;
			offset = eh->shdr[i].offset;
			size = eh->shdr[i].size;
			permission = eh->shdr[i].flags;
			break;
		}
	std::printf("** program \'%s\' loaded. entry point 0x%llx, vaddr 0x%llx, offset 0x%llx, size 0x%llx\n", file, entry, addr, offset, size);
	for(int i = 0 ; i < eh->phnum ; i++)
		if(eh->phdr[i].flags & 1) {vaddr = eh->phdr[i].vaddr; break;}
	elf_close(eh);

	daddr = saddr = -1;
	status = 1;
	breakpoint.clear();
	insn = NULL;
}
void start(pid_t & pid, char * file)
{
	int status;
	pid = fork();
	if(!pid)
	{
		char command[50] = "./";
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) error_msg("ptrace in child process");
		std::strcat(command, file);
		execlp(command, command, NULL);
		exit(0);
	}
	else if(pid < 0) error_msg("fork");
	if(waitpid(pid, &status, 0) < 0) error_msg("waitpid");
	assert(WIFSTOPPED(status));
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
	std::printf("** pid %u\n", pid);


	char path[50];
	sprintf(path, "/proc/%u/maps", pid);
	FILE * fp = std::fopen(path, "r");
	std::fscanf(fp, "%llx", &base);
	std::fclose(fp);

	for(int i = 0 ; i < breakpoint.size() ; i++)
	{
		unsigned long addr = breakpoint[i].first, old_value = ptrace(PTRACE_PEEKTEXT, pid, base + addr - vaddr, 0);
		ptrace(PTRACE_POKETEXT, pid, base + addr - vaddr, (old_value & 0xffffffffffffff00) | 0xCC);
		breakpoint[i].second = old_value;
	}

	::status = 2;
}
unsigned long get_number()
{
	static char number_buffer[20];
	unsigned long ret;

	std::scanf("%s", number_buffer);
	if(std::strlen(number_buffer) > 2 && number_buffer[1] == 'x') std::sscanf(number_buffer + 2, "%lx", &ret);
	else std::sscanf(number_buffer, "%lu", &ret);

	return ret;
}
void print_memory(pid_t pid, char * filename)
{
	if(status == 1)
	{
		std::printf("%016llx-%016llx %c%c%c %llx        %s\n", entry, entry + size, permission & 4 ? 'r' : '-', permission & 2 ? 'w' : '-', permission & 1 ? 'x' : '-', offset, filename);
		return ;
	}
	static char file[50], input[100];
	long long num1, num2;
	std::sprintf(file, "/proc/%u/maps", pid);
	FILE * fp = std::fopen(file, "r");

	while(fp && std::fscanf(fp, "%llx-%llx", & num1, & num2) == 2)
	{
		std::printf("%016llx-%016llx", num1 & 0x7fffffffffffffff, num2 & 0x7fffffffffffffff);
		std::fscanf(fp, "%s", input);
		input[3] = 0;
		std::printf(" %s", input);
		std::fscanf(fp, "%lx", & num1);
		std::fscanf(fp, "%s", input);
		std::fscanf(fp, "%s", input);
		std::printf(" %lx", num1);
		std::fgets(input, 100, fp);
		std::printf(" %s", input);
	}

	std::fclose(fp);
}
void print_reg(char * reg)
{
	if(!reg)
	{
		std::printf("RAX %-10lx RBX %-10lx RCX %-10lx RDX %-10lx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
		std::printf("R8  %-10lx R9  %-10lx R10 %-10lx R11 %-10lx\n", regs.r8, regs.r9, regs.r10, regs.r11);
		std::printf("R12 %-10lx R13 %-10lx R14 %-10lx R15 %-10lx\n", regs.r12, regs.r13, regs.r14, regs.r15);
		std::printf("RDI %-10lx RSI %-10lx RBP %-10lx RSP %-10lx\n", regs.rdi, regs.rsi, regs.rbp, regs.rsp);
		std::printf("RIP %-10lx FLAGS %016lx\n", regs.rip, regs.eflags);
		return ;		
	}
	unsigned long value;
	
	if(!strcmp(reg, "rax")) value = regs.rax;
	if(!strcmp(reg, "rbx")) value = regs.rbx;
	if(!strcmp(reg, "rcx")) value = regs.rcx;
	if(!strcmp(reg, "rdx")) value = regs.rdx;
	if(!strcmp(reg, "r8")) value = regs.r8;
	if(!strcmp(reg, "r9")) value = regs.r9;
	if(!strcmp(reg, "r10")) value = regs.r10;
	if(!strcmp(reg, "r11")) value = regs.r11;
	if(!strcmp(reg, "r12")) value = regs.r12;
	if(!strcmp(reg, "r13")) value = regs.r13;
	if(!strcmp(reg, "r14")) value = regs.r14;
	if(!strcmp(reg, "r15")) value = regs.r15;
	if(!strcmp(reg, "rdi")) value = regs.rdi;
	if(!strcmp(reg, "rsi")) value = regs.rsi;
	if(!strcmp(reg, "rbp")) value = regs.rbp;
	if(!strcmp(reg, "rsp")) value = regs.rsp;
	if(!strcmp(reg, "rip")) value = regs.rip;
	if(!strcmp(reg, "flags")) value = regs.eflags;

	std::printf("%s = %lu (%lx)\n", reg, value, value);
}
void set_reg(char * reg, unsigned long value)
{
	if(!strcmp(reg, "rax")) regs.rax = value;
	if(!strcmp(reg, "rbx")) regs.rbx = value;
	if(!strcmp(reg, "rcx")) regs.rcx = value;
	if(!strcmp(reg, "rdx")) regs.rdx = value;
	if(!strcmp(reg, "r8")) regs.r8 = value;
	if(!strcmp(reg, "r9")) regs.r9 = value;
	if(!strcmp(reg, "r10")) regs.r10 = value;
	if(!strcmp(reg, "r11")) regs.r11 = value;
	if(!strcmp(reg, "r12")) regs.r12 = value;
	if(!strcmp(reg, "r13")) regs.r13 = value;
	if(!strcmp(reg, "r14")) regs.r14 = value;
	if(!strcmp(reg, "r15")) regs.r15 = value;
	if(!strcmp(reg, "rdi")) regs.rdi = value;
	if(!strcmp(reg, "rsi")) regs.rsi = value;
	if(!strcmp(reg, "rbp")) regs.rbp = value;
	if(!strcmp(reg, "rsp")) regs.rsp = value;
	if(!strcmp(reg, "rip")) regs.rip = value;
	if(!strcmp(reg, "flags")) regs.eflags = value;
}
int main(int N, char ** args)
{
	if(N > 2) error_msg("wrong usage");
	static char command[100], * file = N == 2 ? args[1] : NULL;
	pid_t pid = -1;
	
	if(file) load(file);
	breakpoint.clear();

	while(std::printf("sdb> ") && std::scanf("%s", command))
	{
		if(!std::strcmp(command, "load"))
		{
			if(file) delete file;
			file = new char[50];
			std::scanf("%s", file);
			load(file);
		}
		else if(!std::strcmp(command, "start")) start(pid, file);
		else if(!std::strcmp(command, "si")) ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
		else if(!std::strcmp(command, "vmmap") || !std::strcmp(command, "m")) print_memory(pid, file);
		else if(!std::strcmp(command, "get") || !std::strcmp(command, "g"))
		{
			ptrace(PTRACE_GETREGS, pid, NULL, & regs);
			std::scanf("%s", command);
			print_reg(command);
		}
		else if(!std::strcmp(command, "getregs"))
		{
			ptrace(PTRACE_GETREGS, pid, NULL, & regs);
			print_reg(NULL);
		}
		else if(!std::strcmp(command, "set") || !std::strcmp(command, "s"))
		{
			ptrace(PTRACE_GETREGS, pid, NULL, & regs);
			std::scanf("%s", command);
			set_reg(command, get_number());
			ptrace(PTRACE_SETREGS, pid, NULL, & regs);
		}
		else if(!std::strcmp(command, "disasm"))
		{
			long long addr = saddr;

			if(std::fgetc(stdin) != ' ')
			{
				if(addr == -1)
				{
					std::printf("** no addr is given.\n");
					continue;
				}
			}
			else std::scanf("%llx", & addr);
			if(!insn)
			{
				std::memset(buffer, 0, 10000);
				int fd = open(file, O_RDONLY);
				lseek(fd, offset, SEEK_SET);
				read(fd, buffer, sizeof(buffer));
				close(fd);
				if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) error_msg("disasm");
				count = cs_disasm(handle, buffer,  sizeof(buffer) - 1, ::addr, 0, & insn);
			}
			int num = 10;
			for (int i = 0; i < count && num; i++)
			{
				if(insn[i].address < addr) continue;
				std::printf("\t%llx:", insn[i].address);
				for(int j = 0 ; j < 5 ; j++) if(j < insn[i].size) std::printf(" %02x", insn[i].bytes[j]); else std::printf("   ");
				std::printf(" %s   %s\n", insn[i].mnemonic, insn[i].op_str);
				addr = insn[i].address+1;
				num--;
			}
		}
		else if(!std::strcmp(command, "dump") || !std::strcmp(command, "x"))
		{
			long long addr = daddr;;
			static unsigned char data[17];
			unsigned long code;
			int num = 0;

			if(std::fgetc(stdin) != ' ')
			{
				if(addr == -1)
				{
					std::printf("** no addr is given.\n");
					continue;
				}
			}
			else std::scanf("%llx", & addr);

			data[16] = 0;
			for(int i = 0 ; i < 5 ; i++)
			{
				std::printf("\t%llx: ", addr + (i << 4));
				for(int k = 0 ; k < 4 ; k++)
				{
					code = ptrace(PTRACE_PEEKTEXT, pid, base - vaddr + addr + (i << 4) + (k << 2), 0);
					for(int j = 0 ; j < 4 ; j++)
					{
						unsigned char c = * ((unsigned char *)(& code) + j);
						std::printf("%02lx ", c);
						if(c > 31 && c < 127) data[j + (k << 2)] = c;
						else data[j + (k << 2)] = '.';
					}
				}
				std::printf("|%s|\n", data);
			}
			addr += 80;
		}
		else if(!std::strcmp(command, "cont") || !std::strcmp(command, "c"))
		{
			if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) error_msg("ptrace continue");
			int status;
			if(waitpid(pid, &status, 0) < 0) error_msg("waitpid");
			if(WIFEXITED(status)) {std::printf("** child process %u terminiated normally (code %d)\n", pid, WEXITSTATUS(status)); ::status = 1;}
			else
			{
				if(!insn)
				{
					std::memset(buffer, 0, 10000);
					int fd = open(file, O_RDONLY);
					lseek(fd, offset, SEEK_SET);
					read(fd, buffer, sizeof(buffer));
					close(fd);
					if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) error_msg("disasm");
					count = cs_disasm(handle, buffer,  sizeof(buffer) - 1, ::addr, 0, & insn);
				}
				int in;
				ptrace(PTRACE_GETREGS, pid, NULL, & regs);
				for(in = 0 ; in < breakpoint.size() ; in++)
				{
					if(breakpoint[in].first + base - vaddr == regs.rip - 1) break;
				}
				std::printf("** breakpoint @ %llx:", breakpoint[in].first + base - vaddr);
				for (int i = 0; i < count; i++)
				{
					if(insn[i].address != breakpoint[in].first) continue;
					for(int j = 0 ; j < 5 ; j++) if(j < insn[i].size) std::printf(" %02x", insn[i].bytes[j]); else std::printf("   ");
					std::printf(" %s   %s\n", insn[i].mnemonic, insn[i].op_str);
					addr = insn[i].address+1;
				}
			}
		}
		else if(!std::strcmp(command, "run") || !std::strcmp(command, "r"))
		{
			if(status == 2) std::printf("** program %s is already running.\n", file);
			else start(pid, file);
			if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) error_msg("ptrace run");
			int status;
			if(waitpid(pid, &status, 0) < 0) error_msg("waitpid");
			if(WIFEXITED(status)) {std::printf("** child process %u terminiated normally (code %d)\n", pid, WEXITSTATUS(status)); ::status = 1;}
			else
			{
				if(!insn)
				{
					std::memset(buffer, 0, 10000);
					int fd = open(file, O_RDONLY);
					lseek(fd, offset, SEEK_SET);
					read(fd, buffer, sizeof(buffer));
					close(fd);
					if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) error_msg("disasm");
					count = cs_disasm(handle, buffer,  sizeof(buffer) - 1, ::addr, 0, & insn);
				}
				int in;
				ptrace(PTRACE_GETREGS, pid, NULL, & regs);
				for(in = 0 ; in < breakpoint.size() ; in++)
				{
					if(breakpoint[in].first + base - vaddr == regs.rip - 1) break;
				}
				std::printf("** breakpoint @ %llx:", breakpoint[in].first + base - vaddr);
				for (int i = 0; i < count; i++)
				{
					if(insn[i].address != breakpoint[in].first) continue;
					for(int j = 0 ; j < 5 ; j++) if(j < insn[i].size) std::printf(" %02x", insn[i].bytes[j]); else std::printf("   ");
					std::printf(" %s   %s\n", insn[i].mnemonic, insn[i].op_str);
					addr = insn[i].address+1;
				}
			}
		}
		else if(!std::strcmp(command, "break") || !std::strcmp(command, "b"))
		{
			unsigned long addr = get_number(), old_value = ptrace(PTRACE_PEEKTEXT, pid, addr + base - vaddr, 0);
			if(status >= 2) ptrace(PTRACE_POKETEXT, pid, addr + base - vaddr, (old_value & 0xffffffffffffff00) | 0xCC);
			breakpoint.push_back(std::make_pair(addr, old_value));
		}
		else if(!std::strcmp(command, "list") || !strcmp(command, "l"))
		{
			for(unsigned i = 0 ; i < breakpoint.size() ; i++)
			{
				if(!breakpoint[i].first) continue;
				std::printf("     %u:%10lx\n", i, breakpoint[i].first);
			}
		}
		else if(!std::strcmp(command, "delete"))
		{
			unsigned index;
			std::scanf("%u", & index);
			ptrace(PTRACE_POKETEXT, pid, breakpoint[index].first, breakpoint[index].second);
			breakpoint[index].first = 0;
			std::printf("** breakpoint %u deleted.\n", index);
		}
		else if(!std::strcmp(command, "help"))
		{
			std::printf(
			"- break {instruction-address}: add a break point\n"
			"- cont: continue execution\n"
			"- delete {break-point-id}: remove a break point\n"
			"- disasm addr: disassemble instructions in a file or a memory region\n"
			"- dump addr [length]: dump memory content\n"
			"- exit: terminate the debugger\n"
			"- get reg: get a single value from a register\n"
			"- getregs: show registers\n"
			"- help: show this message\n"
			"- list: list break points\n"
			"- load {path/to/a/program}: load a program\n"
			"- run: run the program\n"
			"- vmmap: show memory layout\n"
			"- set reg val: get a single value to a register\n"
			"- si: step into instruction\n"
			"- start: start the program and stop at the first instruction\n");
		}
		else if(!std::strcmp(command, "exit") || !std::strcmp(command, "q")) return 0;
	}
	return 0;
}