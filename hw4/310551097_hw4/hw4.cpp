#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <capstone/capstone.h>

#include <string>
#include <map>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <fstream>
#include <sys/types.h>    
#include <sys/stat.h>    
#include <fcntl.h>

using namespace std;

#define INS_MAX_LEN 15

void help();
void load(string);
void run();
void getregs();
void get();
void dump();
void setbreak();
void c();
void list();
void si();
void vmmap();
unsigned long get_addr();
void reset_all_breakpoint();
void si_and_restore_break();
void disas();
void disas_one(unsigned long rip);
void del();
void set();

static unsigned long elf_text_segment_start = 0;
static unsigned long elf_text_segment_end = 0xffffffffffffffff;
void store_seg_range(string process_name);

void errquit(const char *msg)
{
    perror(msg);
    exit(-1);
}

typedef struct breakpoint
{
    unsigned char savecode;
    unsigned long addr;
} breakpoint_t;

static long idx = 0;
static string state = "not loaded";
static pid_t child;
static int child_status;
static map<unsigned long, breakpoint_t> breakpoints;
static string process_name;
static long restore_idx = -1;
static stringstream global_cmd;
static bool smode = false;
int main(int argc, char *argv[])
{
    dup2(0, 3);
    if (argc > 1)
    {
        int opt;
        int fd;
        while ((opt = getopt(argc, argv, "s:")) != -1)
        {
            switch (opt)
            {
            case 's':
                fd = open(optarg,O_RDONLY);
                dup2(fd,0);
                smode = 1;
                break;
            default:
                cerr << "usage: ./hw4 [-s script] [program]\n";
                exit(EXIT_FAILURE);
            }
        }
        if (optind < argc)
        {
            load(string(argv[optind]));
        }

    }

    string cmd;
    while (smode || cerr << "sdb > ")
    {
        if(!getline(cin, cmd))break;
        global_cmd = stringstream(cmd);
        global_cmd >> cmd;
        if (cmd == "help" || cmd == "h")
        {
            help();
        }
        else if (cmd == "load")
        {
            load("");
        }
        else if(cmd == "start")
        {
            state = "running";
        }
        else if (cmd == "run" || cmd == "r")
        {
            run();
        }
        else if (cmd == "c" || cmd == "cont")
        {
            if(state=="running")c();
        }
        else if (cmd == "getregs")
        {
            if(state == "running")getregs();
        }
        else if (cmd == "get")
        {
            if(state == "running")get();
        }
        else if(cmd == "dump" || cmd == "x")
        {
            if(state=="running")dump();
        }
        else if(cmd == "exit" || cmd == "q")
        {
            exit(0);
        }
        else if(cmd == "break" || cmd == "b")
        {
            if(state=="running")setbreak();
        }
        else if(cmd == "list" || cmd == "l")
        {
            list();
        }
        else if (cmd == "si")
        {
            if(state=="running")si();
        }
        else if(cmd == "vmmap" || cmd == "m")
        {
            if(state=="running")vmmap();
        }
        else if (cmd == "disasm" || cmd == "d")
        {
            if(state=="running")disas();
        }
        else if (cmd == "delete")
        {
            if(state=="running")del();
        }
        else if(cmd == "set" || cmd == "s")
        {
            if(state=="running")set();
        }
    }

    return 0;
}

void set()
{
    string reg;
    global_cmd >> reg;
    unsigned long val = get_addr();

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);

    if(reg == "rax")regs.rax = val;
    if(reg == "rbx")regs.rbx = val;
    if(reg == "rcx")regs.rcx = val;
    if(reg == "rdx")regs.rdx = val;
    if(reg == "r8")regs.r8 = val;
    if(reg == "r9")regs.r9 = val;
    if(reg == "r10")regs.r10 = val;
    if(reg == "r11")regs.r11 = val;
    if(reg == "r12")regs.r12 = val;
    if(reg == "r13")regs.r13 = val;
    if(reg == "r14")regs.r14 = val;
    if(reg == "r15")regs.r15 = val;
    if(reg == "rdi")regs.rdi = val;
    if(reg == "rsi")regs.rsi = val;
    if(reg == "rbp")regs.rbp = val;
    if(reg == "rsp")regs.rsp = val;
    if(reg == "rip")regs.rip = val;
    if(reg == "flags" || reg == "eflags")regs.eflags = val;

    ptrace(PTRACE_SETREGS, child, 0, &regs);
}

void del()
{
    long idx = -1;
    global_cmd >> idx;
    
    if(breakpoints.find(idx) == breakpoints.end() || idx==-1)
    {
        cerr << "** deleting non-existing break points\n";
        return;
    }

    if (restore_idx == idx)restore_idx = -1;
    unsigned long word;
    word = ptrace(PTRACE_PEEKDATA, child, breakpoints[idx].addr, 0);
    if (ptrace(PTRACE_POKETEXT, child, breakpoints[idx].addr, (word & 0xffffffffffffff00) | breakpoints[idx].savecode) != 0)
        errquit("ptrace(POKETEXT)");

    breakpoints.erase(idx);
}

void disas()
{
    unsigned long addr = get_addr();
    if (addr == 0xffffffffffffffff)return;

    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;

    for (int i = 0; i < 10;i++)
    {

        if (addr < elf_text_segment_start || addr >= elf_text_segment_end)
        {
            cerr << "** the address is out of the range of the text segment" << endl;
            break;
        }
        unsigned long code[2]; // 16 byte > MAX_INS_LEN(15)
        code[0] = ptrace(PTRACE_PEEKDATA, child, addr, 0);
        code[1] = ptrace(PTRACE_PEEKDATA, child, addr + 8, 0);

        // restore 0xcc to savecode of breakpoint
        unsigned char *code_str = (unsigned char *)code;
        for (auto b : breakpoints)
        {
            if (b.second.addr >= addr && b.second.addr <= addr + 15)
            {
                code_str[b.second.addr - addr] = b.second.savecode;
            }
        }

        count = cs_disasm(handle, (unsigned char *)code, sizeof(code), addr, 1, &insn);
        stringstream ss;
        ss << hex << insn[0].address << ": ";
        for (int j = 0; j < insn[0].size; j++)
        {
            ss << setw(2) << setfill('0') << hex << (unsigned long)insn[0].bytes[j] << ' ';
        }
        cerr << setw(64) << setfill(' ') << left << ss.str();
        cerr << "\t" << insn[0].mnemonic << "\t" << insn[0].op_str << endl;
        cs_free(insn, count);
        addr += insn[0].size;
    }
}

void disas_one(unsigned long rip)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;

    unsigned long code[2]; // 16 byte > MAX_INS_LEN(15)
    code[0] = ptrace(PTRACE_PEEKDATA, child, rip, 0);
    code[1] = ptrace(PTRACE_PEEKDATA, child, rip + 8, 0);

    // restore 0xcc to savecode of breakpoint
    unsigned char *code_str = (unsigned char *)code;
    for (auto b : breakpoints)
    {
        if (b.second.addr >= rip && b.second.addr <= rip + 15)
        {
            code_str[b.second.addr - rip] = b.second.savecode;
        }
    }

    count = cs_disasm(handle, (unsigned char *)code, sizeof(code), rip, 1, &insn);
    stringstream ss;
    ss << hex << insn[0].address << ": ";
    for (int j = 0; j < insn[0].size; j++)
    {
        ss << setw(2) << setfill('0') << hex << (unsigned long)insn[0].bytes[j] << ' ';
    }
    cerr << setw(64) << setfill(' ') << left << ss.str();
    cerr << "\t" << insn[0].mnemonic << "\t" << insn[0].op_str << endl;
    cs_free(insn, count);
}

void vmmap()
{
    string filename = "/proc/" + to_string(child) + "/maps";
    string line;
    ifstream myfile(filename);
    if (myfile.is_open())
    {
        while (getline(myfile, line))
        {
            stringstream ss(line);
            string address;
            ss >> address;
            cerr << setfill('0') << setw(16) <<address.substr(0, address.find('-'));
            cerr << '-';
            address.erase(0, address.find('-') + 1);
            cerr << setfill('0') << setw(16) << address;
            string rwx;
            ss >> rwx;
            cerr << " " << rwx.substr(0, 3);
            unsigned long offset;
            ss >> hex >> offset;
            cerr << " " << hex << offset;
            string path;
            string ignore;
            {
                ss >> ignore >> ignore >> path;
                cerr << " " << path << endl;
            }
        }
        myfile.close();
    }
}

void si()
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    unsigned long word;
    word = ptrace(PTRACE_PEEKDATA, child, regs.rip, 0);
    if((word & 0xff) == 0xcc)
    {
        for(auto b : breakpoints)
        {
            if(b.second.addr = regs.rip)
            {
                restore_idx = b.first;
                break;
            }
        }
        si_and_restore_break();
    }
    else
    {
        do
        {
            ptrace(PTRACE_SINGLESTEP, child, 0, 0);
            waitpid(child, &child_status, 0);
        } while (!WIFSTOPPED(child_status));
    }
}

void list()
{
    for(auto b : breakpoints)
    {
        cerr << b.first << ":   " << hex << b.second.addr << endl;
    }
}

void setbreak()
{
    unsigned long addr = get_addr();
    if (addr == 0xffffffffffffffff)return;

    unsigned long word;
    word = ptrace(PTRACE_PEEKDATA, child, addr, 0);
    if (ptrace(PTRACE_POKETEXT, child, addr, (word & 0xffffffffffffff00) | 0xcc) != 0)
        errquit("ptrace(POKETEXT)");

    breakpoints.insert({idx++,{(unsigned char)(word & 0xff), addr}});
}

void dump()
{
    unsigned long addr = get_addr();
    if (addr == 0xffffffffffffffff)return;

    for (int i = 0; i < 5;i++)
    {
        unsigned char data[16];
        cerr << "   " << hex << addr << ": ";
        unsigned long word;
        word = ptrace(PTRACE_PEEKDATA, child, addr, 0);
        for (int j = 0; j < 8; j++)
        {
            data[j] = word % 0x100L;
            word = word >> 8;
        }
        word = ptrace(PTRACE_PEEKDATA, child, addr + 8, 0);
        for (int j = 8; j < 16; j++)
        {
            data[j] = word % 0x100L;
            word = word >> 8;
        }

        for (int j = 0; j < 16;j++)
        {
            cerr << setfill('0') << hex << setw(2) << right << (int)data[j] << " ";
        }
        cerr << "|";
        for (int j = 0; j < 16; j++)
        {
            if(isprint(data[j]))
            {
                cerr << data[j];
            }
            else
            {
                cerr << ".";
            }
        }
        cerr << "|\n";
        addr += 16;
    }
}

void get()
{
    string reg;
    global_cmd >> reg;
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    if(reg == "rax")cerr << "rax = " << dec << regs.rax << hex <<" (0x"<< regs.rax <<")"<< endl;
    if(reg == "rbx")cerr << "rbx = " << dec << regs.rbx << hex << " (0x" << regs.rbx << ")" << endl;
    if(reg == "rcx")cerr << "rcx = " << dec << regs.rcx << hex << " (0x" << regs.rcx << ")" << endl;
    if(reg == "rdx")cerr << "rdx = " << dec << regs.rdx << hex << " (0x" << regs.rdx << ")" << endl;
    if(reg == "r8")cerr << "r8 = "  << dec << regs.r8 << hex << " (0x" << regs.r8 << ")" << endl;
    if(reg == "r9")cerr << "r9 = "  << dec << regs.r9 << hex << " (0x" << regs.r9 << ")" << endl;
    if(reg == "r10")cerr << "r10 = "  << dec << regs.r10 << hex << " (0x" << regs.r10 << ")" << endl;
    if(reg == "r11")cerr << "r11 = "  << dec << regs.r11 << hex << " (0x" << regs.r11 << ")" << endl;
    if(reg == "r12")cerr << "r12 = "  << dec << regs.r12 << hex << " (0x" << regs.r12 << ")" << endl;
    if(reg == "r13")cerr << "r13 = "  << dec << regs.r13 << hex << " (0x" << regs.r13 << ")" << endl;
    if(reg == "r14")cerr << "r14 = "  << dec << regs.r14 << hex << " (0x" << regs.r14 << ")" << endl;
    if(reg == "r15")cerr << "r15 = "  << dec << regs.r15 << hex << " (0x" << regs.r15 << ")" << endl;
    if(reg == "rdi")cerr << "rdi = "  << dec << regs.rdi << hex << " (0x" << regs.rdi << ")" << endl;
    if(reg == "rsi")cerr << "rsi = "  << dec << regs.rsi << hex << " (0x" << regs.rsi << ")" << endl;
    if(reg == "rbp")cerr << "rbp = "  << dec << regs.rbp << hex << " (0x" << regs.rbp << ")" << endl;
    if(reg == "rsp")cerr << "rsp = "  << dec << regs.rsp << hex << " (0x" << regs.rsp << ")" << endl;
    if(reg == "rip")cerr << "rip = "  << dec << regs.rip << hex << " (0x" << regs.rip << ")" << endl;
    if(reg == "flags" || reg == "eflags")cerr << reg << " = " << hex << setfill('0') << setw(16) << regs.eflags << endl;
}

void getregs()
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    cerr << "RAX " << hex << regs.rax << endl;
    cerr << "RBX " << hex << regs.rbx << endl;
    cerr << "RCX " << hex << regs.rcx << endl;
    cerr << "RDX " << hex << regs.rdx << endl;
    cerr << "R8 " << hex << regs.r8 << endl;
    cerr << "R9 " << hex << regs.r9 << endl;
    cerr << "R10 " << hex << regs.r10 << endl;
    cerr << "R11 " << hex << regs.r11 << endl;
    cerr << "R12 " << hex << regs.r12 << endl;
    cerr << "R13 " << hex << regs.r13 << endl;
    cerr << "R14 " << hex << regs.r14 << endl;
    cerr << "R15 " << hex << regs.r15 << endl;
    cerr << "RDI " << hex << regs.rdi << endl;
    cerr << "RSI " << hex << regs.rsi << endl;
    cerr << "RBP " << hex << regs.rbp << endl;
    cerr << "RSP " << hex << regs.rsp << endl;
    cerr << "RIP " << hex << regs.rip << endl;
    cerr << "FLAGS " << hex << setfill('0') << setw(16) << regs.eflags << endl;
}

void run()
{
    if(state == "running")
    {
        cerr << "** process is already running!\n";
    }
    state = "running";
    c();
}

void c()
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    unsigned long word;
    word = ptrace(PTRACE_PEEKDATA, child, regs.rip, 0);
    if ((word & 0xff) == 0xcc)
    {
        restore_idx = -1;
        for (auto b : breakpoints)
        {
            if(b.second.addr == regs.rip)
            {
                restore_idx = b.first;
                break;
            }
        }
        if(restore_idx != -1)si_and_restore_break();
    }

    ptrace(PTRACE_CONT, child, 0, 0);
    while (waitpid(child, &child_status, 0) > 0)
    {
        if (WIFEXITED(child_status))
        {
            cerr << "** process exit!\n";
            load(process_name);
            break;
        }

        if (!WIFSTOPPED(child_status))
            continue;

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
            errquit("ptrace(GETREGS)");

        int idx = -1;
        for (auto b : breakpoints)
        {
            if(b.second.addr == regs.rip - 1) 
            {
                idx = b.first;
                break;
            }
        }

        if(idx != -1)
        {
            regs.rip = regs.rip - 1;
            cerr << "** breakpoint @      ";
            disas_one(regs.rip);

            if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0)
                errquit("ptrace(SETREGS)");
        }

        break;
    }
}

void load(string proc_name)
{
    if(proc_name == "")
    {
        global_cmd >> process_name;
    }else
    {
        process_name = proc_name;
    }

    if ((child = fork()) < 0)
        errquit("fork");
    if (child == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            errquit("ptrace@child");
        dup2(3, 0);
        execlp(process_name.c_str(), process_name.c_str(), NULL);
        errquit("execlp");
    }

    int status;
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status))
    {
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child, 0, &regs);
        store_seg_range(process_name);
        cerr << "** program '" << process_name << "' loaded. entry point "<< "0x" << hex << elf_text_segment_start << endl;
        //elf_text_segment_start = regs.rip;
        state = "loaded";
        reset_all_breakpoint();
    }
}

void help()
{
    cerr << R"(    - break {instruction-address}: add a break point
    - cont: continue execution
    - delete {break-point-id}: remove a break point
    - disasm addr: disassemble instructions in a file or a memory region
    - dump addr: dump memory content
    - exit: terminate the debugger
    - get reg: get a single value from a register
    - getregs: show registers
    - help: show this message
    - list: list break points
    - load {path/to/a/program}: load a program
    - run: run the program
    - vmmap: show memory layout
    - set reg val: get a single value to a register
    - si: step into instruction
    - start: start the program and stop at the first instruction
)";
}

unsigned long get_addr()
{
    string addr_str = "";
    unsigned long addr;
    global_cmd >> addr_str;
    if(addr_str == "")
    {
        cerr << "**no addr is given\n";
        return 0xffffffffffffffff;
    }

    stringstream ss;
    ss << addr_str;
    if (addr_str.substr(0, 2) == "0x")
    {
        ss >> hex >> addr;
    }
    else
    {
        ss >> addr;
    }

    return addr;
}

void reset_all_breakpoint()
{
    for (auto b : breakpoints)
    {
        unsigned long word;
        word = ptrace(PTRACE_PEEKDATA, child, b.second.addr, 0);
        if (ptrace(PTRACE_POKETEXT, child, b.second.addr, (word & 0xffffffffffffff00) | 0xcc) != 0)
            errquit("ptrace(POKETEXT)");
    }
    restore_idx = -1;
}

void si_and_restore_break()
{
    /* restore ins */
    unsigned long word = ptrace(PTRACE_PEEKDATA, child, breakpoints[restore_idx].addr, 0);
    if (ptrace(PTRACE_POKETEXT, child, breakpoints[restore_idx].addr, (word & 0xffffffffffffff00) | breakpoints[restore_idx].savecode) != 0)
        errquit("ptrace(POKETEXT)");

    
    do{
        ptrace(PTRACE_SINGLESTEP,child,0,0);
        waitpid(child, &child_status, 0);
    } while (!WIFSTOPPED(child_status));

    /* restore break point */
    reset_all_breakpoint();
}

//only supprot little endina elf x64
void store_seg_range(string process_name)
{
    FILE *file;
    if ((file = fopen(process_name.c_str(), "rb")))
    {
        // section header offset
        unsigned long seg_headers_off;
        fseek(file, 0x28, SEEK_SET);
        fread(&seg_headers_off, 1, 8, file);

        // section header size
        unsigned long e_shentsize = 0;
        fseek(file, 0x3a, SEEK_SET);
        fread(&e_shentsize, 1, 2, file);

        //index of section header name section
        unsigned long e_shstrndx = 0;
        fseek(file, 0x3e, SEEK_SET);
        fread(&e_shstrndx, 1, 2, file);

        //index of section header name section
        unsigned long e_shnum = 0;
        fseek(file, 0x3c, SEEK_SET);
        fread(&e_shnum, 1, 2, file);

        unsigned long e_shstrn_off = seg_headers_off + e_shstrndx * e_shentsize;
        unsigned long e_shstrn_context_off = 0;
        fseek(file, e_shstrn_off + 0x18, SEEK_SET);
        fread(&e_shstrn_context_off, 1, 8, file);

        for (unsigned long i = 0; i < e_shnum; i++)
        {
            unsigned long name_off_in_shstr = 0;
            fseek(file, seg_headers_off + e_shentsize * i, SEEK_SET);
            fread(&name_off_in_shstr, 1, 4, file);

            char name[0x30] = {};
            fseek(file, name_off_in_shstr + e_shstrn_context_off, SEEK_SET);
            fread(name, 1, 0x30, file);

            if (strncmp(name, ".text", 6) == 0)
            {
                unsigned long text_section_addr = 0;
                fseek(file, seg_headers_off + e_shentsize * i + 0x10, SEEK_SET);
                fread(&text_section_addr, 1, 8, file);

                unsigned long text_section_size = 0;
                fseek(file, seg_headers_off + e_shentsize * i + 0x20, SEEK_SET);
                fread(&text_section_size, 1, 8, file);

                elf_text_segment_start = text_section_addr;
                elf_text_segment_end = elf_text_segment_start + text_section_size;
                /*
                if(elf_text_segment_start == text_section_addr)
                {
                    elf_text_segment_end = elf_text_segment_start + text_section_size;
                }else
                {
                    cerr << "** elf parse error (maybe use unsupport elf32/big endian elf/pie)\n" ;
                }*/
                break;
            }
        }
        fclose(file);
    }
    else
    {
        errquit("open file error");
    }
}