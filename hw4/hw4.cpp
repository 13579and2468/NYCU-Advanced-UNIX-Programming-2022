#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <capstone/capstone.h>

#include "disas.hpp"
#include <string>
#include <map>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <fstream>

using namespace std;

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

typedef struct breakpoint
{
    unsigned char savecode;
    unsigned long addr;
} breakpoint_t;

static unsigned long idx = 1;
static string state;
static pid_t child;
static int child_status;
static map<unsigned long, breakpoint_t> breakpoints;
static string process_name;
static unsigned long restore_idx = 0;
static stringstream global_cmd;
int main(int argc, char *argv[])
{
    state = "not loaded";
    string cmd;
    while (cerr << "sdb > ")
    {
        getline(cin, cmd);
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
            c();
        }
        else if (cmd == "getregs")
        {
            getregs();
        }
        else if (cmd == "get")
        {
            get();
        }
        else if(cmd == "dump" || cmd == "x")
        {
            dump();
        }
        else if(cmd == "exit" || cmd == "q")
        {
            exit(0);
        }
        else if(cmd == "break" || cmd == "b")
        {
            setbreak();
        }
        else if(cmd == "list" || cmd == "l")
        {
            list();
        }
        else if (cmd == "si")
        {
            si();
        }else if(cmd == "vmmap" || cmd == "m")
        {
            vmmap();
        }
    }

    return 0;
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
            ss >> ignore >> ignore >> path;
            cerr << " " << path << endl;
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
            cerr << hex << setfill('0') << setw(2) << (int)data[j] << " ";
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
    if(reg == "rax")cerr << "rax = " << regs.rax << hex <<" (0x"<< regs.rax <<")"<< endl;
    if(reg == "rbx")cerr << "rbx = " << regs.rbx << hex << " (0x" << regs.rbx << ")" << endl;
    if(reg == "rcx")cerr << "rcx = " << regs.rcx << hex << " (0x" << regs.rcx << ")" << endl;
    if(reg == "rdx")cerr << "rdx = " << regs.rdx << hex << " (0x" << regs.rdx << ")" << endl;
    if(reg == "r8")cerr << "r8 = " << regs.r8 << hex << " (0x" << regs.r8 << ")" << endl;
    if(reg == "r9")cerr << "r9 = " << regs.r9 << hex << " (0x" << regs.r9 << ")" << endl;
    if(reg == "r10")cerr << "r10 = " << regs.r10 << hex << " (0x" << regs.r10 << ")" << endl;
    if(reg == "r11")cerr << "r11 = " << regs.r11 << hex << " (0x" << regs.r11 << ")" << endl;
    if(reg == "r12")cerr << "r12 = " << regs.r12 << hex << " (0x" << regs.r12 << ")" << endl;
    if(reg == "r13")cerr << "r13 = " << regs.r13 << hex << " (0x" << regs.r13 << ")" << endl;
    if(reg == "r14")cerr << "r14 = " << regs.r14 << hex << " (0x" << regs.r14 << ")" << endl;
    if(reg == "r15")cerr << "r15 = " << regs.r15 << hex << " (0x" << regs.r15 << ")" << endl;
    if(reg == "rdi")cerr << "rdi = " << regs.rdi << hex << " (0x" << regs.rdi << ")" << endl;
    if(reg == "rsi")cerr << "rsi = " << regs.rsi << hex << " (0x" << regs.rsi << ")" << endl;
    if(reg == "rbp")cerr << "rbp = " << regs.rbp << hex << " (0x" << regs.rbp << ")" << endl;
    if(reg == "rsp")cerr << "rsp = " << regs.rsp << hex << " (0x" << regs.rsp << ")" << endl;
    if(reg == "rip")cerr << "rip = " << regs.rip << hex << " (0x" << regs.rip << ")" << endl;
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
    if (restore_idx)si_and_restore_break();

    struct user_regs_struct regs;
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

        int idx = 0;
        for (auto b : breakpoints)
        {
            if(b.second.addr == regs.rip - 1) 
            {
                idx = b.first;
                break;
            }
        }

        if(idx)
        {
            regs.rip = regs.rip - 1;
            restore_idx = idx;
            cerr << "** breakpoint @      " << hex << regs.rip << endl;

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
    }
    if ((child = fork()) < 0)
        errquit("fork");
    if (child == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            errquit("ptrace@child");
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
        cerr << "** program '" << process_name << "' loaded. entry point "<< "0x" << hex << regs.rip << endl;
        process_name = process_name;
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
    restore_idx = 0;
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