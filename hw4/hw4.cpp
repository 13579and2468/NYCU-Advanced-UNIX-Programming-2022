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

using namespace std;

void help();
void load();
void run();
void getregs();
void get();
void dump();

static string state;
static pid_t child;
static int child_status;
int main(int argc, char *argv[])
{
    state = "not loaded";
    string cmd;
    while (cerr << "sdb > " && cin >> cmd )
    {
        if (cmd == "help" || cmd == "h")
        {
            help();
        }
        else if (cmd == "load")
        {
            load();
        }
        else if(cmd == "start")
        {
            state = "running";
        }
        else if (cmd == "run" || cmd == "r")
        {
            run();
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
    }

    return 0;
}

void dump()
{
    string addr_str;
    unsigned long addr;
    cin >> addr_str;
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
    cin >> reg;
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
    ptrace(PTRACE_CONT,child,0,0);
    state = "running";
}

void load()
{
    string argv;
    cin >> argv;
    if ((child = fork()) < 0)
        errquit("fork");
    if (child == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            errquit("ptrace@child");
        execlp(argv.c_str(), argv.c_str(), NULL);
        errquit("execlp");
    }

    int status;
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status))
    {
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child, 0, &regs);
        cerr << "** program '" << argv << "' loaded. entry point " << "0x" << hex << regs.rip << endl;
        state = "loaded";
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