#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <capstone/capstone.h>

#include "ptools.h"

#include <string>
#include <map>
#include <iostream>

using namespace std;

#define PEEKSIZE 8

class instruction1
{
public:
    unsigned char bytes[16];
    int size;
    string opr, opnd;
};

static csh cshandle = 0;
static map<long long, instruction1> instructions;

void errquit(const char *msg)
{
    perror(msg);
    exit(-1);
}

void print_instruction(long long addr, instruction1 *in, const char *module)
{
    int i;
    char bytes[128] = "";
    if (in == NULL)
    {
        fprintf(stderr, "0x%012llx<%s>:\t<cannot disassemble>\n", addr, module);
    }
    else
    {
        for (i = 0; i < in->size; i++)
        {
            snprintf(&bytes[i * 3], 4, "%2.2x ", in->bytes[i]);
        }
        fprintf(stderr, "0x%012llx<%s>: %-32s\t%-10s%s\n", addr, module, bytes, in->opr.c_str(), in->opnd.c_str());
    }
}

void disassemble(pid_t proc, unsigned long long rip, const char *module)
{
    int count;
    char buf[64] = {0};
    unsigned long long ptr = rip;
    cs_insn *insn;
    map<long long, instruction1>::iterator mi; // from memory addr to instruction

    if ((mi = instructions.find(rip)) != instructions.end())
    {
        print_instruction(rip, &mi->second, module);
        return;
    }

    for (ptr = rip; ptr < rip + sizeof(buf); ptr += PEEKSIZE)
    {
        long long peek;
        errno = 0;
        peek = ptrace(PTRACE_PEEKTEXT, proc, ptr, NULL);
        if (errno != 0)
            break;
        memcpy(&buf[ptr - rip], &peek, PEEKSIZE);
    }

    if (ptr == rip)
    {
        print_instruction(rip, NULL, module);
        return;
    }

    if ((count = cs_disasm(cshandle, (uint8_t *)buf, rip - ptr, rip, 0, &insn)) > 0)
    {
        int i;
        for (i = 0; i < count; i++)
        {
            instruction1 in;
            in.size = insn[i].size;
            in.opr = insn[i].mnemonic;
            in.opnd = insn[i].op_str;
            memcpy(in.bytes, insn[i].bytes, insn[i].size);
            instructions[insn[i].address] = in;
        }
        cs_free(insn, count);
    }

    if ((mi = instructions.find(rip)) != instructions.end())
    {
        print_instruction(rip, &mi->second, module);
    }
    else
    {
        print_instruction(rip, NULL, module);
    }

    return;
}

/*
int main(int argc, char *argv[])
{
    string cmd;
    while (cin>>cmd)
    {
        switch
    }

    pid_t child;
    if ((child = fork()) < 0)
        errquit("fork");
    if (child == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            errquit("ptrace@child");
        execvp(argv[1], argv + 1);
        errquit("execvp");
    }
    else
    {
        long long counter = 0LL;
        int wait_status;
        map<range_t, map_entry_t> m;
        map<range_t, map_entry_t>::iterator mi;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
            return -1;

        if (waitpid(child, &wait_status, 0) < 0)
            errquit("waitpid");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        if (load_maps(child, m) > 0)
        {
            fprintf(stderr, "## %zu map entries loaded.\n", m.size());
        }

        while (WIFSTOPPED(wait_status))
        {
            struct user_regs_struct regs;
            counter++;
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) == 0)
            {
                range_t r = {regs.rip, regs.rip};
                mi = m.find(r);
                if (mi == m.end())
                {
                    m.clear();
                    load_maps(child, m);
                    fprintf(stderr, "## %zu map entries re-loaded.\n", m.size());
                    mi = m.find(r);
                }
                disassemble(child, regs.rip, mi != m.end() ? mi->second.name.c_str() : "unknown");
            }
            if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
            {
                perror("ptrace");
                cs_close(&cshandle);
                return -2;
            }
            if (waitpid(child, &wait_status, 0) < 0)
                errquit("waitpid");
        }

        fprintf(stderr, "## %lld instructions(s) monitored\n", counter);
        cs_close(&cshandle);
    }
    return 0;
}*/