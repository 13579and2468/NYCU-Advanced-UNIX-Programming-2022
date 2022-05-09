#include "libmini.h"

int errno;

char* errorlist[134] = {
    "Operation not permitted"
    "No such file or directory"
    "No such process"
    "Interrupted system call"
    "Input/output error"
    "No such device or address"
    "Argument list too long"
    "Exec format error"
    "Bad file descriptor"
    "No child processes"
    "Resource temporarily unavailable"
    "Cannot allocate memory"
    "Permission denied"
    "Bad address"
    "Block device required"
    "Device or resource busy"
    "File exists"
    "Invalid cross-device "
    "No such device"
    "Not a directory"
    "Is a directory"
    "Invalid argument"
    "Too many open files in system"
    "Too many open files"
    "Inappropriate ioctl for device"
    "Text file busy"
    "File too large"
    "No space left on device"
    "Illegal seek"
    "Read-only file system"
    "Too many links"
    "Broken pipe"
    "Numerical argument out of domain"
    "Numerical result out of range"
    "Resource deadlock avoided"
    "File name too long"
    "No locks available"
    "Function not implemented"
    "Directory not empty"
    "Too many levels of symbolic links"
    "Unknown error 41"
    "No message of desired type"
    "Identifier removed"
    "Channel number out of range"
    "Level 2 not synchronized"
    "Level 3 halted"
    "Level 3 reset"
    "Link number out of range"
    "Protocol driver not attached"
    "No CSI structure available"
    "Level 2 halted"
    "Invalid exchange"
    "Invalid request descriptor"
    "Exchange full"
    "No anode"
    "Invalid request code"
    "Invalid slot"
    "Unknown error 58"
    "Bad font file format"
    "Device not a stream"
    "No data available"
    "Timer expired"
    "Out of streams resources"
    "Machine is not on the network"
    "Package not installed"
    "Object is remote"
    "Link has been severed"
    "Advertise error"
    "Srmount error"
    "Communication error on send"
    "Protocol error"
    "Multihop attempted"
    "RFS specific error"
    "Bad message"
    "Value too large for defined data type"
    "Name not unique on network"
    "File descriptor in bad state"
    "Remote address changed"
    "Can not access a needed shared library"
    "Accessing a corrupted shared library"
    ".lib section in a.out corrupted"
    "Attempting to link in too many shared libraries"
    "Cannot exec a shared library directly"
    "Invalid or incomplete multibyte or wide character"
    "Interrupted system call should be restarted"
    "Streams pipe error"
    "Too many users"
    "Socket operation on non-socket"
    "Destination address required"
    "Message too long"
    "Protocol wrong type for socket"
    "Protocol not available"
    "Protocol not supported"
    "Socket type not supported"
    "Operation not supported"
    "Protocol family not supported"
    "Address family not supported by protocol"
    "Address already in use"
    "Cannot assign requested address"
    "Network is down"
    "Network is unreachable"
    "Network dropped connection on reset"
    "Software caused connection abort"
    "Connection reset by peer"
    "No buffer space available"
    "Transport endpoint is already connected"
    "Transport endpoint is not connected"
    "Cannot send after transport endpoint shutdown"
    "Too many references: cannot splice"
    "Connection timed out"
    "Connection refused"
    "Host is down"
    "No route to host"
    "Operation already in progress"
    "Operation now in progress"
    "Stale file handle"
    "Structure needs cleaning"
    "Not a XENIX named type file"
    "No XENIX semaphores available"
    "Is a named type file"
    "Remote I/O error"
    "Disk quota exceeded"
    "No medium found"
    "Wrong medium type"
    "Operation canceled"
    "Required key not available"
    "Key has expired"
    "Key has been revoked"
    "Key was rejected by service"
    "Owner died"
    "State not recoverable"
    "Operation not possible due to RF-kill"
    "Memory page has hardware error"
};

long int syscall(long int sysno, ...)
{
    __builtin_va_list args;
    long int arg0, arg1, arg2, arg3, arg4, arg5;
    long int sys_res = 0;

    /* Load varargs */
    __builtin_va_start(args, sysno);
    arg0 = __builtin_va_arg(args, long int);
    arg1 = __builtin_va_arg(args, long int);
    arg2 = __builtin_va_arg(args, long int);
    arg3 = __builtin_va_arg(args, long int);
    arg4 = __builtin_va_arg(args, long int);
    arg5 = __builtin_va_arg(args, long int);
    __builtin_va_end(args);

    asm volatile("mov rax, %1\n"
                 "mov rdi, %2\n"
                 "mov rsi, %3\n"
                 "mov rdx, %4\n"
                 "mov r10, %5\n"
                 "mov r8,  %6\n"
                 "mov r9,  %7\n"
                 "syscall\n"
                 "mov %0, rax\n"
                 : "=r"(sys_res)
                 : "r"(sysno), "r"(arg0), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5)
                 : "rax","rdi","rsi","rdx","r10","r8","r9");

    if(sys_res < 0)
    {
        errno = -sys_res;
    }
    return sys_res;
}

ssize_t write(int fd, const void *buf, size_t n)
{
    return syscall(1,fd,buf,n);
}

int pause()
{
    return syscall(34);
}

unsigned int sleep(unsigned int seconds)
{
    struct timespec ts = {0, 0};
    do
    {
        ts.tv_sec = seconds;
        seconds = 0;
        if (syscall(35, &ts, &ts) < 0)
            return seconds + ts.tv_sec;
    } while (seconds > 0);
    return 0;
}

void exit(int errno)
{
    syscall(60, errno);
}

size_t strlen(const char *str)
{
    size_t count = 0;
    while ((unsigned char)*str++)
        count++;
    return count;
}

unsigned int alarm(unsigned int seconds)
{
    return syscall(37, seconds);
}

int sigemptyset(sigset_t *set)
{
    *set = 0;
    return 0;
}

int sigfillset(sigset_t *set)
{
    *set = 0xffffffffffffffff;
    return 0;
}

int sigaddset(sigset_t *set, int sig)
{
    *set |= (1UL << (sig - 1));
    return 0;
}

int sigdelset(sigset_t *set, int sig)
{
    *set &= ~(1UL << (sig - 1));
    return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    return syscall(14, how, set, oldset, sizeof(sigset_t));
}

int sigpending(sigset_t *set)
{
    return syscall(127, set, sizeof(sigset_t));
}

void perror(const char *s)
{
    int errno_save = errno;
    if(s && *s)
    {
        write(2, s, strlen(s));
        write(2, ": ", 2);
        if (errno_save >= sizeof(errorlist) / 8)
        {
            write(2, "Unknown error ", sizeof("Unknown error "));  //itoa好麻煩
        }else
        {
            write(2, errorlist[errno_save], strlen(errorlist[errno_save]));
        }
        write(2, "\n", 1);
    }
}

int sigismember(const sigset_t *set, int sig)
{
    return (*set & (1UL << (sig - 1))) != 0;
}

sighandler_t signal(int signum, sighandler_t handler)
{
    struct sigaction act, oact;
    act.sa_handler = handler;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, signum);
    act.sa_flags = SA_RESTART | SA_RESTORE;
    act.sa_restorer = __myrt;
    syscall(13, signum, &act, &oact, sizeof(sigset_t));
    return oact.sa_handler;
}