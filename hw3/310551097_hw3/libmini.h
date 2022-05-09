#ifndef __LIBMINI_H__
#define __LIBMINI_H__

typedef void (*__sighandler_t)(int);
typedef __sighandler_t sighandler_t;
typedef unsigned long int __sigset_t;
typedef __sigset_t sigset_t;

typedef long long ssize_t;
typedef unsigned long size_t;

struct sigaction
{
    sighandler_t sa_handler;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    sigset_t sa_mask;
};

typedef struct jmp_buf_s
{
    long long reg[8]; //RBX, RSP, RBP, R12, R13, R14, R15, and the return address (to the caller of setjmp)
    sigset_t mask;
} jmp_buf[1];

struct timespec
{
    long tv_sec;  /* Seconds.  */
    long tv_nsec; /* Nanoseconds.  */
};

#define NULL 0

/* macros (or constant) */
#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGIOT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGSTKFLT 16
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG 23
#define SIGXCPU 25
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGIO 29
#define SIGPWR 30
#define SIGSYS 31

#define SIG_BLOCK 0   /* for blocking signals */
#define SIG_UNBLOCK 1 /* for unblocking signals */
#define SIG_SETMASK 2 /* for setting the signal mask */

#define SIG_DFL ((__sighandler_t)0)  /* default signal handling */
#define SIG_IGN ((__sighandler_t)1)  /* ignore signal */
#define SIG_ERR ((__sighandler_t)-1) /* error return from signal */

#define SA_RESTART 0x10000000
#define SA_RESTORE 0x04000000

/* function definitions (export it with exactly the same type signature) */
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
int sigismember(const sigset_t *set, int sig);
int sigaddset(sigset_t *set, int sig);
int sigdelset(sigset_t *set, int sig);
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigpending(sigset_t *set);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
sighandler_t signal(int signum, sighandler_t handler);
int setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val);
unsigned int alarm(unsigned int sec);

ssize_t write(int fd, const void *buf, size_t n);
int pause();
void exit(int errno);
size_t strlen(const char *str);
unsigned int alarm(unsigned int seconds);
unsigned int sleep(unsigned int seconds);
void perror(const char *s);
void __myrt();

#endif