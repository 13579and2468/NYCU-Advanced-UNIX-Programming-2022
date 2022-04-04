#ifndef WRAPPER_H
#define WRAPPER_H

#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <typeinfo>
#include <string>
#include <iostream>
#include <string.h>
#include <sstream>
#include <unistd.h>
#include <linux/limits.h>
#include <iomanip>   
#include <sys/stat.h>   
#include <fcntl.h>

int get_out_file_fd();

static int outfile_fd;
static int outfile_fd_isopen = 0;
#define OUTFILE_FD get_out_file_fd()

//cannot output after the process close(2)
//recover fd state
//#define CLOSE_OUTFILE_FD()                                \
//    if (!old_close)                                       \
//        old_close = (int (*)(int))get_old_func("close");  \
//    old_close(outfile_fd);                                \
//    outfile_fd_isopen = 0;

static int (*old_chmod)(const char *path, mode_t mode) = NULL;              /* function pointer */
static int (*old_chown)(const char *path, uid_t owner, gid_t group) = NULL; /* function pointer */
static int (*old_close)(int fd) = NULL;                        /* function pointer */
static int (*old_creat)(const char *pathname, mode_t mode) = NULL; /* function pointer */
static int (*old_fclose)(FILE *stream) = NULL;                     /* function pointer */
static FILE *(*old_fopen)(const char *pathname, const char *mode) = NULL; /* function pointer */
static size_t (*old_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL; /* function pointer */
static size_t (*old_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL; /* function pointer */
static int (*old_open)(const char *pathname, int flags, ...) = NULL;                  /* function pointer */
static ssize_t (*old_read)(int fd, void *buf, size_t count) = NULL;                           /* function pointer */
static int (*old_remove)(const char *pathname) = NULL;
static int (*old_rename)(const char *old_filename, const char *new_filename) = NULL;
static FILE *(*old_tmpfile)(void) = NULL;
static ssize_t (*old_write)(int fd, const void *buf, size_t count) = NULL;

extern "C"
{
    int chmod(const char *path, mode_t mode);
    int chown(const char *path, __uid_t owner, __gid_t group);
    int close(int fd);
    int creat(const char *pathname, mode_t mode);
    int fclose(FILE *stream);
    FILE *fopen(const char *pathname, const char *mode);
    size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
    size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
    int open(const char *pathname, int flags,...);
    ssize_t read(int fd, void *buf, size_t count);
    int remove(const char *pathname);
    int rename(const char *old_filename, const char *new_filename);
    FILE *tmpfile(void);
    ssize_t write(int fd, const void *buf, size_t count);
}

#endif