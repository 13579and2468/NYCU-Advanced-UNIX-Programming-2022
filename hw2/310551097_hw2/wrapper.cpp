#include "wrapper.h"

void *get_old_func(const char *funcname)
{
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    void *return_function = dlsym(handle, funcname);
    if (return_function == NULL)
    {
        dprintf(OUTFILE_FD, "cannot get old_func\n");
        exit(0);
    }
    return return_function;
}

int get_out_file_fd(){

    if (outfile_fd_isopen)
    {
        return outfile_fd;
    }

    if (!old_open)
        old_open = (int (*)(const char *pathname, int flags, ...))get_old_func("open");

    if (getenv("OUTPUT_FILE"))
    {
        outfile_fd = old_open(getenv("OUTPUT_FILE"), O_WRONLY | O_CREAT | O_TRUNC, 00777);
    }else{
        outfile_fd = dup(STDERR_FILENO);
    }
    outfile_fd_isopen = true;
    return outfile_fd;
}

using namespace std;

// three mode <"path","mode","fd"> (others is automatic)
template <typename T>
string arg2str(T argv, string mode=""){
    //std::string type_name = typeid(argv).name();
    //cerr << ":"<<type_name << ":";
    if (is_same<T, const char *>::value || is_same<T, char *>::value || is_same<T, void *>::value || is_same<T, const void *>::value)
    {

        if (mode=="path")
        {
            char *rpath = realpath((char*)argv,NULL);
            if(rpath!=NULL)
            {
                string r = string(rpath);
                free(rpath);
                return "\""+r+"\"";
            }
        }
        //regular character buffer
        string r = string((char *)argv).substr(0, 32);
        for(auto& c : r)
        {
            if(!isprint(c))c = '.';
        }
        return "\"" + r + "\"";
    }
    else if (is_same<T, unsigned int>::value || is_same<T, unsigned long>::value)
    {
        stringstream ss;
        if (mode == "mode")
        {
            ss << setw(3) << setfill('0') << oct << argv;
        }else{
            ss << argv;
        }
        return ss.str();
    }
    else if (is_same<T, int>::value)
    {
        if(mode=="fd")
        {
            string pathname = "/proc/" + to_string(getpid()) + "/fd/" + to_string((unsigned long)argv);
            char target_path[PATH_MAX] = {};
            if (readlink(pathname.c_str(), target_path, sizeof(target_path)) == -1)
            {
                // cannot get filepath from fd
                stringstream ss;
                ss << argv;
                return ss.str();
            }
            string s = string(target_path);
            return "\""+s+"\"";
        }
        else 
        {
            stringstream ss;
            if (mode == "mode")
            {
                ss << setw(3) << setfill('0') << oct << argv;
            }
            else
            {
                ss << argv;
            }
            return ss.str();
        }
    }
    else if (is_same<T, FILE*>::value)
    {
        FILE *stream = (FILE*)argv;
        int fd = fileno(stream);

        // cannot get fd (return pointer address)
        if(fd == -1)
        {
            char r[20];
            sprintf(r,"%p", (void*)argv);
            return string(r);
        }

        string pathname = "/proc/" + to_string(getpid()) + "/fd/" + to_string(fd);
        char target_path[PATH_MAX] = {};
        if (readlink(pathname.c_str(), target_path, sizeof(target_path)) == -1)
        {
            stringstream ss;
            ss << argv;
            return ss.str();
        }
        string s = string(target_path);
        return "\""+s+"\"";
    }

    return "????";
}

int chmod(const char *path, mode_t mode)
{
    if (!old_chmod)
        old_chmod = (int (*)(const char *, mode_t))get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s(%s, %s) = ", __func__, arg2str(path, "path").c_str(), arg2str(mode, "mode").c_str());
    int r = old_chmod(path, mode);
    dprintf(OUTFILE_FD, "%d\n", r);
    
    return r;
}

int close(int fd){
    if (!old_close)
        old_close = (int (*)(int))get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s(%s) = ", __func__, arg2str(fd,"fd").c_str());
    int r = old_close(fd);
    dprintf(OUTFILE_FD, "%d\n", r);
    
    return r;
}

int chown(const char *path, uid_t owner, gid_t group){
    if (!old_chown)
        old_chown = (int (*)(const char *, uid_t, gid_t))get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s(%s, %s, %s) = ", __func__, arg2str(path,"path").c_str(), arg2str(owner).c_str(), arg2str(group).c_str());
    int r = old_chown(path, owner, group);
    dprintf(OUTFILE_FD, "%d\n", r);
    
    return r;
}

int creat(const char *pathname, mode_t mode){
    if (!old_creat)
        old_creat = (int (*)(const char *pathname, mode_t mode))get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s(%s, %s) = ", __func__, arg2str(pathname, "path").c_str(), arg2str(mode, "mode").c_str());
    int r = old_creat(pathname, mode);
    dprintf(OUTFILE_FD, "%d\n", r);
    
    return r;
}

int fclose(FILE *stream){
    if (!old_fclose)
        old_fclose = (int (*)(FILE *)) get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s(%s) = ", __func__, arg2str(stream).c_str());
    int r = old_fclose(stream);
    dprintf(OUTFILE_FD, "%d\n", r);
    
    return r;
}

FILE *fopen(const char *pathname, const char *mode){
    if (!old_fopen)
        old_fopen = (FILE * (*)(const char *pathname, const char *mode)) get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s(%s, %s) = ", __func__, arg2str(pathname, "path").c_str(), arg2str(mode, "mode").c_str());
    FILE *r = old_fopen(pathname, mode);
    dprintf(OUTFILE_FD, "%p\n", r);
    
    return r;
}

FILE *fopen64(const char *pathname, const char *mode)
{
    if (!old_fopen64)
        old_fopen64 = (FILE * (*)(const char *pathname, const char *mode)) get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s(%s, %s) = ", __func__, arg2str(pathname, "path").c_str(), arg2str(mode, "mode").c_str());
    FILE *r = old_fopen64(pathname, mode);
    dprintf(OUTFILE_FD, "%p\n", r);

    return r;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream){
    if (!old_fread)
        old_fread = (size_t (*)(void *ptr, size_t size, size_t nmemb, FILE *stream))get_old_func(__func__);

    size_t r = old_fread(ptr, size, nmemb, stream);
    dprintf(OUTFILE_FD, "[logger] %s(%s, %s, %s, %s) = ", __func__, arg2str(ptr).c_str(), arg2str(size).c_str(), arg2str(nmemb).c_str(), arg2str(stream).c_str());
    dprintf(OUTFILE_FD, "%ld\n", r);
    
    return r;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream){
    if (!old_fwrite)
        old_fwrite = (size_t (*)(const void *ptr, size_t size, size_t nmemb, FILE *stream))get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s(%s, %s, %s, %s) = ", __func__, arg2str(ptr).c_str(), arg2str(size).c_str(), arg2str(nmemb).c_str(), arg2str(stream).c_str());
    size_t r = old_fwrite(ptr, size, nmemb, stream);
    dprintf(OUTFILE_FD, "%ld\n", r);
    
    return r;
}

int open(const char *pathname, int flags, ...){
    if (!old_open)
        old_open = (int (*)(const char *pathname, int flags, ...))get_old_func(__func__);

    int mode = 0;
    if (__OPEN_NEEDS_MODE(flags))
    {
        __builtin_va_list arg;
        __builtin_va_start(arg, flags);
        mode = __builtin_va_arg(arg, int);
        __builtin_va_end(arg);
    }

    dprintf(OUTFILE_FD, "[logger] %s(%s, %s, %s) = ", __func__, arg2str(pathname, "path").c_str(), arg2str(flags, "mode").c_str(), arg2str(mode,"mode").c_str());
    int r = old_open(pathname, flags, mode);
    dprintf(OUTFILE_FD, "%d\n", r);
    
    return r;
}

int open64(const char *pathname, int flags, ...)
{
    if (!old_open64)
        old_open64 = (int (*)(const char *pathname, int flags, ...))get_old_func(__func__);

    int mode = 0;
    if (__OPEN_NEEDS_MODE(flags))
    {
        __builtin_va_list arg;
        __builtin_va_start(arg, flags);
        mode = __builtin_va_arg(arg, int);
        __builtin_va_end(arg);
    }

    dprintf(OUTFILE_FD, "[logger] %s(%s, %s, %s) = ", __func__, arg2str(pathname, "path").c_str(), arg2str(flags, "mode").c_str(), arg2str(mode, "mode").c_str());
    int r = old_open64(pathname, flags, mode);
    dprintf(OUTFILE_FD, "%d\n", r);

    return r;
}

ssize_t read(int fd, void *buf, size_t count){
    if (!old_read)
        old_read = (ssize_t (*)(int fd, void *buf, size_t count))get_old_func(__func__);

    ssize_t r = old_read(fd, buf, count);
    dprintf(OUTFILE_FD, "[logger] %s(%s, %s, %s) = ", __func__, arg2str(fd, "fd").c_str(), arg2str(buf).c_str(), arg2str(count).c_str());
    dprintf(OUTFILE_FD, "%ld\n", r);
    
    return r;
}

int remove(const char *pathname){
    if (!old_remove)
        old_remove = (int (*)(const char *pathname))get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s(%s) = ", __func__, arg2str(pathname, "path").c_str());
    int r = old_remove(pathname);
    dprintf(OUTFILE_FD, "%d\n", r);
    
    return r;
}

int rename(const char *old_filename, const char *new_filename){
    if (!old_rename)
        old_rename = (int (*)(const char *old_filename, const char *new_filename))get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s(%s, %s) = ", __func__, arg2str(old_filename, "path").c_str(), arg2str(new_filename, "path").c_str());
    int r = old_rename(old_filename, new_filename);
    dprintf(OUTFILE_FD, "%d\n", r);
    
    return r;
}

FILE *tmpfile(void){
    if (!old_tmpfile)
        old_tmpfile = (FILE* (*)())get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s() = ", __func__);
    FILE* r = old_tmpfile();
    dprintf(OUTFILE_FD, "%p\n", r);
    
    return r;
}

ssize_t write(int fd, const void *buf, size_t count){
    if (!old_write)
        old_write = (ssize_t (*)(int fd, const void *buf, size_t count)) get_old_func(__func__);

    dprintf(OUTFILE_FD, "[logger] %s(%s, %s, %s) = ", __func__, arg2str(fd, "fd").c_str(), arg2str(buf).c_str(), arg2str(count).c_str());
    ssize_t r = old_write(fd, buf, count);
    dprintf(OUTFILE_FD, "%ld\n", r);
    
    return r;
}