#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <set>
#include <regex>

void dump_pid_info(int pid);
bool outputfilter(const char* cmd,const char* type,const char* filename);
#define FORMAT "%-30s %10d %10s %10s %10s %10d %-30s\n"

using namespace std;

bool cmd_flag = false;
char* cmd_arg;
bool type_flag = false;
char* type_arg;
bool filename_flag = false;
char* filename_arg;

int main(int argc, char *argv[])
{
    if(argc > 1){
        int opt;
        while((opt = getopt(argc, argv, "c:t:f:")) != -1){
            switch(opt) {
                case 'c':
                    cmd_flag = true;
                    cmd_arg = (char*)malloc(strlen(optarg)+1);
                    strcpy(cmd_arg, optarg);
                    break;
                case 't':
                    if(!strcmp(optarg, "REG") || !strcmp(optarg, "CHR") || 
                       !strcmp(optarg, "DIR") || !strcmp(optarg, "FIFO") ||
                       !strcmp(optarg, "SOCK") || !strcmp(optarg, "unknown"))
                    {
                        type_flag = true;
                        type_arg = (char*)malloc(strlen(optarg)+1);
                        strcpy(type_arg, optarg);

                    }else{
                        printf("Invalid TYPE option.\n");
                        return 1;
                    }
                    break;
                case 'f':
                    filename_flag = true;
                    filename_arg = (char*)malloc(strlen(optarg)+1);
                    strcpy(filename_arg, optarg);
                    break;
            }
        }
    }

    DIR *dp;
    struct dirent *dirp;
    dp = opendir("/proc");
    if(dp == NULL)return -1;
    
    printf("%-30s %10s %10s %10s %10s %10s %-30s\n","COMMAND","PID","USER","FD","TYPE","NODE","NAME");

    while ((dirp = readdir(dp)) != NULL)
    {
        int pid;
        if((pid = atoi(dirp->d_name))) //is pid and not self
        {
            dump_pid_info(pid);
        }
    }
    
    closedir(dp);
    return 0;
}

string get_command(int pid){
    ifstream commandfile("/proc/"+to_string(pid)+"/comm");
    stringstream commandline_ss;
    commandline_ss << commandfile.rdbuf();
    string command = commandline_ss.str();
    command = command.substr(0,command.length()-1);
    return command;
}

char* get_user(int pid){
    struct stat stat_buf;
    stat(("/proc/"+to_string(pid)).c_str(),&stat_buf);
    struct passwd *pws;
    pws = getpwuid(stat_buf.st_uid);
    return pws->pw_name;
}

string get_type(string filepath){
    struct stat stat_buf;
    if(stat(filepath.c_str(),&stat_buf)==-1)return "unknown";

    switch (stat_buf.st_mode & S_IFMT) {
        //case S_IFBLK:  return "block device" ;   
        case S_IFCHR:  return "CHR";
        case S_IFDIR:  return "DIR";      
        case S_IFIFO:  return "FIFO";      
        //case S_IFLNK:  return "symlink");        
        case S_IFREG:  return "REG";   
        case S_IFSOCK: return "SOCK";         
        default:       return "unknown";       
    }
}

unsigned int get_node(string path){
    struct stat stat_buf;
    stat(path.c_str(),&stat_buf);
    return stat_buf.st_ino;
}

void show_proc_file(int pid,string filename,string fd)
{
    /* For cwd*/
    string fd_name = ("/proc/"+to_string(pid)+"/"+filename).c_str();

    //permission deny
    if(access(fd_name.c_str(), R_OK)==-1){
        if(outputfilter(get_command(pid).c_str(),get_type(fd_name).c_str(),fd_name.c_str()))
        {
            printf("%-30s %10d %10s %10s %10s %10s %-30s",get_command(pid).c_str(),pid,get_user(pid),fd.c_str(),get_type(fd_name).c_str(),"",fd_name.c_str());
            cout<<" (Permission denied)"<<endl;
        }
    }else{
        char target_path[PATH_MAX] = {};
        if(readlink(fd_name.c_str(), target_path, sizeof(target_path))==-1)return;
        if(outputfilter(get_command(pid).c_str(),get_type(fd_name).c_str(),target_path))
        {
            printf(FORMAT,get_command(pid).c_str(),pid,get_user(pid),fd.c_str(),get_type(fd_name).c_str(),get_node(fd_name),target_path);
        }
    }
}

string trim(string s){
    string rs="";
    int start=1;
    int end=0;
    
    for(int i=0;i<(int)s.length();i++)
    {
        if(!isspace(s[i]))
        {
            start = i;
            break;
        }
    }


    for(int i=(int)s.length()-1;i>=0;i--)
    {
        if(!isspace(s[i]))
        {
            end = i;
            break;
        }
    }

    for(int i =start;i<=end;i++)rs+=s[i];

    return rs;
}

void parse_and_show_maps(int pid){
    ifstream fin("/proc/"+to_string(pid)+"/maps");
    
    string skip;
    set<int> usedset;
    usedset.insert(get_node("/proc/"+to_string(pid)+"/exe"));
    int node_n;
    while(fin>>skip>>skip>>skip>>skip>>node_n)
    {
        string region_name;
        getline(fin,region_name);
        region_name = trim(region_name);
        string pathname="";
        if(region_name.length()>0&&region_name[0]=='/')
        {
            pathname = region_name;
            int DEL = 0;
            if(region_name.find("(deleted)")!=(unsigned long)-1){
                DEL = 1;
                pathname = region_name.substr(0,region_name.length()-10);
            }else{
                pathname = region_name;
            }
            if(usedset.count(node_n)==0)
            {
                usedset.insert(node_n);
                string type = DEL==0?"mem":"DEL";
                if(outputfilter(get_command(pid).c_str(),get_type(pathname).c_str(),pathname.c_str()))
                {
                    printf(FORMAT,get_command(pid).c_str(),pid,get_user(pid),type.c_str(),get_type(pathname).c_str(),node_n,pathname.c_str());
                }
            }
        }

    }
}

string porcfd_append_urw(int pid,string fd){
    struct stat s;
    if(lstat(("/proc/"+to_string(pid)+"/fd/"+fd).c_str(), &s) == -1)return fd;

    if((s.st_mode & S_IREAD) && (s.st_mode & S_IWRITE))return fd+"u";
    if(s.st_mode & S_IREAD)return fd+"r";
    if(s.st_mode & S_IWRITE)return fd+"w";

    return fd;
}

void show_fd(int pid){
    DIR *dp;
    struct dirent *dirp;
    dp = opendir(("/proc/"+to_string(pid)+"/fd").c_str());
    if(dp == NULL)return;

    while ((dirp = readdir(dp)) != NULL)
    {
        if(atoi(dirp->d_name) || strcmp(dirp->d_name,"0")==0) //is fd
        {
            string pathname = "/proc/"+to_string(pid)+"/fd/"+dirp->d_name;
            char target_path[PATH_MAX] = {};
            if(readlink(pathname.c_str(), target_path, sizeof(target_path))==-1)return;

            //trim (deleted)
            
            string s = string(target_path);
            if(s.find("(deleted)")!=(unsigned long)-1)
            {
                s = s.substr(0,s.length()-10);
                strcpy(target_path,s.c_str());
            }

            if(outputfilter(get_command(pid).c_str(),get_type(pathname).c_str(),target_path))
            {
                printf(FORMAT,get_command(pid).c_str(),pid,get_user(pid),porcfd_append_urw(pid,string(dirp->d_name)).c_str(),get_type(pathname).c_str(),get_node(pathname),target_path);
            }
        }
    }
    
    closedir(dp);
}

bool outputfilter(const char* cmd,const char* type,const char* filename){

    bool r = true;

    if(cmd_flag)
    {
        regex reg(cmd_arg);
        string temp = string(cmd);
        if(!regex_search(temp, reg))r = false;
    }

    if(type_flag)
    {
        if(strcmp(type_arg,type)!=0)r = false;
    }

    if(filename_flag)
    {
        regex reg(filename_arg);
        string temp = string(filename);
        if(!regex_search(temp, reg))r = false;
    }

    return r;
}

void dump_pid_info(int pid){
    
    show_proc_file(pid,"cwd","cwd");
    show_proc_file(pid,"root","rtd");
    show_proc_file(pid,"exe","txt");

    string fd = "fd"; 
    string fd_name = ("/proc/"+to_string(pid)+"/"+fd).c_str();

    // parse proc/{pid}/maps
    parse_and_show_maps(pid);

    //proc/{pid}/fd permission deny
    if(access(fd_name.c_str(), R_OK)==-1)
    {
        if(outputfilter(get_command(pid).c_str(),"",fd_name.c_str()))
        {
            printf("%-30s %10d %10s %10s %10s %10s %-30s",get_command(pid).c_str(),pid,get_user(pid),"NOFD","","",fd_name.c_str());
            cout<<" (Permission denied)"<<endl;
        }
    }else{
        show_fd(pid);
    }

}