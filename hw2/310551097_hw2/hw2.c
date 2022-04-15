#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    char ch;
    char output_file[PATH_MAX] = {};
    char so_path[PATH_MAX] = "./logger.so";

    if(argc == 1)
    {
        printf("no command given.\n\n");
        return 0;
    }

    while ((ch = getopt(argc, argv, "o:p:")) != -1)
    {
        switch (ch)
        {
        case 'o':
            strcpy(output_file, optarg);
            setenv("OUTPUT_FILE", output_file, 1);
            break;
        case 'p':
            strcpy(so_path, optarg);
            break;
        case '?':
            printf("usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]\n");
            printf("    -p: set the path to logger.so, default = ./logger.so\n");
            printf("    -o: print output to file, print to \"stderr\" if no file specified\n");
            printf("    --: separate the arguments for logger and for the command\n\n");
            return -1;
        }
    }

    char* argv_child[argc];
    int j = 0;
    int i;
    for (i = optind; i < argc; i++)
    {
        argv_child[j] = malloc(strlen(argv[i])+1);
        strcpy(argv_child[j++], argv[i]);
    }
    argv_child[j] = NULL;

    setenv("LD_PRELOAD", so_path, 1);
    execvp(argv_child[0], argv_child);
}