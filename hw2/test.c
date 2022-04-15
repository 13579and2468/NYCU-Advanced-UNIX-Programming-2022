#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

struct employee
{
    char name[50];
    char designation[50];
    int age;
    float salary;
} emp;

int main()
{
    //chmod("dddd", 0b111111);
    close(15);
    chown("dfasdfas", 66666, 66666);

    char buffer[20]; // Buffer to store data
    FILE *stream;
    stream = fopen("includehelp.txt", "r");
    int j = open("includehelp.txt",O_RDWR);
    int count = fread(&buffer, sizeof(char), 20, stream);
    fclose(stream);
    // Printing data to check validity
    printf("Data read from file: %s \n", buffer);
    printf("Elements read: %d", count);

    FILE *fp;
    char str[] = "This is tutorialspoint.com";

    fp = fopen("includehelp.txt", "w");
    fwrite(str, 1, sizeof(str), fp);

    fclose(fp);

    dup(2);
    dprintf(2, "66666666");
    dprintf(3, "123123123");
    close(5);
    close(5);
    //fclose(fp);
    return 0;
}