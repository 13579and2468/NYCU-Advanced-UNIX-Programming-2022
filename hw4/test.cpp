#include <signal.h>
#include <stdio.h>
#include <iostream>

using namespace std;

int main()
{
    cout << sizeof("abcd\x00");
    unsigned long gg;
    cin >> hex >> gg;
    cout << hex << gg;

    return 0;
}