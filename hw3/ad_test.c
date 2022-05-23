#include "libmini.h"

static jmp_buf buf;

void e() {
    write(1, "e()\n", 4);
    longjmp(buf, 1);
}

void d() {
    e();
    write(1, "d()\n", 4);
}

void c() {
    d();
    write(1, "c()\n", 4);
}

void b() {
    c();
    write(1, "b()\n", 4);
}

void a() {
    b();
    write(1, "a()\n", 4);
}

int main() {
    if (!setjmp(buf)) {
        a();
    } else {
        write(1, "main()\n", 7);
    }
    return 0;
}