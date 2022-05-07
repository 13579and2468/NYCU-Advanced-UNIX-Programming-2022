libmini.so: start.asm libmini.h libmini.c libmini64.asm
        yasm -f elf64 -DYASM -D__x86_64__ -DPIC libmini64.asm -o libmini64.o
        gcc -c -g -Wall -fno-stack-protector -fPIC -nostdlib libmini.c
        ld -shared -o libmini.so libmini64.o libmini.o
        yasm -f elf64 -DYASM -D__x86_64__ -DPIC start.asm -o start.o

write1: write1.c libmini.so
        gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI write1.c
        ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o write1 write1.o start.o -L. -L.. -lmini

alarm1: alarm1.c libmini.so
        gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm1.c
        ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm1 alarm1.o start.o -L. -L.. -lmini

alarm2: alarm2.c libmini.so
        gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm2.c
        ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm2 alarm2.o start.o -L. -L.. -lmini

alarm3: alarm3.c libmini.so
        gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm3.c
        ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm3 alarm3.o start.o -L. -L.. -lmini

jmp1: jmp1.c libmini.so
        gcc -o jmp1.o -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI jmp1.c
        ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o jmp1 jmp1.o start.o -L. -L.. -lmini

clean:
        rm -f *.s *.o *.so write1 alarm1 alarm2 alarm3 jmp1