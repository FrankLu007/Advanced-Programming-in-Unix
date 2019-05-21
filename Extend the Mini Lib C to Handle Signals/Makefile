all:
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC libmini64.asm -o libmini64.o
	gcc -c -g -Wall -fno-stack-protector -fPIC -nostdlib libmini.c
	ld -shared -o libmini.so libmini64.o libmini.o
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC start.asm -o start.o
target:
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI testcase/$(file).c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o $(file) $(file).o start.o -L. -L.. -lmini
	rm $(file).o