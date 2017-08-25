#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o

echo '[+] Generating shellcode file ...'
echo "#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

unsigned char shells[] =\
" > shellcode.c

echo -ne "\"" >>shellcode.c
echo -ne "\""
i=0
for s in `objdump -d $1 | grep "^ " | cut -f2`
do 
     echo -n '\x'$s >> shellcode.c
     echo -n '\x'$s 
     ((i=i+1))
done
echo "\""
echo "\"" >> shellcode.c
echo "; 

int main(){
		int (*ret)() = (int(*)())shells;
		ret();
}
" >> shellcode.c

echo '[+] Compiling shellcode file ...'
gcc -z execstack -o shellcode shellcode.c

echo '[+] Done!'
