#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o

echo '[+] Dumping shellcode ...'
echo -ne "\"" 
i=0
for s in `objdump -d $1 | grep "^ " | cut -f2`
do 
     echo -n '\x'$s
     ((i=i+1))
done
echo "\""
echo "$i bytes"
echo '[+] Done!'



