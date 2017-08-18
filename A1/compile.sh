#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o

echo '[+] Dumping shellcode ...'
echo -ne "\"" 
for s in `objdump -d $1 | grep "^ " | cut -f2`
do 
  if [ $s == "00" ] 
  then
     echo "Shellcode contains a null byte! Aborting!"
     exit
  else
     echo -n '\x'$s
  fi
done
echo "\""

echo '[+] Done!'



