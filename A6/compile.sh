#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o

echo '[+] Dumping shellcode ...'
echo -ne "\"" 
count=0
for s in `objdump -d $1 | grep "^ " | cut -f2`
do 
  if [ $s == "00" ] 
  then
     echo "Shellcode contains a null byte! Aborting!"
     exit
  else
     ((count=count+1))
     echo -n '\x'$s
  fi
done
echo "\""
echo "[+] $count bytes"
echo ''
echo '[+] Done!'



