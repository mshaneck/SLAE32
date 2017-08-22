#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
	char shellcode[2048];// = (char *)malloc(2048);
	int payload_len = read(0, shellcode, 2048);
	if (payload_len <= 0){
		printf("Please enter some shellcode into STDIN.\n");
		exit(1);
	}
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}
