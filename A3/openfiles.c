#include <fcntl.h>
#include <stdio.h>

// Just checking to see how many open file descriptors a process is allowed to have.

int main(){
	int i = 1;
	int fd=1;
	while(fd>0){
		fd = open("test.c",0);
		printf("%d ", fd);
	}
}
