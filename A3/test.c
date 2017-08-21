#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(){
	int zeroAddr = 0;
	int Aaddr=0x41414141;
	char badfilename[] = "nonexistentfile";
	char goodfilename[] = "test.c";
	char gooddir[] = "./";
	int fd = open((const char *)zeroAddr,0);
	printf("Return value for null pointer: %d (0x%x)\n", fd, fd);
	fd = open((const char *)Aaddr,0);
	printf("Return value for AAAA pointer: %d (0x%x)\n", fd, fd);
	fd = open(badfilename, 0);
	printf("Return value for bad filename: %d (0x%x)\n", fd, fd);
	fd = open(goodfilename, 0);
	printf("Return value for goofd filename: %d (0x%x)\n", fd, fd);
	
	printf("Now we will test chdir\n");
	fd = chdir((const char *)zeroAddr);
	printf("Ret val for null pointer: %d\n", fd);
	fd = chdir((const char *)Aaddr);
	printf("Ret val for AAAA pointer: %d\n", fd);
	fd = chdir(badfilename);
	printf("Ret val for bad filename: %d\n", fd);
	fd = chdir(gooddir);
	printf("Ret val for good directory: %d\n", fd);

}

