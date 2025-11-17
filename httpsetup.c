#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <regex.h>

#define PORT 8080
#define BACKLOG 10
#define BUFFER_SIZE 1000000

int main(){
	
	int server_fd;
	struct sockaddr_in server_addr;
	
	if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
		perror("SOCKET FAILED");
		exit(EXIT_FAILURE);
	}
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	
	if (bind(server_fd,(struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
		perror("BIND FAILED");
		exit(EXIT_FAILURE);
	}
	
	if(listen(server_fd, BACKLOG) < 0){
		perror("LISTEN FAILED")
		exit(EXIT_FAILURE);
	}
	
	while(1){
		//Client connections
		struct sockaddr_in client_addr;
		socklent_t client_addr_len = sizeof(client_addr);
		int *client_fd = malloc(sizeof(int));
		
		if((*client_fd = accept(server_fd,(struct sockaddr *)&client_addr_len)) < 0){
			perror("ACCEPT FAILED");
			continue;
		}
		
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, handle_client, (void *)client_fd);
		pthread_detach
		
	}
	
	return 0;
}

void* handle client(void *arg){
	int client_fd = *((int*)arg);
	char *buffer = (char *)malloc(BUFFER_SIZE * sizeof(char));
	
	ssize_t bytes_received =  recv(client_fd, buffer, BUFFER_SIZE, 0 );
	if (bytes_received > 0) {
		regex_t regex;
		regcomp( &regex,"GET /([^ ]*) HTTP/1", REG_EXTENDED);
		regmatch_t matches[2];
		
		if (regexec(&regex, buffer, 2, matches, 0)
		
	}
	
	
	
	
	
	
}