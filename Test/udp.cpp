#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

using namespace std;

void error( char *msg) {
	perror(msg);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
	if (argc < 3) {
		cerr << "Usage: " << argv[0] << " [Server IP] [Server Port]\n";
		exit(1);
	}

	int sockfd;
	sockfd = socket(AF_INET,SOCK_DGRAM,0);
	struct sockaddr_in serv,client;
 
	serv.sin_family = AF_INET;
	serv.sin_port = htons(atoi(argv[2]));
	serv.sin_addr.s_addr = inet_addr(argv[1]);

	char buffer[256];
	socklen_t l = sizeof(client);
	socklen_t m = sizeof(serv);
	cout << "pls enter the mssg to be sent\n";
	fgets(buffer,256,stdin);
	sendto(sockfd,buffer,sizeof(buffer),0,(struct sockaddr *)&serv,m);
	recvfrom(sockfd,buffer,256,0,(struct sockaddr *)&client,&l);
}
