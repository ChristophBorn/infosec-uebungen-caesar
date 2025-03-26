// Server side implementation of UDP client-server model
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "udp.h"
#include "crypt.h"

#define PORT 8080

// Driver code
int main()
{
	// -------------------------------------------------
	// ------------------ SETUP BEGIN ------------------
	// -------------------------------------------------
	int sockfd;
	char buffer[MAXLINE];
	struct sockaddr_in servaddr, cliaddr;

	// Creating socket file descriptor
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));

	// Filling server information
	servaddr.sin_family = AF_INET; // IPv4
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(PORT);

	// Bind the socket with the server address
	if (bind(sockfd, (const struct sockaddr *)&servaddr,
			 sizeof(servaddr)) < 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	cliaddr.sin_family = AF_INET;
	cliaddr.sin_port = htons(PORT);
	inet_aton("192.168.56.102", &cliaddr.sin_addr);
	// -------------------------------------------------
	// ------------------ END SETUP --------------------
	// -------------------------------------------------

	char message[MAXLINE] = "Good Morning Bob!";
	printf("Plain:\n%s\n", message);
	encrypt_ceasar(message);
	udp_send(sockfd, (char *)message, (struct sockaddr *)&cliaddr);
	printf("Sent:\n%s\n", message);

	udp_receive(sockfd, (char *)buffer, (struct sockaddr *)&cliaddr);
	printf("Receive:\n%s\n", buffer);
	decrypt_ceasar(buffer);
	printf("Plain:\n%s\n", buffer);

	return 0;
}