/* Standard Libraries */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
/* Socket Libraries */
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

void established_connection(int);

void error(char *msg)
{
	perror(msg);
	exit(1);
}

/* main() is server management. Established connections are not handled here. */
int main(int argc, char *argv[])
{
	char *BIND_PORT = "9999";
	char *BIND_IP = "::1";

	int sock_fd, newsock_fd, port_number, pid;
	socklen_t client_addr_len;
	struct sockaddr_in6 server_addr, client_addr;

	port_number = atoi(BIND_PORT);

	sock_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock_fd < 0)
	{
		error("socket");
	}

	bzero((char *) &server_addr, sizeof(server_addr));
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_port = htons(port_number);
	inet_pton(AF_INET6, BIND_IP, &server_addr.sin6_addr);

	int optval = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	if (bind(sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
	{
		error("bind");
	}

	listen(sock_fd, 5);

	client_addr_len = sizeof(client_addr);

	while (1)
	{
		newsock_fd = accept(sock_fd, (struct sockaddr *) &client_addr, &client_addr_len);
		if (newsock_fd < 0)
		{
			error("accept");
		}
		pid = fork();
		if (pid < 0)
		{
			error("pid");
		}
		if (pid == 0)
		{
			close(sock_fd);
			established_connection(newsock_fd);
			exit(0);
		}
		else {
			close(newsock_fd);
		}
	}
	close(sock_fd);
	return 0;

}

/* After a connection is successfully established, processing is no longer in main().
 * Instead, all processing within a client connection is handled within established_connection(). */
void established_connection(int sock)
{
	int n;
	char buffer[256];

	bzero(buffer, 256);
	n = read(sock, buffer, 255);
	if (n < 0)
	{
		error("read");
	}
	printf("Message: %s", buffer);

	char ack_msg[] = "Message received.\n";

	n = write(sock, ack_msg, sizeof(ack_msg));
	if (n < 0)
	{
		error("write");
	}
}
