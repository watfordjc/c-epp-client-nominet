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
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
	{
		error("setsockopt");
	}

	if (bind(sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
	{
		error("bind");
	}

	listen(sock_fd, 5);

	client_addr_len = sizeof(client_addr);

	while (1)
	{
		struct timeval timeout_recv;
		timeout_recv.tv_sec = 5;
		timeout_recv.tv_usec = 0;
		struct timeval timeout_send;
		timeout_send.tv_sec = 90;
		timeout_send.tv_usec = 0;

		newsock_fd = accept(sock_fd, (struct sockaddr *) &client_addr, &client_addr_len);
		if (newsock_fd < 0)
		{
			error("accept");
		}
		if (setsockopt(newsock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout_recv, sizeof(timeout_recv)) < 0)
		{
			error("setsockopt");
		}
		if (setsockopt(newsock_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout_send, sizeof(timeout_send)) < 0)
		{
			error("setsockopt");
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
	uint32_t buffer_size = 256;
	uint32_t header_size = 4;

	uint32_t buffer_size_chars = buffer_size - 1;

	uint32_t msg_data_length, position, remaining_chars = 0;
	char buffer[buffer_size], temp[buffer_size];
	int n = 0;

	union {
		uint32_t whole;
		char bytes[header_size];
	} msg_length;

	bzero((char *) buffer, buffer_size);
	n = read(sock, buffer, buffer_size_chars);
	if (errno == EAGAIN)
	{
		exit(0);
	}
	if (n < 0)
	{
		error("first read");
	}
	memcpy(msg_length.bytes, buffer, header_size);
	msg_length.whole = ntohl(msg_length.whole);
	msg_data_length = msg_length.whole - header_size;

//	printf("Message octets: %d %d %d %d\n", msg_length.bytes[0], msg_length.bytes[1], msg_length.bytes[2], msg_length.bytes[3]);
//	printf("Message length: %u\n", msg_length.whole);
//	printf("Message data length: %u\n", msg_data_length);

	bzero((char *) temp, buffer_size);
	memcpy(temp, buffer + header_size, buffer_size - header_size);
//	printf("Message: ");

	/*
	Make msg_data large enough to hold the entire message.
	While we aren't currently storing the entire message in the array, it is there for when we do.
	*/
	char msg_data[msg_data_length - header_size + 1]; // With NUL.
	bzero((char *) msg_data, msg_data_length - header_size + 1);
	/*
	If "msg_data_length" is less than "buffer size chars (buffer size minus 1) plus header_size", then the buffer contains the entire data message.
	*/
	if (msg_data_length < buffer_size_chars - header_size)
	{
		memcpy(msg_data, temp, msg_data_length - header_size);
	}
	/* Otherwise, it only contains the start of the message. */
	else
	{
		memcpy(msg_data, temp, buffer_size_chars - header_size);
		//strcat(msg_data, temp);
	}

	/*
	If the message contains a NUL character printf is not suitable here or in the while loop.
	*/
	printf("%s", msg_data);

	/* Position is how many bytes we have parsed. */
	position = buffer_size_chars - header_size;
	/*
	Keep parsing until position equals the size indicated in the header.
	*/
	while (position < msg_data_length)
	{
		remaining_chars = msg_data_length - position;
		bzero((char *) buffer, buffer_size);
		if (remaining_chars > buffer_size_chars)
		{
			n = read(sock, buffer, buffer_size_chars);
		}
		else if (remaining_chars > 0)
		{
			n = read(sock, buffer, remaining_chars);
		}
		if (errno == EAGAIN)
		{
			/* Connection closed due to read timeout. */
			fprintf(stderr, "Error: Timeout while waiting for rest of data.\n");
			printf("--------------------------------------------------------------------------------\n");
			exit(1);
		}
		if (n < 0)
		{
			error("subsequent read");
		}
		printf("%s", buffer);
		position = position + n;
	}

	printf("\n--------------------------------------------------------------------------------\n");

	char ack_msg[] = "Message received.\n";

	n = write(sock, ack_msg, sizeof(ack_msg));
	if (n < 0)
	{
		error("write");
	}
}
