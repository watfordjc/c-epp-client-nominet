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
/* XML Libraries */
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlmemory.h>
/* Time and Date */
#include <time.h>

void established_connection(int sock, xmlSchemaValidCtxtPtr pSchemaCtxt);
void xml_parse(char *msg_data, uint32_t file_size, xmlSchemaValidCtxtPtr pSchemaCtxt);
void GetclTRID(char *TAG, char *client, char *priority, char *registrantID, char *clTRID);

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

	xmlDocPtr pSchemaDoc;
	xmlSchemaParserCtxtPtr pParser;
	xmlSchemaPtr pSchema;
	xmlSchemaValidCtxtPtr pSchemaCtxt;

	LIBXML_TEST_VERSION;
	xmlInitMemory();

	char *xsdFile = "/home/thejc/Scripts/epp/nom-std-1.0.9-schemas/nom-root-std-1.0.9.xsd";
	pSchemaDoc = xmlReadFile(xsdFile, NULL, XML_PARSE_NONET);
	pParser = xmlSchemaNewDocParserCtxt(pSchemaDoc);
	pSchema = xmlSchemaParse(pParser);
	pSchemaCtxt = xmlSchemaNewValidCtxt(pSchema);

	xmlSchemaSetValidErrors(pSchemaCtxt, NULL, NULL, NULL);

	while (1)
	{
		struct timeval timeout_recv;
		timeout_recv.tv_sec = 300; // 5
		timeout_recv.tv_usec = 0;
		struct timeval timeout_send;
		timeout_send.tv_sec = 90; // 90
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
			established_connection(newsock_fd, pSchemaCtxt);
			exit(0);
		}
		else {
			close(newsock_fd);
		}
	}
	close(sock_fd);

	xmlFreeDoc(pSchemaDoc);
	xmlSchemaFreeValidCtxt(pSchemaCtxt);
	xmlSchemaCleanupTypes();
	xmlCleanupParser();
	xmlMemoryDump();

	return 0;

}

/* After a connection is successfully established, processing is no longer in main().
 * Instead, all processing within a client connection is handled within established_connection(). */
void established_connection(int sock, xmlSchemaValidCtxtPtr pSchemaCtxt)
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
	if (msg_length.whole < header_size) {
		fprintf(stderr,"Error: Data length less than header size.\n");
		printf("--------------------------------------------------------------------------------\n");
		exit(1);
	}
	msg_data_length = msg_length.whole - header_size;

	bzero((char *) temp, buffer_size);
	memcpy(temp, buffer + header_size, buffer_size - header_size);

	/*
	Make msg_data large enough to hold the entire message.
	*/
	char msg_data[msg_data_length - header_size + 1]; // With NUL.
	memset(msg_data, 0, sizeof(msg_data));

	int read_chars;
	/*
	If "msg_data_length" is less than "buffer size chars (buffer size minus 1) minus header_size", then the buffer contains the entire data message.
	*/
	if (msg_data_length < buffer_size_chars - header_size)
	{
		read_chars = msg_data_length - header_size;
	}
	/* Otherwise, it only contains the start of the message. */
	else
	{
		read_chars = buffer_size_chars - header_size;
	}
	memcpy(msg_data, temp, read_chars);

	/* Position is how many bytes we have parsed. */
	position = buffer_size_chars - header_size;
	/*
	Keep parsing until position equals the size indicated in the header.
	*/
	while (position < msg_data_length)
	{
		remaining_chars = msg_data_length - position;
		int read_chars;
		bzero((char *) buffer, buffer_size);

		if (remaining_chars > buffer_size_chars)
		{
			read_chars = buffer_size_chars;
		}
		else if (remaining_chars > 0)
		{
			read_chars = remaining_chars;
		}

		n = read(sock, buffer, read_chars);

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
		if (n == 0)
		{
			error("Possible infinite loop");
		}
		memcpy(msg_data + position, buffer, read_chars);
		position = position + n;
		char *end_of_root = NULL;
		end_of_root = strstr(msg_data, "</epp>");
		if (end_of_root != NULL)
		{
			msg_data_length = end_of_root + 6 - msg_data;
			break;
		}
	}

	char *msgPtr;
	msgPtr = msg_data;
	xml_parse(msgPtr, msg_data_length, pSchemaCtxt);

	printf("\n--------------------------------------------------------------------------------\n");

	char ack_msg[] = "Message received.\n";

	n = write(sock, ack_msg, sizeof(ack_msg));
	if (n < 0)
	{
		error("write");
	}

}

void xml_parse(char *msg_data, uint32_t file_size, xmlSchemaValidCtxtPtr pSchemaCtxt)
{
	char *log_directory = "/home/thejc/Scripts/epp/logs/";
	char *log_file = log_directory;
	/*
	If the message contains a NUL character printf is not suitable here.
	*/
	//printf("%s\n", msg_data);

	xmlKeepBlanksDefault(0);
	xmlDocPtr doc = NULL;
	doc = xmlReadMemory(msg_data, file_size, "noname.xml", NULL, 0);
	if (doc == NULL)
	{
		error("xmlReadMemory");
	}

	int invalid;
	invalid = xmlSchemaValidateDoc(pSchemaCtxt, doc);

	if (invalid)
	{
		error("xmlSchemaValidateDoc");
	}


	char clTRID[64] = "";
	bzero((char *) clTRID, 65);

	char *TAG = "JOHNCOOK";
	char client[3] = "00";
	char priority[2] = "0";

	char *registrantID = "123456";

	GetclTRID(TAG, client, priority, registrantID, clTRID);

	if (clTRID != "")
	{
		xmlNodePtr root_node = NULL;
		xmlNodePtr command_node = NULL;
		xmlNodePtr clTRID_node = NULL;
		xmlNodePtr nodeLevel1 = NULL;
		xmlNodePtr nodeLevel2 = NULL;
		xmlNodePtr nodeLevel3 = NULL;
		xmlNsPtr ns = NULL;

		for(nodeLevel1 = doc->children; nodeLevel1 != NULL; nodeLevel1 = nodeLevel1->next)
		{
			root_node = nodeLevel1;
			xmlDocSetRootElement(doc, root_node);
			ns = xmlSearchNs(doc, root_node, NULL);

			for(nodeLevel2 = nodeLevel1->children; nodeLevel2 != NULL; nodeLevel2 = nodeLevel2->next)
			{
				if (strcmp((char *) nodeLevel2->name,"command") == 0)
				{
					command_node = nodeLevel2;
					for(nodeLevel3 = nodeLevel2->children; nodeLevel3 != NULL; nodeLevel3 = nodeLevel3->next)
					{
						if (strcmp((char *) nodeLevel3->name,"clTRID") == 0)
						{
							clTRID_node = nodeLevel3;
						}
					}
				}
			}
		}
		if (command_node != NULL && clTRID_node == NULL)
		{
			xmlNewChild(command_node, ns, "clTRID", (xmlChar *) clTRID);
		}
		else if (command_node != NULL && clTRID_node != NULL)
		{
			xmlNodeSetContent(clTRID_node,(xmlChar *) clTRID);
		}

		invalid = xmlSchemaValidateDoc(pSchemaCtxt, doc);

		if (invalid)
		{
			error("xmlSchemaValidateDoc");
		}

		char logfile_req[strlen(log_file) + strlen(clTRID) + strlen(".req") + 1];
		memset(logfile_req, 0, sizeof(logfile_req));
		memcpy(logfile_req, log_file, strlen(log_file));
		memcpy(logfile_req + strlen(logfile_req), clTRID, strlen(clTRID));
		memcpy(logfile_req + strlen(logfile_req), ".req\0", 5);

		xmlDocFormatDump(stdout,doc,1);

		int savedBytes = xmlSaveFormatFileEnc(logfile_req, doc, "utf-8", 1);
		if (savedBytes < 0)
		{
			fprintf(stderr, "Unable to save file %s.\n",logfile_req);
		}

	}

	xmlFreeDoc(doc);
}

void GetclTRID(char *TAG, char *client, char *priority, char *registrantID, char *clTRID)
{
	struct timespec unixTime;
	clock_gettime(CLOCK_REALTIME, &unixTime);

	time_t epochSecs;
	epochSecs = unixTime.tv_sec;

	struct tm *dateTime;
	dateTime = gmtime(&epochSecs);

	memcpy(clTRID, TAG, strlen(TAG));
	strftime(clTRID + strlen(clTRID), 18, "-%Y%m%dT%H%M%S.", dateTime);
	snprintf(clTRID + strlen(clTRID), 16, "%09ld%s%s%s%s%s", unixTime.tv_nsec, "-", client, "-", priority, "-");
	memcpy(clTRID + strlen(clTRID), registrantID, strlen(registrantID));
}
