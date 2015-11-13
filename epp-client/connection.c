/* Standard Libraries */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
/* Socket Libraries */
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
/* GnuTLS */
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* Connection Variables:
	BIND_ADDR: Local IPv4 IP address formatted as IPv4-mapped-IPv6 (e.g. ::ffff:127.0.0.1).
	BIND_ADDR6: Local IPv6 IP address.
	EPP_HOSTNAME: string for EPP Server's IP address or hostname.
	EPP_TLS_PORT: string for EPP Server's TLS port.
	EPP_TLS_CAFILE: string for full path to EPP Server's Root CA file.
	EPP_TLS_CIPHERS: string for cipher list - enabled and disabled ciphers (GnuTLS format).
	MSG: string sent to server on successful connection.
	LOG_LEVEL: integer between 0 and 9 for setting GnuTLS log level.
	COMMENTS: build with -DCOMMENTS to enable more verbose commenting for debugging purposes.
*/
char *BIND_ADDR = "::ffff:82.26.77.204";
char *BIND_ADDR6 = "2001:470:1f09:1aab::80:d";
char *EPP_HOSTNAME = "webmail.thejc.me.uk";
char *EPP_TLS_PORT = "443";
char *EPP_TLS_CAFILE = "/etc/ssl/certs/StartCom_Certification_Authority.pem";
//#char * EPP_TLS_CAFILE = "/etc/ssl/certs/Verisign_Class_3_Public_Primary_Certification_Authority.pem";
const char LOG_LEVEL = 0;
char *EPP_TLS_CIPHERS = "PFS";
char *MSG = "GET / HTTP/1.1\r\nhost: webmail.thejc.me.uk\r\nUser-agent: EPP Client\r\n\r\n";

void error_exit(const char *msg);
ssize_t data_push(gnutls_transport_ptr_t, const void*, size_t);
ssize_t data_pull(gnutls_transport_ptr_t, void*, size_t);
void print_logs(int, const char*);
void print_audit_logs(gnutls_session_t, const char*);
int make_one_connection(const char *address, int port);
int hostname_to_ip(char *, char *);
int verify_cert(struct gnutls_session_int *);

int main(int argc, char **argv)
{
	int res;
	gnutls_certificate_credentials_t x509_cred;

	gnutls_global_init();

	gnutls_global_set_log_level(LOG_LEVEL);
	gnutls_global_set_log_function(print_logs);

	gnutls_session_t session;

	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_trust_file(x509_cred, EPP_TLS_CAFILE, GNUTLS_X509_FMT_PEM);

	res = gnutls_init(&session, GNUTLS_CLIENT);
	if (res != GNUTLS_E_SUCCESS)
	{
		fprintf(stderr, "Error code %d in gnutls_init(): %s\n",res,gnutls_strerror(res));
		exit(1);
	}

	gnutls_session_set_ptr(session, (void *) EPP_HOSTNAME);
	gnutls_server_name_set(session, GNUTLS_NAME_DNS, EPP_HOSTNAME, strlen(EPP_HOSTNAME));

	const char *error = NULL;
	res = gnutls_priority_set_direct(session, EPP_TLS_CIPHERS, &error);
	if (res != GNUTLS_E_SUCCESS)
	{
		fprintf(stderr, "Invalid Cipher: %s\n",error);
		fprintf(stderr, "Error code %d in gnutls_priority_set_direct(): %s\n",res,gnutls_strerror(res));
		exit(1);
	}

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);


	char *hostname = EPP_HOSTNAME;
	char ip[INET6_ADDRSTRLEN];
	hostname_to_ip(hostname, ip);
#ifdef COMMENTS
	printf("%s resolved to %s\n", hostname, ip);
#endif

	int connfd = make_one_connection(ip, atoi(EPP_TLS_PORT));

	int *connfdPtr = malloc(sizeof(int));
	*connfdPtr = connfd;
	gnutls_transport_set_ptr(session, connfdPtr);
	gnutls_transport_set_push_function(session, data_push);
	gnutls_transport_set_pull_function(session, data_pull);

	gnutls_certificate_set_verify_function(x509_cred, verify_cert);

	do {
		res = gnutls_handshake(session);
	} while (res != 0 && !gnutls_error_is_fatal(res));

	if (gnutls_error_is_fatal(res))
	{
		fprintf(stderr, "Error code %d in gnutls_handshake(): %s\n",res,gnutls_strerror(res));
		exit(1);
	}


#ifdef COMMENTS
	printf("∨∨∨---From Client---∨∨∨\n");
#endif
	printf("%s\n",MSG);
	gnutls_record_send(session, MSG, strlen(MSG));
#ifdef COMMENTS
	printf("∧∧∧---From Client---∧∧∧\n");

	printf("∨∨∨---From Server---∨∨∨\n");
#endif
	char buf[256];
	res = gnutls_record_recv(session, buf, sizeof(buf));
	while (res != 0)
	{
		if (res == GNUTLS_E_REHANDSHAKE)
		{
			fprintf(stderr, "Error code %d: %s\n",res,gnutls_strerror(res));
			error_exit("Peer wants to re-handshake but we don't support that.\n");
		}
		else if (gnutls_error_is_fatal(res))
		{
			fprintf(stderr, "Error code %d: %s\n",res,gnutls_strerror(res));
			error_exit("Fatal error during read.\n");
		}
		else if (res > 0)
		{
			fwrite(buf, 1, res, stdout);
			fflush(stdout);
		}
		res = gnutls_record_recv(session, buf, sizeof(buf));
	}
#ifdef COMMENTS
	printf("∧∧∧---From Server---∧∧∧\n");
#endif


	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	gnutls_deinit(session);
	close(connfd);
	free(connfdPtr);
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_global_deinit();
#ifdef COMMENTS
	printf("All done!\n");
#endif

	return 0;
}

/* function hostname_to_ip is a modified version of:
	https://gist.github.com/twslankard/1001201
	IPv6 support added, but no preference given.
	First A/AAAA IP address listed by DNS resolver will be used.
	Variables:
	ipv4off: set to 1 to disable the return of an IPv4 address.
	ipv6off: set to 1 to disable the return of an IPv6 address.
*/
int hostname_to_ip(char *hostname, char *ip)
{
	int ipv4off = 0;
	int ipv6off = 1;
	struct addrinfo * _addrinfo;
	struct addrinfo * _res;
	int errorcode = 0;

	if (ipv4off != 0 && ipv6off != 0) {
		printf("hostname_to_ip error: both IPv4 and IPv6 is disabled.\n");
		exit(1);
	}

	errorcode = getaddrinfo(hostname, EPP_TLS_PORT, NULL, &_addrinfo);
	if (errorcode != 0) {
		printf("getaddrinfo: %s\n", gai_strerror(errorcode));
		exit(1);
	}

	for (_res = _addrinfo; _res != NULL; _res = _res->ai_next) {
		if (_res->ai_family == AF_INET && ipv4off == 0) {
			if (NULL == inet_ntop(AF_INET, &((struct sockaddr_in *)_res->ai_addr)->sin_addr, ip, INET6_ADDRSTRLEN)) {
				perror("inet_ntop");
				exit(1);
			} else {
				char * ipv4_mapping;
				ipv4_mapping = "::ffff:";
				char * ipv4_mapped = (char *) malloc(1 + strlen(ipv4_mapping) + strlen(ip));
				strcpy(ipv4_mapped, ipv4_mapping);
				strcat(ipv4_mapped, ip);
				strcpy(ip, ipv4_mapped);
				free(ipv4_mapped);
				return 0;
			}
		}
		if (_res->ai_family == AF_INET6 && ipv6off == 0) {
			if (NULL == inet_ntop(AF_INET6, &((struct sockaddr_in6 *)_res->ai_addr)->sin6_addr, ip, INET6_ADDRSTRLEN)) {
				perror("inet_ntop");
				exit(1);
			} else {
				return 0;
			}
		}
	}

	return 0;
}

void print_logs(int level, const char* msg)
{
	printf("GnuTLS [%d]: %s", level, msg);
}

void print_audit_logs(gnutls_session_t session, const char* message)
{
	printf("GnuTLS Audit: %s", message);
}

void error_exit(const char *msg)
{
	fprintf(stderr, "ERROR: %s", msg);
	exit(1);
}


ssize_t data_push(gnutls_transport_ptr_t ptr, const void* data, size_t len)
{
	int sockfd = *(int*)(ptr);
	return send(sockfd, data, len, 0);
}

ssize_t data_pull(gnutls_transport_ptr_t ptr, void* data, size_t maxlen)
{
	int sockfd = *(int*)(ptr);
	return recv(sockfd, data, maxlen, 0);
}



int make_one_connection(const char *ip, int port)
{
#ifdef COMMENTS
	printf("Connecting to %s\n",ip);
#endif
	int res;
	int connfd = socket(AF_INET6, SOCK_STREAM, 0);

	char *local_bind_address = BIND_ADDR6;
	size_t len = strlen(ip);
	size_t spn = strcspn(ip, ".");
	if (spn != len)
	{
		local_bind_address = BIND_ADDR;
	}
	struct sockaddr_in6 local_addr;
	if (connfd < 0)
	{
		error_exit("socket() failed.\n");
	}
	local_addr.sin6_family = AF_INET6;
	res = inet_pton(AF_INET6, local_bind_address, &local_addr.sin6_addr);
	local_addr.sin6_port = 0;
	res = bind(connfd, (struct sockaddr *)&local_addr, sizeof(local_addr));
	if (res < 0)
	{
		perror("bind");
		exit(1);
	}

	struct sockaddr_in6 serv_addr;
	if (connfd < 0)
	{
		error_exit("socket() failed.\n");
	}
	serv_addr.sin6_family = AF_INET6;
	res = inet_pton(AF_INET6, ip, &serv_addr.sin6_addr);
	serv_addr.sin6_port = htons(port);
	res = connect(connfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if (res < 0)
	{
		perror("connect");
		exit(1);
	}
	return connfd;
}

int verify_cert(gnutls_session_t session)
{
	unsigned int status;
	int ret, type;
	const char *hostname;
	gnutls_datum_t out;

	hostname = gnutls_session_get_ptr(session);

	gnutls_typed_vdata_st data[2];

	memset(data, 0, sizeof(data));

	data[0].type = GNUTLS_DT_DNS_HOSTNAME;
	data[0].data = (void*)hostname;
#ifdef COMMENTS
	printf("hostname: %s\n",hostname);
#endif
	data[1].type = GNUTLS_DT_KEY_PURPOSE_OID;
	data[1].data = (void*)GNUTLS_KP_TLS_WWW_SERVER;

	ret = gnutls_certificate_verify_peers(session, data, 2, &status);

	if (ret < 0)
	{
		fprintf(stderr, "Error\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	type = gnutls_certificate_type_get(session);
	ret = gnutls_certificate_verification_status_print(status, type, &out, 0);

	if (ret < 0)
	{
		fprintf(stderr, "Error\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

#ifdef COMMENTS
	printf("%s\n", out.data);
#endif
	gnutls_free(out.data);


	if (status != 0)
	{
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	return 0;
}
