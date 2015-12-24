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
/* GnuTLS */
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
/* libconfig */
#include <libconfig.h>

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
char *EPP_TLS_CIPHERS = "PFS";
char *MSG = "GET / HTTP/1.1\r\nhost: webmail.thejc.me.uk\r\nUser-agent: EPP Client\r\n\r\n";
int LOG_LEVEL = 0;
int IPV4_ONLY, IPV6_ONLY = 0;

#define config_setting_lookup config_lookup_from

struct login_settings
{
	const char *bundle_file;
	int enabled;
	const char *hostname;
	int port;
	int tls;
	const char *tls_ca_file;
	const char *tls_ciphers;
	int keep_alive;
	const char *xmlns;
	const char *xmlns_xsi;
	const char *xsi_schemaLocation;
	const char *bind_ipv4_mapped;
	const char *bind_ipv6;
	int ipv4_only;
	int ipv6_only;
	const char *clID;
	const char *pw;
	const char *version;
	const char *lang;
	config_setting_t *pointer;
	const char *objURL[];
};

int GetConfigInt(config_setting_t *setting, char* name);
int GetConfigBool(config_setting_t *setting, char* name);
const char* GetConfigString(config_setting_t *setting, char* name);

config_t conf, *config;

char *CONFIG_FILE = "/home/thejc/Scripts/epp/epp-client/epp.config";

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
	config = &conf;
	config_init(config);
	int loaded_config = config_read_file(config, CONFIG_FILE);
	if (loaded_config != 1)
	{
		fprintf(stderr, "Error reading config file %s. Error on line %d: %s\n", config_error_file(config), config_error_line(config), config_error_text(config));
		config_destroy(config);
		error("config_read_file");
	}

	/*
	* Loop through schemas.
	*/
	config_setting_t *conf_schemas = config_lookup(config, "schemas");
	if (conf_schemas == NULL)
	{
		fprintf(stderr, "No schemas found in configuration file.\n");
		exit(1);
	}
	int config_schemas = config_setting_length(conf_schemas);
	printf("Number of schemas: %d\n", config_schemas);

	int i;
	for(i = 0; i < config_schemas; i++)
	{
		config_setting_t *current_element =	config_setting_get_elem(conf_schemas, i);
		if (current_element == NULL)
		{
			continue;
		}
		struct login_settings schema_login;
		schema_login.bundle_file = GetConfigString(current_element, "bundle_file");
		schema_login.pointer = current_element;
		printf("schemas[%d].bundle_file = %s\n", i, schema_login.bundle_file);

		/*
		* Loop through servers.
		*/
		config_setting_t *conf_servers = config_setting_lookup(current_element, "servers");
		if (conf_servers == NULL)
		{
			fprintf(stdout, "No servers defined for schema %d.\n", i);
			continue;
		}
		int config_servers = config_setting_length(conf_servers);
		printf("Number of servers using schema %d: %d\n", i, config_servers);

		int j;
		for(j = 0; j < config_servers; j++)
		{
			config_setting_t *current_element2 = config_setting_get_elem(conf_servers, j);
			if (current_element2 == NULL)
			{
				continue;
			}

			struct login_settings server_login;
			memcpy(&server_login, &schema_login, sizeof(server_login));
			server_login.pointer = current_element2;

			config_setting_t *server_setting = NULL;

			int server_setting_int = GetConfigBool(current_element2, "enabled");
			if (server_setting_int == 0)
			{
				fprintf(stdout, "Server %d is not enabled.\n", j);
				continue;
			}
			else if (server_setting_int > 0)
			{
				server_login.enabled = server_setting_int;
				server_login.hostname = GetConfigString(current_element2, "hostname");
				server_login.port = GetConfigInt(current_element2, "port");
				printf("schemas[%d].servers[%d].enabled = %d\n", i, j, server_login.enabled);
				printf("schemas[%d].servers[%d].hostname = %s\n", i, j, server_login.hostname);
				printf("schemas[%d].servers[%d].port = %d\n", i, j, server_login.port);

				server_setting_int = GetConfigBool(current_element2, "tls");
				if (server_setting_int == 0)
				{
					fprintf(stdout, "Server %d is not configured for TLS. This program only supports TLS servers.\n", j);
					continue;
				}
				else if (server_setting_int > 0)
				{
					server_login.tls = server_setting_int;
					server_login.tls_ca_file = GetConfigString(current_element2, "tls_ca_file");
					server_login.tls_ciphers = GetConfigString(current_element2, "tls_ciphers");
					printf("schemas[%d].servers[%d].tls = %d\n", i, j, server_login.tls);
					printf("schemas[%d].servers[%d].tls_ca_file = %s\n", i, j, server_login.tls_ca_file);
					printf("schemas[%d].servers[%d].tls_ciphers = %s\n", i, j, server_login.tls_ciphers);
				}

				server_login.keep_alive = GetConfigInt(current_element2, "keep_alive");
				server_login.xmlns = GetConfigString(current_element2, "xml.xmlns");
				server_login.xmlns_xsi = GetConfigString(current_element2, "xml.xmlns-xsi");
				server_login.xsi_schemaLocation = GetConfigString(current_element2, "xml.xsi-schemaLocation");

				printf("schemas[%d].servers[%d].keep_alive = %d\n", i, j, server_login.keep_alive);
				printf("schemas[%d].servers[%d].xml.xmlns = %s\n", i, j, server_login.xmlns);
				printf("schemas[%d].servers[%d].xml.xmlns-xsi = %s\n", i, j, server_login.xmlns_xsi);
				printf("schemas[%d].servers[%d].xml.xsi-schemaLocation = %s\n", i, j, server_login.xsi_schemaLocation);

				/*
				* Loop through logins.
				*/
				config_setting_t *conf_logins = config_setting_lookup(current_element2, "logins");
				if (conf_logins == NULL)
				{
					fprintf(stdout, "No logins defined for server %d using schema %d\n", j, i);
					continue;
				}
				int config_logins = config_setting_length(conf_logins);
				printf("Number of logins for server %d using schema %d: %d\n", j, i, config_logins);

				int k;
				for(k = 0; k < config_logins; k++)
				{
					config_setting_t *current_element3 = config_setting_get_elem(conf_logins, k);
					if (current_element3 == NULL)
					{
						continue;
					}

					struct login_settings login;
					memcpy(&login, &server_login, sizeof(login));
					login.pointer = current_element3;

					login.bind_ipv4_mapped = GetConfigString(current_element3, "bind_ipv4_mapped");
					login.bind_ipv6 = GetConfigString(current_element3, "bind_ipv6");
					login.ipv4_only = GetConfigBool(current_element3, "ipv4_only");
					login.ipv6_only = GetConfigBool(current_element3, "ipv6_only");

					printf("schemas[%d].servers[%d].logins[%d].bind_ipv4_mapped = %s\n", i, j, k, login.bind_ipv4_mapped);
					printf("schemas[%d].servers[%d].logins[%d].ipv4_only = %d\n", i, j, k, login.ipv4_only);
					printf("schemas[%d].servers[%d].logins[%d].bind_ipv6 = %s\n", i, j, k, login.bind_ipv6);
					printf("schemas[%d].servers[%d].logins[%d].ipv6_only = %d\n", i, j, k, login.ipv6_only);

					login.clID = GetConfigString(current_element3, "clID");
					login.pw = GetConfigString(current_element3, "pw");

					login.version = GetConfigString(current_element3, "options.version");
					login.lang = GetConfigString(current_element3, "options.lang");

					printf("schemas[%d].servers[%d].logins[%d].clID = %s\n", i, j, k, login.clID);
					printf("schemas[%d].servers[%d].logins[%d].pw = %s\n", i, j, k, login.pw);

					/*
					* Change login.pw and save to file.
					//
					login.pw = "newpassword";
					config_setting_set_string(config_setting_lookup(login.pointer, "pw"), login.pw);
					printf("schemas[%d].servers[%d].logins[%d].pw = %s\n", i, j, k, GetConfigString(current_element3, "pw"));
					config_write_file(config, CONFIG_FILE);
					//
					*/

					printf("schemas[%d].servers[%d].logins[%d].options.version = %s\n", i, j, k, login.version);
					printf("schemas[%d].servers[%d].logins[%d].options.lang = %s\n", i, j, k, login.lang);
					printf("Schema[%d] pointer: %d\n", i, schema_login.pointer);
					printf("Schema[%d] -> Server[%d] pointer: %d\n", i, j, server_login.pointer);
					printf("Schema[%d] -> Server[%d] -> Login[%d] pointer: %d\n", i, j, k, login.pointer);

					/*
					* Loop through objURLs.
					*/
					config_setting_t *conf_objURLs = config_setting_lookup(current_element3, "svcs.objURL");
					if (conf_objURLs == NULL)
					{
						fprintf(stdout, "No objURLs defined for login %d on server %d using schema %d.\n", k, j, i);
						continue;
					}
					int config_objURLs = config_setting_length(conf_objURLs);
					printf("Number of objURLs for login %d on server %d using schema %d: %d\n", k, j, i, config_objURLs);

					int l;
					for(l = 0; l < config_objURLs; l++)
					{
						config_setting_t *current_element4 = config_setting_get_elem(conf_objURLs, l);
						if (current_element4 == NULL)
						{
							continue;
						}
						login.objURL[l] = config_setting_get_string(current_element4);
						printf("schemas[%d].servers[%d].logins[%d].svcs.objURL[%d] = %s\n", i, j, k, l, login.objURL[l]);
					}
				}
			}
		}
	}

	config_destroy(config);
	return 0;
}

int main2(int argc, char **argv)
{
/* Handle command line parameters */
	int c;
	while (1)
	{
		/* Values returned are char, so start at 1001 for long options without short equivalent so they don't interfere with short options (e.g. 'z' = 122). */
		/* If a decision is made to later add a short option, change the number in the array and the case statement for that option (e.g. replacing 1008 with '4'. */
		static struct option long_options[] =
		{
			{"gnutls_log_level", required_argument, 0, 1001},
			{"epp_hostname", required_argument, 0, 1002},
			{"epp_tls_port", required_argument, 0, 1003},
			{"epp_tls_ciphers", required_argument, 0, 1004},
			{"epp_tls_ca_file", required_argument, 0, 1005},
			{"local_bind_addr", required_argument, 0, 1006},
			{"local_bind_addr6", required_argument, 0, 1007},
			{"disable-ipv6", no_argument, 0, '4'},
			{"disable-ipv4", no_argument, 0, '6'},
			{"ipv4-only", no_argument, 0, '4'},
			{"ipv6-only", no_argument, 0, '6'},
			{"help", no_argument, 0, 'h'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		c = getopt_long(argc, argv, "46h", long_options, &option_index);
		if (c == -1)
		{
			break;
		}

		switch (c)
		{
			case 0:
				/* If this option set a flag, do nothing else now. */
				if (long_options[option_index].flag != 0)
				{
					break;
				}
				break;
			case '4':
				IPV4_ONLY = 1;
				break;
			case '6':
				IPV6_ONLY = 1;
				break;
			case 1001:
				LOG_LEVEL = atoi(optarg);
				break;
			case 1002:
				EPP_HOSTNAME = optarg;
				break;
			case 1003:
				EPP_TLS_PORT = optarg;
				break;
			case 1004:
				EPP_TLS_CIPHERS = optarg;
				break;
			case 1005:
				EPP_TLS_CAFILE = optarg;
				break;
			case 1006:
				BIND_ADDR = optarg;
				break;
			case 1007:
				BIND_ADDR6 = optarg;
				break;
			case 'h':
				printf("Usage: %s [options]\n",argv[0]);
				printf("The --help output hasn't been finished yet.\n");
				printf("For a list of command line options, look at the source code.\n");
				printf("Options:\n");
				printf("  --local_bind_addr value\n");
				printf("	Local IPv4 IP address formatted as IPv4-mapped-IPv6 (e.g. ::ffff:127.0.0.1).\n");
				printf("  --local_bind_addr6 value\n");
				printf("	Local IPv6 IP address.\n");
				printf("  --epp_hostname value\n");
				printf("	EPP Server's IP address or hostname.\n");
				printf("  --epp_tls_port value\n");
				printf("	EPP Server's TLS port.\n");
				printf("  --epp_tls_ca_file value\n");
				printf("	Full path to EPP Server's Root CA file.\n");
				printf("  --epp_tls_ciphers value\n");
				printf("	Cipher list - enabled and disabled ciphers (GnuTLS format).\n");
				printf("	Default value: PFS\n");
				printf("  --ipv4-only|--disable-ipv6|-4\n");
				printf("	Runs in IPv4-Only Mode.\n");
				printf("  --ipv6-only|--disable-ipv4|-6\n");
				printf("	Runs in IPv6-Only Mode.\n");
				printf("  --gnutls_log_level value\n");
				printf("	Whole number between 0 and 9 for setting GnuTLS log level.\n");
				printf("	Default value: 0\n");
				exit(0);
				break;
			default:
				abort();
		}

	}

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

/*
* Function GetConfigInt looks up the integer value of 'name'
*. in the configuration setting 'setting' and returns the integer.
*  -1 is returned if 'name' does not exist.
*/
int GetConfigInt(config_setting_t *setting, char* name)
{
	config_setting_t *setting_pointer = NULL;
	setting_pointer = config_setting_lookup(setting, name);
	if (setting_pointer != NULL)
	{
		return config_setting_get_int(setting_pointer);
	}
	else
	{
		return -1;
	}
}

/*
* Function GetConfigBool looks up the boolean value of 'name'
*. in the configuration setting 'setting' and returns it as an integer.
*  -1 is returned if 'name' does not exist.
*/
int GetConfigBool(config_setting_t *setting, char* name)
{
	config_setting_t *setting_pointer = NULL;
	setting_pointer = config_setting_lookup(setting, name);
	if (setting_pointer != NULL)
	{
		return config_setting_get_bool(setting_pointer);
	}
	else
	{
		return -1;
	}
}

/*
* Function GetConfigString looks up the string value of 'name'
*. in the configuration setting 'setting' and returns the string.
*  NULL is returned if 'name' does not exist.
*/
const char* GetConfigString(config_setting_t *setting, char* name)
{
	config_setting_t *setting_pointer = NULL;
	setting_pointer = config_setting_lookup(setting, name);
	if (setting_pointer != NULL)
	{
		return config_setting_get_string(setting_pointer);
	}
	else
	{
		return NULL;
	}
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
	struct addrinfo * _addrinfo;
	struct addrinfo * _res;
	int errorcode = 0;
	static int ip_found = 0;

	if (IPV4_ONLY == 1 && IPV6_ONLY == 1)
	{
		fprintf(stderr, "hostname_to_ip error: both IPv4 and IPv6 is disabled.\n");
		exit(1);
	}

	errorcode = getaddrinfo(hostname, EPP_TLS_PORT, NULL, &_addrinfo);
	if (errorcode != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(errorcode));
		exit(1);
	}

	for (_res = _addrinfo; _res != NULL; _res = _res->ai_next)
	{
		if (_res->ai_family == AF_INET && IPV6_ONLY != 1)
		{
			if (NULL == inet_ntop(AF_INET, &((struct sockaddr_in *)_res->ai_addr)->sin_addr, ip, INET6_ADDRSTRLEN))
			{
				perror("inet_ntop");
				exit(1);
			}
			else
			{
				char * ipv4_mapping;
				ipv4_mapping = "::ffff:";
				char * ipv4_mapped = (char *) malloc(strlen(ipv4_mapping) + strlen(ip) + 1);
				strcpy(ipv4_mapped, ipv4_mapping);
				strcat(ipv4_mapped, ip);
				strcpy(ip, ipv4_mapped);
				free(ipv4_mapped);
				ip_found = 1;
				return 0;
			}
		}
		else if (_res->ai_family == AF_INET6 && IPV4_ONLY != 1)
		{
			if (NULL == inet_ntop(AF_INET6, &((struct sockaddr_in6 *)_res->ai_addr)->sin6_addr, ip, INET6_ADDRSTRLEN))
			{
				perror("inet_ntop");
				exit(1);
			}
			else
			{
				ip_found = 1;
				return 0;
			}
		}
	}

	if (ip_found == 0)
	{
		if (IPV4_ONLY == 1)
		{
			fprintf(stderr, "Hostname %s only has IPv6 IP address(es).\n", EPP_HOSTNAME);
			fprintf(stderr,  "Unable to connect due to running in IPv4-only mode.\n");
		}
		else if (IPV6_ONLY == 1)
		{
			fprintf(stderr, "Hostname %s only has IPv4 IP address(es).\n", EPP_HOSTNAME);
			fprintf(stderr, "Unable to connect due to running in IPv6-only mode.\n");
		}
		exit(1);
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
