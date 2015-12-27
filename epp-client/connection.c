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

#define config_setting_lookup config_lookup_from

/*
* Build (Debian Jessie):
*	* gcc -o connection connection.c -lgnutls -lconfig
* Build (Debian Jessie) with more verbose comments in output:
*	* gcc -o connection connection.c -lgnutls -lconfig -DCOMMENTS
*/

/*
* Global Variables:
*	* LOG_LEVEL: integer between 0 and 9 for setting GnuTLS log level.
*		Set with --gnutls_log_level <level>.
*	* CONFIG_FILE: string containing full path to configuration file.
*		Set with --config <file>.
*/
int LOG_LEVEL = 0;
char *CONFIG_FILE = "";

// Set a maximum number of logins.
int max_logins = 1;
// Create *logins[] - a fixed size array of 1 pointer.
struct login_settings *logins[1];
// logins_iterate() will increase logins_count after each login is parsed.
int logins_count = 0;

struct login_settings
{
	int enabled;
	int ipv4_only;
	int ipv6_only;
	int keep_alive;
	int tls;
	int objURIs;
	int *connectionPtr;
	gnutls_session_t *gnutls_sessionPtr;
	gnutls_certificate_credentials_t x509_cred;
	struct config_setting_t *pointer;
	const char *bind_ipv4_mapped;
	const char *bind_ipv6;
	const char *bundle_file;
	const char *clID;
	const char *hostname;
	const char *lang;
	const char *port;
	const char *pw;
	const char *tls_ca_file;
	const char *tls_ciphers;
	const char *version;
	const char *xmlns;
	const char *xmlns_xsi;
	const char *xsi_schemaLocation;
	const char *objURI[21];
};

struct config_t conf;
struct config_t *config;

void error_exit(const char *msg);

int command_options(int argc, char **argv);
void open_config();
void create_connections();
void close_connections();
void close_connection(struct login_settings login);
void close_config();

int get_root_element_count(config_t *config, char *name, config_setting_t *config_element);
int get_element_count(config_setting_t *config, char *name, config_setting_t *config_element);
int get_config_int(config_setting_t *setting, char *name);
int get_config_bool(config_setting_t *setting, char *name);
const char *get_config_string(config_setting_t *setting, char *name);

ssize_t data_push(gnutls_transport_ptr_t, const void*, size_t);
ssize_t data_pull(gnutls_transport_ptr_t, void*, size_t);
void print_logs(int, const char*);
void print_audit_logs(gnutls_session_t, const char*);
int tls_connection(struct login_settings login);
int make_one_connection(struct login_settings login, const char *address, int port);
int get_ip_from_hostname(struct login_settings login, char *, char *);
int verify_cert(struct gnutls_session_int *);

void schemas_iterate();
void servers_iterate(int schemaInt, struct login_settings schema_login, struct config_setting_t *schema_element);
void logins_iterate(int schemaInt, struct login_settings schema_login, struct config_setting_t *schema_element, int serverInt, struct login_settings server_login, struct config_setting_t *server_element);

int main(int argc, char **argv)
{
	// Parse command line options.
	command_options(argc, argv);

	// Open configuration file into config.
	open_config();

	/*
	* Iterate through configuration file recursively via schemas_iterate(), servers_iterate(), and logins_iterate().
	* logins_iterate() populates *logins[].
	*/
	schemas_iterate();

	// Iterate through *logins[] and create connections.
	create_connections();

	// Iterate through *logins[] and close connections.
//	close_connections();

	// Free logins and destroy config.
	close_config();

	return 0;
}

int command_options(int argc, char **argv)
{
/* Handle command line parameters */
	int c;
	while (1)
	{
		/*
		* Values returned are char, so start at 1001 for long options without short
		*  equivalent so they don't interfere with short options (e.g. 'z' = 122).
		* If a decision is made to later add a short option, change the number in
		*  the array and the case statement for that option (e.g. replacing 1008 with '4'.
		*/
		static struct option long_options[] =
		{
			{"gnutls_log_level", required_argument, 0, 1001},
			{"config", required_argument, 0, 1002},
			{"help", no_argument, 0, 'h'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		c = getopt_long(argc, argv, "h", long_options, &option_index);
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
			case 1001:
				LOG_LEVEL = atoi(optarg);
				break;
			case 1002:
				CONFIG_FILE = optarg;
				break;
			case 'h':
				printf("Usage: %s [options]\n",argv[0]);
				printf("Options:\n");
				printf("  --config <file>\n");
				printf("	Path to configuration file.\n");
				printf("  --gnutls_log_level <value>\n");
				printf("	Whole number between 0 and 9 for setting GnuTLS log level.\n");
				printf("	Default value: 0\n");
				printf("  --help\n");
				printf("	Display this information.\n");
				exit(0);
				break;
			default:
				abort();
		}

	}
}

void open_config()
{
	if (strlen(CONFIG_FILE) == 0)
	{
		fprintf(stderr, "No configuration file specified.\n");
		exit(1);
	}

	config = &conf;
	config_init(config);

	int loaded_config = config_read_file(config, CONFIG_FILE);
	if (loaded_config != 1)
	{
		fprintf(stderr, "Error reading config file %s. Error on line %d: %s\n", config_error_file(config), config_error_line(config), config_error_text(config));
		config_destroy(config);
	}
}

void schemas_iterate(struct login_settings *logins[], int *logins_count, int max_logins)
{
	/*
	* Loop through schemas.
	*/
	struct config_setting_t conf_schemas;
	struct config_setting_t *config_schemas = &conf_schemas;
	int schema_count = get_root_element_count(config, "schemas", config_schemas);
#ifdef COMMENTS
	printf("Number of schemas: %d\n", schema_count);
#endif

	int schemaInt;
	for(schemaInt = 0; schemaInt < schema_count; schemaInt++)
	{
		struct config_setting_t *schema_element = config_setting_get_elem(config_schemas, schemaInt);
		if (schema_element== NULL)
		{
			continue;
		}
		struct login_settings schema_login;
		schema_login.bundle_file = get_config_string(schema_element, "bundle_file");
		schema_login.pointer = schema_element;
#ifdef COMMENTS
		printf("schemas[%d].bundle_file = %s\n", schemaInt, schema_login.bundle_file);
#endif
		servers_iterate(schemaInt, schema_login, schema_element);
	}
}

void servers_iterate(int schemaInt, struct login_settings schema_login, struct config_setting_t *schema_element)
{
	/*
	* Loop through servers.
	*/
	struct config_setting_t conf_servers;
	struct config_setting_t *config_servers = &conf_servers;
	int server_count = get_element_count(schema_element, "servers", config_servers);
	if (config_servers == NULL)
	{
		fprintf(stdout, "No servers defined for schema %d.\n", schemaInt);
		return;
	}
#ifdef COMMENTS
	printf("Number of servers using schema %d: %d\n", schemaInt, server_count);
#endif

	int serverInt;
	for(serverInt = 0; serverInt < server_count; serverInt++)
	{
		struct config_setting_t *server_element = config_setting_get_elem(config_servers, serverInt);
		if (server_element == NULL)
		{
			continue;
		}

		struct login_settings server_login;
		memcpy(&server_login, &schema_login, sizeof(server_login));
		server_login.pointer = server_element;

		struct config_setting_t *server_setting = NULL;

		int server_setting_int = get_config_bool(server_element, "enabled");
		if (server_setting_int == 0)
		{
			fprintf(stdout, "Server %d is not enabled.\n", serverInt);
			continue;
		}
		else if (server_setting_int > 0)
		{
			server_login.enabled = server_setting_int;
			server_login.hostname = get_config_string(server_element, "hostname");
			server_login.port = get_config_string(server_element, "port");
#ifdef COMMENTS
			printf("schemas[%d].servers[%d].enabled = %d\n", schemaInt, serverInt, server_login.enabled);
			printf("schemas[%d].servers[%d].hostname = %s\n", schemaInt, serverInt, server_login.hostname);
			printf("schemas[%d].servers[%d].port = %d\n", schemaInt, serverInt, server_login.port);
#endif

			server_setting_int = get_config_bool(server_element, "tls");
			if (server_setting_int == 0)
			{
				fprintf(stdout, "Server %d is not configured for TLS. This program only supports TLS servers.\n", serverInt);
				continue;
			}
			else if (server_setting_int > 0)
			{
				server_login.tls = server_setting_int;
				server_login.tls_ca_file = get_config_string(server_element, "tls_ca_file");
				server_login.tls_ciphers = get_config_string(server_element, "tls_ciphers");
#ifdef COMMENTS
				printf("schemas[%d].servers[%d].tls = %d\n", schemaInt, serverInt, server_login.tls);
				printf("schemas[%d].servers[%d].tls_ca_file = %s\n", schemaInt, serverInt, server_login.tls_ca_file);
				printf("schemas[%d].servers[%d].tls_ciphers = %s\n", schemaInt, serverInt, server_login.tls_ciphers);
#endif
			}

			server_login.keep_alive = get_config_int(server_element, "keep_alive");
			server_login.xmlns = get_config_string(server_element, "xml.xmlns");
			server_login.xmlns_xsi = get_config_string(server_element, "xml.xmlns-xsi");
			server_login.xsi_schemaLocation = get_config_string(server_element, "xml.xsi-schemaLocation");

#ifdef COMMENTS
			printf("schemas[%d].servers[%d].keep_alive = %d\n", schemaInt, serverInt, server_login.keep_alive);
			printf("schemas[%d].servers[%d].xml.xmlns = %s\n", schemaInt, serverInt, server_login.xmlns);
			printf("schemas[%d].servers[%d].xml.xmlns-xsi = %s\n", schemaInt, serverInt, server_login.xmlns_xsi);
			printf("schemas[%d].servers[%d].xml.xsi-schemaLocation = %s\n", schemaInt, serverInt, server_login.xsi_schemaLocation);
#endif
			logins_iterate(schemaInt, schema_login, schema_element, serverInt, server_login, server_element);
		}
	}
}

void logins_iterate(int schemaInt, struct login_settings schema_login, struct config_setting_t *schema_element, int serverInt, struct login_settings server_login, struct config_setting_t *server_element)
{
	/*
	* Loop through logins.
	*/

	struct config_setting_t *conf_logins = config_setting_lookup(server_element, "logins");
	if (conf_logins == NULL)
	{
		fprintf(stdout, "No logins defined for server %d using schema %d\n", serverInt, schemaInt);
		return;
	}
	int login_count = config_setting_length(conf_logins);
#ifdef COMMENTS
	printf("Number of logins for server %d using schema %d: %d\n", serverInt, schemaInt, login_count);
#endif

	int loginInt;
	for(loginInt = 0; loginInt < login_count; loginInt++)
	{
		struct config_setting_t *login_element = config_setting_get_elem(conf_logins, loginInt);
		if (login_element == NULL)
		{
			continue;
		}

		struct login_settings *loginPtr = NULL;
		loginPtr = (struct login_settings *) malloc(sizeof(struct login_settings));
#ifdef COMMENTS
		printf("Pointer loginPtr: %p\n", loginPtr);
#endif
		memcpy(loginPtr, &server_login, sizeof(struct login_settings));
		loginPtr->pointer = login_element;
		loginPtr->bind_ipv4_mapped = get_config_string(login_element, "bind_ipv4_mapped");
		loginPtr->bind_ipv6 = get_config_string(login_element, "bind_ipv6");
		loginPtr->ipv4_only = get_config_bool(login_element, "ipv4_only");
		loginPtr->ipv6_only = get_config_bool(login_element, "ipv6_only");

#ifdef COMMENTS
		printf("schemas[%d].servers[%d].logins[%d].bind_ipv4_mapped = %s\n", schemaInt, serverInt, loginInt, loginPtr->bind_ipv4_mapped);
		printf("schemas[%d].servers[%d].logins[%d].ipv4_only = %d\n", schemaInt, serverInt, loginInt, loginPtr->ipv4_only);
		printf("schemas[%d].servers[%d].logins[%d].bind_ipv6 = %s\n", schemaInt, serverInt, loginInt, loginPtr->bind_ipv6);
		printf("schemas[%d].servers[%d].logins[%d].ipv6_only = %d\n", schemaInt, serverInt, loginInt, loginPtr->ipv6_only);
#endif

		loginPtr->clID = get_config_string(login_element, "clID");
		loginPtr->pw = get_config_string(login_element, "pw");

		loginPtr->version = get_config_string(login_element, "options.version");
		loginPtr->lang = get_config_string(login_element, "options.lang");

#ifdef COMMENTS
		printf("schemas[%d].servers[%d].logins[%d].clID = %s\n", schemaInt, serverInt, loginInt, loginPtr->clID);
		printf("schemas[%d].servers[%d].logins[%d].pw = %s\n", schemaInt, serverInt, loginInt, loginPtr->pw);
#endif

		/*
		* Change login->pw and save to file.
		*/
		/*
		loginPtr->pw = "newpassword";
		config_setting_set_string(config_setting_lookup(loginPtr->pointer, "pw"), loginPtr->pw);
		printf("schemas[%d].servers[%d].logins[%d].pw = %s\n", schemaInt, serverInt, loginInt, get_config_string(login_element, "pw"));
		config_write_file(config, CONFIG_FILE);
		*/

#ifdef COMMENTS
		printf("schemas[%d].servers[%d].logins[%d].options.version = %s\n", schemaInt, serverInt, loginInt, loginPtr->version);
		printf("schemas[%d].servers[%d].logins[%d].options.lang = %s\n", schemaInt, serverInt, loginInt, loginPtr->lang);
		printf("Schema[%d] pointer: %p\n", schemaInt, schema_login.pointer);
		printf("Schema[%d] -> Server[%d] pointer: %p\n", schemaInt, serverInt, server_login.pointer);
		printf("Schema[%d] -> Server[%d] -> Login[%d] pointer: %p\n", schemaInt, serverInt, loginInt, loginPtr->pointer);
#endif

		/*
		* Loop through objURIs.
		*/
		struct config_setting_t *conf_objURIs = config_setting_lookup(login_element, "svcs.objURI");
		if (conf_objURIs == NULL)
		{
			fprintf(stdout, "No objURIs defined for login %d on server %d using schema %d.\n", loginInt, serverInt, schemaInt);
		}
		else
		{
			int config_objURIs = config_setting_length(conf_objURIs);
#ifdef COMMENTS
			printf("Number of objURIs for login %d on server %d using schema %d: %d\n", loginInt, serverInt, schemaInt, config_objURIs);
#endif

			if (config_objURIs > 21)
			{
				fprintf(stderr, "Maximum objURIs hard-coded to %d but there are %d objURIs for schema[%d].server[%d].login[%d].\n", 21, config_objURIs, loginInt, serverInt, schemaInt);
				exit(1);
			}
			loginPtr->objURIs = config_objURIs;

			int l;
			for(l = 0; l < config_objURIs; l++)
			{
				struct config_setting_t *objURI_element = config_setting_get_elem(conf_objURIs, l);
				if (objURI_element == NULL)
				{
					continue;
				}
				loginPtr->objURI[l] = config_setting_get_string(objURI_element);
#ifdef COMMENTS
				printf("schemas[%d].servers[%d].logins[%d].svcs.objURI[%d] = %s\n", schemaInt, serverInt, loginInt, l, loginPtr->objURI[l]);
#endif
			}
		}

		if (logins_count < max_logins)
		{
			logins[logins_count] = loginPtr;
			logins_count++;
		}
		else
		{
			fprintf(stderr, "Compiled with only %d maximum logins, configuration file contains at least %d.\n", max_logins, logins_count+1);
			fprintf(stderr, "Please modify 'int max_logins = %d' in source code and recompile.\n", max_logins);
			fprintf(stderr, "NOTE: Program currently only supports 1 schema, 1 server, and 1 login.\n");
			config_destroy(config);
			exit(1);
		}
	}
}

void create_connections()
{
	int i;
	// Create connection per login.
	for (i = 0; i < logins_count; i++)
	{
		struct login_settings *loginPtr = logins[i];
		struct login_settings login = *loginPtr;
#ifdef COMMENTS
		printf("logins[%d] pointer: %p\n", i, loginPtr);
#endif

		tls_connection(login);
	}
}

void close_connections()
{
	int i;
	// Close connection per login.
	for (i = 0; i < logins_count; i++)
	{
		struct login_settings *loginPtr = logins[i];
		struct login_settings login = *loginPtr;
		close_connection(login);
	}
}

void close_connection(struct login_settings login)
{
	gnutls_session_t *gnutls_sessionPtr = login.gnutls_sessionPtr;
	gnutls_session_t session = *gnutls_sessionPtr;
	int *connfdPtr = login.connectionPtr;
	int connfd = *connfdPtr;

	char logoutString[4096];
	int n = sprintf(logoutString, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<epp xmlns=\"%s\" xmlns:xsi=\"%s\" xsi:schemaLocation=\"%s\">\n\t<command>\n\t\t<logout />\n\t</command>\n</epp>\n", login.xmlns, login.xmlns_xsi, login.xsi_schemaLocation);
	printf("%s\n",logoutString);
	gnutls_record_send(session, logoutString, strlen(logoutString));

	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	gnutls_deinit(session);
	login.gnutls_sessionPtr = NULL;
	close(connfd);
	free(connfdPtr);
	login.connectionPtr = NULL;
	gnutls_certificate_free_credentials(login.x509_cred);
	gnutls_global_deinit();
}

void close_config()
{
	int i;
	// Cleanup before config_destroy()
	for (i = 0; i < logins_count; i++)
	{
		struct login_settings *loginPtr = logins[i];
		free(loginPtr);
	}

	config_destroy(config);
}

int tls_connection(struct login_settings login)
{

	int res;
	gnutls_certificate_credentials_t x509_cred;

	gnutls_global_init();

	gnutls_global_set_log_level(LOG_LEVEL);
	gnutls_global_set_log_function(print_logs);

	gnutls_session_t session;

	gnutls_certificate_allocate_credentials(&x509_cred);
	login.x509_cred = x509_cred;
	gnutls_certificate_set_x509_trust_file(x509_cred, login.tls_ca_file, GNUTLS_X509_FMT_PEM);
	printf("CA file: %s\n", login.tls_ca_file);

	res = gnutls_init(&session, GNUTLS_CLIENT);
	if (res != GNUTLS_E_SUCCESS)
	{
		fprintf(stderr, "Error code %d in gnutls_init(): %s\n",res,gnutls_strerror(res));
		exit(1);
	}

	gnutls_session_set_ptr(session, (void *) login.hostname);
	gnutls_server_name_set(session, GNUTLS_NAME_DNS, login.hostname, strlen(login.hostname));

	const char *error = NULL;
	res = gnutls_priority_set_direct(session, login.tls_ciphers, &error);
	if (res != GNUTLS_E_SUCCESS)
	{
		fprintf(stderr, "Invalid Cipher: %s\n",error);
		fprintf(stderr, "Error code %d in gnutls_priority_set_direct(): %s\n",res,gnutls_strerror(res));
		exit(1);
	}

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);


	char *hostname = (void *) login.hostname;
	char ip[INET6_ADDRSTRLEN];
	get_ip_from_hostname(login, hostname, ip);
#ifdef COMMENTS
	printf("%s resolved to %s\n", hostname, ip);
	char loginString[4096];
	int n = sprintf(loginString, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<epp xmlns=\"%s\" xmlns:xsi=\"%s\" xsi:schemaLocation=\"%s\">\n\t<command>\n\t\t<login>\n\t\t\t<clID>%s</clID>\n\t\t\t<pw>%s</pw>\n\t\t\t<options>\n\t\t\t\t<version>%s</version>\n\t\t\t\t<lang>%s</lang>\n\t\t\t</options>\n\t\t\t<svcs>\n", login.xmlns, login.xmlns_xsi, login.xsi_schemaLocation, login.clID, login.pw, login.version, login.lang);
	int i;
	for (i = 0; i < login.objURIs; i++)
	{
		char objURI[1024];
		int o = sprintf(objURI, "\t\t\t\t<objURI>%s</objURI>\n", login.objURI[i]);
		n = n+o;
		strcat(loginString, objURI);
	}
	strcat(loginString, "\t\t\t</svcs>\n\t\t</login>\n\t</command>\n</epp>\n");
#endif

	int connfd = make_one_connection(login, ip, atoi(login.port));

	int *connfdPtr = malloc(sizeof(int));
	*connfdPtr = connfd;
	login.connectionPtr = connfdPtr;
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
	printf("%s\n",loginString);
	gnutls_record_send(session, loginString, strlen(loginString));
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

		close_connection(login);

#ifdef COMMENTS
	printf("All done!\n");
#endif

	return 0;
}

/*
* Function get_root_element_count:
*	* Returns number (int) of elements in list 'name' in configuration 'config'.
*	* Updates pointer '*config_element' to point to element 'name'.
*
* config_t *config : pointer to parsed config
* char *name : pointer to name of element
* config_setting_t *conf_element : pointer to element
*/
int get_root_element_count(config_t *config, char *name, config_setting_t *config_element)
{
	config_setting_t *conf_element = config_lookup(config, name);
	if (conf_element == NULL)
	{
		fprintf(stderr, "No %s found in configuration file.\n", name);
		exit(1);
	}
	else
	{
		*config_element = *conf_element;
		return config_setting_length(config_element);
	}
}

/*
* Function get_element_count:
*	* Returns number (int) of elements in list 'name' in configuration setting 'config_setting'.
*	* Updates pointer '*config_element' to point to element 'name'.
*
* config_setting_t *config : pointer to parsed config setting
* char *name : pointer to name of element
* config_setting_t *conf_element : pointer to element
*/
int get_element_count(config_setting_t *config_setting, char *name, config_setting_t *config_element)
{
	config_setting_t *conf_element = config_setting_lookup(config_setting, name);
	if (conf_element == NULL)
	{
		fprintf(stderr, "No %s found in configuration file for this schema.\n", name);
		return 0;
	}
	else {
		*config_element = *conf_element;
		return config_setting_length(config_element);
	}
}

/*
* Function get_config_int looks up the integer value of 'name'
*  in the configuration setting 'setting' and returns the integer.
* -1 is returned if 'name' does not exist.
*/
int get_config_int(config_setting_t *setting, char *name)
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
* Function get_config_bool looks up the boolean value of 'name'
*  in the configuration setting 'setting' and returns it as an integer.
* -1 is returned if 'name' does not exist.
*/
int get_config_bool(config_setting_t *setting, char *name)
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
* Function get_config_string looks up the string value of 'name'
*  in the configuration setting 'setting' and returns the string.
* NULL is returned if 'name' does not exist.
*/
const char *get_config_string(config_setting_t *setting, char *name)
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

/*
* function get_ip_from_hostname is a modified version of:
*  https://gist.github.com/twslankard/1001201
*	* IPv6 support added, but no preference given.
*	* First A/AAAA IP address listed by DNS resolver will be used.
* Variables:
*	* ipv4off: set to 1 to disable the return of an IPv4 address.
*	* ipv6off: set to 1 to disable the return of an IPv6 address.
*/
int get_ip_from_hostname(struct login_settings login, char *hostname, char *ip)
{
	struct addrinfo * _addrinfo;
	struct addrinfo * _res;
	int errorcode = 0;
	static int ip_found = 0;

	if (login.ipv4_only == 1 && login.ipv6_only == 1)
	{
		fprintf(stderr, "get_ip_from_hostname error: both IPv4 and IPv6 is disabled.\n");
		exit(1);
	}

	errorcode = getaddrinfo(hostname, login.port, NULL, &_addrinfo);
	if (errorcode != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(errorcode));
		exit(1);
	}

	for (_res = _addrinfo; _res != NULL; _res = _res->ai_next)
	{
		if (_res->ai_family == AF_INET && login.ipv6_only != 1)
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
		else if (_res->ai_family == AF_INET6 && login.ipv4_only != 1)
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
		if (login.ipv4_only == 1)
		{
			fprintf(stderr, "Hostname %s only has IPv6 IP address(es).\n", login.hostname);
			fprintf(stderr,  "Unable to connect due to running in IPv4-only mode.\n");
		}
		else if (login.ipv6_only == 1)
		{
			fprintf(stderr, "Hostname %s only has IPv4 IP address(es).\n", login.hostname);
			fprintf(stderr, "Unable to connect due to running in IPv6-only mode.\n");
		}
		exit(1);
	}

	return 0;
}

void print_logs(int level, const char *msg)
{
	printf("GnuTLS [%d]: %s", level, msg);
}

void print_audit_logs(gnutls_session_t session, const char *message)
{
	printf("GnuTLS Audit: %s", message);
}

void error_exit(const char *msg)
{
	fprintf(stderr, "ERROR: %s", msg);
	exit(1);
}


ssize_t data_push(gnutls_transport_ptr_t ptr, const void *data, size_t len)
{
	int sockfd = *(int*)(ptr);
	return send(sockfd, data, len, 0);
}

ssize_t data_pull(gnutls_transport_ptr_t ptr, void *data, size_t maxlen)
{
	int sockfd = *(int*)(ptr);
	return recv(sockfd, data, maxlen, 0);
}

int make_one_connection(struct login_settings login, const char *ip, int port)
{
#ifdef COMMENTS
	printf("Connecting to %s\n",ip);
#endif
	int res;
	int connfd = socket(AF_INET6, SOCK_STREAM, 0);

	char *local_bind_address = (void *) login.bind_ipv6;
	size_t len = strlen(ip);
	size_t spn = strcspn(ip, ".");
	if (spn != len)
	{
		local_bind_address = (void *) login.bind_ipv4_mapped;
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
