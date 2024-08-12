/*
 * http.c - API for HTTP exchanges
 *
 * Copyright (C) 2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
  *	  Author Mohamed Kallel <mohamed.kallel@pivasoftware.com>
 *	  Author Ahmed Zribi <ahmed.zribi@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "http.h"
#include "log.h"
#include "event.h"
#include "ubus_utils.h"
#include "config.h"
#include "digauth.h"
#include "session.h"
#include "uci_utils.h"

#define REALM "authenticate@cwmp"
#define OPAQUE "11733b200778ce33060f31c9af70a870ba96ddd4"
#define HTTP_GET_HDR_LEN 512
#define HTTP_FD_FEEDS_COUNT 10 /* Maximum number of lines to be read from HTTP header */

extern pthread_mutex_t mutex_config_load;
static struct curl_slist *header_list = NULL;

static CURL *curl = NULL;
static bool curl_glob_init = false;

void http_set_timeout(void)
{
	if (curl)
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1);
}

int icwmp_http_client_init()
{
	if (CWMP_STRLEN(cwmp_main->conf.acs_url) == 0)
		return -1;

	CWMP_LOG(INFO, "ACS url: %s", cwmp_main->conf.acs_url);

	curl_global_init(CURL_GLOBAL_SSL);
	curl_glob_init = true;
	curl = curl_easy_init();
	if (!curl)
		return -1;

	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
	return 0;
}

void icwmp_http_client_exit(void)
{
	if (header_list) {
		curl_slist_free_all(header_list);
		header_list = NULL;
	}

	if (curl) {
		/* erasing all session cookies from memory */
		curl_easy_setopt(curl, CURLOPT_COOKIELIST, "SESS");
		curl_easy_cleanup(curl);
		curl = NULL;
	}

	if (curl_glob_init) {
		curl_global_cleanup();
		curl_glob_init = false;
	}
}

static size_t http_get_response(void *buffer, size_t size, size_t rxed, void *userp)
{
	char *c;
	char **msg_in;

	if (userp == NULL)
		return 0;

	msg_in = (char **) userp;

	if (buffer == NULL)
		return 0;
	if (cwmp_asprintf(&c, "%s%.*s", *msg_in, (int)(size * rxed), (char *)buffer) == -1) {
		FREE(*msg_in);
		return -1;
	}

	FREE(*msg_in);
	*msg_in = c;

	return size * rxed;
}

static void http_set_security_options()
{
	curl_easy_setopt(curl, CURLOPT_USERNAME, cwmp_main->conf.acs_userid);
	curl_easy_setopt(curl, CURLOPT_PASSWORD, cwmp_main->conf.acs_passwd);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC | CURLAUTH_DIGEST);

	curl_easy_setopt(curl, CURLOPT_CAPATH, cwmp_main->conf.acs_ssl_capath);

	if (cwmp_main->conf.insecure_enable) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	}
}

static void http_set_connection_options()
{
	curl_easy_setopt(curl, CURLOPT_URL, cwmp_main->conf.acs_url);

	curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTP_TIMEOUT);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, HTTP_TIMEOUT);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_UNRESTRICTED_AUTH, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
	curl_easy_setopt(curl, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);
	curl_easy_setopt(curl, CURLOPT_NOBODY, 0);
	curl_easy_setopt(curl, CURLOPT_IPRESOLVE, cwmp_main->net.ip_resolve);


	if (CWMP_STRLEN(cwmp_main->net.interface))
		curl_easy_setopt(curl, CURLOPT_INTERFACE, cwmp_main->net.interface);
}

static bool valid_cookie_path(const char *cookie)
{
	char *ptr = NULL;
	int count;
	char value[5120] = {0};

	if (cookie == NULL)
		return false;

	snprintf(value, sizeof(value), "%s", cookie);
	/* path should be the third field */
	ptr = strtok(value, "\t");
	count = 1;
	while (ptr && count < 3) {
		ptr = strtok(NULL, "\t");
		count = count + 1;
	}

	if (ptr == NULL)
		return true;

	/* allowed path field to remain not filled in */
	if (strcmp(ptr, "TRUE") && strcmp(ptr, "FALSE")) {
		int i;
		int n = strlen(ptr);

		for (i = 0; i < n; i++) {
			switch (ptr[i]) {
			// ? " \ < > * | :
			// these characters can not be used in file or folder names
			//
			case '?':
			case '\\':
			case '<':
			case '>':
			case '*':
			case '|':
			case ':':
				return false;

			// some stupid site sends path value within ", so ignore if
			// first and last char of path
			//
			case '\"':
				if ((i != 0) && (i + 1 != n))
					return false;
				break;

			// Space and point can not be the last character of a file or folder names
			//
			case ' ':
			case '.':
				if ((i + 1 == n) || (ptr[i+1] == '/'))
					return false;
				break;

			// two slashes can not go straight
			//
			case '/':
				if (i > 0 && ptr[i - 1] == '/')
					return false;
				break;
			}
		}
	}

	return true;
}

static void http_filter_valid_cookie()
{
	struct curl_slist *cookies, *nc;
	/* get the known list of cookies */
	if (CURLE_OK != curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies))
		return;

	/* erasing curl's knowledge of cookies */
	curl_easy_setopt(curl, CURLOPT_COOKIELIST, "ALL");

	/* add the cookies having valid path */
	nc = cookies;
	while (nc) {
		if (valid_cookie_path(nc->data))
			curl_easy_setopt(curl, CURLOPT_COOKIELIST, nc->data);
		else
			CWMP_LOG(DEBUG, "Reject cookie (%s)", nc->data);

		nc = nc->next;
	}

	curl_slist_free_all(cookies);
}

static void http_set_header_list_options()
{
	switch (cwmp_main->conf.compression) {
	case COMP_NONE:
		break;
	case COMP_GZIP:
		curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
		header_list = curl_slist_append(header_list, "Content-Encoding: gzip");
		break;
	case COMP_DEFLATE:
		curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "deflate");
		header_list = curl_slist_append(header_list, "Content-Encoding: deflate");
		break;
	}
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
}

static void http_set_inout_options(char *msg_out, int msg_out_len, char **msg_in)
{
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, msg_out);
	if (msg_out)
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)msg_out_len);
	else
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_get_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, msg_in);
}

int icwmp_http_send_message(char *msg_out, int msg_out_len, char **msg_in)
{
	unsigned char buf[sizeof(struct in6_addr)];
	int tmp = 0;
	CURLcode res;
	long http_code = 0;
	static char ip_acs[128] = { 0 };
	char *ip = NULL;
	char errbuf[CURL_ERROR_SIZE];

	header_list = NULL;
	header_list = curl_slist_append(header_list, "User-Agent: iopsys-cwmp");
	if (!header_list)
		return -1;

	header_list = curl_slist_append(header_list, "Content-Type: text/xml");
	if (!header_list)
		return -1;

	if (cwmp_main->conf.http_disable_100continue) {
		header_list = curl_slist_append(header_list, "Expect:");
		if (!header_list)
			return -1;
	}

	http_set_connection_options();
	http_filter_valid_cookie();
	http_set_security_options();
	http_set_header_list_options();
	http_set_inout_options(msg_out, msg_out_len, msg_in);

	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

	*msg_in = (char *)calloc(1, sizeof(char));

	res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		size_t len = strlen(errbuf);
		if (len) {
			if (errbuf[len - 1] == '\n')
				errbuf[len - 1] = '\0';
			CWMP_LOG(ERROR, "libcurl: (%d) %s", res, errbuf);
		} else {
			CWMP_LOG(ERROR, "libcurl: [%d] %s", res, curl_easy_strerror(res));
		}
	}

	if (*msg_in && !strlen(*msg_in))
		FREE(*msg_in);

	curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &ip);
	if (CWMP_STRLEN(ip)) {
		if (ip_acs[0] == '\0' || strcmp(ip_acs, ip) != 0) {
			CWMP_STRNCPY(ip_acs, ip, sizeof(ip_acs));
			tmp = inet_pton(AF_INET, ip, buf);
			if (tmp == 1) {
				tmp = 0;
			} else {
				tmp = inet_pton(AF_INET6, ip, buf);
			}

			if (tmp) {
				set_uci_path_value(VARSTATE_CONFIG, "icwmp.acs.ip6", ip_acs);
			} else {
				set_uci_path_value(VARSTATE_CONFIG, "icwmp.acs.ip", ip_acs);
			}

			// Trigger firewall to reload firewall.cwmp
			if (cwmp_main->cr_policy != CR_POLICY_Port_Only) {
				system(FIREWALL_CWMP);
			}
		}
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code == 204) {
		CWMP_LOG(INFO, "Receive HTTP 204 No Content");
	}

	if (http_code == 415) {
		cwmp_main->conf.compression = COMP_NONE;
		goto error;
	}
	if (http_code != 200 && http_code != 204)
		goto error;

	if (header_list) {
		curl_slist_free_all(header_list);
		header_list = NULL;
	}

	if (res)
		goto error;

	return 0;

error:
	FREE(*msg_in);
	if (header_list) {
		curl_slist_free_all(header_list);
		header_list = NULL;
	}
	return -1;
}

static void http_success_cr(void)
{
	CWMP_LOG(INFO, "Connection Request triggering ...");
	int retry = 0, rc = -1;
	while (rc != 0 && retry < 5) {
		rc = system("ubus call tr069 inform");
		retry = retry + 1;
	}

	if (rc != 0)
		CWMP_LOG(ERROR, "Failed to send Inform message after 5 retry");
}

static void http_cr_new_client(int client, bool service_available)
{
	FILE *fp = NULL;
	char data[BUFSIZ] = {0};
	char buffer[BUFSIZ] = {0};
	char auth_digest_buffer[BUFSIZ] = {0};
	int8_t auth_status = 0;
	bool auth_digest_checked = false;
	bool method_is_get = false;
	bool internal_error = false;
	char request_host[2049] = {0};
	char cr_http_get_head[HTTP_GET_HDR_LEN] = {0};
	fd_set rfds;
	struct timeval tv;
	int fd_feed = 0;
	int status = 0;

	pthread_mutex_lock(&mutex_config_load);
	char *username = (strlen(cwmp_main->conf.cpe_userid) != 0) ? strdup(cwmp_main->conf.cpe_userid) : NULL;
	char *password = (strlen(cwmp_main->conf.cpe_passwd) != 0) ? strdup(cwmp_main->conf.cpe_passwd) : NULL;
	char *cr_path = (strlen(cwmp_main->conf.connection_request_path) != 0) ? strdup(cwmp_main->conf.connection_request_path) : NULL;
	int cr_timeout = cwmp_main->conf.cr_timeout;
	pthread_mutex_unlock(&mutex_config_load);

	if (!username || !password) {
		// if we dont have username or password configured proceed with connecting to ACS
		service_available = false;
		goto http_end;
	}

	snprintf(cr_http_get_head, sizeof(cr_http_get_head), "GET %s HTTP/1.1", cr_path);
	CWMP_MEMSET(auth_digest_buffer, 0, BUFSIZ);

	/* Initialize timeout of select, so that it will wait for specific time
	 * period before timed out to receive data from client. Otherwise if client
	 * will not send any data after a successful connection then server will
	 * wait forever and not entertain any other connection requests
	 */
	tv.tv_sec = cr_timeout;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(client, &rfds);

	/* Make FD non blocking, so that no operation on FD will block and make the
	 * server halt forever.
	 */
	if (fcntl(client, F_SETFL, O_NONBLOCK) < 0) {
		CWMP_LOG(ERROR, "Failed to set NONBLOCK");
		goto http_end;
	}

	fp = fdopen(client, "r+");
	if (fp == NULL) {
		CWMP_LOG(ERROR, "Failed to open client socket");
		goto http_end;
	}

	bool read_done = false;
	/* Perform read from FD until all required data are collected or
	 * HTTP_FD_FEEDS_COUNT number of read operation has been performed.
	 * So that flooding of data not blocks the server.
	 */
	while (!read_done && fd_feed < HTTP_FD_FEEDS_COUNT) {
		status = select(client+1, &rfds, NULL, NULL, &tv);
		if (status <= 0) {
			CWMP_LOG(INFO, "TIMEOUT occurred or select failed");
			break;
		}

		/* Check how many bytes available in the FD */
		int read_bytes = 0;
		if (ioctl(client, FIONREAD, &read_bytes) == -1) {
			CWMP_LOG(INFO, "ioctl failed");
			break;
		}

		if (read_bytes < 1) {
			/* It means the client has been disconnected */
			CWMP_LOG(INFO, "client disconnected");
			break;
		}

		/* Read upto the number of bytes or HTTP_FD_FEEDS_COUNT number of
		 * read operation whichever is earlier, to avoid halt on data flooding
		 */
		while (read_bytes > 0 && fd_feed < HTTP_FD_FEEDS_COUNT) {
			if (fgets(buffer, sizeof(buffer), fp) == NULL) {
				CWMP_LOG(INFO, "No more data from FD");
				break;
			}

			size_t buf_len = strlen(buffer);
			read_bytes = read_bytes - buf_len;
			fd_feed = fd_feed + 1;

			/* Check if a whole line has been read, since a non blocking FD so
			 * possible to have fewer bytes than its in whole line based on the
			 * availability of data in the FD
			 */
			if (buffer[buf_len - 1] != '\n') {
				/* there should be more data in current line, store the current
				 * data and wait for next read if max data length not exceeded
				 */
				size_t avail_space = (size_t)(sizeof(data) - strlen(data));
				if (buf_len < avail_space) {
					strcat(data, buffer);
					continue;
				}
			} else {
				/* A whole line has been read, so store it if max data length is
				 * not exceeded and process the data
				 */
				size_t avail_space = (size_t)(sizeof(data) - strlen(data));
				if (buf_len < avail_space) {
					strcat(data, buffer);
				}
			}

			strip_lead_trail_char(data, '\n');
			strip_lead_trail_char(data, '\r');

			if (strlen(data) == 0) {
				/* empty line reached */
				CWMP_LOG(DEBUG, "Empty line found in packet");
				read_done = true;
				break;
			}

			if (fd_feed == 1 && (strstr(data, "GET ") == NULL || strstr(data, "HTTP/1.1") == NULL)) {
				CWMP_LOG(INFO, "GET not found at initial:: %s", data);
				read_done = true;
				break;
			}

			CWMP_LOG(DEBUG, "Data:: (%s)", data);

			if (strstr(data, "GET ") != NULL && strstr(data, "HTTP/1.1") != NULL) {
				// check if extra url parameter then ignore extra params
				int j = 0;
				bool ignore = false;
				char rec_http_get_head[HTTP_GET_HDR_LEN] = {0};

				CWMP_MEMSET(rec_http_get_head, 0, HTTP_GET_HDR_LEN);
				for (size_t i = 0; i < strlen(data) && j < (HTTP_GET_HDR_LEN - 1); i++) {
					if (data[i] == '?')
						ignore = true;
					if (data[i] == ' ')
						ignore = false;
					if (ignore == false) {
						rec_http_get_head[j] = data[i];
						j++;
					}
				}

				if (!strncasecmp(rec_http_get_head, cr_http_get_head, strlen(cr_http_get_head)))
					method_is_get = true;
			}

			if (!strncasecmp(data, "Authorization: Digest ", strlen("Authorization: Digest "))) {
				auth_digest_checked = true;
				CWMP_STRNCPY(auth_digest_buffer, data, BUFSIZ);
			}

			if (strncasecmp(data, "Host: ", strlen("Host: ")) == 0 && strlen(data) > strlen("Host: ")) {
				snprintf(request_host, sizeof(request_host), "http://%s", data + strlen("Host: "));
			}

			CWMP_MEMSET(data, 0, sizeof(data));
		}
	}

	if (!service_available || !method_is_get) {
		goto http_end;
	}

	CWMP_LOG(DEBUG, "Received host: (%s)", request_host);
	int auth_check = validate_http_digest_auth("GET", cr_path, auth_digest_buffer + strlen("Authorization: Digest "), REALM, username, password, cwmp_main->conf.session_timeout, request_host);

	if (auth_check == -1) { /* invalid nonce */
		internal_error = true;
		goto http_end;
	}
	if (auth_digest_checked && auth_check == 1)
		auth_status = 1;
	else
		auth_status = 0;
http_end:
	if (fp) {
		fflush(fp);
	}

	if (!service_available || !method_is_get) {
		CWMP_LOG(INFO, "Receive Connection Request: Return 503 Service Unavailable");
		if (fp) {
			fputs("HTTP/1.1 503 Service Unavailable\r\n", fp);
			fputs("Connection: close\r\n", fp);
			fputs("Content-Length: 0\r\n", fp);
			fputs("\r\n", fp);
			fclose(fp);
		}
		close(client);
	} else if (auth_status) {
		CWMP_LOG(INFO, "Receive Connection Request: success authentication");
		if (fp) {
			fputs("HTTP/1.1 200 OK\r\n", fp);
			fputs("Connection: close\r\n", fp);
			fputs("Content-Length: 0\r\n", fp);
			fputs("\r\n", fp);
			fclose(fp);
		}
		close(client);
		http_success_cr();
	} else if (internal_error) {
		CWMP_LOG(INFO, "Receive Connection Request: Return 500 Internal Error");
		if (fp) {
			fputs("HTTP/1.1 500 Internal Server Error\r\n", fp);
			fputs("Connection: close\r\n", fp);
			fputs("Content-Length: 0\r\n", fp);
			fputs("\r\n", fp);
			fclose(fp);
		}
		close(client);
	} else {
		CWMP_LOG(INFO, "Receive Connection Request: Return 401 Unauthorized");
		if (fp) {
			fputs("HTTP/1.1 401 Unauthorized\r\n", fp);
			fputs("Connection: close\r\n", fp);
			http_authentication_failure_resp(fp, "GET", cr_path, REALM, OPAQUE);
			fputs("\r\n", fp);
			fputs("\r\n", fp);
			fclose(fp);
		}
		close(client);
	}

	FREE(username);
	FREE(password);
	FREE(cr_path);
}

void icwmp_http_server_init(void)
{
	struct sockaddr_in6 server = { 0 };
	unsigned short cr_port;
	unsigned short prev_cr_port = (unsigned short)(cwmp_main->conf.connection_request_port);

	for (;;) {
		cr_port = (unsigned short)(cwmp_main->conf.connection_request_port);
		unsigned short i = (DEFAULT_CONNECTION_REQUEST_PORT == cr_port) ? 1 : 0;
		//Create socket
		if (cwmp_stop)
			return;

		cwmp_main->cr_socket_desc = socket(AF_INET6, SOCK_STREAM, 0);
		if (cwmp_main->cr_socket_desc == -1) {
			CWMP_LOG(ERROR, "Could not open server socket for Connection Requests, Error no is : %d, Error description is : %s", errno, strerror(errno));
			sleep(1);
			continue;
		}

		fcntl(cwmp_main->cr_socket_desc, F_SETFD, fcntl(cwmp_main->cr_socket_desc, F_GETFD) | FD_CLOEXEC);

		int reusaddr = 1;
		if (setsockopt(cwmp_main->cr_socket_desc, SOL_SOCKET, SO_REUSEADDR, &reusaddr, sizeof(int)) < 0) {
			CWMP_LOG(WARNING, "setsockopt(SO_REUSEADDR) failed");
		}

		//Prepare the sockaddr_in structure
		server.sin6_family = AF_INET6;
		server.sin6_addr = in6addr_any;

		for (;; i++) {
			if (cwmp_stop)
				return;

			server.sin6_port = htons(cr_port);
			//Bind
			if (bind(cwmp_main->cr_socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
				//print the error message
				CWMP_LOG(ERROR, "Could not bind server socket on the port %d, Error no is : %d, Error description is : %s", cr_port, errno, strerror(errno));
				cr_port = DEFAULT_CONNECTION_REQUEST_PORT + i;
				CWMP_LOG(INFO, "Trying to use another connection request port: %d", cr_port);
				continue;
			}
			break;
		}
		break;
	}

	if (cr_port != prev_cr_port) {
		char cr_port_str[6];
		snprintf(cr_port_str, 6, "%hu", cr_port);
		cr_port_str[5] = '\0';
		set_uci_path_value(NULL, "cwmp.cpe.port", cr_port_str);
		system(FIREWALL_CWMP);
		connection_request_port_value_change(cr_port);
	}

	CWMP_LOG(INFO, "Connection Request server initiated with the port: %d", cr_port);
}

void icwmp_http_server_listen(void)
{
	int c;
	int cr_request = 0;
	time_t restrict_start_time = 0;
	struct sockaddr_in6 client;

	//Listen
	listen(cwmp_main->cr_socket_desc, 3);

	//Accept and incoming connection
	c = sizeof(struct sockaddr_in);
	do {
		if (cwmp_stop)
			return;

		int client_sock = accept(cwmp_main->cr_socket_desc, (struct sockaddr *)&client, (socklen_t *)&c);
		if (client_sock < 0) {
			CWMP_LOG(ERROR, "Could not accept connections for Connection Request!");
			shutdown(cwmp_main->cr_socket_desc, SHUT_RDWR);
			icwmp_http_server_init();
			listen(cwmp_main->cr_socket_desc, 3);
			cr_request = 0;
			restrict_start_time = 0;
			continue;
		}

		bool service_available;
		time_t current_time;

		current_time = time(NULL);
		service_available = true;
		if ((restrict_start_time == 0) || ((current_time - restrict_start_time) > CONNECTION_REQUEST_RESTRICT_PERIOD)) {
			restrict_start_time = current_time;
			cr_request = 1;
		} else {
			cr_request++;
			if (cr_request > CONNECTION_REQUEST_RESTRICT_REQUEST) {
				restrict_start_time = current_time;
				service_available = false;
			}
		}
		http_cr_new_client(client_sock, service_available);
	} while (1);
}
