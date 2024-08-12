/*
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Copyright (C) 2013-2021 iopsys Software Solutions AB
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include <pthread.h>
#include "common.h"
#include "cwmp_http.h"
#include "http.h"
#include "log.h"
#include "uci_utils.h"

struct uloop_fd http_event6;

pthread_t http_cr_server_thread;

void http_server_listen_uloop(struct uloop_fd *ufd __attribute__((unused)), unsigned events __attribute__((unused)))
{
	icwmp_http_server_listen();
}

void http_server_start_uloop(void)
{
	icwmp_http_server_init();
	http_event6.fd = cwmp_main->cr_socket_desc;
	http_event6.cb = http_server_listen_uloop;
	uloop_fd_add(&http_event6, ULOOP_READ | ULOOP_EDGE_TRIGGER);
}

static void *thread_http_cr_server_listen(void *v __attribute__((unused)))
{
	icwmp_http_server_listen();
	return NULL;
}

void http_server_start(void)
{
	int error = pthread_create(&http_cr_server_thread, NULL, &thread_http_cr_server_listen, NULL);
	if (error < 0) {
		CWMP_LOG(ERROR, "Error when creating the http connection request server thread!");
	}
}

void http_server_stop(void)
{
	pthread_join(http_cr_server_thread, NULL);
}

static void set_http_ip_resolve(long ip_resolve)
{
	cwmp_main->net.ip_resolve = ip_resolve;
	set_uci_path_value(VARSTATE_CONFIG, "icwmp.acs.ip_version", (ip_resolve == CURL_IPRESOLVE_V6) ? "6" : "4");
}

int icwmp_check_http_connection(void)
{
	if (!cwmp_main->net.ipv6_status) {
		set_http_ip_resolve(CURL_IPRESOLVE_V4);
		return CWMP_OK;
	}

	long resolve = CURL_IPRESOLVE_V6;
	while(1) {
		CURL *c = curl_easy_init();
		if(c) {
			CURLcode ret;
			curl_easy_setopt(c, CURLOPT_FAILONERROR, true);
			curl_easy_setopt(c, CURLOPT_URL, cwmp_main->conf.acs_url);
			curl_easy_setopt(c, CURLOPT_CONNECT_ONLY, 1L);
			curl_easy_setopt(c, CURLOPT_IPRESOLVE, resolve);
			curl_easy_setopt(c, CURLOPT_TIMEOUT, 2);

			if (CWMP_STRLEN(cwmp_main->net.interface))
				curl_easy_setopt(c, CURLOPT_INTERFACE, cwmp_main->net.interface);

			ret = curl_easy_perform(c);
			if(ret == CURLE_OK) {
				int tmp = 1;
				char *ip = NULL;
				curl_easy_getinfo(c, CURLINFO_PRIMARY_IP, &ip);
				if (ip) {
					unsigned char buf[sizeof(struct in6_addr)];
					tmp = inet_pton(AF_INET, ip, buf);
				}

				if (tmp)
					set_http_ip_resolve(CURL_IPRESOLVE_V4);
				else
					set_http_ip_resolve(CURL_IPRESOLVE_V6);

				curl_easy_cleanup(c);
				return CWMP_OK;
			}
			curl_easy_cleanup(c);
		}
		if (resolve == CURL_IPRESOLVE_V6)
			resolve = CURL_IPRESOLVE_V4;
		else if (resolve == CURL_IPRESOLVE_V4)
			resolve = CURL_IPRESOLVE_WHATEVER;
		else
			break;
	}

	return -1;
}
