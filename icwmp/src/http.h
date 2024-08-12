/*
 * http.h - API for HTTP exchanges
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
#ifndef _FREECWMP_HTTP_H__
#define _FREECWMP_HTTP_H__

#include <curl/curl.h>

#include "common.h"

#define HTTP_TIMEOUT 60

void http_set_timeout(void);

int icwmp_http_client_init();
void icwmp_http_client_exit(void);
int icwmp_http_send_message(char *msg_out, int msg_out_len, char **msg_in);

int http_cr_server_init(void);
void icwmp_http_server_listen(void);
void icwmp_http_server_init(void);
#endif
