/*
 * digauth.h - HTTP digest authentication utility
 *
 * Copyright (C) 2022, IOPSYS Software Solutions AB.
 *
 * Author: suvendhu.hansa@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */
#ifndef DIGAUTH_H_
#define DIGAUTH_H_

#include <stdio.h>

extern char *nonce_key;

void strip_lead_trail_char(char *str, char ch);
int get_nonce_key(void);
int validate_http_digest_auth(const char *http_meth, const char *uri, const char *hdr,
			      const char *rlm, const char *usr, const char *psw,
				  unsigned int timeout, const char *req_host);
int http_authentication_failure_resp(FILE *fp, const char *http_meth, const char *uri,
				     const char *rlm, const char *opq);

#endif /* DIGAUTH_H_ */
