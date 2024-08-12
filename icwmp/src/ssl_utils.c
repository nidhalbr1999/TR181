/*
 * ssl_utils.c: Utility functions with ssl
 *
 * Copyright (C) 2022-2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * See LICENSE file for license related information.
 */

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <string.h>
#include <stdlib.h>

#include "ssl_utils.h"
#include "common.h"
#include "log.h"

static int rand_bytes(unsigned char *output, size_t len)
{
	return RAND_bytes(output, len);
}

char *generate_random_string(size_t size)
{
	unsigned char *buf = NULL;
	char *hex = NULL;

	buf = (unsigned char *)calloc(size + 1, sizeof(unsigned char));
	if (buf == NULL) {
		CWMP_LOG(ERROR, "Unable to allocate memory for buf string");
		goto end;
	}

	int written = rand_bytes(buf, size);
	if (written != 1) {
		CWMP_LOG(ERROR,"Failed to get random bytes");
		goto end;
	}

	hex = string_to_hex(buf, size);
	if (hex == NULL)
		goto end;

	hex[size] = '\0';

end:
	FREE(buf);
	return hex;
}

void message_compute_signature(char *msg_out, char *signature, size_t len)
{
	int result_len = 20;
	struct config *conf;
	unsigned char result[EVP_MAX_MD_SIZE] = {0};

	conf = &(cwmp_main->conf);
	HMAC(EVP_sha1(), conf->acs_passwd, CWMP_STRLEN(conf->acs_passwd), (unsigned char *)msg_out, CWMP_STRLEN(msg_out), result, NULL);

	for (int i = 0; i < result_len; i++) {
		if (len - CWMP_STRLEN(signature) < 3) // each time 2 hex chars + '\0' at end so needed space is 3 bytes
			break;

		snprintf(&(signature[i * 2]), 3, "%02X", result[i]);
	}
}


void calulate_md5_hash(struct list_head *buff_list, uint8_t *output, size_t outlen)
{
	unsigned int bytes = 0;

	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];

	if (!buff_list || !output)
		return;

	md = EVP_get_digestbyname("MD5");
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);

	if (md == NULL)
		goto end;

	bin_list_t *iter;
	list_for_each_entry(iter, buff_list, list) {
		EVP_DigestUpdate(mdctx, iter->bin, iter->len);
	}

	bytes = 0;
	EVP_DigestFinal_ex(mdctx, md_value, &bytes);

	CWMP_MEMCPY(output, &md_value, ((bytes<outlen)?bytes:outlen));

end:
	EVP_MD_CTX_destroy(mdctx);
	EVP_cleanup();
}

