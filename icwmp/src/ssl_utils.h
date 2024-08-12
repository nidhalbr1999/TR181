/*
 * ssl_utils.h: Utility functions with ssl
 *
 * Copyright (C) 2022-2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * See LICENSE file for license related information.
 */

#ifndef _SSL_UTILS
#define _SSL_UTILS

#include <libubox/list.h>

char *generate_random_string(size_t size);
void message_compute_signature(char *msg_out, char *signature, size_t len);
void calulate_md5_hash(struct list_head *buf_list, uint8_t *output, size_t outlen);

#endif
