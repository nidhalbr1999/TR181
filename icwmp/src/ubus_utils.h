/*
 * ubus_utils.h - ubus methods and utility functions
 *
 * Copyright (C) 2022, IOPSYS Software Solutions AB.
 *
 * Author: suvendhu.hansa@iopsys.eu
 *
 * See LICENSE file for license related information
 *
 */
#ifndef __ICWMP_UBUS_UTILS_H__
#define __ICWMP_UBUS_UTILS_H__

#include <libubus.h>
#include "common.h"

typedef void (*icwmp_ubus_cb)(struct ubus_request *req, int type, struct blob_attr *msg);

void bb_add_string(struct blob_buf *bb, const char *name, const char *value);
int icwmp_register_object(struct ubus_context *ctx);
int icwmp_delete_object(struct ubus_context *ctx);
int icwmp_ubus_invoke(const char *obj, const char *method, struct blob_attr *msg,
		      icwmp_ubus_cb icwmp_callback, void *callback_arg);
int icwmp_uloop_ubus_init();
void icwmp_uloop_ubus_exit();
int initiate_autonomous_complpolicy(void);
void clean_autonomous_complpolicy(void);
int initiate_interface_update(void);
void clean_interface_update(void);
#endif /* __ICWMP_UBUS_UTILS_H__ */
