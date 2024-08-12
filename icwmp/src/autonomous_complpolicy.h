/*
 * autonomous_complpolicy.h - CWMP autonomous notification header
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef __AUTONOMOUS_COMPL_H
#define __AUTONOMOUS_COMPL_H

#include "libubus.h"
#include "common.h"

void autonomous_notification_handler(struct ubus_context *ctx __attribute__((unused)),
			struct ubus_event_handler *ev __attribute__((unused)),
			const char *type __attribute__((unused)), struct blob_attr *msg);
int cwmp_rpc_acs_destroy_data_autonomous_du_state_change_complete(struct rpc *rpc);
int cwmp_rpc_acs_destroy_data_autonomous_transfer_complete(struct rpc *rpc);
void free_autonomous_du_state_change_complete_data(auto_du_state_change_compl *p);
void free_autonomous_transfer_complete_data(auto_transfer_complete *p);
#endif
