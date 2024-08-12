/*
 * upload.h - Upload method corresponding functions
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef CWMP_UPLOAD_H
#define CWMP_UPLOAD_H

#include "common.h"

#define MAX_UPLOAD_QUEUE 10

extern struct list_head list_upload;
extern int count_upload_queue;

int cwmp_launch_upload(struct upload *pupload, struct transfer_complete **ptransfer_complete);
void *thread_cwmp_rpc_cpe_upload(void *v);
int cwmp_scheduledUpload_remove_all();
int cwmp_free_upload_request(struct upload *upload);
void cwmp_start_upload(struct uloop_timeout *timeout);
void apply_upload();
#endif
