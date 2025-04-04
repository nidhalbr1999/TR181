/*
 * download.h - Download method functions
 *
 * Copyright (C) 2022, IOPSYS Software Solutions AB.
 *
 * 		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */
#ifndef CWMP_DOWNLOAD_H
#define CWMP_DOWNLOAD_H
#include "common.h"

#define DOWNLOAD_PROTOCOL_HTTP "http://"
#define DOWNLOAD_PROTOCOL_HTTPS "https://"
#define DOWNLOAD_PROTOCOL_FTP "ftp://"
#define ICWMP_DOWNLOAD_FILE "/tmp/icwmp_download"
#define FIRMWARE_UPGRADE_IMAGE "/tmp/firmware.bin"
#define WEB_CONTENT_FILE "/tmp/web_content.ipk"
#define VENDOR_CONFIG_FILE "/tmp/vendor_conf_file"

#define FIRMWARE_UPGRADE_IMAGE_FILE_TYPE "1 Firmware Upgrade Image"
#define WEB_CONTENT_FILE_TYPE "2 Web Content"
#define VENDOR_CONFIG_FILE_TYPE "3 Vendor Configuration File"
#define TONE_FILE_TYPE "4 Tone File"
#define RINGER_FILE_TYPE "5 Ringer File"
#define STORED_FIRMWARE_IMAGE_FILE_TYPE "6 Stored Firmware Image"

#define MAX_DOWNLOAD_QUEUE 10

extern struct list_head list_download;
extern struct list_head list_schedule_download;

extern int count_download_queue;

int cwmp_free_download_request(struct download *download);
int cwmp_free_schedule_download_request(struct download *schedule_download);
int cwmp_scheduledDownload_remove_all();
int cwmp_scheduled_Download_remove_all();
int cwmp_rpc_acs_destroy_data_transfer_complete(struct rpc *rpc);
int cwmp_launch_download(struct download *pdownload, char *download_file_name, enum load_type ltype, struct transfer_complete **ptransfer_complete);
void cwmp_start_download(struct uloop_timeout *timeout);
void apply_downloads();
void apply_schedule_downloads();
void cwmp_start_schedule_download(struct uloop_timeout *timeout);
#endif
