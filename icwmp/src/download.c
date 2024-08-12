/*
 * download.c - Download method functions
 *
 * Copyright (C) 2022, IOPSYS Software Solutions AB.
 *
 * 		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */
#include <curl/curl.h>
#include <string.h>
#include <libubox/blobmsg_json.h>

#include "download.h"
#include "ubus_utils.h"
#include "backupSession.h"
#include "log.h"
#include "event.h"
#include "common.h"
#include "subprocess.h"
#include "session.h"
#include "uci_utils.h"

LIST_HEAD(list_download);
LIST_HEAD(list_schedule_download);

struct fwbank_dump {
	int bank_id;
	int status;
};

int count_download_queue = 0;

/*
 * Download File
 */
int download_file(const char *file_path, const char *url, const char *username, const char *password)
{
	if (url == NULL) {
		CWMP_LOG(ERROR, "download %s: no url specified", __FUNCTION__);
		return -1;
	}
	int res_code = 0;
	CURL *curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
		curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
		if (CWMP_STRLEN(username) > 0) {
			char userpass[1024];
			snprintf(userpass, sizeof(userpass), "%s:%s", username, password);
			curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
		}
		if (CWMP_STRNCMP(url, "https://", 8) == 0)
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_ANY);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 10000L);
		curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
		curl_easy_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, 1L);
		if (file_path == NULL)
			file_path = "/tmp/download_file";
		FILE *fp = fopen(file_path, "wb");
		if (fp) {
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
			curl_easy_perform(curl);
			fclose(fp);
		}
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res_code);

		curl_easy_cleanup(curl);
	}

	return res_code;
}

char *download_file_task_function(char *task)
{

	struct blob_buf bbuf;
	CWMP_MEMSET(&bbuf, 0, sizeof(struct blob_buf));
	blob_buf_init(&bbuf, 0);

	if (task == NULL) {
		CWMP_LOG(ERROR, "download %s: task is null", __FUNCTION__);
		return NULL;
	}
	if (blobmsg_add_json_from_string(&bbuf, task) == false) {
		blob_buf_free(&bbuf);
		return NULL;
	}
	const struct blobmsg_policy p[5] = { { "task", BLOBMSG_TYPE_STRING }, { "file_path", BLOBMSG_TYPE_STRING }, { "url", BLOBMSG_TYPE_STRING }, { "username", BLOBMSG_TYPE_STRING }, { "password", BLOBMSG_TYPE_STRING } };

	struct blob_attr *tb[5] = { NULL, NULL, NULL, NULL, NULL};
	blobmsg_parse(p, 5, tb, blobmsg_data(bbuf.head), blobmsg_len(bbuf.head));
	char *task_name = blobmsg_get_string(tb[0]);
	if (CWMP_STRCMP(task_name, "download") != 0)
		return NULL;
	char *file_path = blobmsg_get_string(tb[1]);
	char *url = blobmsg_get_string(tb[2]);
	char *username = blobmsg_get_string(tb[3]);
	char *password = blobmsg_get_string(tb[4]);

	int http_code = download_file(file_path, url, username, password);
	char *http_ret = (char *)malloc(4 * sizeof(char));
	snprintf(http_ret, 4, "%d", http_code);
	http_ret[3] = 0;
	return http_ret;
}

int download_file_in_subprocess(const char *file_path, const char *url, const char *username, const char *password)
{
	if (CWMP_OK != subprocess_start(download_file_task_function)) {
		CWMP_LOG(ERROR, "Failed to spawn subprocess to start download");
		return 500;
	}

	if (url == NULL) {
		CWMP_LOG(ERROR, "download %s: url is null");
		return 500;
	}

	struct blob_buf bbuf;
	CWMP_MEMSET(&bbuf, 0, sizeof(struct blob_buf));
	blob_buf_init(&bbuf, 0);
	blobmsg_add_string(&bbuf, "task", "download");
	blobmsg_add_string(&bbuf, "file_path", file_path ? file_path : "");
	blobmsg_add_string(&bbuf, "url", url ? url : "");
	blobmsg_add_string(&bbuf, "username", username ? username : "");
	blobmsg_add_string(&bbuf, "password", password ? password : "");
	char *download_task = blobmsg_format_json(bbuf.head, true);
	blob_buf_free(&bbuf);

	if (download_task != NULL) {
		char *ret = execute_task_in_subprocess(download_task);
		return ret ? atoi(ret) : 500;
	}

	return 500;
}
/*
 * Check if the downloaded image can be applied
 */
void ubus_check_image_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	if (msg == NULL) {
		CWMP_LOG(ERROR, "download %s: msg is null");
		return;
	}
	int *code = (int *)req->priv;
	const struct blobmsg_policy p[2] = { { "code", BLOBMSG_TYPE_INT32 }, { "stdout", BLOBMSG_TYPE_STRING } };
	struct blob_attr *tb[2] = { NULL, NULL };
	blobmsg_parse(p, 2, tb, blobmsg_data(msg), blobmsg_len(msg));

	*code = tb[0] ? blobmsg_get_u32(tb[0]) : 1;
}

int cwmp_check_image()
{
	int code = 0, e;
	struct blob_buf b = { 0 };
	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	CWMP_LOG(INFO, "Check downloaded image ...");
	e = icwmp_ubus_invoke("rpc-sys", "upgrade_test", b.head, ubus_check_image_callback, &code);
	if (e != 0) {
		CWMP_LOG(INFO, "rpc-sys upgrade_test ubus method failed: Ubus err code: %d", e);
		code = 1;
	}
	blob_buf_free(&b);
	return code;
}

/*
 * Get available bank
 */
void ubus_get_available_bank_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	if (msg == NULL) {
		CWMP_LOG(ERROR, "download: msg is null");
		return;
	}
	int *bank_id = (int *)req->priv;
	struct blob_attr *banks = NULL;
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, msg, rem)
	{
		if (blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY) {
			banks = cur;
			break;
		}
	}

	const struct blobmsg_policy p[8] = { { "name", BLOBMSG_TYPE_STRING },  { "id", BLOBMSG_TYPE_INT32 },	 { "active", BLOBMSG_TYPE_BOOL },  { "upgrade", BLOBMSG_TYPE_BOOL },
					     { "fwver", BLOBMSG_TYPE_STRING }, { "swver", BLOBMSG_TYPE_STRING }, { "fwver", BLOBMSG_TYPE_STRING }, { "status", BLOBMSG_TYPE_STRING } };

	blobmsg_for_each_attr(cur, banks, rem)
	{
		struct blob_attr *tb[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
		blobmsg_parse(p, 8, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[0])
			continue;

		if (blobmsg_get_bool(tb[2]) == false) {
			*bank_id = blobmsg_get_u32(tb[1]);
			break;
		}
	}
}

int get_available_bank_id()
{
	int bank_id = 0, e;
	struct blob_buf b = { 0 };
	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	e = icwmp_ubus_invoke("fwbank", "dump", b.head, ubus_get_available_bank_callback, &bank_id);
	if (e != 0) {
		CWMP_LOG(INFO, "fwbank dump ubus method failed: Ubus err code: %d", e);
	}

	blob_buf_free(&b);
	return bank_id;
}

/*
 * Get Bank Status
 */
void ubus_get_bank_status_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	if (msg == NULL) {
		CWMP_LOG(ERROR, "download %s: msg is null");
		return;
	}
	struct fwbank_dump *bank = (struct fwbank_dump *)req->priv;
	bool bank_found = false;
	struct blob_attr *banks = NULL;
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, msg, rem)
	{
		if (blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY) {
			banks = cur;
			break;
		}
	}

	const struct blobmsg_policy p[8] = { { "name", BLOBMSG_TYPE_STRING },  { "id", BLOBMSG_TYPE_INT32 },	 { "active", BLOBMSG_TYPE_BOOL },  { "upgrade", BLOBMSG_TYPE_BOOL },
					     { "fwver", BLOBMSG_TYPE_STRING }, { "swver", BLOBMSG_TYPE_STRING }, { "fwver", BLOBMSG_TYPE_STRING }, { "status", BLOBMSG_TYPE_STRING } };

	blobmsg_for_each_attr(cur, banks, rem)
	{
		struct blob_attr *tb[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
		blobmsg_parse(p, 8, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[0])
			continue;

		if (blobmsg_get_u32(tb[1]) == (uint32_t)bank->bank_id) {
			bank_found = true;
			char *status = blobmsg_get_string(tb[7]);
			if (CWMP_STRCMP(status, "Available") == 0 || CWMP_STRCMP(status, "Active") == 0)
				bank->status = 1;
			else
				bank->status = 0;
		}
	}
	if (bank_found == false)
		bank->status = 0;
}

int get_applied_firmware_status(struct fwbank_dump *bank)
{
	int e;
	struct blob_buf b = { 0 };
	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	e = icwmp_ubus_invoke("fwbank", "dump", b.head, ubus_get_available_bank_callback, &bank);

	if (e != 0) {
		CWMP_LOG(INFO, "fwbank dump ubus method failed: Ubus err code: %d", e);
	}
	blob_buf_free(&b);
	return e;
}

/*
 * Apply the new firmware
 */
int cwmp_apply_firmware()
{
	int e;
	struct blob_buf b = { 0 };
	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "keep", cwmp_main->conf.fw_upgrade_keep_settings);

	CWMP_LOG(INFO, "Apply downloaded image ...");
	e = icwmp_ubus_invoke("rpc-sys", "upgrade_start", b.head, NULL, NULL);
	if (e != 0) {
		CWMP_LOG(INFO, "rpc-sys upgrade_start ubus method failed: Ubus err code: %d", e);
	}

	blob_buf_free(&b);
	return e;
}

/*
 * Apply the web content
 */
static void ubus_get_download_status(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	if (msg == NULL) {
		CWMP_LOG(ERROR, "received msg is null");
		return;
	}

	bool *status = (bool *)req->priv;
	if (status == NULL)
		return;

	const struct blobmsg_policy p[1] = { { "success", BLOBMSG_TYPE_BOOL } };
	struct blob_attr *tb[1] = { NULL };
	blobmsg_parse(p, 1, tb, blobmsg_data(msg), blobmsg_len(msg));
	if (tb[0] == NULL) {
		CWMP_LOG(ERROR, "status not exists in received msg");
		return;
	}

	*status = blobmsg_get_bool(tb[0]);
}

bool cwmp_apply_web_content(char *filepath)
{
	int e;
	bool status = false;
	struct blob_buf b = { 0 };
	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "url", filepath ? filepath: "");
	blobmsg_add_string(&b, "filetype", WEB_CONTENT_FILE_TYPE);

	CWMP_LOG(INFO, "Apply downloaded web content ...");
	e = icwmp_ubus_invoke("cwmp.rpc", "download", b.head, ubus_get_download_status, &status);
	if (e != 0) {
		CWMP_LOG(INFO, "web-content install ubus method failed: Ubus err code: %d", e);
		status = false;
	}

	blob_buf_free(&b);
	return status;
}

void wait_firmware_to_be_applied(int bank_id)
{
	int count = 0;

	do {
		struct fwbank_dump bank = {.bank_id = bank_id, .status = 0};
		if (get_applied_firmware_status(&bank) != CWMP_OK)
			continue;

		if (bank.status == 1)
			break;

		sleep(2);
		count++;
	} while(count < 20);
}

int cwmp_apply_multiple_firmware()
{
	int e;
	int bank_id = get_available_bank_id();
	if (bank_id <= 0)
		return -1;

	struct blob_buf b = { 0 };
	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	bb_add_string(&b, "path", FIRMWARE_UPGRADE_IMAGE);
	blobmsg_add_u8(&b, "auto_activate", false);
	blobmsg_add_u32(&b, "bank", bank_id);
	blobmsg_add_u8(&b, "keep_settings", cwmp_main->conf.fw_upgrade_keep_settings);

	e = icwmp_ubus_invoke("fwbank", "upgrade", b.head, NULL, NULL);
	blob_buf_free(&b);

	if (e != 0) {
		CWMP_LOG(INFO, "fwbank upgrade ubus method failed: Ubus err code: %d", e);
		return -2;
	}
	//wait until the apply completes
	wait_firmware_to_be_applied(bank_id);
	return CWMP_OK;
}

char *apply_multiple_firmware_task_function(char *task __attribute__((unused)))
{
	int ret = cwmp_apply_multiple_firmware();

	char *ret_str = (char *)malloc(2 * sizeof(char));
	snprintf(ret_str, 2, "%d", ret);
	ret_str[1] = 0;
	return ret_str;
}

int cwmp_apply_multiple_firmware_in_subprocess()
{
	subprocess_start(apply_multiple_firmware_task_function);
	char *ret = execute_task_in_subprocess("{}"); //empty json object
	return ret ? atoi(ret) : 500;
}

int cwmp_launch_download(struct download *pdownload, char *download_file_name, enum load_type ltype, struct transfer_complete **ptransfer_complete)
{
	int error = FAULT_CPE_NO_FAULT;
	char *download_startTime;
	struct transfer_complete *p;
	char err_msg[256] = {0};

	download_startTime = get_time(time(NULL));

	bkp_session_delete_element((ltype == TYPE_DOWNLOAD) ? "download" : "schedule_download", pdownload->id);
	bkp_session_save();

	if (flashsize < pdownload->file_size) {
		error = FAULT_CPE_DOWNLOAD_FAILURE;
		snprintf(err_msg, sizeof(err_msg), "File size (%u) is larger than flash size (%u)", pdownload->file_size, flashsize);
		goto end_download;
	}

	int http_code = download_file_in_subprocess(ICWMP_DOWNLOAD_FILE, pdownload->url, pdownload->username, pdownload->password);
	if (http_code == 404) {
		error = FAULT_CPE_DOWNLOAD_FAIL_CONTACT_SERVER;
		snprintf(err_msg, sizeof(err_msg), "Failed to contact the file server (err_code: %d)", http_code);
	} else if (http_code == 401) {
		error = FAULT_CPE_DOWNLOAD_FAIL_FILE_AUTHENTICATION;
		snprintf(err_msg, sizeof(err_msg), "File server authentication failed (err_code: %d)", http_code);
	} else if (http_code != 200) {
		error = FAULT_CPE_DOWNLOAD_FAILURE;
		snprintf(err_msg, sizeof(err_msg), "File download failed (err_code: %d)", http_code);
	}

	if (error != FAULT_CPE_NO_FAULT)
		goto end_download;

	if (pdownload->file_type == NULL) {
		error = FAULT_CPE_INVALID_ARGUMENTS;
		snprintf(err_msg, sizeof(err_msg), "File type: null is not a valid value");
		goto end_download;
	}
	if (CWMP_STRCMP(pdownload->file_type, FIRMWARE_UPGRADE_IMAGE_FILE_TYPE) == 0 || CWMP_STRCMP(pdownload->file_type, STORED_FIRMWARE_IMAGE_FILE_TYPE) == 0) {
		rename(ICWMP_DOWNLOAD_FILE, FIRMWARE_UPGRADE_IMAGE);
		int ret = cwmp_check_image();

		if (ret == 0) {
			unsigned int file_size = get_file_size(FIRMWARE_UPGRADE_IMAGE);
			if (file_size > flashsize) {
				error = FAULT_CPE_DOWNLOAD_FAILURE;
				snprintf(err_msg, sizeof(err_msg), "File size: (%u) is larger than flash size: (%u)", file_size, flashsize);;
				remove(FIRMWARE_UPGRADE_IMAGE);
				goto end_download;
			} else {
				error = FAULT_CPE_NO_FAULT;
				goto end_download;
			}
		} else {
			error = FAULT_CPE_DOWNLOAD_FAIL_FILE_CORRUPTED;
			snprintf(err_msg, sizeof(err_msg), "Failed validation with %d of Downloaded file", ret);
			remove(FIRMWARE_UPGRADE_IMAGE);
		}
	} else if (CWMP_STRCMP(pdownload->file_type, WEB_CONTENT_FILE_TYPE) == 0) {
		if (download_file_name != NULL) {
			char file_path[512];
			snprintf(file_path, sizeof(file_path), "/tmp/%s", download_file_name);
			rename(ICWMP_DOWNLOAD_FILE, file_path);
		} else
			rename(ICWMP_DOWNLOAD_FILE, WEB_CONTENT_FILE);

		error = FAULT_CPE_NO_FAULT;
		goto end_download;
	} else if (CWMP_STRCMP(pdownload->file_type, VENDOR_CONFIG_FILE_TYPE) == 0) {
		if (download_file_name != NULL) {
			char file_path[512];
			snprintf(file_path, sizeof(file_path), "/tmp/%s", download_file_name);
			rename(ICWMP_DOWNLOAD_FILE, file_path);
		} else
			rename(ICWMP_DOWNLOAD_FILE, VENDOR_CONFIG_FILE);

		error = FAULT_CPE_NO_FAULT;
	}  else if (CWMP_STRCMP(pdownload->file_type, TONE_FILE_TYPE) == 0) {
		//TODO Not Supported
		error = FAULT_CPE_NO_FAULT;
	} else if (CWMP_STRCMP(pdownload->file_type, RINGER_FILE_TYPE) == 0) {
		//TODO Not Supported
		error = FAULT_CPE_NO_FAULT;

	} else {
		remove(ICWMP_DOWNLOAD_FILE);
		error = FAULT_CPE_INVALID_ARGUMENTS;
		snprintf(err_msg, sizeof(err_msg), "Invalid file type: (%s)", pdownload->file_type);
	}

end_download:
	p = calloc(1, sizeof(struct transfer_complete));
	if (p == NULL || ptransfer_complete == NULL) {
		CWMP_LOG(ERROR, "%s: Failed to allocate memory", __FUNCTION__);
		error = FAULT_CPE_INTERNAL_ERROR;
		return error;
	}

	p->command_key = pdownload->command_key ? strdup(pdownload->command_key) : strdup("");
	p->start_time = CWMP_STRDUP(download_startTime);
	p->complete_time = CWMP_STRDUP(get_time(time(NULL)));
	p->type = ltype;
	p->file_type = CWMP_STRDUP(pdownload->file_type);
	if (error != FAULT_CPE_NO_FAULT) {
		p->fault_code = error;
	}

	p->fault_string = strdup(err_msg);
	*ptransfer_complete = p;

	return error;
}

char *get_file_name_by_download_url(char *url)
{
	if (url == NULL) {
		CWMP_LOG(ERROR, "download %s: url is null", __FUNCTION__);
		return NULL;
	}
	char *slash = strrchr(url, '/');
	if (slash == NULL)
			return NULL;
	return slash+1;
}

int apply_downloaded_file(struct download *pdownload, char *download_file_name, struct transfer_complete *ptransfer_complete)
{
	int error = FAULT_CPE_NO_FAULT;
	char err_msg[256] = {0};

	if (pdownload->file_type[0] == '1') {
		ptransfer_complete->old_software_version = cwmp_main->deviceid.softwareversion;
	}
	if (ptransfer_complete->id <= 0) {
		if ((cwmp_main->tc_id < 0) || (cwmp_main->tc_id >= MAX_INT_ID)) {
			cwmp_main->tc_id = 0;
		}
		cwmp_main->tc_id++;
		ptransfer_complete->id = cwmp_main->tc_id;
	}
	bkp_session_insert_transfer_complete(ptransfer_complete);
	bkp_session_save();
	if (CWMP_STRCMP(pdownload->file_type, FIRMWARE_UPGRADE_IMAGE_FILE_TYPE) == 0) {
		set_uci_path_value(NULL, "cwmp.cpe.exec_download", "1");
		if (cwmp_apply_firmware() != 0) {
			error = FAULT_CPE_DOWNLOAD_FAIL_FILE_CORRUPTED;
			snprintf(err_msg, sizeof(err_msg), "Failed in applying the downloaded firmware image, may be corrupted file");
		}

		if (error == FAULT_CPE_NO_FAULT) {
			sleep(70);
			error = FAULT_CPE_DOWNLOAD_FAIL_FILE_CORRUPTED;
			snprintf(err_msg, sizeof(err_msg), "Downloaded firmware could not applied or reboot has not been taken after upgrade");
		}

	} else if (CWMP_STRCMP(pdownload->file_type, WEB_CONTENT_FILE_TYPE) == 0) {
		// apply web content file
		char file_path[512] = {0};
		if (download_file_name != NULL) {
			snprintf(file_path, sizeof(file_path), "file:///tmp/%s", download_file_name);
		} else {
			snprintf(file_path, sizeof(file_path), "file://%s", WEB_CONTENT_FILE);
		}

		if (cwmp_apply_web_content(file_path) == false) {
			error = FAULT_CPE_DOWNLOAD_FAIL_FILE_CORRUPTED;
			snprintf(err_msg, sizeof(err_msg), "Failed in applying the downloaded web content, may be corrupted file");
		} else
			error = FAULT_CPE_NO_FAULT;

		remove(file_path);
	} else if (CWMP_STRCMP(pdownload->file_type, VENDOR_CONFIG_FILE_TYPE) == 0) {
		int err = CWMP_OK;
		if (download_file_name != NULL) {
			char file_path[512];

			snprintf(file_path, sizeof(file_path), "/tmp/%s", download_file_name);
			if (strstr(download_file_name, ".uci.conf") != NULL) {
				err = import_uci_package(NULL, file_path);
			} else {
				err = import_uci_package(download_file_name, file_path);
			}
			remove(file_path);
		} else {
			err = import_uci_package("vendor_conf_file", VENDOR_CONFIG_FILE);
			remove(VENDOR_CONFIG_FILE);
		}

		if (err == CWMP_OK)
			error = FAULT_CPE_NO_FAULT;
		else if (err == CWMP_GEN_ERR) {
			error = FAULT_CPE_INTERNAL_ERROR;
			snprintf(err_msg, sizeof(err_msg), "Failed to commit the config file changes");
		} else if (err == -1) {
			error = FAULT_CPE_DOWNLOAD_FAIL_FILE_CORRUPTED;
			snprintf(err_msg, sizeof(err_msg), "UCI operation failed, could not import config file");
		}
	} else if (CWMP_STRCMP(pdownload->file_type, TONE_FILE_TYPE) == 0) {
		//TODO Not Supported
		error = FAULT_CPE_NO_FAULT;
	} else if (CWMP_STRCMP(pdownload->file_type, RINGER_FILE_TYPE) == 0) {
		//TODO Not Supported
		error = FAULT_CPE_NO_FAULT;

	} else if (CWMP_STRCMP(pdownload->file_type, STORED_FIRMWARE_IMAGE_FILE_TYPE) == 0) {
		int err = cwmp_apply_multiple_firmware();
		//int err = cwmp_apply_multiple_firmware_in_subprocess();
		if (err == CWMP_OK)
			error = FAULT_CPE_NO_FAULT;
		else {
			error = FAULT_CPE_DOWNLOAD_FAILURE;
			if (err == -1)
				snprintf(err_msg, sizeof(err_msg), "Failed to get available bank id");
			else
				snprintf(err_msg, sizeof(err_msg), "Failed in fwbank upgrade ubus method");
		}
	} else {
		error = FAULT_CPE_INVALID_ARGUMENTS;
		snprintf(err_msg, sizeof(err_msg), "Invalid file type argument (%s)", pdownload->file_type);
	}

	if ((error == FAULT_CPE_NO_FAULT) &&
	    (pdownload->file_type[0] == '1' || pdownload->file_type[0] == '3' || pdownload->file_type[0] == '2')) {
		set_rpc_parameter_key(pdownload->command_key);
		if (pdownload->file_type[0] == '3' || pdownload->file_type[0] == '2') {
			CWMP_LOG(INFO, "Download and apply new file type \"%s\" is done successfully", pdownload->file_type);
			//cwmp_root_cause_transfer_complete(ptransfer_complete);
			bkp_session_delete_element_by_key("transfer_complete", "start_time", ptransfer_complete->start_time);
		}
		return FAULT_CPE_NO_FAULT;
	}
	if (error != FAULT_CPE_NO_FAULT) {
		bkp_session_delete_element_by_key("transfer_complete", "start_time", ptransfer_complete->start_time);
		ptransfer_complete->fault_code = error;
	}
	if (ptransfer_complete->id <= 0) {
		if ((cwmp_main->tc_id < 0) || (cwmp_main->tc_id >= MAX_INT_ID)) {
			cwmp_main->tc_id = 0;
		}
		cwmp_main->tc_id++;
		ptransfer_complete->id = cwmp_main->tc_id;
	}
	ptransfer_complete->fault_string = strdup(err_msg);

	bkp_session_insert_transfer_complete(ptransfer_complete);
	bkp_session_save();
	//cwmp_root_cause_transfer_complete(ptransfer_complete);
	return error;
}

struct transfer_complete *set_download_error_transfer_complete(struct download *pdownload, enum load_type ltype)
{
	struct transfer_complete *ptransfer_complete;
	ptransfer_complete = calloc(1, sizeof(struct transfer_complete));
	if (ptransfer_complete != NULL) {
		ptransfer_complete->command_key = strdup(pdownload && pdownload->command_key ? pdownload->command_key : "");
		ptransfer_complete->start_time = CWMP_STRDUP(get_time(time(NULL)));
		ptransfer_complete->complete_time = strdup(ptransfer_complete->start_time ? ptransfer_complete->start_time  : "");
		ptransfer_complete->fault_code = ltype == TYPE_DOWNLOAD ? FAULT_CPE_DOWNLOAD_FAILURE : FAULT_CPE_DOWNLOAD_FAIL_WITHIN_TIME_WINDOW;
		ptransfer_complete->type = ltype;
		if (ptransfer_complete->id <= 0) {
			if ((cwmp_main->tc_id < 0) || (cwmp_main->tc_id >= MAX_INT_ID)) {
				cwmp_main->tc_id = 0;
			}
			cwmp_main->tc_id++;
			ptransfer_complete->id = cwmp_main->tc_id;
		}
		bkp_session_insert_transfer_complete(ptransfer_complete);
		cwmp_root_cause_transfer_complete(ptransfer_complete);
	}
	return ptransfer_complete;
}

int cwmp_free_download_request(struct download *download)
{
	if (download != NULL) {
		if (download->command_key != NULL)
			free(download->command_key);

		if (download->file_type != NULL)
			free(download->file_type);

		if (download->url != NULL)
			free(download->url);

		if (download->username != NULL)
			free(download->username);

		if (download->password != NULL)
			free(download->password);

		free(download);
	}
	return CWMP_OK;
}

int cwmp_free_schedule_download_request(struct download *schedule_download)
{
	if (schedule_download != NULL) {
		if (schedule_download->command_key != NULL)
			free(schedule_download->command_key);

		if (schedule_download->file_type != NULL)
			free(schedule_download->file_type);

		if (schedule_download->url != NULL)
			free(schedule_download->url);

		if (schedule_download->username != NULL)
			free(schedule_download->username);

		if (schedule_download->password != NULL)
			free(schedule_download->password);

		for (int i = 0; i <= 1; i++) {
			if (schedule_download->timewindowstruct[i].windowmode != NULL)
				free(schedule_download->timewindowstruct[i].windowmode);

			if (schedule_download->timewindowstruct[i].usermessage != NULL)
				free(schedule_download->timewindowstruct[i].usermessage);
		}
		free(schedule_download);
	}
	return CWMP_OK;
}

int cwmp_scheduledDownload_remove_all()
{
	while (list_download.next != &(list_download)) {
		struct download *download;
		download = list_entry(list_download.next, struct download, list);
		list_del(&(download->list));
		bkp_session_delete_element("schedule_download", download->id);
		if (download->scheduled_time != 0)
			count_download_queue--;
		cwmp_free_download_request(download);
	}

	return CWMP_OK;
}

int cwmp_scheduled_Download_remove_all()
{
	while (list_schedule_download.next != &(list_schedule_download)) {
		struct download *schedule_download;
		schedule_download = list_entry(list_schedule_download.next, struct download, list);
		list_del(&(schedule_download->list));
		bkp_session_delete_element("schedule_download", schedule_download->id);
		if (schedule_download->timewindowstruct[0].windowstart != 0)
			count_download_queue--;
		cwmp_free_schedule_download_request(schedule_download);
	}

	return CWMP_OK;
}

int cwmp_rpc_acs_destroy_data_transfer_complete(struct rpc *rpc)
{
	if (rpc && rpc->extra_data) {
		struct transfer_complete *p = (struct transfer_complete *)rpc->extra_data;
		bkp_session_delete_element_by_key("transfer_complete", "start_time", p->start_time);

		bkp_session_save();
		FREE(p->command_key);
		FREE(p->start_time);
		FREE(p->complete_time);
		FREE(p->old_software_version);
		FREE(p->file_type);
		FREE(p->fault_string);
	}
	if (rpc)
		FREE(rpc->extra_data);
	return 0;
}

void cwmp_start_download(struct uloop_timeout *timeout)
{
	struct download *pdownload;
	int error = FAULT_CPE_NO_FAULT;
	struct transfer_complete *ptransfer_complete;
	pdownload = container_of(timeout, struct download, handler_timer);

	char *download_file_name = get_file_name_by_download_url(pdownload->url);
	CWMP_LOG(INFO, "Launch download file %s", pdownload->url);
	error = cwmp_launch_download(pdownload, download_file_name, TYPE_DOWNLOAD, &ptransfer_complete);
	sleep(3);
	if (error != FAULT_CPE_NO_FAULT) {
		CWMP_LOG(ERROR, "Error while downloading the file: %s", pdownload->url);
		if (ptransfer_complete->id <= 0) {
			if ((cwmp_main->tc_id < 0) || (cwmp_main->tc_id >= MAX_INT_ID)) {
				cwmp_main->tc_id = 0;
			}
			cwmp_main->tc_id++;
			ptransfer_complete->id = cwmp_main->tc_id;
		}
		bkp_session_insert_transfer_complete(ptransfer_complete);
		bkp_session_save();
		//cwmp_root_cause_transfer_complete(ptransfer_complete);
		//bkp_session_delete_transfer_complete(ptransfer_complete);
	} else {
		error = apply_downloaded_file(pdownload, download_file_name, ptransfer_complete);
		if (error != FAULT_CPE_NO_FAULT) {
			CWMP_LOG(ERROR, "Error while applying the downloaded file: %s", download_file_name);
			if (ptransfer_complete->id <= 0) {
				if ((cwmp_main->tc_id < 0) || (cwmp_main->tc_id >= MAX_INT_ID)) {
					cwmp_main->tc_id = 0;
				}
				cwmp_main->tc_id++;
				ptransfer_complete->id = cwmp_main->tc_id;
			}
			bkp_session_insert_transfer_complete(ptransfer_complete);
			bkp_session_save();
			//cwmp_root_cause_transfer_complete(ptransfer_complete);
			//bkp_session_delete_transfer_complete(ptransfer_complete);
		}
	}
	if (error == FAULT_CPE_NO_FAULT && pdownload->file_type[0] == '3') {
		//cwmp_root_cause_transfer_complete(ptransfer_complete);
		bkp_session_delete_element_by_key("transfer_complete", "start_time", ptransfer_complete->start_time);
		bkp_session_delete_element("download", pdownload->id);
		bkp_session_save();
	}
	list_del(&(pdownload->list));
	if (pdownload->scheduled_time != 0)
		count_download_queue--;
	cwmp_free_download_request(pdownload);

	struct session_timer_event *download_inform_event = calloc(1, sizeof(struct session_timer_event));

	download_inform_event->extra_data = ptransfer_complete;
	download_inform_event->session_timer_evt.cb = cwmp_schedule_session_with_event;
	download_inform_event->event = TransferClt_Evt;
	trigger_cwmp_session_timer_with_event(&download_inform_event->session_timer_evt);
}

void apply_downloads()
{
	struct list_head *ilist;
	list_for_each (ilist, &(list_download)) {
		struct download *download = list_entry(ilist, struct download, list);
		int download_delay = 0;
		if (download->scheduled_time > time(NULL)) {
			download_delay = download->scheduled_time - time(NULL);
		}
		uloop_timeout_set(&download->handler_timer, 1000 * download_delay);
	}
}

void cwmp_start_schedule_download(struct uloop_timeout *timeout)
{
	struct download *sched_download;
	struct transfer_complete *ptransfer_complete;
	sched_download = container_of(timeout, struct download, handler_timer);
	bool outdate = false;
	int delay;
	int window_index;

	time_t now = time(NULL);
	if (sched_download->timewindowstruct[0].windowstart > now) {
		delay = sched_download->timewindowstruct[0].windowstart - now;
		uloop_timeout_set(&sched_download->handler_timer, 1000 * delay);
		return;
	} else if (sched_download->timewindowstruct[0].windowend >= now) {
		outdate = false;
		window_index = 0;
	} else if (sched_download->timewindowstruct[1].windowstart > now) {
		delay = sched_download->timewindowstruct[1].windowstart - now;
		uloop_timeout_set(&sched_download->handler_timer, 1000 * delay);
		return;
	} else if (sched_download->timewindowstruct[1].windowend >= now) {
		outdate = false;
		window_index = 1;
	} else {
		outdate = true;
	}

	if (!outdate) {
		int error;
		char *download_file_name = get_file_name_by_download_url(sched_download->url);
		CWMP_LOG(INFO, "Launch download file %s", sched_download->url);
		error = cwmp_launch_download(sched_download, download_file_name, TYPE_DOWNLOAD, &ptransfer_complete);
		sleep(3);
		if (error != FAULT_CPE_NO_FAULT) {
			CWMP_LOG(ERROR, "Error while downloading the file: %s", sched_download->url);
			goto retry;
		} else {
			error = apply_downloaded_file(sched_download, download_file_name, ptransfer_complete);
			if (error != FAULT_CPE_NO_FAULT) {
				CWMP_LOG(ERROR, "Error while applying the downloaded file: %s", download_file_name);
				goto retry;
			}
		}
		if (error == FAULT_CPE_NO_FAULT && sched_download->file_type[0] == '3') {
			//cwmp_root_cause_transfer_complete(ptransfer_complete);
			bkp_session_delete_element("schedule_download", sched_download->id);
			bkp_session_delete_element_by_key("transfer_complete", "start_time", ptransfer_complete->start_time);
			bkp_session_save();
		}
	} else {
		CWMP_LOG(ERROR, "Schedule Download out of date");
		ptransfer_complete = calloc(1, sizeof(struct transfer_complete));
		if (ptransfer_complete == NULL) {
			// error = FAULT_CPE_INTERNAL_ERROR;
			return;
		}

		ptransfer_complete->command_key = sched_download->command_key ? strdup(sched_download->command_key) : strdup("");
		ptransfer_complete->start_time = CWMP_STRDUP(get_time(now));
		ptransfer_complete->complete_time = CWMP_STRDUP(get_time(now));
		ptransfer_complete->type = TYPE_DOWNLOAD;
		ptransfer_complete->fault_code = FAULT_CPE_INTERNAL_ERROR;
		if (ptransfer_complete->id <= 0) {
			if ((cwmp_main->tc_id < 0) || (cwmp_main->tc_id >= MAX_INT_ID)) {
				cwmp_main->tc_id = 0;
			}
			cwmp_main->tc_id++;
			ptransfer_complete->id = cwmp_main->tc_id;
		}
		bkp_session_insert_transfer_complete(ptransfer_complete);
		bkp_session_save();
		//cwmp_root_cause_transfer_complete(ptransfer_complete);
		bkp_session_delete_element_by_key("transfer_complete", "start_time", ptransfer_complete->start_time);
	}

	return;

retry:
	if (sched_download->timewindowstruct[window_index].maxretries > 0) {
		uloop_timeout_set(&sched_download->handler_timer, 10);
		sched_download->timewindowstruct[window_index].maxretries--;
		return;
	} else {
		if (ptransfer_complete->id <= 0) {
			if ((cwmp_main->tc_id < 0) || (cwmp_main->tc_id >= MAX_INT_ID)) {
				cwmp_main->tc_id = 0;
			}
			cwmp_main->tc_id++;
			ptransfer_complete->id = cwmp_main->tc_id;
		}
		bkp_session_insert_transfer_complete(ptransfer_complete);
		bkp_session_save();
		//cwmp_root_cause_transfer_complete(ptransfer_complete);
		bkp_session_delete_element_by_key("transfer_complete", "start_time", ptransfer_complete->start_time);
		bkp_session_save();
	}
	list_del(&(sched_download->list));
	if (sched_download->scheduled_time != 0)
		count_download_queue--;
	cwmp_free_schedule_download_request(sched_download);

	struct session_timer_event *sched_download_inform_event = calloc(1, sizeof(struct session_timer_event));

	sched_download_inform_event->extra_data = ptransfer_complete;
	sched_download_inform_event->session_timer_evt.cb = cwmp_schedule_session_with_event;
	sched_download_inform_event->event = TransferClt_Evt;
	trigger_cwmp_session_timer_with_event(&sched_download_inform_event->session_timer_evt);
}

void apply_schedule_downloads()
{
	struct list_head *ilist;
	list_for_each (ilist, &(list_schedule_download)) {
		struct download *sched_download = list_entry(ilist, struct download, list);
		time_t now = time(NULL);
		int download_delay;
		if (sched_download->timewindowstruct[0].windowstart > now)
			download_delay = sched_download->timewindowstruct[0].windowstart - now;
		else if (sched_download->timewindowstruct[0].windowend >= now)
			download_delay = 1;
		else if (now < sched_download->timewindowstruct[1].windowstart)
			download_delay = sched_download->timewindowstruct[1].windowstart - now;
		else if (sched_download->timewindowstruct[1].windowend >= now)
			download_delay = 1;
		else
			download_delay = 1;

		uloop_timeout_set(&sched_download->handler_timer, 1000 * download_delay);
	}
}
