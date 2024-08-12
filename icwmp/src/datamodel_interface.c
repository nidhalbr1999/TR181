/*
 * datamodel_interface.c - API to call BBF datamodel functions (set, get, add, delete, setattributes, getattributes, getnames, ...)
 *
 * Copyright (C) 2021-2023, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 *
 */

#include <libubox/blobmsg_json.h>

#include "datamodel_interface.h"
#include "ubus_utils.h"
#include "log.h"

unsigned int transaction_id = 0;

struct list_params_result {
	struct list_head *parameters_list;
	int error;
};

struct setm_values_res {
	bool status;
	struct list_head *faults_list;
};

/*
 * Common functions
 */
static struct blob_attr *get_results_array(struct blob_attr *msg)
{
	struct blob_attr *tb[1] = {0};
	const struct blobmsg_policy p[1] = {
			{ "results", BLOBMSG_TYPE_ARRAY }
	};

	if (msg == NULL)
		return NULL;

	blobmsg_parse(p, 1, tb, blobmsg_data(msg), blobmsg_len(msg));

	return tb[0];
}

static void prepare_optional_table(struct blob_buf *b)
{
	void *table = blobmsg_open_table(b, "optional");
	bb_add_string(b, "proto", "cwmp");
	bb_add_string(b, "format", "raw");
	blobmsg_add_u32(b, "instance_mode", cwmp_main->conf.instance_mode);
	blobmsg_add_u32(b, "transaction_id", transaction_id);
	blobmsg_close_table(b, table);
}

/*
 * Transaction Functions
 */
static void ubus_transaction_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *tb[3] = {0};
	const struct blobmsg_policy p[3] = {
			{ "status", BLOBMSG_TYPE_BOOL },
			{ "transaction_id", BLOBMSG_TYPE_INT32 },
			{ "updated_services", BLOBMSG_TYPE_ARRAY }
	};

	if (msg == NULL || req == NULL)
		return;

	bool *status = (bool *)req->priv;

	blobmsg_parse(p, 3, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[0]) {
		*status = false;
		return;
	}

	*status = blobmsg_get_u8(tb[0]);
	if (*status == false)
		return;

	if (tb[1]) {
		transaction_id = blobmsg_get_u32(tb[1]);
	}

	if (tb[2]) {
		struct blob_attr *updated_services = tb[2];
		struct blob_attr *service = NULL;
		size_t rem;

		blobmsg_for_each_attr(service, updated_services, rem) {
			char *service_name = blobmsg_get_string(service);

			if (CWMP_STRLEN(service_name) == 0)
				continue;

			CWMP_LOG(DEBUG, "Detected service: %s will be restarted in the end session", service_name);
			icwmp_add_service(service_name);
		}
	}
}

bool cwmp_transaction(const char *cmd)
{
	struct blob_buf b = {0};
	bool status = false;

	if (CWMP_STRLEN(cmd) == 0)
		return false;

	int start_cmp = CWMP_STRCMP(cmd, "start");
	int commit_cmp = CWMP_STRCMP(cmd, "commit");
	int abort_cmp = CWMP_STRCMP(cmd, "abort");

	if (start_cmp != 0 && commit_cmp != 0 && abort_cmp != 0)
		return false;

	if ((start_cmp == 0 && transaction_id != 0) ||
			((commit_cmp == 0 || abort_cmp == 0) && transaction_id == 0))
		return false;

	CWMP_LOG(INFO, "Transaction %s ...", cmd);

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));

	blob_buf_init(&b, 0);
	bb_add_string(&b, "cmd", cmd);
	blobmsg_add_u8(&b, "restart_services", false);
	prepare_optional_table(&b);

	int e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "transaction", b.head, ubus_transaction_callback, &status);

	blob_buf_free(&b);

	if (commit_cmp == 0 || abort_cmp == 0)
		transaction_id = 0;

	if (e != 0) {
		CWMP_LOG(INFO, "Transaction %s failed: Ubus err code: %d", cmd, e);
		return false;
	}

	if (!status) {
		CWMP_LOG(INFO, "Transaction %s failed: Status => false", cmd);
		return false;
	}

	return true;
}

/*
 * Get parameter value
 */
static void ubus_get_single_parameter_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *cur = NULL;
	int rem = 0;

	if (msg == NULL || req == NULL)
		return;

	struct cwmp_dm_parameter *result = (struct cwmp_dm_parameter *)req->priv;
	struct blob_attr *parameters = get_results_array(msg);

	if (parameters == NULL) {
		result->notification = FAULT_CPE_INTERNAL_ERROR;
		return;
	}

	blobmsg_for_each_attr(cur, parameters, rem) {
		struct blob_attr *tb[4] = {0};
		const struct blobmsg_policy p[4] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING },
				{ "fault", BLOBMSG_TYPE_INT32 }
		};

		blobmsg_parse(p, 4, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (tb[3]) {
			result->notification = blobmsg_get_u32(tb[3]);
			return;
		}

		result->name = icwmp_strdup(tb[0] ? blobmsg_get_string(tb[0]) : "");
		result->value = icwmp_strdup(tb[1] ? blobmsg_get_string(tb[1]) : "");
		result->type = icwmp_strdup(tb[2] ? blobmsg_get_string(tb[2]) : "");

		break;
	}
}

bool cwmp_get_parameter_value(const char *parameter_name, struct cwmp_dm_parameter *dm_parameter)
{
	struct blob_buf b = {0};
	int len = CWMP_STRLEN(parameter_name);

	if (len == 0 || parameter_name[len - 1] == '.')
		return false;

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	bb_add_string(&b, "path", parameter_name);
	prepare_optional_table(&b);

	int e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "get", b.head, ubus_get_single_parameter_callback, dm_parameter);

	blob_buf_free(&b);

	if (e < 0) {
		CWMP_LOG(INFO, "get ubus method failed: Ubus err code: %d", e);
		return false;
	}

	if (dm_parameter->notification) {
		CWMP_LOG(INFO, "Get parameter value of %s failed, fault_code: %d", parameter_name, dm_parameter->notification);
		return false;
	}

	return true;
}

/*
 * Get parameter Values/Names
 */
static void ubus_get_parameter_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *cur = NULL;
	int rem = 0;
	const struct blobmsg_policy p[4] = {
			{ "path", BLOBMSG_TYPE_STRING },
			{ "data", BLOBMSG_TYPE_STRING },
			{ "type", BLOBMSG_TYPE_STRING },
			{ "fault", BLOBMSG_TYPE_INT32 }
	};

	if (msg == NULL || req == NULL)
		return;

	struct list_params_result *result = (struct list_params_result *)req->priv;
	struct blob_attr *parameters = get_results_array(msg);

	if (parameters == NULL) {
		result->error = FAULT_CPE_INTERNAL_ERROR;
		return;
	}

	blobmsg_for_each_attr(cur, parameters, rem) {
		struct blob_attr *tb[4] = {0};

		blobmsg_parse(p, 4, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (tb[3]) {
			result->error = blobmsg_get_u32(tb[3]);
			return;
		}

		if (!tb[0]) continue;

		char *param_name = blobmsg_get_string(tb[0]);
		char *param_value = tb[1] ? blobmsg_get_string(tb[1]) : "";
		char *param_type = tb[2] ? blobmsg_get_string(tb[2]) : "";
		bool writable = strcmp(param_value, "1") == 0 ? true : false;

		add_dm_parameter_to_list(result->parameters_list, param_name, param_value, param_type, 0, writable);
	}
}

char *cwmp_get_parameter_values(const char *parameter_name, struct list_head *parameters_list)
{
	struct blob_buf b = {0};
	struct list_params_result get_result = {
			.parameters_list = parameters_list,
			.error = FAULT_CPE_NO_FAULT
	};
	unsigned int len = CWMP_STRLEN(parameter_name);

	if (len > 2 && parameter_name[len - 1] == '.' && parameter_name[len - 2] == '*')
		return "9005";

	const char *param = len ? parameter_name : "";

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	bb_add_string(&b, "path", param);
	prepare_optional_table(&b);

	int e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "get", b.head, ubus_get_parameter_callback, &get_result);
	blob_buf_free(&b);

	if (e < 0) {
		CWMP_LOG(WARNING, "Get failed (%s) Ubus err code: %d", param, e);
		return "9002";
	}

	if (get_result.error) {
		char buf[8] = {0};

		CWMP_LOG(WARNING, "Get parameter values (%s) failed: fault_code: %d", param, get_result.error);

		snprintf(buf, sizeof(buf), "%d", get_result.error);
		return icwmp_strdup(buf);
	}

	return NULL;
}

char *cwmp_get_parameter_names(const char *parameter_name, bool next_level, struct list_head *parameters_list)
{
	struct blob_buf b = {0};
	struct list_params_result get_result = {
			.parameters_list = parameters_list,
			.error = FAULT_CPE_NO_FAULT
	};
	unsigned int len = CWMP_STRLEN(parameter_name);

	if (len > 2 && parameter_name[len - 1] == '.' && parameter_name[len - 2] == '*')
		return "9005";

	const char *object = len ? parameter_name : "";

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	bb_add_string(&b, "path", object);
	blobmsg_add_u8(&b, "first_level", next_level);
	prepare_optional_table(&b);

	int e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "schema", b.head, ubus_get_parameter_callback, &get_result);
	blob_buf_free(&b);

	if (e < 0) {
		CWMP_LOG(INFO, "object_names ubus method failed: Ubus err code: %d", e);
		return "9002";
	}

	if (get_result.error) {
		char buf[8] = {0};

		CWMP_LOG(WARNING, "Get parameter Names (%s) failed: fault_code: %d", object, get_result.error);

		snprintf(buf, sizeof(buf), "%d", get_result.error);
		return icwmp_strdup(buf);
	}

	return NULL;
}

char *cwmp_validate_parameter_name(const char *param_name, bool next_level, struct list_head *param_list)
{
	struct blob_buf buf = {0};
	struct list_params_result get_result = {
			.parameters_list = param_list,
			.error = FAULT_CPE_NO_FAULT
	};
	unsigned int len = CWMP_STRLEN(param_name);

	if (len > 2 && param_name[len - 1] == '.' && param_name[len - 2] == '*')
		return "9005";

	const char *object = len ? param_name : "";

	CWMP_MEMSET(&buf, 0, sizeof(struct blob_buf));
	blob_buf_init(&buf, 0);

	bb_add_string(&buf, "path", object);
	blobmsg_add_u8(&buf, "first_level", next_level);
	prepare_optional_table(&buf);

	int e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "schema", buf.head, ubus_get_parameter_callback, &get_result);
	blob_buf_free(&buf);

	if (e < 0)
		return "9002";

	if (get_result.error) {
		char err[8] = {0};

		snprintf(err, sizeof(err), "%d", get_result.error);
		return icwmp_strdup(err);
	}

	return NULL;
}

/*
 * Set multiple parameter values
 */
static void ubus_set_value_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *cur = NULL;
	int rem = 0;
	const struct blobmsg_policy p[4] = {
			{ "path", BLOBMSG_TYPE_STRING },
			{ "data", BLOBMSG_TYPE_STRING },
			{ "fault", BLOBMSG_TYPE_INT32 },
			{ "fault_msg", BLOBMSG_TYPE_STRING },
	};

	if (msg == NULL || req == NULL)
		return;

	struct setm_values_res *result = (struct setm_values_res *)req->priv;
	struct blob_attr *parameters = get_results_array(msg);

	if (parameters == NULL) {
		result->status = false;
		return;
	}

	blobmsg_for_each_attr(cur, parameters, rem) {
		struct blob_attr *tb[4] = {0};

		blobmsg_parse(p, 4, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[0]) {
			result->status = false;
			continue;
		}

		if (tb[1]) continue;

		result->status = false;
		if (!tb[2]) continue;

		cwmp_add_list_fault_param(blobmsg_get_string(tb[0]), blobmsg_get_string(tb[3]), blobmsg_get_u32(tb[2]), result->faults_list);
	}
}

int cwmp_set_parameter_value(const char *parameter_name, const char *parameter_value, struct list_head *faults_list)
{
	struct blob_buf b = {0};
	int param_len = CWMP_STRLEN(parameter_name);
	struct setm_values_res set_result = {
			.faults_list = faults_list,
			.status = true
	};

	if (param_len == 0 || parameter_name[param_len - 1] == '.' || parameter_value == NULL)
		return FAULT_CPE_INVALID_ARGUMENTS;

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	bb_add_string(&b, "path", parameter_name);
	bb_add_string(&b, "value", parameter_value);
	prepare_optional_table(&b);

	int e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "set", b.head, ubus_set_value_callback, &set_result);

	blob_buf_free(&b);

	if (e < 0) {
		CWMP_LOG(INFO, "set ubus method failed: Ubus err code: %d", e);
		return FAULT_CPE_INTERNAL_ERROR;
	}

	if (set_result.status == false) {
		CWMP_LOG(INFO, "Set parameter value of %s  with %s value is failed", parameter_name, parameter_value);
		return FAULT_CPE_INVALID_ARGUMENTS;
	}

	return FAULT_CPE_NO_FAULT;
}

int cwmp_set_multi_parameters_value(struct list_head *parameters_values_list, struct list_head *faults_list)
{
	struct cwmp_dm_parameter *param_value = NULL;
	bool fault_occured = false;

	list_for_each_entry (param_value, parameters_values_list, list) {

		if (CWMP_STRLEN(param_value->name) == 0)
			continue;

		int res = cwmp_set_parameter_value(param_value->name, param_value->value, faults_list);
		if (res != FAULT_CPE_NO_FAULT)
			fault_occured = true;
	}

	return fault_occured ? FAULT_CPE_INVALID_ARGUMENTS : FAULT_CPE_NO_FAULT;
}

/*
 * Add Delete object
 */
static void ubus_objects_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *cur = NULL;
	int rem = 0;
	const struct blobmsg_policy p[3] = {
			{ "data", BLOBMSG_TYPE_STRING },
			{ "fault", BLOBMSG_TYPE_INT32 },
			{ "fault_msg", BLOBMSG_TYPE_STRING },
	};

	if (msg == NULL || req == NULL)
		return;

	struct object_result *result = (struct object_result *)req->priv;
	struct blob_attr *objects = get_results_array(msg);

	if (objects == NULL) {
		result->fault_code = FAULT_9002;
		return;
	}

	blobmsg_for_each_attr(cur, objects, rem) {
		struct blob_attr *tb[3] = {0};

		blobmsg_parse(p, 3, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (tb[1]) {
			result->fault_code = blobmsg_get_u32(tb[1]);
			snprintf(result->fault_msg, sizeof(result->fault_msg), "%s", tb[2] ? blobmsg_get_string(tb[2]) : "");
			return;
		}

		if (tb[0])
			result->instance = CWMP_STRDUP(blobmsg_get_string(tb[0]));
	}
}

bool cwmp_add_object(const char *object_name, struct object_result *res)
{
	struct blob_buf b = {0};

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	bb_add_string(&b, "path", object_name);
	prepare_optional_table(&b);

	int e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "add", b.head, ubus_objects_callback, res);

	blob_buf_free(&b);

	if (e < 0) {
		CWMP_LOG(INFO, "add_object ubus method failed: Ubus err code: %d", e);
		return false;
	}

	if (res->fault_code) {
		CWMP_LOG(WARNING, "Add Object (%s) failed: fault_code: %d", object_name, res->fault_code);
		return false;
	}

	return true;
}

bool cwmp_delete_object(const char *object_name, struct object_result *res)
{
	struct blob_buf b = {0};

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	bb_add_string(&b, "path", object_name);
	prepare_optional_table(&b);

	int e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "del", b.head, ubus_objects_callback, res);

	blob_buf_free(&b);

	if (e < 0) {
		CWMP_LOG(INFO, "delete object ubus method failed: Ubus err code: %d", e);
		return false;
	}

	if (res->fault_code) {
		CWMP_LOG(WARNING, "Delete Object (%s) failed: fault_code: %d", object_name, res->fault_code);
		return false;
	}

	return true;
}
