/*
 * cwmp-du_state.c - ChangeDUState method corresponding functions
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#include <libubox/blobmsg_json.h>
#include <stdlib.h>
#include <regex.h>

#include "cwmp_du_state.h"
#include "ubus_utils.h"
#include "log.h"
#include "datamodel_interface.h"
#include "backupSession.h"
#include "event.h"
#include "session.h"
#include <uuid/uuid.h>

LIST_HEAD(list_change_du_state);

static char *generate_uuid(void)
{
	uuid_t binuuid;

	uuid_generate_random(binuuid);
	char *uuid = malloc(37);
	uuid_unparse(binuuid, uuid);

	return uuid;
}

void ubus_du_state_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	char **fault = (char **)req->priv;
	const struct blobmsg_policy p[1] = { { "Result", BLOBMSG_TYPE_ARRAY } };
	struct blob_attr *tb[1] = { NULL };
	blobmsg_parse(p, 1, tb, blobmsg_data(msg), blobmsg_len(msg));
	if (tb[0]) {
		struct blob_attr *head = blobmsg_data(tb[0]);
		int len = blobmsg_data_len(tb[0]);
		struct blob_attr *attr;

		__blob_for_each_attr(attr, head, len) {
			struct blob_attr *data = blobmsg_data(attr);
			int data_len = blobmsg_data_len(attr);
			struct blob_attr *param;
			__blob_for_each_attr(param, data, data_len) {
				struct blobmsg_hdr *hdr = blob_data(attr);
				if (hdr && CWMP_STRCMP((char*)hdr->name, "fault") == 0) {
					*fault = strdup("9010");
					return;
				}
			}
		}
		*fault = NULL;
	} else {
		*fault = strdup("9010");
	}
}

static void prepare_blob_msg(struct blob_buf *b, char *url, char *uuid, char *user, char *pass, char *path, char *env_ref, int op)
{
	char command[256] = {0};
	void *tbl = NULL;

	if (b == NULL || CWMP_STRLEN(path) == 0)
		return;

	switch (op) {
	case DU_INSTALL:
		snprintf(command, sizeof(command), "%sInstallDU()", path);
		bb_add_string(b, "command", command);
		bb_add_string(b, "command_key", "cwmp_install_du");
		tbl = blobmsg_open_table(b, "input");
		bb_add_string(b, "UUID", uuid ? uuid : "");
		bb_add_string(b, "ExecutionEnvRef", env_ref ? env_ref : "");
		bb_add_string(b, "URL", url ? url : "");
		bb_add_string(b, "Username", user ? user : "");
		bb_add_string(b, "Password", pass ? pass : "");
		blobmsg_close_table(b, tbl);
		break;
	case DU_UPDATE:
		snprintf(command, sizeof(command), "%sUpdate()", path);
		bb_add_string(b, "command", command);
		bb_add_string(b, "command_key", "cwmp_update_du");
		tbl = blobmsg_open_table(b, "input");
		bb_add_string(b, "URL", url ? url : "");
		bb_add_string(b, "Username", user ? user : "");
		bb_add_string(b, "Password", pass ? pass : "");
		blobmsg_close_table(b, tbl);
		break;
	case DU_UNINSTALL:
		snprintf(command, sizeof(command), "%sUninstall()", path);
		bb_add_string(b, "command", command);
		bb_add_string(b, "command_key", "cwmp_uninstall_du");
		break;
	default:
		CWMP_LOG(ERROR, "Invalid DU operation");
	}
}

int cwmp_du_install(char *url, char *uuid, char *user, char *pass, char *path, char *env_ref, char **fault_code)
{
	int e;
	struct blob_buf b = { 0 };
	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	int len = CWMP_STRLEN(env_ref);
	if (len > 0 && env_ref[len - 1] == '.')
		env_ref[len - 1] = '\0';

	prepare_blob_msg(&b, url, uuid, user, pass, path, env_ref, DU_INSTALL);
	e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "operate", b.head, ubus_du_state_callback, fault_code);
	blob_buf_free(&b);

	if (e < 0) {
		CWMP_LOG(INFO, "Change du state install failed: Ubus err code: %d", e);
		return FAULT_CPE_INTERNAL_ERROR;
	}
	return FAULT_CPE_NO_FAULT;
}

int cwmp_du_update(char *url, char *user, char *pass, char *du_path, char **fault_code)
{
	struct blob_buf b = {0};

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	prepare_blob_msg(&b, url, 0, user, pass, du_path, "", DU_UPDATE);

	int e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "operate", b.head, ubus_du_state_callback, fault_code);
	blob_buf_free(&b);

	if (e < 0) {
		CWMP_LOG(INFO, "Change du state update failed: Ubus err code: %d", e);
		return FAULT_CPE_INTERNAL_ERROR;
	}
	return FAULT_CPE_NO_FAULT;
}

int cwmp_du_uninstall(char *du_path, char **fault_code)
{
	struct blob_buf b = {0};

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	prepare_blob_msg(&b, "", 0, "", "", du_path, "", DU_UNINSTALL);

	int e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "operate", b.head, ubus_du_state_callback, fault_code);
	blob_buf_free(&b);

	if (e < 0) {
		CWMP_LOG(INFO, "Change du state uninstall failed: Ubus err code: %d", e);
		return FAULT_CPE_INTERNAL_ERROR;
	}
	return FAULT_CPE_NO_FAULT;
}


static char *get_software_module_object_eq(char *param1, char *val1, char *param2, char *val2, struct list_head *sw_parameters)
{
	char *err = NULL;

	err = cwmp_get_parameter_values("Device.SoftwareModules.DeploymentUnit.", sw_parameters);
	if (err)
		return NULL;

	struct cwmp_dm_parameter *param_value;
	char instance[8] = {0};
	regex_t regex1 = {};
	regex_t regex2 = {};
	bool softwaremodule_filter_param = false;
	char regstr1[256];
	snprintf(regstr1, sizeof(regstr1), "^Device.SoftwareModules.DeploymentUnit.[0-9][0-9]*.%s$",param1);
	regcomp(&regex1, regstr1, 0);
	if (param2) {
		char regstr2[256];
		snprintf(regstr2, sizeof(regstr2), "^Device.SoftwareModules.DeploymentUnit.[0-9][0-9]*.%s$",param2);
		regcomp(&regex2, regstr2, 0);
	}

	list_for_each_entry (param_value, sw_parameters, list) {
		if (regexec(&regex1, param_value->name, 0, NULL, 0) == 0 && CWMP_STRCMP(param_value->value, val1) == 0)
			softwaremodule_filter_param = true;

		if (param2 && regexec(&regex2, param_value->name, 0, NULL, 0) == 0 && CWMP_STRCMP(param_value->value, val2) == 0)
			softwaremodule_filter_param = true;

		if (softwaremodule_filter_param == false)
			continue;

		snprintf(instance, (size_t)(strchr(param_value->name + strlen("Device.SoftwareModules.DeploymentUnit."), '.') - param_value->name - strlen("Device.SoftwareModules.DeploymentUnit.") + 1), "%s", (char *)(param_value->name + strlen("Device.SoftwareModules.DeploymentUnit.")));
		break;
	}
	return (strlen(instance) > 0) ? strdup(instance) : NULL;
}

static int get_deployment_unit_name_version(char *uuid, char **name, char **version, char **env)
{
	char *sw_by_uuid_instance = NULL, name_param[128], version_param[128], environment_param[128];
	LIST_HEAD(sw_parameters);
	sw_by_uuid_instance = get_software_module_object_eq("UUID", uuid, NULL, NULL, &sw_parameters);
	if (!sw_by_uuid_instance)
		return 0;

	snprintf(name_param, sizeof(name_param), "Device.SoftwareModules.DeploymentUnit.%s.Name", sw_by_uuid_instance);
	snprintf(version_param, sizeof(version_param), "Device.SoftwareModules.DeploymentUnit.%s.Version", sw_by_uuid_instance);
	snprintf(environment_param, sizeof(environment_param), "Device.SoftwareModules.DeploymentUnit.%s.ExecutionEnvRef", sw_by_uuid_instance);
	struct cwmp_dm_parameter *param_value = NULL;
	list_for_each_entry (param_value, &sw_parameters, list) {
		if (param_value->name == NULL)
			continue;
		if (strcmp(param_value->name, name_param) == 0) {
			*name = strdup(param_value->value ? param_value->value : "");
			continue;
		}
		if (strcmp(param_value->name, version_param) == 0) {
			*version = strdup(param_value->value ? param_value->value : "");
			continue;
		}
		if (strcmp(param_value->name, environment_param) == 0) {
			*env = strdup(param_value->value ? param_value->value : "");
			continue;
		}
	}
	cwmp_free_all_dm_parameter_list(&sw_parameters);
	return 1;
}

char *get_deployment_unit_by_uuid(char *uuid)
{
	if (uuid == NULL)
		return NULL;
	char *sw_by_uuid_instance = NULL;
	LIST_HEAD(sw_parameters);
	sw_by_uuid_instance = get_software_module_object_eq("UUID", uuid, NULL, NULL, &sw_parameters);
	return sw_by_uuid_instance;
}

static bool environment_exists(char *environment_path)
{
	LIST_HEAD(environment_list);
	char *err = cwmp_get_parameter_values(environment_path, &environment_list);
	cwmp_free_all_dm_parameter_list(&environment_list);
	if (err)
		return false;
	else
		return true;
}

static int cwmp_launch_du_install(char *url, char *uuid, char *user, char *pass, char *path, char *env_ref, struct opresult **pchange_du_state_complete)
{
	int error = FAULT_CPE_NO_FAULT;
	char *fault_code;

	(*pchange_du_state_complete)->start_time = strdup(get_time(time(NULL)));

	if (uuid == NULL) {
		(*pchange_du_state_complete)->fault_msg = strdup("No UUID information present");
		return FAULT_CPE_INTERNAL_ERROR;
	}

	/* store uuid in list for du state change event */
	du_op_uuid *node = (du_op_uuid *)malloc(sizeof(du_op_uuid));
	if (node == NULL) {
		(*pchange_du_state_complete)->fault_msg = strdup("Failed to allocate memory");
		return FAULT_CPE_INTERNAL_ERROR;
	}

	CWMP_MEMSET(node, 0, sizeof(du_op_uuid));
	snprintf(node->uuid, sizeof(node->uuid), "%s", uuid);
	snprintf(node->operation, sizeof(node->operation), "%s", "Install");

	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, &du_uuid_list);

	cwmp_du_install(url, uuid, user, pass, path, env_ref, &fault_code);

	if (fault_code != NULL) {
		if (fault_code[0] == '9') {
			int i;
			for (i = 1; i < __FAULT_CPE_MAX; i++) {
				if (strcmp(FAULT_CPE_ARRAY[i].CODE, fault_code) == 0) {
					error = i;
					break;
				}
			}
		}
		free(fault_code);
	}
	return error;
}

static int cwmp_launch_du_update(char *url, char *uuid, char *user, char *pass, char *du_path, struct opresult **pchange_du_state_complete)
{
	int error = FAULT_CPE_NO_FAULT;
	char *fault_code;

	(*pchange_du_state_complete)->start_time = strdup(get_time(time(NULL)));

	if (uuid == NULL) {
		(*pchange_du_state_complete)->fault_msg = strdup("No UUID information");
		return FAULT_CPE_INTERNAL_ERROR;
	}

	/* store uuid in list for du state change event */
	du_op_uuid *node = (du_op_uuid *)malloc(sizeof(du_op_uuid));
	if (node == NULL) {
		(*pchange_du_state_complete)->fault_msg = strdup("Failed to allocate memory");
		return FAULT_CPE_INTERNAL_ERROR;
	}

	CWMP_MEMSET(node, 0, sizeof(du_op_uuid));
	snprintf(node->uuid, sizeof(node->uuid), "%s", uuid);
	snprintf(node->operation, sizeof(node->operation), "%s", "Update");

	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, &du_uuid_list);

	cwmp_du_update(url, user, pass, du_path, &fault_code);
	if (fault_code != NULL) {
		if (fault_code[0] == '9') {
			int i;
			for (i = 1; i < __FAULT_CPE_MAX; i++) {
				if (strcmp(FAULT_CPE_ARRAY[i].CODE, fault_code) == 0) {
					error = i;
					break;
				}
			}
		}
		free(fault_code);
	}
	return error;
}

static int cwmp_launch_du_uninstall(char *du_path, char *uuid, struct opresult **pchange_du_state_complete)
{
	int error = FAULT_CPE_NO_FAULT;
	char *fault_code;

	(*pchange_du_state_complete)->start_time = strdup(get_time(time(NULL)));

	if (uuid == NULL) {
		(*pchange_du_state_complete)->fault_msg = strdup("No UUID value provided");
		return FAULT_CPE_INTERNAL_ERROR;
	}

	/* store uuid in list for du state change event */
	du_op_uuid *node = (du_op_uuid *)malloc(sizeof(du_op_uuid));
	if (node == NULL) {
		(*pchange_du_state_complete)->fault_msg = strdup("Failed to allocate memory");
		return FAULT_CPE_INTERNAL_ERROR;
	}

	CWMP_MEMSET(node, 0, sizeof(du_op_uuid));
	snprintf(node->uuid, sizeof(node->uuid), "%s", uuid);
	snprintf(node->operation, sizeof(node->operation), "%s", "Uninstall");

	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, &du_uuid_list);

	cwmp_du_uninstall(du_path, &fault_code);

	if (fault_code != NULL) {
		if (fault_code[0] == '9') {
			int i;
			for (i = 1; i < __FAULT_CPE_MAX; i++) {
				if (strcmp(FAULT_CPE_ARRAY[i].CODE, fault_code) == 0) {
					error = i;
					break;
				}
			}
		}
		free(fault_code);
	}
	return error;
}

char *get_package_name_by_url(char *url)
{
        char *slash = strrchr(url, '/');
        if (slash == NULL)
                return NULL;
        return slash+1;
}

int change_du_state_fault(struct change_du_state *pchange_du_state, struct du_state_change_complete **pdu_state_change_complete)
{
	int error = FAULT_CPE_NO_FAULT;
	struct operations *p, *q;

	*pdu_state_change_complete = calloc(1, sizeof(struct du_state_change_complete));
	if (*pdu_state_change_complete == NULL)
		return FAULT_CPE_INTERNAL_ERROR;

	error = FAULT_CPE_DOWNLOAD_FAILURE;
	INIT_LIST_HEAD(&((*pdu_state_change_complete)->list_opresult));
	(*pdu_state_change_complete)->command_key = strdup(pchange_du_state->command_key ? pchange_du_state->command_key : "");
	(*pdu_state_change_complete)->timeout = pchange_du_state->timeout;
	list_for_each_entry_safe (p, q, &pchange_du_state->list_operation, list) {
		struct opresult *res = calloc(1, sizeof(struct opresult));
		list_add_tail(&(res->list), &((*pdu_state_change_complete)->list_opresult));

		// cppcheck-suppress uninitvar
		if (CWMP_STRLEN(p->uuid) == 0) {
			char *uuid = generate_uuid();
			res->uuid = strdup(uuid);
			FREE(uuid);
		} else {
			res->uuid = strdup(p->uuid);
		}

		res->version = strdup(p->version);
		res->current_state = strdup("Failed");
		res->start_time = strdup(get_time(time(NULL)));
		res->complete_time = strdup(res->start_time);
		res->fault = error;
		res->fault_msg = strdup("Timeout expired");
	}
	if ((cwmp_main->cdu_complete_id < 0) || (cwmp_main->cdu_complete_id >= MAX_INT_ID)) {
		cwmp_main->cdu_complete_id = 0;
	}
	cwmp_main->cdu_complete_id++;
	(*pdu_state_change_complete)->id = cwmp_main->cdu_complete_id;
	bkp_session_insert_du_state_change_complete(*pdu_state_change_complete);
	bkp_session_save();
	//cwmp_root_cause_changedustate_complete(*pdu_state_change_complete);
	list_del(&(pchange_du_state->list));
	cwmp_free_change_du_state_request(pchange_du_state);
	return FAULT_CPE_NO_FAULT;
}

void change_du_state_execute(struct uloop_timeout *utimeout)
{
	int error = FAULT_CPE_NO_FAULT;
	char *package_version = NULL;
	char *package_name = NULL;
	char *package_env = NULL;
	struct operations *p, *q;
	struct opresult *res;
	struct du_state_change_complete *pdu_state_change_complete;
	char *du_ref = NULL;
	char du_path[2048] = {0};

	//struct session_timer_event cdu_inform_event = {.session_timer_evt = {.cb = cwmp_schedule_session_with_event}, .event = CDU_Evt};
	struct session_timer_event *cdu_inform_event = calloc(1, sizeof(struct session_timer_event));
	if (cdu_inform_event == NULL) {
		CWMP_LOG(ERROR, "%s:%d Failed to allocate memory", __func__, __LINE__);
		return;
	}

	struct change_du_state *pchange_du_state = container_of(utimeout, struct change_du_state, handler_timer);

	time_t current_time = time(NULL);
	time_t timeout = current_time - pchange_du_state->timeout;

	if ((timeout >= 0) && (timeout > CDU_TIMEOUT)) {
		int err = change_du_state_fault(pchange_du_state, &pdu_state_change_complete);
		if (err) {
			CWMP_LOG(ERROR, "Not able to create CDU Change Complete fault because of an internal error");
			return;
		}
		goto end;
	}

	pdu_state_change_complete = calloc(1, sizeof(struct du_state_change_complete));
	if (pdu_state_change_complete == NULL) {
		CWMP_LOG(ERROR, "%s:%d CDU state change failed in memory allocation", __func__, __LINE__);
		return;
	}

	error = FAULT_CPE_NO_FAULT;
	INIT_LIST_HEAD(&(pdu_state_change_complete->list_opresult));
	pdu_state_change_complete->command_key = strdup(pchange_du_state->command_key);
	pdu_state_change_complete->timeout = pchange_du_state->timeout;

	list_for_each_entry_safe (p, q, &pchange_du_state->list_operation, list) {
		res = calloc(1, sizeof(struct opresult));
		if (res == NULL) {
			CWMP_LOG(ERROR, "%s:%d CDU state change failed in memory allocation", __func__, __LINE__);
			break;
		}

		list_add_tail(&(res->list), &(pdu_state_change_complete->list_opresult));
		switch (p->type) {
		case DU_INSTALL:
			if (CWMP_STRLEN(p->executionenvref) != 0) {
				if (!environment_exists(p->executionenvref)) {
					res->fault = FAULT_CPE_INTERNAL_ERROR; //TODO
					res->fault_msg = strdup("Invalid execution environment reference");
					break;
				}
			}

			char *path = "Device.SoftwareModules.";
			bool uuid_generated = false;

			if (CWMP_STRLEN(p->uuid) == 0) {
				FREE(p->uuid);
				p->uuid = generate_uuid();
				if (p->uuid == NULL) {
					res->fault = FAULT_CPE_INTERNAL_ERROR;
					res->fault_msg = strdup("Failed to generate UUID");
					break;
				}

				uuid_generated = true;
			}

			error = cwmp_launch_du_install(p->url, p->uuid, p->username, p->password, path, p->executionenvref, &res);

			package_name = get_package_name_by_url(p->url);

			if (error != FAULT_CPE_NO_FAULT) {
				res->uuid = strdup(p->uuid);
				res->current_state = strdup("Failed");
				res->resolved = 0;
				res->complete_time = strdup(get_time(time(NULL)));
				res->fault = error;

				if (res->fault_msg == NULL)
					res->fault_msg = strdup(FAULT_CPE_ARRAY[error].DESCRIPTION);
				/* du state change event will be scheduled here, so remove uuid from list */
				remove_node_from_uuid_list(p->uuid, "Install");
			}

			FREE(du_ref);
			if (uuid_generated)
				FREE(p->uuid);

			break;

		case DU_UPDATE:
			if (p->url == NULL || p->uuid == NULL || *(p->url) == '\0' || *(p->uuid) == '\0') {
				error = FAULT_CPE_UNKNOWN_DEPLOYMENT_UNIT;
				res->fault_msg = strdup("No such argument to identify exact DU");
				break;
			}

			du_ref = get_deployment_unit_by_uuid(p->uuid);
			if (CWMP_STRLEN(du_ref) == 0) {
				error = FAULT_CPE_UNKNOWN_DEPLOYMENT_UNIT;
				res->fault_msg = strdup("Failed to identify the DU from the UUID");
				break;
			}

			snprintf(du_path, sizeof(du_path), "Device.SoftwareModules.DeploymentUnit.%s.", du_ref);

			error = cwmp_launch_du_update(p->url, p->uuid, p->username, p->password, du_path, &res);
			res->uuid = strdup(p->uuid);

			if (error != FAULT_CPE_NO_FAULT) {
				struct cwmp_dm_parameter dm_param = {0};
				char version_param_path[128] = {0};

				snprintf(version_param_path, sizeof(version_param_path), "%s.Version", du_ref);
				cwmp_get_parameter_value(version_param_path, &dm_param);

				res->current_state = strdup("Failed");
				res->resolved = 0;
				res->version = strdup(dm_param.value ? dm_param.value : "");
				res->du_ref = strdup(du_path);
				res->complete_time = strdup(get_time(time(NULL)));
				res->fault = error;

				if (res->fault_msg == NULL)
					res->fault_msg = strdup(FAULT_CPE_ARRAY[error].DESCRIPTION);

				/* du state change event will be scheduled here, so remove uuid from list */
				remove_node_from_uuid_list(p->uuid, "Update");
			}

			FREE(du_ref);
			break;

		case DU_UNINSTALL:
			if (p->uuid == NULL || *(p->uuid) == '\0') {
				res->fault = FAULT_CPE_UNKNOWN_DEPLOYMENT_UNIT;
				res->fault_msg = strdup("No UUID has been provided");
				break;
			}

			get_deployment_unit_name_version(p->uuid, &package_name, &package_version, &package_env);
			if (!package_name || *package_name == '\0' || !package_env || *package_env == '\0') {
				res->fault = FAULT_CPE_UNKNOWN_DEPLOYMENT_UNIT;
				res->fault_msg = strdup("Failed to get DU name and environment");
				break;
			}

			unsigned int pkg_eeid = 0, req_eeid = 0;
			if (CWMP_STRLEN(p->executionenvref) != 0) {
				sscanf(p->executionenvref, "Device.SoftwareModules.ExecEnv.%u", &req_eeid);
				sscanf(package_env, "Device.SoftwareModules.ExecEnv.%u", &pkg_eeid);

				if (req_eeid != pkg_eeid) {
					res->fault = FAULT_CPE_UNKNOWN_DEPLOYMENT_UNIT;
					res->fault_msg = strdup("Invalid execution environment information");
					break;
				}
			}

			du_ref = get_deployment_unit_by_uuid(p->uuid);
			if (CWMP_STRLEN(du_ref) == 0) {
				res->fault = FAULT_CPE_UNKNOWN_DEPLOYMENT_UNIT;
				res->fault_msg = strdup("Failed to identify the DU from UUID");
				break;
			}

			snprintf(du_path, sizeof(du_path), "Device.SoftwareModules.DeploymentUnit.%s.", du_ref);

			error = cwmp_launch_du_uninstall(du_path, p->uuid, &res);
			if (error != FAULT_CPE_NO_FAULT) {
				res->current_state = strdup("Installed");
				res->resolved = 1;
				res->du_ref = strdup(du_path);
				res->uuid = strdup(p->uuid);
				res->version = strdup(package_version ? package_version : "");
				res->complete_time = strdup(get_time(time(NULL)));
				res->fault = error;

				if (res->fault_msg == NULL)
					res->fault_msg = strdup(FAULT_CPE_ARRAY[error].DESCRIPTION);

				/* du state change event will be scheduled here, so remove uuid from list */
				remove_node_from_uuid_list(p->uuid, "Uninstall");
			}

			FREE(du_ref);
			FREE(package_name);
			FREE(package_version);
			FREE(package_env);
			break;
		}
	}
	bkp_session_delete_element("change_du_state", pchange_du_state->id);
	bkp_session_save();
	if ((cwmp_main->cdu_complete_id < 0) || (cwmp_main->cdu_complete_id >= MAX_INT_ID)) {
		cwmp_main->cdu_complete_id = 0;
	}
	cwmp_main->cdu_complete_id++;
	pdu_state_change_complete->id = cwmp_main->cdu_complete_id;
	bkp_session_insert_du_state_change_complete(pdu_state_change_complete);
	bkp_session_save();
	//cwmp_root_cause_changedustate_complete(pdu_state_change_complete);

	list_del(&(pchange_du_state->list));
	cwmp_free_change_du_state_request(pchange_du_state);
end:
	cdu_inform_event->extra_data = pdu_state_change_complete;
	cdu_inform_event->session_timer_evt.cb = cwmp_schedule_session_with_event;
	cdu_inform_event->event = CDU_Evt;
	trigger_cwmp_session_timer_with_event(&cdu_inform_event->session_timer_evt);

}

int cwmp_rpc_acs_destroy_data_du_state_change_complete(struct rpc *rpc)
{
	if (rpc && rpc->extra_data) {
		struct du_state_change_complete *p;
		p = (struct du_state_change_complete *)rpc->extra_data;
		bkp_session_delete_element("du_state_change_complete", p->id);
		bkp_session_save();
		FREE(p->command_key);

		struct opresult *data = NULL, *tmp = NULL;
		list_for_each_entry_safe(data, tmp, &(p->list_opresult), list) {
			FREE(data->uuid);
			FREE(data->du_ref);
			FREE(data->version);
			FREE(data->current_state);
			FREE(data->execution_unit_ref);
			FREE(data->start_time);
			FREE(data->complete_time);
			FREE(data->fault_msg);
			list_del(&(data->list));
			FREE(data);
		}

		FREE(rpc->extra_data);
	}

	return 0;
}

int cwmp_free_change_du_state_request(struct change_du_state *change_du_state)
{
	if (change_du_state != NULL) {
		struct list_head *ilist, *q;

		list_for_each_safe (ilist, q, &(change_du_state->list_operation)) {
			struct operations *operation = list_entry(ilist, struct operations, list);
			FREE(operation->url);
			FREE(operation->uuid);
			FREE(operation->username);
			FREE(operation->password);
			FREE(operation->version);
			FREE(operation->executionenvref);
			list_del(&(operation->list));
			FREE(operation);
		}
		FREE(change_du_state->command_key);
		FREE(change_du_state);
	}
	return CWMP_OK;
}

void apply_change_du_state()
{
	struct list_head *ilist;
	list_for_each (ilist, &(list_change_du_state)) {
		struct change_du_state *pchange_du_state = list_entry(ilist, struct change_du_state, list);;
		uloop_timeout_set(&pchange_du_state->handler_timer, 10);
	}
}

void remove_node_from_uuid_list(char *uuid, char *operation)
{
	if (uuid == NULL || operation == NULL)
		return;

	du_op_uuid *tmp, *q;
	list_for_each_entry_safe(tmp, q, &du_uuid_list, list) {
		if (CWMP_STRCMP(tmp->uuid, uuid) == 0 && CWMP_STRCMP(tmp->operation, operation) == 0) {
			list_del(&tmp->list);
			free(tmp);
			break;
		}
	}
}

bool exists_in_uuid_list(char *uuid, char *operation)
{
	if (uuid == NULL || operation == NULL)
		return false;

	du_op_uuid *tmp, *q;
	list_for_each_entry_safe(tmp, q, &du_uuid_list, list) {
		if (CWMP_STRCMP(tmp->uuid, uuid) == 0 && CWMP_STRCMP(tmp->operation, operation) == 0)
			return true;
	}

	return false;
}

void clean_du_uuid_list(void)
{
	du_op_uuid *tmp, *q;
	list_for_each_entry_safe(tmp, q, &du_uuid_list, list) {
		list_del(&tmp->list);
		free(tmp);
	}
}
