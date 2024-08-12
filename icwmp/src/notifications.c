/*
 * notifications.c - Manage CWMP Notifications
 *
 * Copyright (C) 2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#include <netdb.h>
#include <fcntl.h>

#include "notifications.h"
#include "uci_utils.h"
#include "datamodel_interface.h"
#include "ssl_utils.h"
#include "log.h"
#include "event.h"
#include "xml.h"
#include "cwmp_event.h"

#define UPSTREAM_STABILITY_CHECK_TIMESPAN 5  // In seconds
#define MANAGEABLE_DEVICES_NBRE "Device.ManagementServer.ManageableDeviceNumberOfEntries"
LIST_HEAD(list_value_change);

LIST_HEAD(list_lw_value_change);
LIST_HEAD(list_param_obj_notify);

struct uloop_timeout check_notify_timer = { .cb = periodic_check_notifiy };

char *supported_notification_types[7] = {"disabled" , "passive", "active", "passive_lw", "passive_passive_lw", "active_lw", "passive_active_lw"};

char *default_active_notifications_parameters[] = {
	"Device.ManagementServer.ConnectionRequestURL",
	"Device.ManagementServer.ConnReqJabberID",
	"Device.GatewayInfo.ManufacturerOUI",
	"Device.GatewayInfo.ProductClass",
	"Device.GatewayInfo.SerialNumber",
	"Device.SoftwareModules.ExecutionUnit.*.Status",
};

char *forced_notifications_parameters[] = {
	"Device.DeviceInfo.SoftwareVersion",
	"Device.DeviceInfo.ProvisioningCode"
};

/*
 * Common functions
 */
static bool parameter_is_subobject_of_parameter(char *parent, char *child)
{
	if (child == NULL) {
		CWMP_LOG(WARNING, "notifications %s: child is null", __FUNCTION__);
		return false;
	}
	if (parent == NULL)
		parent = "Device.";

	if (strcmp(parent, child) == 0)
		return false;
	if (strncmp(parent, child, strlen(parent)) == 0)
		return true;
	return false;
}

int check_parameter_forced_notification(const char *parameter)
{
	int i;

	if (parameter == NULL) {
		CWMP_LOG(WARNING, "notifications %s: parameter is null", __FUNCTION__);
		return 0;
	}

	for (i = 0; i < (int)ARRAY_SIZE(forced_notifications_parameters); i++) {
		if (strcmp(forced_notifications_parameters[i], parameter) == 0)
			return 2;
	}

	return 0;
}

char *check_valid_parameter_path(char *parameter_name)
{
	char *error = NULL;
	LIST_HEAD(parameters_list);

	/*check if parameter name is valid parameter path*/
	error = cwmp_validate_parameter_name(parameter_name, false, &parameters_list);

	if (error && CWMP_STRCMP(error, "9003") == 0)
		error = cwmp_get_parameter_values(parameter_name, &parameters_list);

	cwmp_free_all_dm_parameter_list(&parameters_list);

	return error;
}

/*
 * SetParameterAttributes
 */

// Add parameter_name to the suitable notifications list
int add_uci_option_notification(char *parameter_name, int type)
{
	char notif_path[BUF_SIZE_256] = {0};
	int ret;

	set_uci_path_value(ICWMPD_CONFIG, "cwmp_notifications.notifications", "notifications");
	snprintf(notif_path, BUF_SIZE_256, "cwmp_notifications.notifications.%s", supported_notification_types[type]);

	ret = set_uci_list_value(ICWMPD_CONFIG, notif_path, parameter_name);
	if (ret != UCI_OK)
		return -1;

	return ret;
}

bool check_parent_with_different_notification(char *parameter_name, int notification)
{
	int i;
	bool ret = false;

	for (i = 0; i < 7; i++) {
		char notif_path[BUF_SIZE_256] = {0};
		struct cwmp_dm_parameter *param_iter = NULL;
		LIST_HEAD(local_notify_list);

		snprintf(notif_path, BUF_SIZE_256, "cwmp_notifications.notifications.%s", supported_notification_types[i]);
		get_uci_dm_list(ICWMPD_CONFIG, notif_path, &local_notify_list, i);
		list_for_each_entry(param_iter, &local_notify_list, list) {
			if (CWMP_STRLEN(param_iter->name) == 0)
				continue;
			if (parameter_is_subobject_of_parameter(param_iter->name, parameter_name)) {
				ret = true;
				break;
			}
		}
		cwmp_free_all_dm_parameter_list(&local_notify_list);
		if (ret == true) {
			break;
		}
	}
	return ret;
}

bool update_notifications_list(char *parameter_name, int notification)
{
	int i;
	bool update_ret = true;

	if (parameter_name == NULL)
		parameter_name = "Device.";

	
	// Parse all possible lists of notifications one by one
	for (i = 0; i < 7; i++) {
		char notif_path[BUF_SIZE_256] = {0};
		struct cwmp_dm_parameter *param_iter = NULL;
		LIST_HEAD(local_notify_list);

		snprintf(notif_path, BUF_SIZE_256, "cwmp_notifications.notifications.%s", supported_notification_types[i]);
		get_uci_dm_list(ICWMPD_CONFIG, notif_path, &local_notify_list, i);
		list_for_each_entry(param_iter, &local_notify_list, list) {
			if (CWMP_STRLEN(param_iter->name) == 0)
				continue;

			if ((CWMP_STRCMP(parameter_name, param_iter->name) == 0 && (i != notification)) || parameter_is_subobject_of_parameter(parameter_name, param_iter->name))
				del_uci_list_value(ICWMPD_CONFIG, notif_path, param_iter->name);
			if ((CWMP_STRCMP(parameter_name, param_iter->name) == 0 || parameter_is_subobject_of_parameter(param_iter->name, parameter_name) ) && (i == notification))
				update_ret = false;
		}
		cwmp_free_all_dm_parameter_list(&local_notify_list);
	}

	if (update_ret && notification == 0 && !check_parent_with_different_notification(parameter_name, 0))
		update_ret = false;
	return update_ret;
}

char *cwmp_set_parameter_attributes(char *parameter_name, int notification)
{
       char *error = NULL;
 
       if (parameter_name == NULL)
               parameter_name = "Device.";
 
       /*Check if the parameter name is present in TR-181 datamodel*/
       error = check_valid_parameter_path(parameter_name);
       if (error != NULL)
               return error;

       /*Mustn't set notifications for forced notifications parameter*/
       if (check_parameter_forced_notification(parameter_name))
               return "9009";

       /*checks if the notifications lists need to be updated*/
       if (update_notifications_list(parameter_name, notification) == true)
               add_uci_option_notification(parameter_name, notification);

       return NULL;
}

int cwmp_set_parameter_attributes_list(struct list_head *parameters_list)
{
	struct cwmp_dm_parameter *param_iter = NULL;
	int ret = CWMP_OK;

	list_for_each_entry (param_iter, parameters_list, list) {
		char *parameter_name = param_iter->name;
		int notif_type = param_iter->notification;
		char *error = NULL;

		error = cwmp_set_parameter_attributes(parameter_name, notif_type);
		if (error != NULL) {
			CWMP_LOG(ERROR, "Invalid/forced parameter %s, skipped %s", parameter_name, error);
			continue;
		}
	}

	return ret;
}

/*
 * GetPrameterAttributes
 */
int get_parameter_family_notifications(char *parameter_name, struct list_head *childs_notifications) {

	int i, notif_ret = 0;

	if (parameter_name == NULL)
		parameter_name = "Device.";

	for (i = 0; i < 7; i++) {
		char *parent_param = NULL;
		char notif_path[BUF_SIZE_256] = {0};
		LIST_HEAD(local_notify_list);
		struct cwmp_dm_parameter *param_iter = NULL;

		snprintf(notif_path, BUF_SIZE_256, "cwmp_notifications.notifications.%s", supported_notification_types[i]);
		get_uci_dm_list(ICWMPD_CONFIG, notif_path, &local_notify_list, i);
		list_for_each_entry(param_iter, &local_notify_list, list) {
			if (CWMP_STRLEN(param_iter->name) == 0)
				continue;

			if (parameter_is_subobject_of_parameter(parameter_name, param_iter->name)) {
				add_dm_parameter_to_list(childs_notifications, param_iter->name, "", "", i, false);
			}

			// cppcheck-suppress knownConditionTrueFalse
			if (parameter_is_subobject_of_parameter(param_iter->name, parameter_name) && (parent_param == NULL || parameter_is_subobject_of_parameter(parent_param, param_iter->name))) {

				parent_param = CWMP_STRDUP(param_iter->name);
				notif_ret = i;
			}
			if (CWMP_STRCMP(parameter_name, param_iter->name) == 0)
				notif_ret = i;
		}
		FREE(parent_param);
		cwmp_free_all_dm_parameter_list(&local_notify_list);
	}

	return notif_ret;
}

int get_parameter_leaf_notification_from_childs_list(char *parameter_name, struct list_head *childs_list)
{
	char *parent = NULL;
	int ret_notif = -1;
	struct cwmp_dm_parameter *param_value = NULL;
	if (childs_list == NULL)
		return -1;
	list_for_each_entry (param_value, childs_list, list) {
		if (CWMP_STRCMP(param_value->name, parameter_name) == 0) {
			ret_notif = param_value->notification;
			break;
		}
		if (parameter_is_subobject_of_parameter(param_value->name, parameter_name) && ( parent == NULL || parameter_is_subobject_of_parameter(parent, param_value->name))) {
			parent = param_value->name;
			ret_notif = param_value->notification;
		}
	}
	return ret_notif;
}

char *cwmp_get_parameter_attributes(char *parameter_name, struct list_head *parameters_list)
{
	char *error = NULL;

	if (parameter_name == NULL || parameters_list == NULL) {
		CWMP_LOG(ERROR, "notifications %s: childs_list is null", __FUNCTION__);
		return NULL;
	}

	error = check_valid_parameter_path(parameter_name);
	if (error != NULL)
		return error;

	LIST_HEAD(childs_notifs);
	int notification = get_parameter_family_notifications(parameter_name, &childs_notifs);
	LIST_HEAD(params_list);
	error = cwmp_get_parameter_values(parameter_name, &params_list);
	if (error != NULL) {
		cwmp_free_all_dm_parameter_list(&childs_notifs);
		return error;
	}
	struct cwmp_dm_parameter *param_value = NULL;
	list_for_each_entry (param_value, &params_list, list) {
		int notif_leaf;
		notif_leaf = check_parameter_forced_notification(param_value->name);
		if (notif_leaf > 0) {
			add_dm_parameter_to_list(parameters_list, param_value->name, "", "", notif_leaf, false);
			continue;
		}
		notif_leaf = get_parameter_leaf_notification_from_childs_list(param_value->name, &childs_notifs);
		if (notif_leaf == -1) { //param_value is not among childs_notifs
			add_dm_parameter_to_list(parameters_list, param_value->name, "", "", notification, false);
		}
		else { //param_value is among childs_notifs
			add_dm_parameter_to_list(parameters_list, param_value->name, "", "", notif_leaf, false);
		}
	}
	cwmp_free_all_dm_parameter_list(&childs_notifs);
	cwmp_free_all_dm_parameter_list(&params_list);
	return NULL;
}

/*
 * Update notify file
 */
bool parameter_is_other_notif_object_child(char *parent, char *parameter)
{
	struct list_head list_iter, *list_ptr;
	list_iter.next = list_param_obj_notify.next;
	list_iter.prev = list_param_obj_notify.prev;

	if (parent == NULL)
		parent = "Device.";
	if (parameter == NULL)
		parameter = "Device.";
	while (list_iter.prev != &list_param_obj_notify) {
		struct cwmp_dm_parameter *dm_parameter;
		if (list_iter.prev == NULL)
			continue;

		dm_parameter = list_entry(list_iter.prev, struct cwmp_dm_parameter, list);
		list_ptr = list_iter.prev;
		list_iter.prev = list_ptr->prev;
		list_iter.next = list_ptr->next;
		if (dm_parameter->name == NULL)
			continue;
		if (CWMP_STRCMP(parent, dm_parameter->name) == 0)
			continue;
		if (CWMP_STRNCMP(parent, dm_parameter->name, strlen(parent)) == 0 && CWMP_STRNCMP(parameter, dm_parameter->name, strlen(dm_parameter->name)) == 0)
			return true;
	}
	return false;
}

char* update_list_param_leaf_notify_with_sub_parameter_list(struct list_head *list_param_leaf_notify, char* parent_parameter, int parent_notification, bool parent_forced_notif, void (*update_notify_file_line_arg)(FILE *notify_file, char *param_name, char *param_type, char *param_value, int notification), FILE* notify_file_arg)
{
	struct cwmp_dm_parameter *param_iter = NULL;
	LIST_HEAD(params_list);
	char *err = cwmp_get_parameter_values(parent_parameter, &params_list);
	if (err)
		return err;
	list_for_each_entry (param_iter, &params_list, list) {
		if (parent_forced_notif || (!parameter_is_other_notif_object_child(parent_parameter, param_iter->name) && !check_parameter_forced_notification(param_iter->name))) {
			if (list_param_leaf_notify != NULL)
				add_dm_parameter_to_list(list_param_leaf_notify, param_iter->name, param_iter->value, "", parent_notification, false);
			if (notify_file_arg != NULL && update_notify_file_line_arg != NULL)
				update_notify_file_line_arg(notify_file_arg, param_iter->name, param_iter->type, param_iter->value, parent_notification);
		}
	}
	cwmp_free_all_dm_parameter_list(&params_list);
	return NULL;
}

void create_list_param_leaf_notify(struct list_head *list_param_leaf_notify, void (*update_notify_file_line_arg)(FILE *notify_file, char *param_name, char *param_type, char *param_value, int notification), FILE* notify_file_arg)
{
	struct cwmp_dm_parameter *param_iter = NULL;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(forced_notifications_parameters); i++)
		update_list_param_leaf_notify_with_sub_parameter_list(list_param_leaf_notify, forced_notifications_parameters[i], 2, true, update_notify_file_line_arg, notify_file_arg);

	list_for_each_entry (param_iter, &list_param_obj_notify, list) {
		if (param_iter->notification == 0)
			continue;
		update_list_param_leaf_notify_with_sub_parameter_list(list_param_leaf_notify, param_iter->name, param_iter->notification, false, update_notify_file_line_arg, notify_file_arg);
	}
}

void init_list_param_notify()
{
	int i;

	for (i = 0; i < 7; i++) {
		char notif_path[BUF_SIZE_256] = {0};

		snprintf(notif_path, BUF_SIZE_256, "cwmp_notifications.notifications.%s", supported_notification_types[i]);
		get_uci_dm_list(ICWMPD_CONFIG, notif_path, &list_param_obj_notify, i);
	}
}

void clean_list_param_notify()
{
	cwmp_free_all_dm_parameter_list(&list_param_obj_notify);
}

void reinit_list_param_notify()
{
	clean_list_param_notify();
	init_list_param_notify();
}

void update_notify_file_line(FILE *notify_file, char *param_name, char *param_type, char *param_value, int notification)
{
	if (notify_file == NULL)
		return;
	if (param_name == NULL)
		return;
	struct blob_buf bbuf;
	CWMP_MEMSET(&bbuf, 0, sizeof(struct blob_buf));
	blob_buf_init(&bbuf, 0);
	blobmsg_add_string(&bbuf, "parameter", param_name);
	blobmsg_add_u32(&bbuf, "notification", notification);
	blobmsg_add_string(&bbuf, "type", param_type ? param_type : "xsd:string");
	blobmsg_add_string(&bbuf, "value", param_value ? param_value : "");
	char *notification_line = blobmsg_format_json(bbuf.head, true);
	if (notification_line != NULL) {
		fprintf(notify_file, "%s\n", notification_line);
		FREE(notification_line);
	}
	blob_buf_free(&bbuf);
}

void cwmp_update_enabled_notify_file(void)
{
	FILE *fp = NULL;

	LIST_HEAD(list_notify_params);
	remove(DM_ENABLED_NOTIFY);
	fp = fopen(DM_ENABLED_NOTIFY, "a");
	if (fp == NULL)
		return;

	create_list_param_leaf_notify(NULL, update_notify_file_line, fp);
	fclose(fp);
}

/*
 * Load custom notify json file
 */
void load_custom_notify_json(void)
{
	struct blob_buf bbuf = {0};
	struct blob_attr *cur = NULL;
	struct blob_attr *custom_notify_list = NULL;
	int rem = 0;

	cwmp_main->custom_notify_active = false;
	if (!file_exists(cwmp_main->conf.custom_notify_json))
		return;

	// Check for custom notification success import marker
	if (file_exists(NOTIFY_MARKER) == true)
		return;

	CWMP_MEMSET(&bbuf, 0, sizeof(struct blob_buf));
	blob_buf_init(&bbuf, 0);

	// Create success marker in temp area, so that it can be in sync with backup script
	if (blobmsg_add_json_from_file(&bbuf, cwmp_main->conf.custom_notify_json) == false) {
		CWMP_LOG(WARNING, "The file %s is not a valid JSON file", cwmp_main->conf.custom_notify_json);
		blob_buf_free(&bbuf);
		creat(RUN_NOTIFY_MARKER, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		return;
	}

	struct blob_attr *tb_notif[1] = {0};
	const struct blobmsg_policy p_notif[1] = {
			{ "custom_notification", BLOBMSG_TYPE_ARRAY }
	};

	blobmsg_parse(p_notif, 1, tb_notif, blobmsg_data(bbuf.head), blobmsg_len(bbuf.head));
	if (tb_notif[0] == NULL) {
		CWMP_LOG(WARNING, "The JSON file %s doesn't contain a notify parameters list", cwmp_main->conf.custom_notify_json);
		blob_buf_free(&bbuf);
		creat(RUN_NOTIFY_MARKER, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		return;
	}

	custom_notify_list = tb_notif[0];

	const struct blobmsg_policy p[2] = {
			{ "parameter", BLOBMSG_TYPE_STRING },
			{ "notify_type", BLOBMSG_TYPE_STRING }
	};

	LIST_HEAD(notification_list_head);
	blobmsg_for_each_attr(cur, custom_notify_list, rem) {
		struct blob_attr *tb[2] = { 0, 0 };

		blobmsg_parse(p, 2, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[0] || !tb[1])
			continue;

		if (!icwmp_validate_int_in_range(blobmsg_get_string(tb[1]), 0, 6)) {
			CWMP_LOG(WARNING, "Wrong notification value: %s", blobmsg_get_string(tb[1]));
			continue;
		}

		add_dm_parameter_to_list(&notification_list_head, blobmsg_get_string(tb[0]), "", "", atoi(blobmsg_get_string(tb[1])), false);
	}
	blob_buf_free(&bbuf);
	cwmp_set_parameter_attributes_list(&notification_list_head);
	cwmp_free_all_dm_parameter_list(&notification_list_head);

	creat(RUN_NOTIFY_MARKER, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	cwmp_main->custom_notify_active = true;
}

void set_default_forced_active_parameters_notifications()
{
	LIST_HEAD(forced_list_head);
	for (size_t i = 0; i < ARRAY_SIZE(default_active_notifications_parameters); i++) {
		add_dm_parameter_to_list(&forced_list_head, default_active_notifications_parameters[i], "", "", 2, false);
	}
	cwmp_set_parameter_attributes_list(&forced_list_head);
	cwmp_free_all_dm_parameter_list(&forced_list_head);
}

/*
 * Check value change
 */
void get_parameter_value_from_parameters_list(struct list_head *params_list, char *parameter_name, char **value, char **type)
{
	struct cwmp_dm_parameter *param_value = NULL;

	if (params_list == NULL) {
		CWMP_LOG(ERROR, "notifications %s: params_list is null", __FUNCTION__);
		return;
	}
	if (parameter_name == NULL)
		parameter_name = "Device.";

	list_for_each_entry (param_value, params_list, list) {
		if (param_value->name == NULL)
			continue;
		if (strcmp(parameter_name, param_value->name) != 0)
			continue;
		*value = strdup(param_value->value ? param_value->value : "");
		*type = strdup(param_value->type ? param_value->type : "");
	}
}

int check_value_change(void)
{
	FILE *fp;
	char buf[1280];
	char *dm_value = NULL, *dm_type = NULL;
	int notif_ret = 0;
	struct blob_buf bbuf;

	char *parameter = NULL, *value = NULL;
	int notification = 0;
	fp = fopen(DM_ENABLED_NOTIFY, "r");
	if (fp == NULL)
		return notif_ret;

	LIST_HEAD(list_notify_params);
	create_list_param_leaf_notify(&list_notify_params, NULL, NULL);
	while (fgets(buf, 1280, fp) != NULL) {
		int len = strlen(buf);
		if (len)
			buf[len - 1] = '\0';

		CWMP_MEMSET(&bbuf, 0, sizeof(struct blob_buf));
		blob_buf_init(&bbuf, 0);

		if (blobmsg_add_json_from_string(&bbuf, buf) == false) {
			blob_buf_free(&bbuf);
			continue;
		}
		const struct blobmsg_policy p[4] = { { "parameter", BLOBMSG_TYPE_STRING }, { "notification", BLOBMSG_TYPE_INT32 }, { "type", BLOBMSG_TYPE_STRING }, { "value", BLOBMSG_TYPE_STRING } };

		struct blob_attr *tb[4] = { NULL, NULL, NULL, NULL };
		blobmsg_parse(p, 4, tb, blobmsg_data(bbuf.head), blobmsg_len(bbuf.head));
		parameter = blobmsg_get_string(tb[0]);
		notification = blobmsg_get_u32(tb[1]);
		//type = blobmsg_get_string(tb[2]);
		value = blobmsg_get_string(tb[3]);
		get_parameter_value_from_parameters_list(&list_notify_params, parameter, &dm_value, &dm_type);
		if (dm_value == NULL && dm_type == NULL){
			blob_buf_free(&bbuf);
			parameter = NULL;
			notification = 0;
			//type = NULL;
			value = NULL;
			continue;
		}
		if ((notification >= 1) && (dm_value != NULL) && value && (strcmp(dm_value, value) != 0)) {

			if (cwmp_main->conf.md_notif_limit > 0 && CWMP_STRCMP(parameter, MANAGEABLE_DEVICES_NBRE) == 0 && notification == 2) {
				unsigned int time_from_last_vc = time(NULL) - cwmp_main->md_value_change_last_time;
				if ((cwmp_main->md_value_change_last_time <= 0) || (time_from_last_vc >= cwmp_main->conf.md_notif_limit)) {
					cwmp_main->md_value_change_last_time = time(NULL);
					add_list_value_change(MANAGEABLE_DEVICES_NBRE, dm_value, dm_type);
				}
			} else if (notification == 1 || notification == 2)
				add_list_value_change(parameter, dm_value, dm_type);
			else
				add_lw_list_value_change(parameter, dm_value, dm_type);

			if (notification == 1)
				notif_ret |= NOTIF_PASSIVE;
			if (notification == 2)
				notif_ret |= NOTIF_ACTIVE;

			if (notification == 5 || notification == 6)
				notif_ret |= NOTIF_LW_ACTIVE;
		}
		FREE(dm_value);
		FREE(dm_type);
		parameter = NULL;
		notification = 0;
		//type = NULL;
		value = NULL;
		blob_buf_free(&bbuf);
	}
	fclose(fp);
	cwmp_free_all_dm_parameter_list(&list_notify_params);
	return notif_ret;
}

void cwmp_prepare_value_change()
{
	struct event_container *event_container;
	if (list_value_change.next == &(list_value_change))
		return;
	event_container = cwmp_add_event_container(EVENT_IDX_4VALUE_CHANGE, "");
	if (!event_container)
		return;
	list_splice_init(&(list_value_change), &(event_container->head_dm_parameter));
	cwmp_save_event_container(event_container);
}

void sotfware_version_value_change(struct transfer_complete *p)
{
	char *current_software_version = NULL;

	if (p == NULL) {
		CWMP_LOG(ERROR, "notifications %s: p is null", __FUNCTION__);
		return;
	}
	if (!p->old_software_version || p->old_software_version[0] == 0)
		return;

	current_software_version = cwmp_main->deviceid.softwareversion;
	if (p->old_software_version && current_software_version && strcmp(p->old_software_version, current_software_version) != 0)
		cwmp_add_event_container(EVENT_IDX_4VALUE_CHANGE, "");
}

void periodic_check_notifiy(struct uloop_timeout *timeout  __attribute__((unused)))
{
	int is_notify = 0;
	if (cwmp_stop)
		return;

	/* If ConnectionRequestURL is empty then reschedule the timer after 5 second for
	 * maximum of 3 times to check the upstream connection is stable, before enqueing
	 * for notification. This can be a case of DHCP lease renewal phase for e.g
	 * renew of old address is NACKED by the server (In this case interface releases its
	 * current IP and waits for a new IP from server) */
	// An empty connection url cause CDR test to break
	static int cr_url_retry = 3;

	if (cr_url_retry) {
		struct cwmp_dm_parameter cwmp_dm_param = {0};

		if (!cwmp_get_parameter_value("Device.ManagementServer.ConnectionRequestURL", &cwmp_dm_param)) {
			uloop_timeout_set(&check_notify_timer, UPSTREAM_STABILITY_CHECK_TIMESPAN * 1000);
			cr_url_retry = cr_url_retry - 1;
			return;
		}

		if (CWMP_STRLEN(cwmp_dm_param.value) == 0) {
			uloop_timeout_set(&check_notify_timer, UPSTREAM_STABILITY_CHECK_TIMESPAN * 1000);
			cr_url_retry = cr_url_retry - 1;
			return;
		}
	}

	// restore the retry count
	cr_url_retry = 3;

	is_notify = check_value_change();
	if (is_notify > 0)
		cwmp_update_enabled_notify_file();
	if (is_notify & NOTIF_ACTIVE) {
		send_active_value_change();
		int last_session_interval = time(NULL) - cwmp_main->session->session_status.last_end_time;
		if (!cwmp_main->throttle_session_triggered && (cwmp_main->session->session_status.last_status == SESSION_SUCCESS) && (cwmp_main->conf.active_notif_throttle > 0)) {
			cwmp_main->throttle_session_triggered = true;
			if (last_session_interval < cwmp_main->conf.active_notif_throttle)
				trigger_cwmp_throttle_session_timer(cwmp_main->conf.active_notif_throttle - last_session_interval);
			else
				trigger_cwmp_throttle_session_timer(0);
		}
		else if (cwmp_main->conf.active_notif_throttle == 0)
			trigger_cwmp_session_timer();
	}

	if (is_notify & NOTIF_LW_ACTIVE)
		cwmp_lwnotification();

	uloop_timeout_set(&check_notify_timer, cwmp_main->conf.periodic_notify_interval * 1000);
}

void trigger_periodic_notify_check()
{
	uloop_timeout_set(&check_notify_timer, 10);
}

void add_list_value_change(char *param_name, char *param_data, char *param_type)
{
	add_dm_parameter_to_list(&list_value_change, param_name, param_data, param_type, 0, false);
}

void clean_list_value_change()
{
	cwmp_free_all_dm_parameter_list(&list_value_change);
}

void send_active_value_change(void)
{
	struct event_container *event_container;

	event_container = cwmp_add_event_container(EVENT_IDX_4VALUE_CHANGE, "");
	if (event_container == NULL)
		return;

	cwmp_save_event_container(event_container);
	return;
}

/*
 * Light Weight Notifications
 */
void add_lw_list_value_change(char *param_name, char *param_data, char *param_type) { add_dm_parameter_to_list(&list_lw_value_change, param_name, param_data, param_type, 0, false); }
static void udplw_server_param(struct addrinfo **res)
{
	struct addrinfo hints = { 0 };
	struct config *conf = &(cwmp_main->conf);
	char port[32];

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	snprintf(port, sizeof(port), "%d", conf->lwn_port);
	getaddrinfo(conf->lwn_hostname, port, &hints, res);
}

char *calculate_lwnotification_cnonce()
{
	char *cnonce = calloc(33, sizeof(char));
	if (cnonce == NULL)
		return NULL;

	char *rand = generate_random_string(16);
	if (rand == NULL) {
		free(cnonce);
		return NULL;
	}

	snprintf(cnonce, 33, "%s", rand);
	free(rand);
	return cnonce;
}

static void send_udp_message(struct addrinfo *servaddr, char *msg)
{
	int fd;

	if (msg == NULL) {
		CWMP_LOG(ERROR, "notifications %s: msg is null", __FUNCTION__);
		return;
	}
	fd = socket(servaddr->ai_family, SOCK_DGRAM, 0);

	if (fd >= 0) {
		sendto(fd, msg, strlen(msg), 0, servaddr->ai_addr, servaddr->ai_addrlen);
		close(fd);
	}
}

void del_list_lw_notify(struct cwmp_dm_parameter *dm_parameter)
{
	list_del(&dm_parameter->list);
	free(dm_parameter->name);
	free(dm_parameter);
}

static void free_all_list_lw_notify()
{
	while (list_lw_value_change.next != &list_lw_value_change) {
		struct cwmp_dm_parameter *dm_parameter;
		if (list_lw_value_change.next == NULL)
			continue;
		dm_parameter = list_entry(list_lw_value_change.next, struct cwmp_dm_parameter, list);
		del_list_lw_notify(dm_parameter);
	}
}

void cwmp_lwnotification()
{
	char msg[1024], *msg_out = NULL;
	char signature[41];
	struct addrinfo *servaddr;
	struct config *conf;
	conf = &(cwmp_main->conf);

	udplw_server_param(&servaddr);
	xml_prepare_lwnotification_message(&msg_out);
	if (msg_out == NULL) {
		CWMP_LOG(ERROR, "%s: msg_out is null", __FUNCTION__);
		return;
	}
	message_compute_signature(msg_out, signature, sizeof(signature));
	snprintf(msg, sizeof(msg), "%s \n %s: %s \n %s: %s \n %s: %zu\n %s: %s\n\n%s", "POST /HTTPS/1.1", "HOST", conf->lwn_hostname, "Content-Type", "test/xml; charset=utf-8", "Content-Lenght", strlen(msg_out), "Signature", signature, msg_out);

	send_udp_message(servaddr, msg);
	free_all_list_lw_notify();
	//freeaddrinfo(servaddr); //To check
	FREE(msg_out);
}
