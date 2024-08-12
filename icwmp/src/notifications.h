/*
 * notifications.h - Manage CWMP Notifications
 *
 * Copyright (C) 2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef NOTIFICATIONS_H_
#define NOTIFICATIONS_H_

#include <pthread.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "common.h"

#define CWMP_NOTIFICATIONS_PACKAGE "/etc/icwmpd/cwmp_notifications"

enum NOTIFICATION_STATUS
{
	NOTIF_NONE = 0,
	NOTIF_PASSIVE = 1 << 1,
	NOTIF_ACTIVE = 1 << 2,
	NOTIF_LW_PASSIVE = 1 << 3,
	NOTIF_LW_ACTIVE = 1 << 4
};

extern char *forced_notifications_parameters[];
extern struct list_head list_lw_value_change;
extern struct list_head list_value_change;
extern struct list_head list_param_obj_notify;
extern struct uloop_timeout check_notify_timer;

#define DM_ENABLED_NOTIFY "/var/run/icwmpd/dm_enabled_notify"
#define NOTIFY_MARKER "/etc/icwmpd/icwmpd_notify_import_marker"
#define RUN_NOTIFY_MARKER "/var/run/icwmpd/icwmpd_notify_import_marker"
int create_cwmp_notifications_package();
void ubus_check_value_change_callback(struct ubus_request *req, int type, struct blob_attr *msg);
void cwmp_update_enabled_notify_file(void);
int check_value_change(void);
void create_list_param_obj_notify();
void create_list_param_leaf_notify();
void sotfware_version_value_change(struct transfer_complete *p);
void *thread_periodic_check_notify(void *v);
void send_active_value_change(void);
void add_list_value_change(char *param_name, char *param_data, char *param_type);
void clean_list_value_change();
char *cwmp_set_parameter_attributes(char *parameter_name, int notification);
char *cwmp_get_parameter_attributes(char *parameter_name, struct list_head *parameters_list);
void load_custom_notify_json(void);
void set_default_forced_active_parameters_notifications();
void add_lw_list_value_change(char *param_name, char *param_data, char *param_type);
char *calculate_lwnotification_cnonce();
void cwmp_lwnotification();
void clean_list_param_notify();
void init_list_param_notify();
void reinit_list_param_notify();
void cwmp_prepare_value_change();
void periodic_check_notifiy(struct uloop_timeout *timeout  __attribute__((unused)));
void trigger_periodic_notify_check();
#endif /* SRC_INC_NOTIFICATIONS_H_ */
