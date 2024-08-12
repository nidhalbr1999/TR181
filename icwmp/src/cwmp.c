/*
 * cwmp.c - icwmp Main file
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Mohamed Kallel <mohamed.kallel@pivasoftware.com>
 *	  Author Ahmed Zribi <ahmed.zribi@pivasoftware.com>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#include <math.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/file.h>
#include <sys/socket.h>

#include "common.h"
#include "ssl_utils.h"
#include "xml.h"
#include "notifications.h"
#include "event.h"
#include "uci_utils.h"
#include "log.h"
#include "session.h"
#include "diagnostic.h"
#include "http.h"
#include "rpc.h"
#include "config.h"
#include "backupSession.h"
#include "ubus_utils.h"
#include "digauth.h"
#include "upload.h"
#include "download.h"
#include "sched_inform.h"
#include "datamodel_interface.h"
#include "cwmp_du_state.h"
#include "heartbeat.h"
#include "cwmp_http.h"

bool g_firewall_restart = false;
struct list_head intf_reset_list;
struct list_head du_uuid_list;
struct list_head force_inform_list;

static bool interface_reset_req(char *param_name, char *value)
{
	if (param_name == NULL || value == NULL)
		return false;

	char reg_exp[100] = {0};
	snprintf(reg_exp, sizeof(reg_exp), "^(%s|%s)[0-9]+\\.Reset$", DM_IP_INTERFACE_PATH, DM_PPP_INTERFACE_PATH);

	if (match_reg_exp(reg_exp, param_name) == false)
		return false;

	if (CWMP_STRCMP(value, "1") != 0 && CWMP_STRCMP(value, "true") != 0)
		return false;

	return true;
}

void set_interface_reset_request(char *param_name, char *value)
{
	if (param_name == NULL || value == NULL)
		return;

	if (interface_reset_req(param_name, value) == false) {
		return;
	}

	// Store the interface path to handle after session end
	int len = 0;
	char *pos = strrchr(param_name, '.');
	if (pos == NULL)
		return;

	len = pos - param_name + 2;
	if (len <= 0)
		return;

	intf_reset_node *node = (intf_reset_node *)malloc(sizeof(intf_reset_node));
	if (node == NULL) {
		CWMP_LOG(ERROR, "Out of memory");
		return;
	}

	CWMP_MEMSET(node, 0, sizeof(intf_reset_node));
	snprintf(node->path, len, "%s", param_name);
	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, &intf_reset_list);
}

static int create_cwmp_temporary_files(void)
{
	if (!file_exists(VARSTATE_CONFIG"/icwmp")) {
		creat(VARSTATE_CONFIG"/icwmp", S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	}

	set_uci_path_value(VARSTATE_CONFIG, "icwmp.acs", "acs");
	set_uci_path_value(VARSTATE_CONFIG, "icwmp.cpe", "cpe");

	if (!file_exists(CWMP_NOTIFICATIONS_PACKAGE)) {
		creat(CWMP_NOTIFICATIONS_PACKAGE, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	}

	set_uci_path_value("/etc/icwmpd", "cwmp_notifications.notifications", "notifications");

	if (!folder_exists("/var/run/icwmpd")) {
		if (mkdir("/var/run/icwmpd", S_IRWXU | S_IRWXG | S_IRWXO) == -1) {
			CWMP_LOG(INFO, "Not able to create the folder /var/run/icwmpd");
			return CWMP_GEN_ERR;
		}
	}

	return CWMP_OK;
}

static bool g_bbf_object_available = false;

static void lookup_event_cb(struct ubus_context *ctx __attribute__((unused)),
		struct ubus_event_handler *ev __attribute__((unused)),
		const char *type, struct blob_attr *msg)
{
	const struct blobmsg_policy policy = {
		"path", BLOBMSG_TYPE_STRING
	};
	struct blob_attr *attr;
	const char *path;

	if (CWMP_STRCMP(type, "ubus.object.add") != 0)
		return;

	blobmsg_parse(&policy, 1, &attr, blob_data(msg), blob_len(msg));
	if (!attr)
		return;

	path = blobmsg_data(attr);
	if (CWMP_STRCMP(path, BBFDM_OBJECT_NAME) == 0) {
		g_bbf_object_available = true;
		uloop_end();
	}
}

static void lookup_timeout_cb(struct uloop_timeout *timeout __attribute__((unused)))
{
	uloop_end();
}

static int wait_for_bbf_object()
{
#define BBF_WAIT_TIMEOUT 60

	struct ubus_context *uctx;
	int ret;
	uint32_t ubus_id;
	struct ubus_event_handler add_event;
	struct uloop_timeout u_timeout;

	g_bbf_object_available = false;
	uctx = ubus_connect(NULL);
	if (uctx == NULL) {
		CWMP_LOG(ERROR, "Can't create ubus context");
		return FAULT_CPE_INTERNAL_ERROR;
	}

	uloop_init();
	ubus_add_uloop(uctx);

	// register for add event
	CWMP_MEMSET(&add_event, 0, sizeof(struct ubus_event_handler));
	add_event.cb = lookup_event_cb;
	ubus_register_event_handler(uctx, &add_event, "ubus.object.add");

	// check if object already present
	ret = ubus_lookup_id(uctx, BBFDM_OBJECT_NAME, &ubus_id);
	if (ret == 0) {
		g_bbf_object_available = true;
		goto end;
	}

	// Set timeout to expire lookup
	CWMP_MEMSET(&u_timeout, 0, sizeof(struct uloop_timeout));
	u_timeout.cb = lookup_timeout_cb;
	uloop_timeout_set(&u_timeout, BBF_WAIT_TIMEOUT * 1000);

	uloop_run();
	uloop_done();

end:
	ubus_free(uctx);

	if (g_bbf_object_available == false) {
		CWMP_LOG(ERROR, "%s object not found", BBFDM_OBJECT_NAME);
		return FAULT_CPE_INTERNAL_ERROR;
	}

	return 0;
}

static int cwmp_init(void)
{
	openlog("cwmp", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	cwmp_main = (struct cwmp *)calloc(1, sizeof(struct cwmp));

	CWMP_MEMSET(cwmp_main, 0, sizeof(struct cwmp));

	get_preinit_config();

	CWMP_LOG(INFO, "STARTING ICWMP with PID :%d", getpid());

	icwmp_init_list_services();

	/* Only One instance should run*/
	cwmp_main->pid_file = fopen("/var/run/icwmpd.pid", "w+");
	fcntl(fileno(cwmp_main->pid_file), F_SETFD, fcntl(fileno(cwmp_main->pid_file), F_GETFD) | FD_CLOEXEC);
	int rc = flock(fileno(cwmp_main->pid_file), LOCK_EX | LOCK_NB);
	if (rc) {
		if (EWOULDBLOCK != errno) {
			char *piderr = "PID file creation failed: Quit the daemon!";
			fprintf(stderr, "%s\n", piderr);
			CWMP_LOG(ERROR, "%s", piderr);
			exit(EXIT_FAILURE);
		} else
			exit(EXIT_SUCCESS);
	}

	if (cwmp_main->pid_file)
		fclose(cwmp_main->pid_file);

	CWMP_LOG(DEBUG, "Loading icwmpd configuration");
	cwmp_config_load();
	CWMP_LOG(DEBUG, "Successfully load icwmpd configuration");

	cwmp_main->prev_periodic_enable = cwmp_main->conf.periodic_enable;
	cwmp_main->prev_periodic_interval = cwmp_main->conf.period;
	cwmp_main->prev_periodic_time = cwmp_main->conf.time;
	cwmp_main->prev_heartbeat_enable = cwmp_main->conf.heart_beat_enable;
	cwmp_main->prev_heartbeat_interval = cwmp_main->conf.heartbeat_interval;
	cwmp_main->prev_heartbeat_time = cwmp_main->conf.heart_time;

	if (cwmp_stop == true)
		return CWMP_GEN_ERR;

	cwmp_get_deviceid();

	/* Load default force inform parameters */
	CWMP_MEMSET(&force_inform_list, 0, sizeof(struct list_head));
	INIT_LIST_HEAD(&force_inform_list);
	load_default_forced_inform();

	/* Load custom notify and force inform parameters */
	load_forced_inform_json();
	load_custom_notify_json();
	set_default_forced_active_parameters_notifications();
	init_list_param_notify();

	create_cwmp_session_structure();
	get_nonce_key();

	CWMP_MEMSET(&intf_reset_list, 0, sizeof(struct list_head));
	INIT_LIST_HEAD(&intf_reset_list);

	CWMP_MEMSET(&du_uuid_list, 0, sizeof(struct list_head));
	INIT_LIST_HEAD(&du_uuid_list);

	cwmp_main->start_time = time(NULL);

	return CWMP_OK;
}

static void cwmp_free()
{
	http_server_stop();
	FREE(nonce_key);
	clean_list_param_notify();
	bkp_tree_clean();
	icwmp_uloop_ubus_exit();
	icwmp_cleanmem();
	rpc_exit();
	clean_cwmp_session_structure();
	FREE(cwmp_main);
	CWMP_LOG(INFO, "EXIT ICWMP");
	closelog();
}

void cwmp_exit()
{
	cwmp_stop = true;

	if (cwmp_main->session->session_status.last_status == SESSION_RUNNING)
		http_set_timeout();

	uloop_timeout_cancel(&retry_session_timer);
	uloop_timeout_cancel(&periodic_session_timer);
	uloop_timeout_cancel(&session_timer);
	uloop_timeout_cancel(&heartbeat_session_timer);
	clean_autonomous_complpolicy();
	clean_interface_update();
	clean_du_uuid_list();
	clean_force_inform_list();
	FREE(cwmp_main->ev);
	FREE(cwmp_main->intf_ev);
	uloop_end();
	shutdown(cwmp_main->cr_socket_desc, SHUT_RDWR);
	FREE(global_session_event);

	/* Free all memory allocation */
	cwmp_free();
}

int main(int argc, char **argv)
{
	int error;
	struct env env;

	error = wait_for_bbf_object();
	if (error)
		return error;

	CWMP_MEMSET(&env, 0, sizeof(struct env));
	if ((error = global_env_init(argc, argv, &env)))
		return error;

	if ((error = create_cwmp_temporary_files()))
		return error;

	if ((error = cwmp_init()))
		return error;

	CWMP_MEMCPY(&(cwmp_main->env), &env, sizeof(struct env));

	if ((error = cwmp_init_backup_session(NULL, ALL)))
		return error;

	if ((error = cwmp_root_cause_events()))
		return error;

	icwmp_http_server_init();

	uloop_init();

	icwmp_uloop_ubus_init();

	if (0 != initiate_autonomous_complpolicy())
		return error;

	if (0 != initiate_interface_update())
		return error;

	trigger_cwmp_session_timer();

	intiate_heartbeat_procedures();

	initiate_cwmp_periodic_session_feature();

	http_server_start();

	uloop_run();
	uloop_done();

	cwmp_exit();

	return CWMP_OK;
}
