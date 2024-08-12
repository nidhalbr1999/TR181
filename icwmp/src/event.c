/*
 * event.c - Manage CWMP Events
 *
 * Copyright (C) 2022, IOPSYS Software Solutions AB.
 *
 *	  Author Mohamed Kallel <mohamed.kallel@pivasoftware.com>
 *	  Author Ahmed Zribi <ahmed.zribi@pivasoftware.com>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#include "backupSession.h"
#include "event.h"
#include "sched_inform.h"
#include "download.h"
#include "upload.h"
#include "log.h"
#include "session.h"
#include "cwmp_event.h"
#include "notifications.h"

//#include <libubox/list.h>

const struct EVENT_CONST_STRUCT EVENT_CONST[] = {
		[EVENT_IDX_0BOOTSTRAP] = { "0 BOOTSTRAP", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_1BOOT] = { "1 BOOT", EVENT_RETRY_AFTER_TRANSMIT_FAIL },
		[EVENT_IDX_2PERIODIC] = { "2 PERIODIC", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_3SCHEDULED] = { "3 SCHEDULED", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_4VALUE_CHANGE] = { "4 VALUE CHANGE", EVENT_RETRY_AFTER_TRANSMIT_FAIL },
		[EVENT_IDX_5KICKED] = { "5 KICKED", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_6CONNECTION_REQUEST] = { "6 CONNECTION REQUEST", 0 },
		[EVENT_IDX_7TRANSFER_COMPLETE] = { "7 TRANSFER COMPLETE", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_8DIAGNOSTICS_COMPLETE] = { "8 DIAGNOSTICS COMPLETE", EVENT_RETRY_AFTER_TRANSMIT_FAIL },
		[EVENT_IDX_9REQUEST_DOWNLOAD] = { "9 REQUEST DOWNLOAD", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_10AUTONOMOUS_TRANSFER_COMPLETE] = { "10 AUTONOMOUS TRANSFER COMPLETE", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_11DU_STATE_CHANGE_COMPLETE] = { "11 DU STATE CHANGE COMPLETE", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_12AUTONOMOUS_DU_STATE_CHANGE_COMPLETE] = { "12 AUTONOMOUS DU STATE CHANGE COMPLETE", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_13WAKEUP] = { "13 WAKEUP", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_14HEARTBEAT] = { "14 HEARTBEAT", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_M_Reboot] = { "M Reboot", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_M_ScheduleInform] = { "M ScheduleInform", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_M_Download] = { "M Download", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_M_Schedule_Download] = { "M ScheduleDownload", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_M_Upload] = { "M Upload", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT },
		[EVENT_IDX_M_ChangeDUState] = { "M ChangeDUState", EVENT_RETRY_AFTER_TRANSMIT_FAIL | EVENT_RETRY_AFTER_REBOOT }
};

void cwmp_save_event_container(struct event_container *event_container)
{
	if (event_container == NULL) {
		CWMP_LOG(ERROR, "event %s: event_container is null", __FUNCTION__);
		return;
	}

	if (EVENT_CONST[event_container->code].RETRY & EVENT_RETRY_AFTER_REBOOT) {
		struct list_head *ilist;
		mxml_node_t *b;

		b = bkp_session_insert_event(event_container->code, event_container->command_key, event_container->id);

		list_for_each (ilist, &(event_container->head_dm_parameter)) {
			struct cwmp_dm_parameter *dm_parameter;
			dm_parameter = list_entry(ilist, struct cwmp_dm_parameter, list);
			bkp_session_insert(b, "Parameter", dm_parameter->name);
		}
		bkp_session_save();
	}
}

static int cwmp_root_cause_event_boot(void)
{
	if (cwmp_main->env.boot == CWMP_START_BOOT) {
		struct event_container *event_container;
		cwmp_main->env.boot = 0;

		event_container = cwmp_add_event_container(EVENT_IDX_1BOOT, "");
		if (event_container == NULL) {
			CWMP_LOG(ERROR, "event %s: event_container is null", __FUNCTION__);
			return CWMP_MEM_ERR;
		}

		cwmp_save_event_container(event_container);
	}
	return CWMP_OK;
}

int event_remove_noretry_event_container()
{
	struct list_head *ilist, *q;

	list_for_each_safe (ilist, q, &(cwmp_main->session->events)) {
		struct event_container *event_container;
		event_container = list_entry(ilist, struct event_container, list);

		if (EVENT_CONST[event_container->code].CODE[0] == '6')
			cwmp_main->cwmp_cr_event = 1;

		if (EVENT_CONST[event_container->code].RETRY == 0) {
			if (event_container->command_key)
				free(event_container->command_key);
			cwmp_free_all_dm_parameter_list(&(event_container->head_dm_parameter));
			list_del(&(event_container->list));
			free(event_container);
		}
	}
	return CWMP_OK;
}

static int cwmp_root_cause_event_bootstrap(void)
{
	char *acsurl = NULL;

	cwmp_load_saved_session(&acsurl, ACS);

	if (acsurl == NULL || CWMP_STRCMP(cwmp_main->conf.acs_url, acsurl) != 0) {
		struct event_container *event_container;
		event_container = cwmp_add_event_container(EVENT_IDX_0BOOTSTRAP, "");
		if (event_container == NULL) {
			FREE(acsurl);
			CWMP_LOG(ERROR, "event %s: event_container is null", __FUNCTION__);
			return CWMP_MEM_ERR;
		}

		cwmp_save_event_container(event_container);
		cwmp_scheduleInform_remove_all();
		cwmp_scheduledDownload_remove_all();
		cwmp_scheduled_Download_remove_all();
		cwmp_scheduledUpload_remove_all();
	}

	FREE(acsurl);

	return CWMP_OK;
}

int cwmp_root_cause_transfer_complete(struct transfer_complete *p)
{
	struct event_container *event_container;
	struct rpc *rpc_acs;

	event_container = cwmp_add_event_container(EVENT_IDX_7TRANSFER_COMPLETE, "");
	if (event_container == NULL) {
		CWMP_LOG(ERROR, "event %s: event_container is null", __FUNCTION__);
		return CWMP_MEM_ERR;
	}

	if ((rpc_acs = cwmp_add_session_rpc_acs(RPC_ACS_TRANSFER_COMPLETE)) == NULL) {
		CWMP_LOG(ERROR, "event %s: rpc_acs is null", __FUNCTION__);
		return CWMP_MEM_ERR;
	}

	switch (p->type) {
	case TYPE_DOWNLOAD:
		event_container = cwmp_add_event_container(EVENT_IDX_M_Download, p->command_key ? p->command_key : "");
		if (event_container == NULL) {
			CWMP_LOG(ERROR, "event %s: event_container is null", __FUNCTION__);
			return CWMP_MEM_ERR;
		}
		break;
	case TYPE_UPLOAD:
		event_container = cwmp_add_event_container(EVENT_IDX_M_Upload, p->command_key ? p->command_key : "");
		if (event_container == NULL) {
			CWMP_LOG(ERROR, "event %s: event_container is null", __FUNCTION__);
			return CWMP_MEM_ERR;
		}
		break;
	case TYPE_SCHEDULE_DOWNLOAD:
		event_container = cwmp_add_event_container(EVENT_IDX_M_Schedule_Download, p->command_key ? p->command_key : "");
		if (event_container == NULL) {
			CWMP_LOG(ERROR, "event %s: event_container is null", __FUNCTION__);
			return CWMP_MEM_ERR;
		}
		break;
	}
	rpc_acs->extra_data = (void *)p;
	return CWMP_OK;
}

int cwmp_root_cause_autonomous_cdu_complete(auto_du_state_change_compl *p)
{
	struct event_container *event_container;
	struct rpc *rpc_acs;

	event_container = cwmp_add_event_container(EVENT_IDX_12AUTONOMOUS_DU_STATE_CHANGE_COMPLETE, "");
	if (event_container == NULL) {
		CWMP_LOG(ERROR, "event %s: event_container is null", __FUNCTION__);
		return CWMP_MEM_ERR;
	}

	if ((rpc_acs = cwmp_add_session_rpc_acs(RPC_ACS_AUTONOMOUS_DU_STATE_CHANGE_COMPLETE)) == NULL) {
		CWMP_LOG(ERROR, "event %s: rpc_acs is null", __FUNCTION__);
		return CWMP_MEM_ERR;
	}
	rpc_acs->extra_data = (void *)p;
	return CWMP_OK;
}

int cwmp_root_cause_autonomous_transfer_complete(auto_transfer_complete *p)
{
	struct event_container *event_container;
	struct rpc *rpc_acs;

	event_container = cwmp_add_event_container(EVENT_IDX_10AUTONOMOUS_TRANSFER_COMPLETE, "");
	if (event_container == NULL) {
		CWMP_LOG(ERROR, "event %s: event_container is null", __FUNCTION__);
		return CWMP_MEM_ERR;
	}

	if ((rpc_acs = cwmp_add_session_rpc_acs(RPC_ACS_AUTONOMOUS_TRANSFER_COMPLETE)) == NULL) {
		CWMP_LOG(ERROR, "event %s: rpc_acs is null", __FUNCTION__);
		return CWMP_MEM_ERR;
	}
	rpc_acs->extra_data = (void *)p;
	return CWMP_OK;
}

int cwmp_root_cause_changedustate_complete(struct du_state_change_complete *p)
{
	struct event_container *event_container;
	struct rpc *rpc_acs;

	event_container = cwmp_add_event_container(EVENT_IDX_11DU_STATE_CHANGE_COMPLETE, "");
	if (event_container == NULL) {
		CWMP_LOG(ERROR, "event %s: event_container is null", __FUNCTION__);
		return CWMP_MEM_ERR;
	}

	event_container = cwmp_add_event_container(EVENT_IDX_M_ChangeDUState, p->command_key ? p->command_key : "");
	if (event_container == NULL) {
		CWMP_LOG(ERROR, "event %s: event_container is null", __FUNCTION__);
		return CWMP_MEM_ERR;
	}

	if ((rpc_acs = cwmp_add_session_rpc_acs(RPC_ACS_DU_STATE_CHANGE_COMPLETE)) == NULL) {
		CWMP_LOG(ERROR, "event %s: rpc_acs is null", __FUNCTION__);
		return CWMP_MEM_ERR;
	}

	rpc_acs->extra_data = (void *)p;
	return CWMP_OK;
}

int cwmp_root_cause_schedule_inform(struct schedule_inform *schedule_inform)
{
	struct event_container *event_container;
	event_container = cwmp_add_event_container(EVENT_IDX_3SCHEDULED, "");
	if (event_container != NULL) {
		cwmp_save_event_container(event_container);
	}
	event_container = cwmp_add_event_container(EVENT_IDX_M_ScheduleInform, schedule_inform->commandKey);
	if (event_container != NULL) {
		cwmp_save_event_container(event_container);
	}
	remove_schedule_inform(schedule_inform);
	count_schedule_inform_queue--;
	bkp_session_save();
	return CWMP_OK;
}

static int cwmp_root_cause_get_rpc_method(void )
{
	if (cwmp_main->env.periodic == CWMP_START_PERIODIC) {
		struct event_container *event_container;

		cwmp_main->env.periodic = 0;
		event_container = cwmp_add_event_container(EVENT_IDX_2PERIODIC, "");
		if (event_container == NULL)
			return CWMP_MEM_ERR;

		cwmp_save_event_container(event_container);
		if (cwmp_main->conf.acs_getrpc && cwmp_add_session_rpc_acs(RPC_ACS_GET_RPC_METHODS) == NULL)
			return CWMP_MEM_ERR;
	}

	return CWMP_OK;
}

bool event_exist_in_list(int event)
{
	struct event_container *event_container = NULL;
	list_for_each_entry (event_container, &cwmp_main->session->events, list) {
		if (event_container->code == event)
			return true;
	}
	return false;
}

static int cwmp_root_cause_event_periodic(void)
{
	char local_time[27] = { 0 };
	struct tm *t_tm;

	if (cwmp_main->cwmp_period == cwmp_main->conf.period && cwmp_main->cwmp_periodic_enable == cwmp_main->conf.periodic_enable && cwmp_main->cwmp_periodic_time == cwmp_main->conf.time)
		return CWMP_OK;

	cwmp_main->cwmp_period = cwmp_main->conf.period;
	cwmp_main->cwmp_periodic_enable = cwmp_main->conf.periodic_enable;
	cwmp_main->cwmp_periodic_time = cwmp_main->conf.time;
	CWMP_LOG(INFO, cwmp_main->cwmp_periodic_enable ? "Periodic event is enabled. Interval period = %ds" : "Periodic event is disabled", cwmp_main->cwmp_period);

	t_tm = localtime(&cwmp_main->cwmp_periodic_time);
	if (t_tm == NULL)
		return CWMP_GEN_ERR;

	if (strftime(local_time, sizeof(local_time), "%FT%T%z", t_tm) == 0)
		return CWMP_GEN_ERR;

	local_time[25] = local_time[24];
	local_time[24] = local_time[23];
	local_time[22] = ':';
	local_time[26] = '\0';

	CWMP_LOG(INFO, cwmp_main->cwmp_periodic_time ? "Periodic time is %s" : "Periodic time is Unknown", local_time);
	return CWMP_OK;
}

void connection_request_port_value_change(int port)
{
	char *bport = NULL;
	char bufport[16];

	snprintf(bufport, sizeof(bufport), "%d", port);

	cwmp_load_saved_session(&bport, CR_PORT);

	if (bport == NULL) {
		CWMP_LOG(ERROR, "bport %s: bip is null", __FUNCTION__);
		bkp_session_simple_insert_in_parent("connection_request", "port", bufport);
		bkp_session_save();
		return;
	}
	if (CWMP_STRCMP(bport, bufport) != 0) {
		struct event_container *event_container;
		event_container = cwmp_add_event_container(EVENT_IDX_4VALUE_CHANGE, "");
		if (event_container == NULL) {
			FREE(bport);
			return;
		}
		cwmp_save_event_container(event_container);
		bkp_session_simple_insert_in_parent("connection_request", "port", bufport);
		bkp_session_save();
	}
	FREE(bport);
}

int cwmp_root_cause_events(void)
{
	int error;

	if ((error = cwmp_root_cause_event_bootstrap()))
		return error;

	if ((error = cwmp_root_cause_event_boot()))
		return error;

	if ((error = cwmp_root_cause_get_rpc_method()))
		return error;

	if ((error = cwmp_root_cause_event_periodic()))
		return error;

	return CWMP_OK;
}

bool event_code_is_valid(const char *code)
{
	int i;
	if (CWMP_STRLEN(code) == 0)
		return true;
	for (i=0; i < __EVENT_IDX_MAX; i++) {
		if (CWMP_STRCMP(code, EVENT_CONST[i].CODE) == 0)
			return true;
	}
	return false;
}

int cwmp_get_int_event_code(const char *code)
{

	if (!event_code_is_valid(code))
		return -1;

	if (CWMP_STRNCMP(code, "1 ", 2) == 0)
		return EVENT_IDX_1BOOT;

	else if (CWMP_STRNCMP(code, "2 ", 2) == 0)
		return EVENT_IDX_2PERIODIC;

	else if (CWMP_STRNCMP(code, "3 ", 2) == 0)
		return EVENT_IDX_3SCHEDULED;

	else if (CWMP_STRNCMP(code, "4 ", 2) == 0)
		return EVENT_IDX_4VALUE_CHANGE;

	else if (CWMP_STRNCMP(code, "5 ", 2) == 0)
		return EVENT_IDX_5KICKED;

	else if (CWMP_STRNCMP(code, "6 ", 2) == 0)
		return EVENT_IDX_6CONNECTION_REQUEST;

	else if (CWMP_STRNCMP(code, "7 ", 2) == 0)
		return EVENT_IDX_7TRANSFER_COMPLETE;

	else if (CWMP_STRNCMP(code, "8 ", 2) == 0)
		return EVENT_IDX_8DIAGNOSTICS_COMPLETE;

	else if (CWMP_STRNCMP(code, "9 ", 2) == 0)
		return EVENT_IDX_9REQUEST_DOWNLOAD;

	else if (CWMP_STRNCMP(code, "10", 2) == 0)
		return EVENT_IDX_10AUTONOMOUS_TRANSFER_COMPLETE;

	else if (CWMP_STRNCMP(code, "11", 2) == 0)
		return EVENT_IDX_11DU_STATE_CHANGE_COMPLETE;

	else if (CWMP_STRNCMP(code, "12", 2) == 0)
		return EVENT_IDX_12AUTONOMOUS_DU_STATE_CHANGE_COMPLETE;

	else if (CWMP_STRNCMP(code, "13", 2) == 0)
		return EVENT_IDX_13WAKEUP;

	else if (CWMP_STRNCMP(code, "14", 2) == 0)
		return EVENT_IDX_14HEARTBEAT;

	else if (CWMP_STRCMP(code, "M Reboot") == 0)
		return EVENT_IDX_M_Reboot;

	else if (CWMP_STRCMP(code, "M ScheduleInform") == 0)
		return EVENT_IDX_M_ScheduleInform;

	else if (CWMP_STRCMP(code, "M Download") == 0)
		return EVENT_IDX_M_Download;

	else if (CWMP_STRCMP(code, "M ScheduleDownload") == 0)
		return EVENT_IDX_M_Schedule_Download;

	else if (CWMP_STRCMP(code, "M Upload") == 0)
		return EVENT_IDX_M_Upload;

	else if (CWMP_STRCMP(code, "M ChangeDUState") == 0)
		return EVENT_IDX_M_ChangeDUState;

	else
		return EVENT_IDX_6CONNECTION_REQUEST;
}
