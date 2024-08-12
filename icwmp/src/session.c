/*
 * session.c - API for CWMP Session
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#include <stdlib.h>
#include <fcntl.h>
#include <mxml.h>

#include "common.h"
#include "session.h"
#include "config.h"
#include "event.h"
#include "rpc.h"
#include "backupSession.h"
#include "heartbeat.h"
#include "http.h"
#include "download.h"
#include "upload.h"
#include "xml.h"
#include "log.h"
#include "notifications.h"
#include "ssl_utils.h"
#include "cwmp_event.h"
#include "diagnostic.h"
#include "heartbeat.h"
#include "sched_inform.h"
#include "cwmp_du_state.h"
#include "cwmp_http.h"
#include "uci_utils.h"


static void cwmp_periodic_session_timer(struct uloop_timeout *timeout);
struct uloop_timeout session_timer = { .cb = cwmp_schedule_session };
struct uloop_timeout periodic_session_timer = { .cb = cwmp_periodic_session_timer };
struct uloop_timeout retry_session_timer = { .cb = cwmp_schedule_session };
struct uloop_timeout throttle_session_timer = { .cb = cwmp_schedule_throttle_session };
struct uloop_timeout restart_timer = { .cb = cwmp_restart_service };


unsigned int end_session_flag = 0;

int create_cwmp_session_structure()
{
	cwmp_main->session = calloc(1, sizeof(struct session));
	if (cwmp_main->session == NULL)
		return CWMP_GEN_ERR;
	INIT_LIST_HEAD(&(cwmp_main->session->events));
	INIT_LIST_HEAD(&(cwmp_main->session->head_rpc_acs));
	cwmp_main->session->session_status.is_heartbeat = false;
	cwmp_main->session->session_status.next_heartbeat = false;
	return CWMP_OK;
}

int cwmp_session_init()
{
	struct rpc *rpc_acs;

	cwmp_main->cwmp_cr_event = 0;

	/*
	 * Set Required methods as initial value of
	 */
	if (cwmp_main->conf.acs_getrpc) {
		rpc_acs = cwmp_add_session_rpc_acs_head(RPC_ACS_GET_RPC_METHODS);
		if (rpc_acs == NULL)
			return CWMP_GEN_ERR;
	}

	rpc_acs = cwmp_add_session_rpc_acs_head(RPC_ACS_INFORM);
	if (rpc_acs == NULL)
		return CWMP_GEN_ERR;

	cwmp_main->session->rpc_cpe = NULL;

	set_cwmp_session_status(SESSION_RUNNING, 0);
	return CWMP_OK;
}

int clean_cwmp_session_structure()
{
	FREE(cwmp_main->session);
	return 0;
}

int cwmp_session_rpc_destructor(struct rpc *rpc)
{
	if (rpc == NULL)
		return CWMP_GEN_ERR;
	list_del(&(rpc->list));
	free(rpc);
	return CWMP_OK;
}

int cwmp_session_exit()
{
	rpc_exit();
	icwmp_cleanmem();
	return CWMP_OK;
}

static int cwmp_rpc_cpe_handle_message(struct rpc *rpc_cpe)
{
	if (xml_prepare_msg_out())
		return -1;
	if (rpc_cpe_methods[rpc_cpe->type].handler(rpc_cpe))
		return -1;
	if (xml_set_cwmp_id_rpc_cpe())
		return -1;

	return 0;
}

int cwmp_schedule_rpc()
{
	struct list_head *ilist;
	struct rpc *rpc_acs;

	if (icwmp_http_client_init() || cwmp_stop) {
		CWMP_LOG(INFO, "Initializing http client failed");
		goto retry;
	}

	while (1) {
		list_for_each (ilist, &(cwmp_main->session->head_rpc_acs)) {
			rpc_acs = list_entry(ilist, struct rpc, list);
			if (rpc_acs_methods[rpc_acs->type].acs_support == RPC_ACS_NOT_SUPPORT) {
				CWMP_LOG(WARNING, "The RPC method %s is not included in the RPCs list supported by the ACS", rpc_acs_methods[rpc_acs->type].name);
				cwmp_session_rpc_destructor(rpc_acs);
				continue;
			}
			if (!rpc_acs->type || cwmp_stop)
				goto retry;

			CWMP_LOG(INFO, "Preparing the %s RPC message to send to the ACS", rpc_acs_methods[rpc_acs->type].name);
			if (rpc_acs_methods[rpc_acs->type].prepare_message(rpc_acs) || cwmp_stop)
				goto retry;

			if (xml_set_cwmp_id() || cwmp_stop)
				goto retry;

			CWMP_LOG(INFO, "Send the %s RPC message to the ACS", rpc_acs_methods[rpc_acs->type].name);
			if (xml_send_message(rpc_acs) || cwmp_stop)
				goto retry;

			CWMP_LOG(INFO, "Get the %sResponse message from the ACS", rpc_acs_methods[rpc_acs->type].name);
			if (rpc_acs_methods[rpc_acs->type].parse_response || cwmp_stop)
				if (rpc_acs_methods[rpc_acs->type].parse_response(rpc_acs))
					goto retry;

			ilist = ilist->prev;
			if (rpc_acs_methods[rpc_acs->type].extra_clean != NULL)
				rpc_acs_methods[rpc_acs->type].extra_clean(rpc_acs);
			cwmp_session_rpc_destructor(rpc_acs);
			MXML_DELETE(cwmp_main->session->tree_in);
			MXML_DELETE(cwmp_main->session->tree_out);
			if (cwmp_main->session->hold_request || cwmp_stop)
				break;
		}

		// If restart service caused firewall restart, wait for firewall restart to complete
		if (g_firewall_restart == true)
			check_firewall_restart_state();

		CWMP_LOG(INFO, "Send empty message to the ACS");
		if (xml_send_message(NULL) || cwmp_stop)
			goto retry;
		if (!cwmp_main->session->tree_in || cwmp_stop)
			goto next;

		CWMP_LOG(INFO, "Receive request from the ACS");
		if (xml_handle_message() || cwmp_stop)
			goto retry;

		while (cwmp_main->session->rpc_cpe) {
			CWMP_LOG(INFO, "Preparing the %s%s message", rpc_cpe_methods[cwmp_main->session->rpc_cpe->type].name, (cwmp_main->session->rpc_cpe->type != RPC_CPE_FAULT) ? "Response" : "");
			if (cwmp_rpc_cpe_handle_message(cwmp_main->session->rpc_cpe) || cwmp_stop)
				goto retry;
			MXML_DELETE(cwmp_main->session->tree_in);

			CWMP_LOG(INFO, "Send the %s%s message to the ACS", rpc_cpe_methods[cwmp_main->session->rpc_cpe->type].name, (cwmp_main->session->rpc_cpe->type != RPC_CPE_FAULT) ? "Response" : "");
			if (xml_send_message(cwmp_main->session->rpc_cpe) || cwmp_stop)
				goto retry;
			MXML_DELETE(cwmp_main->session->tree_out);
			FREE(cwmp_main->session->rpc_cpe);

			if (!cwmp_main->session->tree_in || cwmp_stop)
				break;

			CWMP_LOG(INFO, "Receive request from the ACS");
			if (xml_handle_message() || cwmp_stop)
				goto retry;
		}

	next:
		if (cwmp_main->session->head_rpc_acs.next == &(cwmp_main->session->head_rpc_acs))
			break;
		MXML_DELETE(cwmp_main->session->tree_in);
		MXML_DELETE(cwmp_main->session->tree_out);
	}

	cwmp_main->session->error = CWMP_OK;
	goto end;

retry:
	CWMP_LOG(INFO, "RPC Failed");
	cwmp_main->session->error = CWMP_RETRY_SESSION;
	event_remove_noretry_event_container();

end:
	MXML_DELETE(cwmp_main->session->tree_in);
	MXML_DELETE(cwmp_main->session->tree_out);
	icwmp_http_client_exit();
	xml_exit();
	return cwmp_main->session->error;
}

static int cwmp_get_retry_interval(void)
{
	unsigned int retry_count = 0;
	double min = 0;
	double max = 0;
	int m = cwmp_main->conf.retry_min_wait_interval;
	int k = cwmp_main->conf.retry_interval_multiplier;
	int exp = cwmp_main->retry_count_session;

	if (exp == 0)
		return MAX_INT32;

	if (exp > 10)
		exp = 10;

	min = pow(((double)k / 1000), (double)(exp - 1)) * m;
	max = pow(((double)k / 1000), (double)exp) * m;
	char *rand = generate_random_string(4);
	if (rand) {
		unsigned int dividend = (unsigned int)strtoul(rand, NULL, 16);
		retry_count = dividend % ((unsigned int)max + 1 - (unsigned int)min) + (unsigned int)min;
		free(rand);
	}

	return (retry_count);
}

static void set_cwmp_session_status_state(int status)
{
	char *state = NULL;

	// Create sess_status config section
	set_uci_path_value(VARSTATE_CONFIG, "icwmp.sess_status", "sess_status");

	switch (status) {
	case SESSION_WAITING:
		state = "waiting";
		break;
	case SESSION_RUNNING:
		state = "running";
		break;
	case SESSION_FAILURE:
		state = "failure";
		break;
	case SESSION_SUCCESS:
		state = "success";
		break;
	}

	set_uci_path_value(VARSTATE_CONFIG, "icwmp.sess_status.current_status", state ? state : "N/A");
}

void set_cwmp_session_status(int status, int retry_time)
{
	CWMP_LOG(DEBUG, "%s:%d entry", __func__, __LINE__);
	cwmp_main->session->session_status.last_status = status;
	set_cwmp_session_status_state(status);
	if (status == SESSION_SUCCESS) {
		cwmp_main->session->session_status.last_end_time = time(NULL);
		cwmp_main->session->session_status.next_retry = 0;
		cwmp_main->session->session_status.success_session++;
	} else if (status == SESSION_RUNNING) {
		cwmp_main->session->session_status.last_end_time = 0;
		cwmp_main->session->session_status.next_retry = 0;
		cwmp_main->session->session_status.last_start_time = time(NULL);
	} else {
		cwmp_main->session->session_status.last_end_time = time(NULL);
		cwmp_main->session->session_status.next_retry = time(NULL) + retry_time;
		cwmp_main->session->session_status.failure_session++;
	}
	CWMP_LOG(DEBUG, "%s:%d exit", __func__, __LINE__);
}

void rpc_exit()
{
	if (cwmp_main == NULL || cwmp_main->session == NULL)
		return;

	if (!list_empty(&(cwmp_main->session->head_rpc_acs))) {
		while (cwmp_main->session->head_rpc_acs.next != &(cwmp_main->session->head_rpc_acs)) {
			struct rpc *rpc = list_entry(cwmp_main->session->head_rpc_acs.next, struct rpc, list);
			if (!rpc)
				break;
			if (rpc_acs_methods[rpc->type].extra_clean != NULL)
				rpc_acs_methods[rpc->type].extra_clean(rpc);
			cwmp_session_rpc_destructor(rpc);
		}
	}
	FREE(cwmp_main->session->rpc_cpe);
}

static void schedule_session_retry(void)
{
	cwmp_main->retry_count_session++;
	int t = cwmp_get_retry_interval();
	CWMP_LOG(INFO, "Retry session, retry count = %d, retry in %ds", cwmp_main->retry_count_session, t);
	trigger_periodic_notify_check();

	if (!cwmp_main->session->session_status.is_heartbeat) {
		set_cwmp_session_status(SESSION_FAILURE, t);
		uloop_timeout_set(&retry_session_timer, 1000 * t);
	} else {
		uloop_timeout_cancel(&heartbeat_session_timer);
		uloop_timeout_set(&heartbeat_session_timer, 1000 * t);
	}
}

void start_cwmp_session(void)
{
	int error;
	char exec_download[BUF_SIZE_256] = {0};

	uloop_timeout_cancel(&check_notify_timer);
	if (cwmp_session_init() != CWMP_OK) {
		CWMP_LOG(ERROR, "Not able to init a CWMP session");
		schedule_session_retry();
		return;
	}

	if (cwmp_main->session->session_status.last_status == SESSION_FAILURE) {
		cwmp_config_load();
	}

	if (is_ipv6_status_changed()) {
		if (icwmp_check_http_connection() != CWMP_OK || cwmp_stop) {
			CWMP_LOG(INFO, "Failed to check http connection");
			if (!cwmp_stop)
				schedule_session_retry();
			return;
		}
	}

	/*
	 * Value changes
	 */
	if (!cwmp_main->session->session_status.is_heartbeat) {
		int is_notify = 0;
		if (file_exists(DM_ENABLED_NOTIFY)) {
			if (!event_exist_in_list(EVENT_IDX_4VALUE_CHANGE))
				is_notify = check_value_change();
		}
		if (is_notify > 0 || !file_exists(DM_ENABLED_NOTIFY) || cwmp_main->custom_notify_active) {
			cwmp_main->custom_notify_active = false;
			cwmp_update_enabled_notify_file();
		}
		cwmp_prepare_value_change(cwmp_main);
		clean_list_value_change();
	}
	/*
	 * Start session
	 */

	CWMP_LOG(INFO, "Start session");

	get_uci_path_value(NULL, "cwmp.cpe.exec_download", exec_download, BUF_SIZE_256);
	if (CWMP_STRCMP(exec_download, "1") == 0) {
		CWMP_LOG(INFO, "Firmware downloaded and applied successfully");
		set_uci_path_value(NULL, "cwmp.cpe.exec_download", "0");
	}

	error = cwmp_schedule_rpc();
	if (error != CWMP_OK) {
		CWMP_LOG(ERROR, "CWMP session error: %d", error);
	}

	/*
	 * End session
	 */
	CWMP_LOG(INFO, "End session");

	if (cwmp_stop) {
		cwmp_remove_all_session_events();
		run_session_end_func();
		cwmp_session_exit();

		return;
	}

	if (cwmp_main->session->error == CWMP_RETRY_SESSION && (!list_empty(&(cwmp_main->session->events)) || (list_empty(&(cwmp_main->session->events)) && cwmp_main->cwmp_cr_event == 0))) { //CWMP Retry session
		schedule_session_retry();
	} else {
		save_acs_bkp_config();
		if (!cwmp_main->session->session_status.is_heartbeat) {
			cwmp_remove_all_session_events();
		} else {
			remove_single_event(EVENT_IDX_14HEARTBEAT);
		}

		cwmp_main->retry_count_session = 0;
		set_cwmp_session_status(SESSION_SUCCESS, 0);
		if (cwmp_main->throttle_session_triggered == true) {
			cwmp_main->throttle_session_triggered = false;
			if (!cwmp_main->throttle_session) {
				uloop_timeout_cancel(&throttle_session_timer);
			} else {
				cwmp_main->throttle_session = false;
			}
		}
	}
	run_session_end_func();
	cwmp_session_exit();

	if (cwmp_main->acs_changed) {
		CWMP_LOG(INFO, "%s: Schedule session with new ACS since URL changed", __func__);
		uloop_timeout_cancel(&heartbeat_session_timer);
		cwmp_main->session->session_status.next_heartbeat = true;
		cwmp_main->session->session_status.is_heartbeat = false;
		cwmp_main->retry_count_session = 0;
		trigger_cwmp_session_timer();
		cwmp_main->acs_changed = false;
		return;
	}

	CWMP_LOG(INFO, "Waiting the next session");
	if (cwmp_main->session->session_status.next_heartbeat && (cwmp_main->session->session_status.last_status == SESSION_SUCCESS)) {
		cwmp_main->session->session_status.next_heartbeat = false;
		uloop_timeout_cancel(&heartbeat_session_timer);
		uloop_timeout_set(&heartbeat_session_timer, 1000);

	} else {
		cwmp_main->session->session_status.is_heartbeat = false;
		trigger_periodic_notify_check();
	}
}

void trigger_cwmp_session_timer()
{
	uloop_timeout_cancel(&retry_session_timer);
	uloop_timeout_set(&session_timer, 500);
}

void trigger_cwmp_throttle_session_timer(unsigned int delay)
{
	uloop_timeout_cancel(&retry_session_timer);
	uloop_timeout_set(&throttle_session_timer, delay * 1000 + 10);
}

void cwmp_schedule_session(struct uloop_timeout *timeout  __attribute__((unused)))
{
	cwmp_main->throttle_session = false;
	start_cwmp_session();
}


void cwmp_schedule_throttle_session(struct uloop_timeout *timeout  __attribute__((unused)))
{
	cwmp_main->throttle_session = true;
	start_cwmp_session();
}

void trigger_cwmp_session_timer_with_event(struct uloop_timeout *timeout)
{
	uloop_timeout_cancel(&retry_session_timer);
	uloop_timeout_cancel(timeout);
	uloop_timeout_set(timeout, 10);
}

void cwmp_schedule_session_with_event(struct uloop_timeout *timeout)
{
	struct session_timer_event *session_event = container_of(timeout, struct session_timer_event, session_timer_evt);
	if (session_event == NULL) {
		CWMP_LOG(ERROR, "session %s: session_event is null", __FUNCTION__);
		return;
	}
	FREE(global_session_event);
	global_session_event = session_event;
	if (session_event->event == TransferClt_Evt) {
		struct transfer_complete *ptransfer_complete = (struct transfer_complete *)session_event->extra_data;
		cwmp_root_cause_transfer_complete(ptransfer_complete);
	} else if (session_event->event == CDU_Evt) {
		struct du_state_change_complete *pdu_state_change_complete = (struct du_state_change_complete *)session_event->extra_data;
		cwmp_root_cause_changedustate_complete(pdu_state_change_complete);
	} else if (session_event->event == Schedule_Inform_Evt) {
		struct schedule_inform *schedule_inform = (struct schedule_inform *)session_event->extra_data;
		cwmp_root_cause_schedule_inform(schedule_inform);
	} else if (session_event->event == EVENT_IDX_14HEARTBEAT) {
		cwmp_main->session->session_status.next_heartbeat = false;
		cwmp_main->session->session_status.is_heartbeat = true;
		cwmp_add_event_container(EVENT_IDX_14HEARTBEAT, "");
		start_cwmp_session();
		return;
	} else if (session_event->event == EVENT_IDX_10AUTONOMOUS_TRANSFER_COMPLETE) {
		auto_transfer_complete *auto_trnsfr_complete = (auto_transfer_complete *)session_event->extra_data;
		cwmp_root_cause_autonomous_transfer_complete(auto_trnsfr_complete);
	} else if (session_event->event == EVENT_IDX_12AUTONOMOUS_DU_STATE_CHANGE_COMPLETE) {
		auto_du_state_change_compl *data = (auto_du_state_change_compl *)session_event->extra_data;
		cwmp_root_cause_autonomous_cdu_complete(data);
	} else if (session_event->event >= 0) {
		struct event_container *event_container = NULL;
		event_container = cwmp_add_event_container(session_event->event, "");
		if (event_container == NULL) {
			CWMP_LOG(ERROR, "Not able to add the event %s for the new session", EVENT_CONST[session_event->event].CODE);
		}
		session_event->event = -1;
		cwmp_save_event_container(event_container);
	}

	trigger_cwmp_session_timer();
}

static void cwmp_periodic_session_timer(struct uloop_timeout *timeout  __attribute__((unused)))
{
	if (cwmp_main->conf.periodic_enable && cwmp_main->conf.period > 0) {
		cwmp_main->session->session_status.next_periodic = time(NULL) + cwmp_main->conf.period;
		uloop_timeout_set(&periodic_session_timer, cwmp_main->conf.period * 1000);
	}
	if (cwmp_main->conf.periodic_enable) {
		struct session_timer_event *periodic_inform_event = calloc(1, sizeof(struct session_timer_event));

		periodic_inform_event->session_timer_evt.cb = cwmp_schedule_session_with_event;
		periodic_inform_event->event = EVENT_IDX_2PERIODIC;
		trigger_cwmp_session_timer_with_event(&periodic_inform_event->session_timer_evt);
	}
}

long int cwmp_periodic_session_time(void)
{
	long int delta_time;
	long int periodic_time;

	delta_time = time(NULL) - cwmp_main->conf.time;
	if(delta_time > 0)
		periodic_time = cwmp_main->conf.period - (delta_time % cwmp_main->conf.period);
	else
		periodic_time = (-delta_time) % cwmp_main->conf.period;

	cwmp_main->session->session_status.next_periodic = time(NULL) + periodic_time;
	return  periodic_time;
}

void initiate_cwmp_periodic_session_feature()
{
	uloop_timeout_cancel(&periodic_session_timer);
	if (cwmp_main->conf.periodic_enable && cwmp_main->conf.period > 0) {
		if (cwmp_main->conf.time > 0){
			CWMP_LOG(INFO, "Init periodic inform: periodic_inform time = %ld, interval = %d", cwmp_main->conf.time, cwmp_main->conf.period);
			uloop_timeout_set(&periodic_session_timer, cwmp_periodic_session_time() * 1000);
		} else {
			CWMP_LOG(INFO, "Init periodic inform: interval = %d", cwmp_main->conf.period);
			cwmp_main->session->session_status.next_periodic = time(NULL) + cwmp_main->conf.period;
			uloop_timeout_set(&periodic_session_timer, cwmp_main->conf.period * 1000);
		}
	}
}

void reinit_cwmp_periodic_session_feature()
{
	if (cwmp_main->conf.periodic_enable) {
		if (!cwmp_main->prev_periodic_enable || (cwmp_main->prev_periodic_interval != cwmp_main->conf.period) || (cwmp_main->prev_periodic_time != cwmp_main->conf.time)) {
			uloop_timeout_cancel(&periodic_session_timer);
			if ((cwmp_main->prev_periodic_time != cwmp_main->conf.time) && cwmp_main->conf.time > 0)
				uloop_timeout_set(&periodic_session_timer, cwmp_periodic_session_time() * 1000);
			else
				uloop_timeout_set(&periodic_session_timer, cwmp_main->conf.period * 1000);
		}
	} else
		uloop_timeout_cancel(&periodic_session_timer);

	cwmp_main->prev_periodic_enable = cwmp_main->conf.periodic_enable;
	cwmp_main->prev_periodic_interval = cwmp_main->conf.period;
	cwmp_main->prev_periodic_time = cwmp_main->conf.time;
}

struct rpc *build_sessin_rcp_cpe(int type)
{
	struct rpc *rpc_cpe;

	rpc_cpe = calloc(1, sizeof(struct rpc));
	if (rpc_cpe == NULL) {
		return NULL;
	}
	rpc_cpe->type = type;
	return rpc_cpe;
}

struct rpc *cwmp_add_session_rpc_acs(int type)
{
	struct rpc *rpc_acs;
	rpc_acs = calloc(1, sizeof(struct rpc));
	if (rpc_acs == NULL) {
		return NULL;
	}
	rpc_acs->type = type;
	list_add_tail(&(rpc_acs->list), &(cwmp_main->session->head_rpc_acs));
	return rpc_acs;
}

int cwmp_apply_acs_changes(void)
{
	int error;

	if ((error = cwmp_config_reload()))
		return error;

	if ((error = cwmp_root_cause_events()))
		return error;

	return CWMP_OK;
}

struct rpc *cwmp_add_session_rpc_acs_head(int type)
{
	struct rpc *rpc_acs;

	rpc_acs = calloc(1, sizeof(struct rpc));
	if (rpc_acs == NULL) {
		return NULL;
	}
	rpc_acs->type = type;
	list_add(&(rpc_acs->list), &(cwmp_main->session->head_rpc_acs));
	return rpc_acs;
}

void cwmp_set_end_session(unsigned int flag)
{
	end_session_flag |= flag;
}

int run_session_end_func(void)
{
	CWMP_LOG(INFO, "Handling end session with: (%u)", end_session_flag);

	if (end_session_flag & END_SESSION_RESTART_SERVICES) {
		CWMP_LOG(INFO, "Restart modified services");
		icwmp_restart_services();
	}

	if (cwmp_apply_acs_changes() != CWMP_OK) {
		CWMP_LOG(ERROR, "config reload failed at session end");
	}

	reinit_cwmp_periodic_session_feature();
	reinit_heartbeat_procedures();

	if (end_session_flag & END_SESSION_INIT_NOTIFY) {
		CWMP_LOG(INFO, "SetParameterAttributes end session: reinit list notify");
		reinit_list_param_notify();
	}

	if (end_session_flag & END_SESSION_SET_NOTIFICATION_UPDATE) {
		CWMP_LOG(INFO, "SetParameterAttributes/Values end session: update enabled notify file");
		cwmp_update_enabled_notify_file();
	}

	if (end_session_flag & END_SESSION_NSLOOKUP_DIAGNOSTIC) {
		CWMP_LOG(INFO, "Executing nslookupdiagnostic: end session request");
		cwmp_nslookup_diagnostics();
	}

	if (end_session_flag & END_SESSION_TRACEROUTE_DIAGNOSTIC) {
		CWMP_LOG(INFO, "Executing traceroutediagnostic: end session request");
		cwmp_traceroute_diagnostics();
	}

	if (end_session_flag & END_SESSION_UDPECHO_DIAGNOSTIC) {
		CWMP_LOG(INFO, "Executing udpechodiagnostic: end session request");
		cwmp_udp_echo_diagnostics();
	}

	if (end_session_flag & END_SESSION_SERVERSELECTION_DIAGNOSTIC) {
		CWMP_LOG(INFO, "Executing serverselectiondiagnostic: end session request");
		cwmp_serverselection_diagnostics();
	}

	if (end_session_flag & END_SESSION_IPPING_DIAGNOSTIC) {
		CWMP_LOG(INFO, "Executing ippingdiagnostic: end session request");
		cwmp_ip_ping_diagnostics();
	}

	if (end_session_flag & END_SESSION_DOWNLOAD_DIAGNOSTIC) {
		CWMP_LOG(INFO, "Executing download diagnostic: end session request");
		cwmp_download_diagnostics();
	}

	if (end_session_flag & END_SESSION_UPLOAD_DIAGNOSTIC) {
		CWMP_LOG(INFO, "Executing upload diagnostic: end session request");
		cwmp_upload_diagnostics();
	}

	if (end_session_flag & END_SESSION_NEIGBORING_WIFI_DIAGNOSTIC) {
		CWMP_LOG(INFO, "Executing wifi neighboring diagnostic: end session request");
		cwmp_wifi_neighboring__diagnostics();
	}

	if (end_session_flag & END_SESSION_IPLAYERCAPACITY_DIAGNOSTIC) {
		CWMP_LOG(INFO, "Executing IP layer capacity diagnostic: end session request");
		cwmp_ip_layer_capacity_diagnostics();
	}

	if (end_session_flag & END_SESSION_PACKETCAPTURE_DIAGNOSTIC) {
		CWMP_LOG(INFO, "Executing packet capture diagnostic: end session request");
		cwmp_packet_capture_diagnostics();
	}

	if (end_session_flag & END_SESSION_SELFTEST_DIAGNOSTIC) {
		CWMP_LOG(INFO, "Executing self test diagnostic: end session request");
		cwmp_selftest_diagnostics();
	}

	if (cwmp_main->diag_session) {
		struct session_timer_event *periodic_inform_event = calloc(1, sizeof(struct session_timer_event));
		periodic_inform_event->session_timer_evt.cb = cwmp_schedule_session_with_event;
		periodic_inform_event->event = EVENT_IDX_8DIAGNOSTICS_COMPLETE;
		trigger_cwmp_session_timer_with_event(&periodic_inform_event->session_timer_evt);
		cwmp_main->diag_session = false;
	}

	if (end_session_flag & END_SESSION_DOWNLOAD) {
		CWMP_LOG(INFO, "Apply Downaload Calls");
		apply_downloads();
	}

	if (end_session_flag & END_SESSION_SCHEDULE_DOWNLOAD) {
		CWMP_LOG(INFO, "Apply ScheduleDownaload Calls");
		apply_schedule_downloads();
	}

	if (end_session_flag & END_SESSION_UPLOAD) {
		CWMP_LOG(INFO, "Apply Upload Calls");
		apply_upload();
	}

	if (end_session_flag & END_SESSION_SCHEDULE_INFORM) {
		CWMP_LOG(INFO, "Apply ScheduleInform Calls");
		apply_schedule_inform();
	}

	if (end_session_flag & END_SESSION_CDU) {
		CWMP_LOG(INFO, "Apply CDU Calls");
		apply_change_du_state();
	}

	if (cwmp_main->heart_session) {
		uloop_timeout_cancel(&heartbeat_session_timer);
		uloop_timeout_set(&heartbeat_session_timer, cwmp_main->heart_session_interval * 1000);
		cwmp_main->heart_session = false;
	}

	if (end_session_flag & END_SESSION_REBOOT) {
		CWMP_LOG(INFO, "Executing Reboot: end session request");
		cwmp_reboot(commandKey);
		exit(EXIT_SUCCESS);
	}

	if (end_session_flag & END_SESSION_FACTORY_RESET) {
		CWMP_LOG(INFO, "Executing factory reset: end session request");
		cwmp_factory_reset();
		exit(EXIT_SUCCESS);
	}

	if (end_session_flag & END_SESSION_X_FACTORY_RESET_SOFT) {
		CWMP_LOG(INFO, "Executing factory reset soft: end session request");
		cwmp_factory_reset();
		exit(EXIT_SUCCESS);
	}

	// check if any interface reset request exists then take action
	intf_reset_node *iter = NULL, *node = NULL;
	list_for_each_entry_safe(iter, node, &intf_reset_list, list) {
		CWMP_LOG(INFO, "Executing interface reset: end session request");
		cwmp_invoke_intf_reset(iter->path);
		list_del(&iter->list);
		free(iter);
	}

	INIT_LIST_HEAD(&intf_reset_list);

	end_session_flag = 0;
	return CWMP_OK;
}

void trigger_cwmp_restart_timer(void)
{
	uloop_timeout_set(&restart_timer, 10);
}
