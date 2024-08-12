/*
 * session.h - API for CWMP Session
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef SESSION_H_
#define SESSION_H_

#include <mxml.h>
#include "common.h"

typedef struct session_status {
	time_t last_start_time;
	time_t last_end_time;
	int last_status;
	bool is_heartbeat;
	time_t next_periodic;
	time_t next_retry;
	bool next_heartbeat;
	unsigned int success_session;
	unsigned int failure_session;
} session_status;

typedef struct session {
	struct list_head head_rpc_acs;
	struct rpc *rpc_cpe;
	struct list_head events;
	struct session_status session_status;
	mxml_node_t *tree_in;
	mxml_node_t *tree_out;
	mxml_node_t *body_in;
	char fault_msg[256];
	bool hold_request;
	int fault_code;
	int error;
} session;

struct session_timer_event {
	struct uloop_timeout session_timer_evt;
	int event;
	void *extra_data;
};


//extern struct session_timer_event session_timer_evt;

enum end_session_enum
{
	END_SESSION_REBOOT = 1,
	END_SESSION_EXTERNAL_ACTION = 1 << 1,
	END_SESSION_RELOAD = 1 << 2,
	END_SESSION_FACTORY_RESET = 1 << 3,
	END_SESSION_X_FACTORY_RESET_SOFT = 1 << 4,

	END_SESSION_IPPING_DIAGNOSTIC = 1 << 5,
	END_SESSION_DOWNLOAD_DIAGNOSTIC = 1 << 6,
	END_SESSION_UPLOAD_DIAGNOSTIC = 1 << 7,
	END_SESSION_NSLOOKUP_DIAGNOSTIC = 1 << 8,
	END_SESSION_TRACEROUTE_DIAGNOSTIC = 1 << 9,
	END_SESSION_UDPECHO_DIAGNOSTIC = 1 << 10,
	END_SESSION_SERVERSELECTION_DIAGNOSTIC = 1 << 11,
	END_SESSION_NEIGBORING_WIFI_DIAGNOSTIC = 1<<12,
	END_SESSION_IPLAYERCAPACITY_DIAGNOSTIC = 1 << 13,

	END_SESSION_SET_NOTIFICATION_UPDATE = 1 << 14,
	END_SESSION_RESTART_SERVICES = 1 << 15,
	END_SESSION_INIT_NOTIFY = 1 << 16,
	END_SESSION_DOWNLOAD = 1 << 17,
	END_SESSION_SCHEDULE_DOWNLOAD = 1 << 18,
	END_SESSION_UPLOAD = 1 << 19,
	END_SESSION_SCHEDULE_INFORM = 1 << 20,
	END_SESSION_CDU = 1 << 21,
	END_SESSION_PACKETCAPTURE_DIAGNOSTIC = 1 << 22,
	END_SESSION_SELFTEST_DIAGNOSTIC = 1 << 23,
};

enum enum_session_status
{
	SESSION_WAITING,
	SESSION_RUNNING,
	SESSION_FAILURE,
	SESSION_SUCCESS
};

extern unsigned int end_session_flag;

void cwmp_set_end_session(unsigned int flag);
struct rpc *build_sessin_rcp_cpe(int type);
struct rpc *cwmp_add_session_rpc_acs(int type);
struct rpc *cwmp_add_session_rpc_acs_head(int type);
int cwmp_session_rpc_destructor(struct rpc *rpc);
void trigger_cwmp_session_timer();
void trigger_cwmp_throttle_session_timer(unsigned int delay);
void trigger_session_by_ubus(char *event);
void initiate_cwmp_periodic_session_feature();
int run_session_end_func(void);
void cwmp_schedule_session(struct uloop_timeout *timeout);
void cwmp_schedule_throttle_session(struct uloop_timeout *timeout  __attribute__((unused)));
void cwmp_schedule_session_with_event(struct uloop_timeout *timeout);
void trigger_cwmp_session_timer_with_event(struct uloop_timeout *timeout);
void start_cwmp_session();
int create_cwmp_session_structure();
int clean_cwmp_session_structure();
void set_cwmp_session_status(int status, int retry_time);
int cwmp_session_init();
int cwmp_session_exit();
int cwmp_schedule_rpc();
int cwmp_apply_acs_changes(void);
void rpc_exit();
void trigger_cwmp_restart_timer(void);
#endif /* SRC_INC_SESSION_H_ */
