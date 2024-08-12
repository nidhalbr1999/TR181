/*
 * event.h - Manage CWMP Events
 *
 * Copyright (C) 2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef EVENT_H_
#define EVENT_H_

#include "common.h"
#include "event.h"

typedef struct event_container {
	struct list_head list;
	int code; /* required element of type xsd:string */
	bool next_session;
	char *command_key;
	struct list_head head_dm_parameter;
	int id;
} event_container;

typedef struct EVENT_CONST_STRUCT {
	char *CODE;
	unsigned short RETRY;

} EVENT_CONST_STRUCT;

enum event_retry_after_enum
{
	EVENT_RETRY_AFTER_TRANSMIT_FAIL = 0x1,
	EVENT_RETRY_AFTER_REBOOT = 0x2,
	EVENT_RETRY_AFTER_BOOTSTRAP = 0x4
};

enum event_idx_enum
{
	EVENT_IDX_0BOOTSTRAP,
	EVENT_IDX_1BOOT,
	EVENT_IDX_2PERIODIC,
	EVENT_IDX_3SCHEDULED,
	EVENT_IDX_4VALUE_CHANGE,
	EVENT_IDX_5KICKED,
	EVENT_IDX_6CONNECTION_REQUEST,
	EVENT_IDX_7TRANSFER_COMPLETE,
	EVENT_IDX_8DIAGNOSTICS_COMPLETE,
	EVENT_IDX_9REQUEST_DOWNLOAD,
	EVENT_IDX_10AUTONOMOUS_TRANSFER_COMPLETE,
	EVENT_IDX_11DU_STATE_CHANGE_COMPLETE,
	EVENT_IDX_12AUTONOMOUS_DU_STATE_CHANGE_COMPLETE,
	EVENT_IDX_13WAKEUP,
	EVENT_IDX_14HEARTBEAT,
	EVENT_IDX_M_Reboot,
	EVENT_IDX_M_ScheduleInform,
	EVENT_IDX_M_Download,
	EVENT_IDX_M_Schedule_Download,
	EVENT_IDX_M_Upload,
	EVENT_IDX_M_ChangeDUState,
	TransferClt_Evt,
	Schedule_Inform_Evt,
	CDU_Evt,
	__EVENT_IDX_MAX
};

extern const struct EVENT_CONST_STRUCT EVENT_CONST[__EVENT_IDX_MAX];

int event_remove_noretry_event_container();
void cwmp_save_event_container(struct event_container *event_container);
void connection_request_port_value_change(int port);
int cwmp_get_int_event_code(const char *code);
bool event_exist_in_list(int event);
int cwmp_root_cause_events(void);
int cwmp_root_cause_transfer_complete(struct transfer_complete *p);
int cwmp_root_cause_changedustate_complete(struct du_state_change_complete *p);
int cwmp_root_cause_schedule_inform(struct schedule_inform *schedule_inform);
int cwmp_root_cause_autonomous_cdu_complete(auto_du_state_change_compl *p);
int cwmp_root_cause_autonomous_transfer_complete(auto_transfer_complete *p);
#endif /* SRC_INC_EVENT_H_ */
