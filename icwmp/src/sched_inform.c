/*
 * sched_inform.c - ScheduleInform method corresponding functions
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#include "sched_inform.h"
#include "backupSession.h"
#include "event.h"
#include "log.h"
#include "cwmp_event.h"
#include "session.h"

LIST_HEAD(list_schedule_inform);

int count_schedule_inform_queue = 0;

int remove_schedule_inform(struct schedule_inform *schedule_inform)
{
	if (schedule_inform != NULL) {
		list_del(&(schedule_inform->list));
		bkp_session_delete_element("schedule_inform", schedule_inform->id);
		FREE(schedule_inform->commandKey);
		free(schedule_inform);
	}
	return CWMP_OK;
}

int cwmp_scheduleInform_remove_all()
{
	while (list_schedule_inform.next != &(list_schedule_inform)) {
		struct schedule_inform *schedule_inform;
		schedule_inform = list_entry(list_schedule_inform.next, struct schedule_inform, list);

		remove_schedule_inform(schedule_inform);
	}
	bkp_session_save();

	return CWMP_OK;
}

void cwmp_start_schedule_inform(struct uloop_timeout *timeout)
{
	struct schedule_inform *schedule_inform = container_of(timeout, struct schedule_inform, handler_timer);;

	struct session_timer_event *schedinform_inform_event = calloc(1, sizeof(struct session_timer_event));

	schedinform_inform_event->extra_data = schedule_inform;
	schedinform_inform_event->session_timer_evt.cb = cwmp_schedule_session_with_event;
	schedinform_inform_event->event = Schedule_Inform_Evt;
	trigger_cwmp_session_timer_with_event(&schedinform_inform_event->session_timer_evt);

}

void apply_schedule_inform()
{
	struct list_head *ilist;
	list_for_each (ilist, &(list_schedule_inform)) {
		struct schedule_inform *sched_inform = list_entry(ilist, struct schedule_inform, list);
		int sched_inform_delay = 0;
		if (sched_inform->scheduled_time > time(NULL)) {
			sched_inform_delay = sched_inform->scheduled_time - time(NULL);
		}
		uloop_timeout_set(&sched_inform->handler_timer, 1000 * sched_inform_delay);
	}
}
