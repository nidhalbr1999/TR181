/*
 * sched_inform.h - ScheduleInform method corresponding functions
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef CWMP_SCHED_INFORM_H
#define CWMP_SCHED_INFORM_H
#include "common.h"
extern struct list_head list_schedule_inform;
extern int count_schedule_inform_queue;

void cwmp_start_schedule_inform(struct uloop_timeout *timeout);
int cwmp_scheduleInform_remove_all();
void apply_schedule_inform();
int remove_schedule_inform(struct schedule_inform *schedule_inform);
#endif
