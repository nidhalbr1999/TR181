#ifndef CWMP_EVENT_H
#define CWMP_EVENT_H
#include "event.h"
struct event_container *cwmp_add_event_container(int event_code, char *command_key);
void move_next_session_events_to_actual_session();
int cwmp_remove_all_session_events();
int remove_single_event(int event_code);
#endif
