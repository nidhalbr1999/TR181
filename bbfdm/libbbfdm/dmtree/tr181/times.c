/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *
 */

#include "times.h"

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_time_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *path = "/etc/rc.d/*ntpd";

	if (check_file(path))
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_time_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	pid_t pid;
	
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if(b) {
				dmcmd("/etc/rc.common", 2, "/etc/init.d/ntpd", "enable");
				pid = get_pid("ntpd");
				if (pid < 0) {
					dmcmd("/etc/rc.common", 2, "/etc/init.d/ntpd", "start");
				}
			} else {
				dmcmd("/etc/rc.common", 2, "/etc/init.d/ntpd", "disable");
				pid = get_pid("ntpd");
				if (pid > 0) {
					dmcmd("/etc/rc.common", 2, "/etc/init.d/ntpd", "stop");
				}
			}
			return 0;
	}
	return 0;
}

static int get_time_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (check_file("/etc/rc.d/*ntpd")) ? "Synchronized" : "Disabled";
	return 0;
}

static int get_time_CurrentLocalTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return dm_time_format(time(NULL), value);
}

/*#Device.Time.LocalTimeZone!UCI:system/system,@system[0]/timezone*/
static int get_time_LocalTimeZone(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("system", "@system[0]", "timezone", value);
	return 0;
}

static int set_time_LocalTimeZone(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("system", "@system[0]", "timezone", value);
			break;
	}
	return 0;
}

static int get_time_ntpserver(char *refparam, struct dmctx *ctx, char **value, int index)
{
	bool found = 0;
	struct uci_list *v;
	struct uci_element *e = NULL;
	
	dmuci_get_option_value_list("system","ntp","server", &v);
	if (v) {
		int element = 0;

		uci_foreach_element(v, e) {
			element++;
			if (element == index) {
				*value = dmstrdup(e->name);
				found = 1; 
				break;
			}
		}
	}
	if (!found) {
		*value = "";
		return 0;
	}
	if (DM_LSTRCMP(*value, "none") == 0) {
		*value = "";
	}
	return 0;
}

static int get_time_ntpserver1(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_time_ntpserver(refparam, ctx, value, 1);
}

static int get_time_ntpserver2(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_time_ntpserver(refparam, ctx, value, 2);
}

static int get_time_ntpserver3(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_time_ntpserver(refparam, ctx, value, 3);
}

static int get_time_ntpserver4(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_time_ntpserver(refparam, ctx, value, 4);
}

static int get_time_ntpserver5(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_time_ntpserver(refparam, ctx, value, 5);
}

static int set_time_ntpserver(char *refparam, struct dmctx *ctx, int action, char *value, int index)
{
	struct uci_list *v;
	struct uci_element *e = NULL;
	int count = 0, i = 0;
	char *ntp[5] = {0};
	
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_option_value_list("system", "ntp", "server", &v);
			if (v) {
				uci_foreach_element(v, e) {
					if ((count + 1) == index)
						ntp[count] = dmstrdup(value);
					else
						ntp[count] = dmstrdup(e->name);
					count++;
					if (count > 4)
						break;
				}
			}
			if (index > count) {
				ntp[index - 1] = dmstrdup(value);
				count = index;
			}
			for (i = 0; i < 5; i++) {
				if (ntp[i] && (*ntp[i]) != '\0')
					count = i+1;
			}
			dmuci_delete("system", "ntp", "server", NULL);
			for (i = 0; i < count; i++) {
				dmuci_add_list_value("system", "ntp", "server", ntp[i] ? ntp[i] : "");
				dmfree(ntp[i]);
			}
			return 0;
	}
	return 0;
}

static int set_time_ntpserver1(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_time_ntpserver(refparam, ctx, action, value, 1);
}

static int set_time_ntpserver2(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_time_ntpserver(refparam, ctx, action, value, 2);
}

static int set_time_ntpserver3(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_time_ntpserver(refparam, ctx, action, value, 3);
}

static int set_time_ntpserver4(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_time_ntpserver(refparam, ctx, action, value, 4);
}

static int set_time_ntpserver5(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_time_ntpserver(refparam, ctx, action, value, 5);
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.Time. *** */
DMLEAF tTimeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_time_enable, set_time_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_time_status, NULL, BBFDM_BOTH},
{"NTPServer1", &DMWRITE, DMT_STRING, get_time_ntpserver1, set_time_ntpserver1, BBFDM_BOTH},
{"NTPServer2", &DMWRITE, DMT_STRING, get_time_ntpserver2, set_time_ntpserver2, BBFDM_BOTH},
{"NTPServer3", &DMWRITE, DMT_STRING, get_time_ntpserver3, set_time_ntpserver3, BBFDM_BOTH},
{"NTPServer4", &DMWRITE, DMT_STRING, get_time_ntpserver4, set_time_ntpserver4, BBFDM_BOTH},
{"NTPServer5", &DMWRITE, DMT_STRING, get_time_ntpserver5, set_time_ntpserver5, BBFDM_BOTH},
{"CurrentLocalTime", &DMREAD, DMT_TIME, get_time_CurrentLocalTime, NULL, BBFDM_BOTH},
{"LocalTimeZone", &DMWRITE, DMT_STRING, get_time_LocalTimeZone, set_time_LocalTimeZone, BBFDM_BOTH},
{0}
};
