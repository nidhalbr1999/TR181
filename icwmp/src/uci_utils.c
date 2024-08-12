/*
 * uci_utils.c - API to manage UCI packages/sections/options
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 * See LICENSE file for license related information.
 *
 */

#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "uci_utils.h"
#include "log.h"

pthread_mutex_t mutex_config_load = PTHREAD_MUTEX_INITIALIZER;

// STATIC functions
static int _uci_get_value_by_section_string(struct uci_section *s, char *option, char *value, int len)
{
	struct uci_element *e;

	if (s == NULL || option == NULL)
		return UCI_ERR_NOTFOUND;

	uci_foreach_element(&s->options, e)
	{
		struct uci_option *o;

		o = (uci_to_option(e));
		if (o && !CWMP_STRCMP(o->e.name, option)) {
			if (o->type == UCI_TYPE_STRING) {
				CWMP_STRNCPY(value, o->v.string, len);
			}
			break;
		}
	}

	return 0;
}

static char *get_value_from_uci_option(struct uci_option *tb)
{
	if (tb == NULL)
		return "";

	if (tb->type == UCI_TYPE_STRING)
		return tb->v.string;

	return "";
}

static void config_get_acs_elements(struct uci_section *s)
{
	enum {
		UCI_ACS_SSL_CAPATH,
		UCI_ACS_HTTP_DISABLE_100CONTINUE,
		UCI_ACS_INSECURE_ENABLE,
		UCI_ACS_DHCP_DISCOVERY,
		UCI_ACS_URL,
		UCI_ACS_DHCP_URL,
		UCI_ACS_USERID,
		UCI_ACS_PASSWR,
		UCI_ACS_RETRY_MIN_WAIT_INTERVAL,
		UCI_ACS_DHCP_RETRY_MIN_WAIT_INTERVAL,
		UCI_ACS_RETRY_INTERVAL_MULTIPLIER,
		UCI_ACS_DHCP_RETRY_INTERVAL_MULTIPLIER,
		UCI_ACS_COMPRESSION,
		UCI_ACS_GETRPC,
		UCI_ACS_PERIODIC_INFORM_TIME,
		UCI_ACS_PERIODIC_INFORM_INTERVAL,
		UCI_ACS_PERIODIC_INFORM_ENABLE,
		UCI_ACS_HEARTBEAT_ENABLE,
		UCI_ACS_HEARTBEAT_INTERVAL,
		UCI_ACS_HEARTBEAT_TIME,
		__MAX_NUM_UCI_ACS_ATTRS,
	};

	const struct uci_parse_option acs_opts[] = {
		[UCI_ACS_SSL_CAPATH] = { .name = "ssl_capath", .type = UCI_TYPE_STRING },
		[UCI_ACS_HTTP_DISABLE_100CONTINUE] = { .name = "http_disable_100continue", .type = UCI_TYPE_STRING },
		[UCI_ACS_INSECURE_ENABLE] = { .name = "insecure_enable", .type = UCI_TYPE_STRING },
		[UCI_ACS_DHCP_DISCOVERY] = { .name = "dhcp_discovery", .type = UCI_TYPE_STRING },
		[UCI_ACS_URL] = { .name = "url", .type = UCI_TYPE_STRING },
		[UCI_ACS_DHCP_URL] = { .name = "dhcp_url", .type = UCI_TYPE_STRING },
		[UCI_ACS_USERID] = { .name = "userid", .type = UCI_TYPE_STRING },
		[UCI_ACS_PASSWR] = { .name = "passwd", .type = UCI_TYPE_STRING },
		[UCI_ACS_RETRY_MIN_WAIT_INTERVAL] = { .name = "retry_min_wait_interval", .type = UCI_TYPE_STRING },
		[UCI_ACS_DHCP_RETRY_MIN_WAIT_INTERVAL] = { .name = "dhcp_retry_min_wait_interval", .type = UCI_TYPE_STRING },
		[UCI_ACS_RETRY_INTERVAL_MULTIPLIER] = { .name = "retry_interval_multiplier", .type = UCI_TYPE_STRING },
		[UCI_ACS_DHCP_RETRY_INTERVAL_MULTIPLIER] = { .name = "dhcp_retry_interval_multiplier", .type = UCI_TYPE_STRING },
		[UCI_ACS_COMPRESSION] = { .name = "compression", .type = UCI_TYPE_STRING },
		[UCI_ACS_GETRPC] = { .name = "get_rpc_methods", .type = UCI_TYPE_STRING },
		[UCI_ACS_PERIODIC_INFORM_TIME] = { .name = "periodic_inform_time", .type = UCI_TYPE_STRING },
		[UCI_ACS_PERIODIC_INFORM_INTERVAL] = { .name = "periodic_inform_interval", .type = UCI_TYPE_STRING },
		[UCI_ACS_PERIODIC_INFORM_ENABLE] = { .name = "periodic_inform_enable", .type = UCI_TYPE_STRING },
		[UCI_ACS_HEARTBEAT_ENABLE] = { .name = "heartbeat_enable", .type = UCI_TYPE_STRING },
		[UCI_ACS_HEARTBEAT_INTERVAL] = { .name = "heartbeat_interval", .type = UCI_TYPE_STRING },
		[UCI_ACS_HEARTBEAT_TIME] = { .name = "heartbeat_time", .type = UCI_TYPE_STRING },
	};

	struct uci_option *acs_tb[__MAX_NUM_UCI_ACS_ATTRS];

	CWMP_MEMSET(acs_tb, 0, sizeof(acs_tb));
	uci_parse_section(s, acs_opts, __MAX_NUM_UCI_ACS_ATTRS, acs_tb);

	cwmp_main->conf.http_disable_100continue = str_to_bool(get_value_from_uci_option(acs_tb[UCI_ACS_HTTP_DISABLE_100CONTINUE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs http disable 100continue: %d", cwmp_main->conf.http_disable_100continue);

	cwmp_main->conf.insecure_enable = str_to_bool(get_value_from_uci_option(acs_tb[UCI_ACS_INSECURE_ENABLE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs insecure enable: %d", cwmp_main->conf.insecure_enable);

	cwmp_main->conf.dhcp_discovery = str_to_bool(get_value_from_uci_option(acs_tb[UCI_ACS_DHCP_DISCOVERY]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs dhcp discovery: %d", cwmp_main->conf.dhcp_discovery);

	char *get_rpc = get_value_from_uci_option(acs_tb[UCI_ACS_GETRPC]);
	cwmp_main->conf.acs_getrpc = CWMP_STRLEN(get_rpc) ? str_to_bool(get_rpc) : true;
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs get rpc: %d", cwmp_main->conf.acs_getrpc);

	char *url = get_value_from_uci_option(acs_tb[UCI_ACS_URL]);
	char *dhcp_url = get_value_from_uci_option(acs_tb[UCI_ACS_DHCP_URL]);
	char *new_url = cwmp_main->conf.dhcp_discovery ? (CWMP_STRLEN(dhcp_url) ? dhcp_url : url) : url;

	if (CWMP_STRCMP(cwmp_main->conf.acs_url, new_url) != 0) {
		if (CWMP_STRLEN(cwmp_main->conf.acs_url) != 0 && CWMP_STRLEN(new_url) != 0)
			cwmp_main->acs_changed = true;

		snprintf(cwmp_main->conf.acs_url, sizeof(cwmp_main->conf.acs_url), "%s", new_url);
	}

	CWMP_LOG(DEBUG, "CWMP CONFIG - acs url: %s", cwmp_main->conf.acs_url);

	snprintf(cwmp_main->conf.acs_userid, sizeof(cwmp_main->conf.acs_userid), "%s", get_value_from_uci_option(acs_tb[UCI_ACS_USERID]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs username: %s", cwmp_main->conf.acs_userid);

	snprintf(cwmp_main->conf.acs_passwd, sizeof(cwmp_main->conf.acs_passwd), "%s", get_value_from_uci_option(acs_tb[UCI_ACS_PASSWR]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs password: %s", cwmp_main->conf.acs_passwd);

	snprintf(cwmp_main->conf.acs_ssl_capath, sizeof(cwmp_main->conf.acs_ssl_capath), "%s", get_value_from_uci_option(acs_tb[UCI_ACS_SSL_CAPATH]));
	// Use default system cert path if ssl_capath not defined
	if (CWMP_STRLEN(cwmp_main->conf.acs_ssl_capath) == 0) {
		CWMP_STRNCPY(cwmp_main->conf.acs_ssl_capath, "/etc/ssl/certs", sizeof(cwmp_main->conf.acs_ssl_capath));
	}
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs ssl capath: %s", cwmp_main->conf.acs_ssl_capath);

	cwmp_main->conf.retry_min_wait_interval = DEFAULT_RETRY_MINIMUM_WAIT_INTERVAL;
	char *acs_retry_min_wait_interval = get_value_from_uci_option(acs_tb[UCI_ACS_RETRY_MIN_WAIT_INTERVAL]);
	char *acs_dhcp_retry_min_wait_interval = get_value_from_uci_option(acs_tb[UCI_ACS_DHCP_RETRY_MIN_WAIT_INTERVAL]);
	char *op_interval = cwmp_main->conf.dhcp_discovery ? acs_dhcp_retry_min_wait_interval : acs_retry_min_wait_interval;
	if (strlen(op_interval) != 0) {
		if (cwmp_main->conf.amd_version >= AMD_3) {
			int a = atoi(op_interval);
			cwmp_main->conf.retry_min_wait_interval = (a <= 65535 && a >= 1) ? a : DEFAULT_RETRY_MINIMUM_WAIT_INTERVAL;
		}
	}
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs retry minimum wait interval: %d", cwmp_main->conf.retry_min_wait_interval);

	cwmp_main->conf.retry_interval_multiplier = DEFAULT_RETRY_INTERVAL_MULTIPLIER;
	char *acs_retry_interval_multiplier = get_value_from_uci_option(acs_tb[UCI_ACS_RETRY_INTERVAL_MULTIPLIER]);
	char *acs_dhcp_retry_interval_multiplier = get_value_from_uci_option(acs_tb[UCI_ACS_DHCP_RETRY_INTERVAL_MULTIPLIER]);
	char *op_multi = cwmp_main->conf.dhcp_discovery ? acs_dhcp_retry_interval_multiplier : acs_retry_interval_multiplier;
	if (strlen(op_multi) != 0) {
		if (cwmp_main->conf.amd_version >= AMD_3) {
			int a = atoi(op_multi);
			cwmp_main->conf.retry_interval_multiplier = (a <= 65535 && a >= 1000) ? a : DEFAULT_RETRY_INTERVAL_MULTIPLIER;
		}
	}
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs retry interval multiplier: %d", cwmp_main->conf.retry_interval_multiplier);

	cwmp_main->conf.compression = COMP_NONE;
	char *acs_comp = get_value_from_uci_option(acs_tb[UCI_ACS_COMPRESSION]);
	if (cwmp_main->conf.amd_version >= AMD_5 && strlen(acs_comp) != 0) {
		if (strcasecmp(acs_comp, "gzip") == 0) {
			cwmp_main->conf.compression = COMP_GZIP;
		} else if (strcasecmp(acs_comp, "deflate") == 0) {
			cwmp_main->conf.compression = COMP_DEFLATE;
		} else {
			cwmp_main->conf.compression = COMP_NONE;
		}
	}

	cwmp_main->conf.time = 0;
	char *time = get_value_from_uci_option(acs_tb[UCI_ACS_PERIODIC_INFORM_TIME]);
	if (strlen(time) != 0) {
		cwmp_main->conf.time = convert_datetime_to_timestamp(time);
	}

	cwmp_main->conf.period = PERIOD_INFORM_DEFAULT;
	char *inform_interval = get_value_from_uci_option(acs_tb[UCI_ACS_PERIODIC_INFORM_INTERVAL]);
	if (strlen(inform_interval) != 0) {
		int a = atoi(inform_interval);
		cwmp_main->conf.period = (a >= PERIOD_INFORM_MIN) ? a : PERIOD_INFORM_DEFAULT;
	}
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs periodic inform: %d", cwmp_main->conf.period);

	cwmp_main->conf.periodic_enable = str_to_bool(get_value_from_uci_option(acs_tb[UCI_ACS_PERIODIC_INFORM_ENABLE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs periodic enable: %d", cwmp_main->conf.periodic_enable);

	cwmp_main->conf.heart_beat_enable = str_to_bool(get_value_from_uci_option(acs_tb[UCI_ACS_HEARTBEAT_ENABLE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs heart beat enable: %d", cwmp_main->conf.heart_beat_enable);

	cwmp_main->conf.heartbeat_interval = 30;
	char *heartbeat_interval = get_value_from_uci_option(acs_tb[UCI_ACS_HEARTBEAT_INTERVAL]);
	if (strlen(heartbeat_interval) != 0) {
		int a = atoi(heartbeat_interval);
		cwmp_main->conf.heartbeat_interval = a;
	}
	CWMP_LOG(DEBUG, "CWMP CONFIG - acs heartbeat interval: %d", cwmp_main->conf.heartbeat_interval);

	cwmp_main->conf.heart_time = 0;
	char *heartbeat_time = get_value_from_uci_option(acs_tb[UCI_ACS_HEARTBEAT_TIME]);
	if (strlen(heartbeat_time) != 0) {
		cwmp_main->conf.heart_time = convert_datetime_to_timestamp(heartbeat_time);
	}
}

static void config_get_cpe_elements(struct uci_section *s)
{
	enum {
		UCI_CPE_CON_REQ_TIMEOUT,
		UCI_CPE_USER_ID,
		UCI_CPE_PASSWD,
		UCI_CPE_PORT,
		UCI_CPE_CRPATH,
		UCI_CPE_NOTIFY_PERIODIC_ENABLE,
		UCI_CPE_NOTIFY_PERIOD,
		UCI_CPE_SCHEDULE_REBOOT,
		UCI_CPE_DELAY_REBOOT,
		UCI_CPE_ACTIVE_NOTIF_THROTTLE,
		UCI_CPE_MANAGEABLE_DEVICES_NOTIF_LIMIT,
		UCI_CPE_SESSION_TIMEOUT,
		UCI_CPE_INSTANCE_MODE,
		UCI_CPE_JSON_CUSTOM_NOTIFY_FILE,
		UCI_CPE_JSON_FORCED_INFORM_FILE,
		UCI_CPE_FORCE_IPV4,
		UCI_CPE_KEEP_SETTINGS,
		UCI_CPE_DEFAULT_WAN_IFACE,
		__MAX_NUM_UCI_CPE_ATTRS,
	};

	const struct uci_parse_option cpe_opts[] = {
		[UCI_CPE_USER_ID] = { .name = "userid", .type = UCI_TYPE_STRING },
		[UCI_CPE_PASSWD] = { .name = "passwd", .type = UCI_TYPE_STRING },
		[UCI_CPE_PORT] = { .name = "port", .type = UCI_TYPE_STRING },
		[UCI_CPE_CRPATH] = { .name = "path", .type = UCI_TYPE_STRING },
		[UCI_CPE_NOTIFY_PERIODIC_ENABLE] = { .name = "periodic_notify_enable", .type = UCI_TYPE_STRING },
		[UCI_CPE_NOTIFY_PERIOD] = { .name = "periodic_notify_interval", .type = UCI_TYPE_STRING },
		[UCI_CPE_SCHEDULE_REBOOT] = { .name = "schedule_reboot", .type = UCI_TYPE_STRING },
		[UCI_CPE_DELAY_REBOOT] = { .name = "delay_reboot", .type = UCI_TYPE_STRING },
		[UCI_CPE_ACTIVE_NOTIF_THROTTLE] = { .name = "active_notif_throttle", .type = UCI_TYPE_STRING },
		[UCI_CPE_MANAGEABLE_DEVICES_NOTIF_LIMIT] = { .name = "md_notif_limit", .type = UCI_TYPE_STRING },
		[UCI_CPE_SESSION_TIMEOUT] = { .name = "session_timeout", .type = UCI_TYPE_STRING },
		[UCI_CPE_INSTANCE_MODE] = { .name = "instance_mode", .type = UCI_TYPE_STRING },
		[UCI_CPE_JSON_CUSTOM_NOTIFY_FILE] = { .name = "custom_notify_json", .type = UCI_TYPE_STRING },
		[UCI_CPE_JSON_FORCED_INFORM_FILE] = { .name = "forced_inform_json", .type = UCI_TYPE_STRING },
		[UCI_CPE_CON_REQ_TIMEOUT] = { .name = "cr_timeout", .type = UCI_TYPE_STRING },
		[UCI_CPE_FORCE_IPV4] = { .name = "force_ipv4", .type = UCI_TYPE_STRING },
		[UCI_CPE_KEEP_SETTINGS] = { .name = "fw_upgrade_keep_settings", .type = UCI_TYPE_STRING },
		[UCI_CPE_DEFAULT_WAN_IFACE] = { .name = "default_wan_interface", .type = UCI_TYPE_STRING }
	};

	struct uci_option *cpe_tb[__MAX_NUM_UCI_CPE_ATTRS];

	CWMP_MEMSET(cpe_tb, 0, sizeof(cpe_tb));
	uci_parse_section(s, cpe_opts, __MAX_NUM_UCI_CPE_ATTRS, cpe_tb);

	snprintf(cwmp_main->conf.cpe_userid, sizeof(cwmp_main->conf.cpe_userid), "%s", get_value_from_uci_option(cpe_tb[UCI_CPE_USER_ID]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe username: %s", cwmp_main->conf.cpe_userid);

	snprintf(cwmp_main->conf.cpe_passwd, sizeof(cwmp_main->conf.cpe_passwd), "%s", get_value_from_uci_option(cpe_tb[UCI_CPE_PASSWD]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe password: %s", cwmp_main->conf.cpe_passwd);

	cwmp_main->conf.cr_timeout = DEFAULT_CR_TIMEOUT;
	char *tm_out = get_value_from_uci_option(cpe_tb[UCI_CPE_CON_REQ_TIMEOUT]);
	if (strlen(tm_out) != 0) {
		int a = strtod(tm_out, NULL);
		if (a > 0) {
			cwmp_main->conf.cr_timeout = a;
		}
	}
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe connection request timeout: %d", cwmp_main->conf.cr_timeout);

	cwmp_main->conf.connection_request_port = DEFAULT_CONNECTION_REQUEST_PORT;
	char *port = get_value_from_uci_option(cpe_tb[UCI_CPE_PORT]);
	if (strlen(port) != 0) {
		int a = atoi(port);
		cwmp_main->conf.connection_request_port = (a != 0) ? a : DEFAULT_CONNECTION_REQUEST_PORT;
	}
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe connection request port: %d", cwmp_main->conf.connection_request_port);

	char *crpath = get_value_from_uci_option(cpe_tb[UCI_CPE_CRPATH]);
	snprintf(cwmp_main->conf.connection_request_path, sizeof(cwmp_main->conf.connection_request_path), "%s", strlen(crpath) ? (*crpath == '/') ? crpath + 1 : crpath : "/");
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe connection request path: %s", cwmp_main->conf.connection_request_path);

	cwmp_main->conf.periodic_notify_enable = str_to_bool(get_value_from_uci_option(cpe_tb[UCI_CPE_NOTIFY_PERIODIC_ENABLE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe periodic notify enable: %d", cwmp_main->conf.periodic_notify_enable);

	cwmp_main->conf.periodic_notify_interval = DEFAULT_NOTIFY_PERIOD;
	char *notify_period = get_value_from_uci_option(cpe_tb[UCI_CPE_NOTIFY_PERIOD]);
	if (strlen(notify_period) != 0) {
		int a = atoi(notify_period);
		cwmp_main->conf.periodic_notify_interval = (a != 0) ? a : DEFAULT_NOTIFY_PERIOD;
	}
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe periodic notify interval: %d", cwmp_main->conf.periodic_notify_interval);

	cwmp_main->conf.schedule_reboot = 0;
	char *schedule_reboot = get_value_from_uci_option(cpe_tb[UCI_CPE_SCHEDULE_REBOOT]);
	if (strlen(schedule_reboot) != 0) {
		cwmp_main->conf.schedule_reboot = convert_datetime_to_timestamp(schedule_reboot);
	}

	cwmp_main->conf.delay_reboot = -1;
	char *delay_reboot = get_value_from_uci_option(cpe_tb[UCI_CPE_DELAY_REBOOT]);
	if (strlen(delay_reboot) != 0) {
		int a = atoi(delay_reboot);
		cwmp_main->conf.delay_reboot = (a > 0) ? a : -1;
	}

	cwmp_main->conf.active_notif_throttle = 0;
	char *notify_thottle = get_value_from_uci_option(cpe_tb[UCI_CPE_ACTIVE_NOTIF_THROTTLE]);
	if (strlen(notify_thottle) != 0) {
		int a = atoi(notify_thottle);
		cwmp_main->conf.active_notif_throttle = (a > 0) ? a : 0;
	}

	cwmp_main->conf.md_notif_limit = 0;
	char *notify_limit = get_value_from_uci_option(cpe_tb[UCI_CPE_MANAGEABLE_DEVICES_NOTIF_LIMIT]);
	if (strlen(notify_limit) != 0) {
		int a = atoi(notify_limit);
		cwmp_main->conf.md_notif_limit = (a > 0) ? a : 0;
	}

	cwmp_main->conf.session_timeout = DEFAULT_SESSION_TIMEOUT;
	char *session_timeout = get_value_from_uci_option(cpe_tb[UCI_CPE_SESSION_TIMEOUT]);
	if (strlen(session_timeout) != 0) {
		int a = atoi(session_timeout);
		cwmp_main->conf.session_timeout = (a >= 1) ? a : DEFAULT_SESSION_TIMEOUT;
	}

	cwmp_main->conf.instance_mode = DEFAULT_INSTANCE_MODE;
	char *instance_mode = get_value_from_uci_option(cpe_tb[UCI_CPE_INSTANCE_MODE]);
	if (strlen(instance_mode) != 0) {
		if (CWMP_STRCMP(instance_mode, "InstanceNumber") == 0) {
			cwmp_main->conf.instance_mode = INSTANCE_MODE_NUMBER;
		} else {
			cwmp_main->conf.instance_mode = INSTANCE_MODE_ALIAS;
		}
	}

	snprintf(cwmp_main->conf.custom_notify_json, sizeof(cwmp_main->conf.custom_notify_json), "%s", get_value_from_uci_option(cpe_tb[UCI_CPE_JSON_CUSTOM_NOTIFY_FILE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe custom notify json path: %s", cwmp_main->conf.custom_notify_json);

	snprintf(cwmp_main->conf.forced_inform_json, sizeof(cwmp_main->conf.forced_inform_json), "%s", get_value_from_uci_option(cpe_tb[UCI_CPE_JSON_FORCED_INFORM_FILE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe forced inform json path: %s", cwmp_main->conf.forced_inform_json);

	cwmp_main->conf.force_ipv4 = str_to_bool(get_value_from_uci_option(cpe_tb[UCI_CPE_FORCE_IPV4]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe force ipv4 enable: %d", cwmp_main->conf.force_ipv4);

	cwmp_main->conf.fw_upgrade_keep_settings = cpe_tb[UCI_CPE_KEEP_SETTINGS] ? str_to_bool(get_value_from_uci_option(cpe_tb[UCI_CPE_KEEP_SETTINGS])) : true;
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe keep settings enable: %d", cwmp_main->conf.fw_upgrade_keep_settings);

	char *value = get_value_from_uci_option(cpe_tb[UCI_CPE_DEFAULT_WAN_IFACE]);
	char *wan_intf = CWMP_STRLEN(value) ? value : "wan";

	if (strcmp(cwmp_main->conf.default_wan_iface, wan_intf) != 0) {
		snprintf(cwmp_main->conf.default_wan_iface, sizeof(cwmp_main->conf.default_wan_iface), "%s", wan_intf);
		memset(cwmp_main->net.interface, 0, sizeof(cwmp_main->net.interface));
	}
	CWMP_LOG(DEBUG, "CWMP CONFIG - cpe default_wan_interface: %s", cwmp_main->conf.default_wan_iface);
}

static void config_get_lwn_elements(struct uci_section *s)
{
	enum {
		UCI_LWN_ENABLE,
		UCI_LWN_HOSTNAME,
		UCI_LWN_PORT,
		__MAX_NUM_UCI_LWN_ATTRS,
	};

	const struct uci_parse_option acs_opts[] = {
		[UCI_LWN_ENABLE] = { .name = "enable", .type = UCI_TYPE_STRING },
		[UCI_LWN_HOSTNAME] = { .name = "hostname", .type = UCI_TYPE_STRING },
		[UCI_LWN_PORT] = { .name = "port", .type = UCI_TYPE_STRING },
	};

	struct uci_option *lwn_tb[__MAX_NUM_UCI_LWN_ATTRS];

	CWMP_MEMSET(lwn_tb, 0, sizeof(lwn_tb));
	uci_parse_section(s, acs_opts, __MAX_NUM_UCI_LWN_ATTRS, lwn_tb);

	cwmp_main->conf.lwn_enable = str_to_bool(get_value_from_uci_option(lwn_tb[UCI_LWN_ENABLE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - lwn enable: %d", cwmp_main->conf.lwn_enable);

	snprintf(cwmp_main->conf.lwn_hostname, sizeof(cwmp_main->conf.lwn_hostname), "%s", get_value_from_uci_option(lwn_tb[UCI_LWN_HOSTNAME]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - lwn hostname: %s", cwmp_main->conf.lwn_hostname);

	cwmp_main->conf.lwn_port = DEFAULT_LWN_PORT;
	char *port = get_value_from_uci_option(lwn_tb[UCI_LWN_PORT]);
	if (strlen(port) != 0) {
		int a = atoi(port);
		cwmp_main->conf.lwn_port = a;
	}
	CWMP_LOG(DEBUG, "CWMP CONFIG - lwn port: %d", cwmp_main->conf.lwn_port);
}

static void config_get_tc_elements(struct uci_section *s)
{
	enum {
		UCI_TC_ENABLE,
		UCI_TC_TRANSFERTYPE,
		UCI_TC_RESULTTYPE,
		UCI_TC_FILETYPE,
		__MAX_NUM_UCI_TC_ATTRS,
	};

	const struct uci_parse_option acs_opts[] = {
		[UCI_TC_ENABLE] = { .name = "enable", .type = UCI_TYPE_STRING },
		[UCI_TC_TRANSFERTYPE] = { .name = "transfer_type", .type = UCI_TYPE_STRING },
		[UCI_TC_RESULTTYPE] = { .name = "result_type", .type = UCI_TYPE_STRING },
		[UCI_TC_FILETYPE] = { .name = "file_type", .type = UCI_TYPE_STRING },
	};

	struct uci_option *tc_tb[__MAX_NUM_UCI_TC_ATTRS];

	CWMP_MEMSET(tc_tb, 0, sizeof(tc_tb));
	uci_parse_section(s, acs_opts, __MAX_NUM_UCI_TC_ATTRS, tc_tb);

	cwmp_main->conf.auto_tc_enable = str_to_bool(get_value_from_uci_option(tc_tb[UCI_TC_ENABLE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - tc enable: %d", cwmp_main->conf.auto_tc_enable);

	snprintf(cwmp_main->conf.auto_tc_transfer_type, sizeof(cwmp_main->conf.auto_tc_transfer_type), "%s", get_value_from_uci_option(tc_tb[UCI_TC_TRANSFERTYPE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - tc transfer type: %s", cwmp_main->conf.auto_tc_transfer_type);

	snprintf(cwmp_main->conf.auto_tc_result_type, sizeof(cwmp_main->conf.auto_tc_result_type), "%s", get_value_from_uci_option(tc_tb[UCI_TC_RESULTTYPE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - tc result type: %s", cwmp_main->conf.auto_tc_result_type);

	snprintf(cwmp_main->conf.auto_tc_file_type, sizeof(cwmp_main->conf.auto_tc_file_type), "%s", get_value_from_uci_option(tc_tb[UCI_TC_FILETYPE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - tc file type: %s", cwmp_main->conf.auto_tc_file_type);
}

static void config_get_cds_elements(struct uci_section *s)
{
	enum {
		UCI_CDS_ENABLE,
		UCI_CDS_OPTYPE,
		UCI_CDS_RESULTYPE,
		UCI_CDS_FAULTCODE,
		__MAX_NUM_UCI_CDS_ATTRS,
	};

	const struct uci_parse_option cdu_opts[] = {
		[UCI_CDS_ENABLE] = { .name = "enable", .type = UCI_TYPE_STRING },
		[UCI_CDS_OPTYPE] = { .name = "operation_type", .type = UCI_TYPE_STRING },
		[UCI_CDS_RESULTYPE] = { .name = "result_type", .type = UCI_TYPE_STRING },
		[UCI_CDS_FAULTCODE] = { .name = "fault_code", .type = UCI_TYPE_STRING },
	};

	struct uci_option *cds_tb[__MAX_NUM_UCI_CDS_ATTRS];

	CWMP_MEMSET(cds_tb, 0, sizeof(cds_tb));
	uci_parse_section(s, cdu_opts, __MAX_NUM_UCI_CDS_ATTRS, cds_tb);

	cwmp_main->conf.auto_cdu_enable = str_to_bool(get_value_from_uci_option(cds_tb[UCI_CDS_ENABLE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - cds enable: %d", cwmp_main->conf.auto_cdu_enable);

	snprintf(cwmp_main->conf.auto_cdu_oprt_type, sizeof(cwmp_main->conf.auto_cdu_oprt_type), "%s", get_value_from_uci_option(cds_tb[UCI_CDS_OPTYPE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - cds operation type: %s", cwmp_main->conf.auto_cdu_oprt_type);

	snprintf(cwmp_main->conf.auto_cdu_result_type, sizeof(cwmp_main->conf.auto_cdu_result_type), "%s", get_value_from_uci_option(cds_tb[UCI_CDS_RESULTYPE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - cds result type: %s", cwmp_main->conf.auto_cdu_result_type);

	snprintf(cwmp_main->conf.auto_cdu_fault_code, sizeof(cwmp_main->conf.auto_cdu_fault_code), "%s", get_value_from_uci_option(cds_tb[UCI_CDS_FAULTCODE]));
	CWMP_LOG(DEBUG, "CWMP CONFIG - cds fault type: %s", cwmp_main->conf.auto_cdu_fault_code);
}

static int _export_uci_package(struct uci_context *uci_ctx, char *package, const char *output_path)
{
	struct uci_ptr ptr = { 0 };
	int ret = 0;

	if (output_path == NULL)
		return -1;

	FILE *out = fopen(output_path, "a");
	if (!out)
		return -1;

	if (uci_ctx == NULL) {
		ret = -1;
		goto end;
	}

	if (uci_lookup_ptr(uci_ctx, &ptr, package, true) != UCI_OK) {
		ret = -1;
		goto end;
	}

	if (uci_export(uci_ctx, out, ptr.p, true) != UCI_OK)
		ret = -1;

end:
	fclose(out);
	return ret;
}

// PUBLIC ##
int export_uci_package(char *package, const char *output_path)
{
	struct uci_context *uci_ctx = NULL;

	pthread_mutex_lock(&mutex_config_load);
	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		goto end;
	}

	_export_uci_package(uci_ctx, package, output_path);

end:
	if (uci_ctx) {
		uci_free_context(uci_ctx);
	}
	pthread_mutex_unlock(&mutex_config_load);

	return 0;
}

int export_std_uci(const char *output_path)
{
	struct uci_context *uci_ctx = NULL;
	char **configs = NULL;
	char **p;

	pthread_mutex_lock(&mutex_config_load);
	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		goto end;
	}

	if (uci_list_configs(uci_ctx, &configs) != UCI_OK) {
		goto end;
	}

	if (configs == NULL) {
		goto end;
	}

	for (p = configs; *p; p++) {
		_export_uci_package(uci_ctx, *p, output_path);
	}

end:
	FREE(configs);
	if (uci_ctx) {
		uci_free_context(uci_ctx);
	}
	pthread_mutex_unlock(&mutex_config_load);
	return 0;
}

int import_uci_package(char *package_name, const char *input_path)
{
	struct uci_context *uci_ctx = NULL;
	struct uci_package *package = NULL;
	struct uci_element *e = NULL;
	int ret = CWMP_OK;
	FILE *input;

	if (CWMP_STRLEN(input_path) == 0) {
		return -1;
	}

	input = fopen(input_path, "r");
	if (!input)
		return -1;

	pthread_mutex_lock(&mutex_config_load);
	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		goto end;
	}

	if (uci_import(uci_ctx, input, package_name, &package, (package_name != NULL)) != UCI_OK) {
		ret = -1;
		goto end;
	}

	uci_foreach_element(&uci_ctx->root, e)
	{
		struct uci_package *p = uci_to_package(e);
		if (uci_commit(uci_ctx, &p, true) != UCI_OK) {
			ret |= CWMP_GEN_ERR;
		}
	}

end:
	if (uci_ctx) {
		uci_free_context(uci_ctx);
	}
	fclose(input);
	pthread_mutex_unlock(&mutex_config_load);
	return ret;
}

int get_uci_path_value(const char *conf_dir, char *path, char *value, size_t max_value_len)
{
	struct uci_context *uci_ctx = NULL;
	struct uci_ptr ptr;
	int ret = UCI_ERR_NOTFOUND;
	char *str = NULL;

	if (!path || !value || max_value_len == 0) {
		CWMP_LOG(ERROR, "Invalid input options");
		return -1;
	}

	// init with default null data
	value[0]='\0';
	pthread_mutex_lock(&mutex_config_load);
	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		CWMP_LOG(ERROR, "Failed to get uci context");
		ret = -1;
		goto exit;
	}

	if (conf_dir) {
		uci_set_confdir(uci_ctx, conf_dir);
	}

	str = CWMP_STRDUP(path);
	if (uci_lookup_ptr(uci_ctx, &ptr, str, true) != UCI_OK) {
		CWMP_LOG(INFO, "Failed to loopup uci [%s]", path);
		ret = UCI_ERR_NOTFOUND;
		goto exit;
	}

	if (ptr.flags & UCI_LOOKUP_COMPLETE) {
		ret = 0;
		if (ptr.o->type == UCI_TYPE_STRING) {
			CWMP_STRNCPY(value, ptr.o->v.string, max_value_len);
		} else if (ptr.o->type == UCI_TYPE_LIST) {
			struct uci_element *e;
			size_t len;

			uci_foreach_element(&ptr.o->v.list, e) {
				len = CWMP_STRLEN(value);
				if (max_value_len < len + CWMP_STRLEN(e->name)) {
					break;
				}
				snprintf(value + len, max_value_len - len, "%s,", e->name);
			}
			len = CWMP_STRLEN(value);
			value[len - 1] = '\0';
		} else if (ptr.s) {
			CWMP_STRNCPY(value, ptr.s->type, max_value_len);
		}
	}

	CWMP_LOG(DEBUG, "UCI [%s::%s]", path, value);
exit:
	FREE(str);
	if (uci_ctx) {
		uci_free_context(uci_ctx);
	}
	pthread_mutex_unlock(&mutex_config_load);
	return ret;
}

int get_uci_dm_list(const char *conf_dir, char *path, struct list_head *head, int notif_type)
{
	struct uci_context *uci_ctx = NULL;
	struct uci_ptr ptr;
	int ret = 0;
	char *str = NULL;

	if (!path) {
		return -1;
	}

	pthread_mutex_lock(&mutex_config_load);
	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		CWMP_LOG(ERROR, "Failed to get uci context");
		goto exit;
	}

	if (conf_dir) {
		uci_set_confdir(uci_ctx, conf_dir);
	}

	str = CWMP_STRDUP(path);
	if (uci_lookup_ptr(uci_ctx, &ptr, str, true) != UCI_OK) {
		ret = -1;
		goto exit;
	}

	if ((ptr.flags & UCI_LOOKUP_COMPLETE) && (ptr.o != NULL) && (ptr.o->type == UCI_TYPE_LIST)) {
		struct uci_element *e;

		uci_foreach_element(&ptr.o->v.list, e) {
			add_dm_parameter_to_list(head, e->name, "", "", notif_type, false);
		}
		ret = 0;
	}

exit:
	FREE(str);
	if (uci_ctx) {
		uci_free_context(uci_ctx);
	}
	pthread_mutex_unlock(&mutex_config_load);
	return ret;
}

int set_uci_path_value(const char *conf_dir, char *path, char *value)
{
	struct uci_context *uci_ctx = NULL;
	struct uci_ptr ptr;
	int ret = -1;
	char str[BUF_SIZE_256] = {0};

	if ((CWMP_STRLEN(path) == 0) || (value == NULL)) {
		CWMP_LOG(ERROR, "Invalid input options");
		return -1;
	}

	pthread_mutex_lock(&mutex_config_load);
	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		CWMP_LOG(ERROR, "Failed to get uci context");
		goto exit;
	}

	if (conf_dir) {
		uci_set_confdir(uci_ctx, conf_dir);
	}

	snprintf(str, BUF_SIZE_256, "%s=%s", path, value);
	if (uci_lookup_ptr(uci_ctx, &ptr, str, true) != UCI_OK) {
		ret = -1;
		goto exit;
	}
	ret = uci_set(uci_ctx, &ptr);
	if (ret == UCI_OK) {
		ret = uci_save(uci_ctx, ptr.p);
	}
	if (ret == UCI_OK) {
		ret = uci_commit(uci_ctx, &ptr.p, false);
	}
exit:
	if (uci_ctx) {
		uci_free_context(uci_ctx);
	}
	pthread_mutex_unlock(&mutex_config_load);
	return ret;
}

int del_uci_list_value(const char *conf_dir, char *path, char *value)
{
	struct uci_context *uci_ctx = NULL;
	struct uci_ptr ptr;
	int ret = 0;
	char str[BUF_SIZE_256] = {0};

	if ((CWMP_STRLEN(path) == 0) || (CWMP_STRLEN(value) == 0))
		return -1;

	pthread_mutex_lock(&mutex_config_load);
	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		goto exit;
	}

	if (conf_dir) {
		uci_set_confdir(uci_ctx, conf_dir);
	}

	snprintf(str, BUF_SIZE_256, "%s=%s", path, value);
	if (uci_lookup_ptr(uci_ctx, &ptr, str, true) != UCI_OK) {
		ret = -1;
		goto exit;
	}
	ret = uci_del_list(uci_ctx, &ptr);
	if (ret == UCI_OK) {
		ret = uci_save(uci_ctx, ptr.p);
	}
	if (ret == UCI_OK) {
		ret = uci_commit(uci_ctx, &ptr.p, false);
	}
exit:
	if (uci_ctx) {
		uci_free_context(uci_ctx);
	}
	pthread_mutex_unlock(&mutex_config_load);
	return ret;
}

int set_uci_list_value(const char *conf_dir, char *path, char *value)
{
	struct uci_context *uci_ctx = NULL;
	struct uci_ptr ptr;
	int ret = 0;
	char str[BUF_SIZE_256] = {0};

	if ((CWMP_STRLEN(path) == 0) || (CWMP_STRLEN(value) == 0))
		return -1;

	pthread_mutex_lock(&mutex_config_load);
	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		goto exit;
	}

	if (conf_dir) {
		uci_set_confdir(uci_ctx, conf_dir);
	}

	snprintf(str, BUF_SIZE_256, "%s=%s", path, value);
	if (uci_lookup_ptr(uci_ctx, &ptr, str, true) != UCI_OK) {
		ret = -1;
		goto exit;
	}
	ret = uci_add_list(uci_ctx, &ptr);
	if (ret == UCI_OK) {
		ret = uci_save(uci_ctx, ptr.p);
	}
	if (ret == UCI_OK) {
		ret = uci_commit(uci_ctx, &ptr.p, false);
	}
exit:
	if (uci_ctx) {
		uci_free_context(uci_ctx);
	}
	pthread_mutex_unlock(&mutex_config_load);
	return ret;
}

int get_global_config()
{
	struct uci_context *uci_ctx = NULL;
	struct uci_package *pkg;
	struct uci_element *e;

	pthread_mutex_lock(&mutex_config_load);
	uci_ctx = uci_alloc_context();
	if (uci_ctx == NULL) {
		goto exit;
	}

	if (uci_load(uci_ctx, "cwmp", &pkg)) {
		goto exit;
	}

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		if (s == NULL || s->type == NULL)
			continue;

		if (CWMP_STRCMP(s->type, "acs") == 0) {
			config_get_acs_elements(s);
		} else if (CWMP_STRCMP(s->type, "cpe") == 0) {
			config_get_cpe_elements(s);
		} else if (CWMP_STRCMP(s->type, "lwn") == 0) {
			config_get_lwn_elements(s);
		} else if (CWMP_STRCMP(s->type, "transfer_complete") == 0) {
			config_get_tc_elements(s);
		} else if (CWMP_STRCMP(s->type, "du_state_change") == 0) {
			config_get_cds_elements(s);
		}
	}

exit:
	if (uci_ctx) {
		uci_free_context(uci_ctx);
	}
	pthread_mutex_unlock(&mutex_config_load);
	return CWMP_OK;
}

int get_inform_parameters_uci(struct list_head *inform_head)
{
	struct uci_context *uci_ctx = NULL;
	struct uci_package *pkg;
	int ret = 0;

	pthread_mutex_lock(&mutex_config_load);
	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		ret = -1;
		goto exit;
	}

	if (uci_load(uci_ctx, "cwmp", &pkg)) {
		ret = -1;
		goto exit;
	}

	struct uci_element *e;
	uci_foreach_element(&pkg->sections, e) {
		char enable[BUF_SIZE_8] = {0};
		char parameter_name[BUF_SIZE_256] = {0};
		char events_str_list[BUF_SIZE_256] = {0};
		struct uci_section *s = uci_to_section(e);

		if (CWMP_STRCMP(s->type, "inform_parameter") != 0) {
			continue;
		}
		_uci_get_value_by_section_string(s, "enable", enable, BUF_SIZE_8);
		_uci_get_value_by_section_string(s, "parameter_name", parameter_name, BUF_SIZE_256);
		_uci_get_value_by_section_string(s, "events_list", events_str_list, BUF_SIZE_256);

		add_dm_parameter_to_list(inform_head, parameter_name, events_str_list, "", 0, str_to_bool(enable));
	}

exit:
	if (uci_ctx) {
		uci_free_context(uci_ctx);
	}
	pthread_mutex_unlock(&mutex_config_load);
	return ret;
}

int commit_uci_package(char *package)
{
	struct uci_context *uci_ctx = NULL;
	struct uci_ptr ptr = {0};
	int ret = 0;

	pthread_mutex_lock(&mutex_config_load);
	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		ret = -1;
		goto exit;
	}

	if (uci_lookup_ptr(uci_ctx, &ptr, package, true) != UCI_OK) {
		ret = -1;
		goto exit;
	}

	if (uci_commit(uci_ctx, &ptr.p, false) != UCI_OK) {
		ret = -1;
		goto exit;
	}

exit:
	if (uci_ctx) {
		uci_free_context(uci_ctx);
	}
	pthread_mutex_unlock(&mutex_config_load);

	return ret;
}
