/*
 * config.c - load/store icwmp application configuration
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

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include "common.h"
#include "config.h"
#include "log.h"
#include "reboot.h"
#include "uci_utils.h"
#include "ubus_utils.h"
#include "ssl_utils.h"
#include "datamodel_interface.h"
#include "heartbeat.h"
#include "cwmp_http.h"

static void set_cr_incoming_rule(const char *rule)
{
	if (CWMP_LSTRCASECMP(rule, "ip_only") == 0) {
		cwmp_main->cr_policy = CR_POLICY_IP_Only;
	} else if (CWMP_LSTRCASECMP(rule, "ip_port") == 0) {
		cwmp_main->cr_policy = CR_POLICY_BOTH;
	} else {
		cwmp_main->cr_policy = CR_POLICY_Port_Only; // Default case
	}
}

int get_preinit_config()
{
	char value[BUF_SIZE_256] = {0};

	get_uci_path_value(NULL, UCI_LOG_SEVERITY_PATH, value, BUF_SIZE_256);
	log_set_severity_idx(value);

	get_uci_path_value(NULL, UCI_CPE_LOG_FILE_NAME, value, BUF_SIZE_256);
	log_set_log_file_name(value);

	get_uci_path_value(NULL, UCI_CPE_LOG_MAX_SIZE, value, BUF_SIZE_256);
	log_set_file_max_size(value);

	get_uci_path_value(NULL, UCI_CPE_ENABLE_STDOUT_LOG, value, BUF_SIZE_256);
	log_set_on_console(value);

	get_uci_path_value(NULL, UCI_CPE_ENABLE_FILE_LOG, value, BUF_SIZE_256);
	log_set_on_file(value);

	get_uci_path_value(NULL, UCI_CPE_ENABLE_SYSLOG, value, BUF_SIZE_256);
	log_set_on_syslog(value);

	get_uci_path_value(NULL, UCI_CPE_DEFAULT_WAN_IFACE, cwmp_main->conf.default_wan_iface, BUF_SIZE_32);
	if (CWMP_STRLEN(cwmp_main->conf.default_wan_iface) == 0) {
		CWMP_STRNCMP(cwmp_main->conf.default_wan_iface, "wan", sizeof(cwmp_main->conf.default_wan_iface));
	}

	get_uci_path_value(NULL, UCI_CPE_INCOMING_RULE, value, BUF_SIZE_256);
	set_cr_incoming_rule(value);

	cwmp_main->conf.amd_version = DEFAULT_AMD_VERSION;
	get_uci_path_value(NULL, UCI_CPE_AMD_VERSION, value, BUF_SIZE_256);
	if (CWMP_STRLEN(value) != 0) {
		int a = atoi(value);
		cwmp_main->conf.amd_version = (a >= 1 && a <= 6) ? a : DEFAULT_AMD_VERSION;
	}

	cwmp_main->conf.supported_amd_version = cwmp_main->conf.amd_version;

	CWMP_LOG(DEBUG, "CWMP CONFIG - default wan interface: %s", cwmp_main->conf.default_wan_iface);
	CWMP_LOG(DEBUG, "CWMP CONFIG - amendement version: %d", cwmp_main->conf.amd_version);

	return CWMP_OK;
}


static int global_conf_init()
{
	get_global_config();

	/* Launch reboot methods if needed */
	launch_reboot_methods();

	return 0;
}

void cwmp_config_load()
{
	int error = CWMP_GEN_ERR;

	global_conf_init();

	if (cwmp_stop == true)
		return;

	cwmp_main->net.ipv6_status = is_ipv6_enabled();
	error = icwmp_check_http_connection();

	while (error != CWMP_OK && cwmp_stop != true) {
		CWMP_LOG(DEBUG, "Init: failed to check http connection");
		sleep(UCI_OPTION_READ_INTERVAL);
		global_conf_init();
		cwmp_main->net.ipv6_status = is_ipv6_enabled();
		error = icwmp_check_http_connection();
	}
}

int cwmp_get_deviceid()
{
	struct cwmp_dm_parameter dm_param = {0};

	if (CWMP_STRLEN(cwmp_main->deviceid.manufacturer) == 0) {
		cwmp_get_parameter_value("Device.DeviceInfo.Manufacturer", &dm_param);
		snprintf(cwmp_main->deviceid.manufacturer, sizeof(cwmp_main->deviceid.manufacturer), "%s", dm_param.value ? dm_param.value : "");
	}

	if (CWMP_STRLEN(cwmp_main->deviceid.serialnumber) == 0) {
		cwmp_get_parameter_value("Device.DeviceInfo.SerialNumber", &dm_param);
		snprintf(cwmp_main->deviceid.serialnumber, sizeof(cwmp_main->deviceid.serialnumber), "%s", dm_param.value ? dm_param.value : "");
	}

	if (CWMP_STRLEN(cwmp_main->deviceid.productclass) == 0) {
		cwmp_get_parameter_value("Device.DeviceInfo.ProductClass", &dm_param);
		snprintf(cwmp_main->deviceid.productclass, sizeof(cwmp_main->deviceid.productclass), "%s", dm_param.value ? dm_param.value : "");
	}

	if (CWMP_STRLEN(cwmp_main->deviceid.oui) == 0) {
		cwmp_get_parameter_value("Device.DeviceInfo.ManufacturerOUI", &dm_param);
		snprintf(cwmp_main->deviceid.oui, sizeof(cwmp_main->deviceid.oui), "%s", dm_param.value ? dm_param.value : "");
	}

	if (CWMP_STRLEN(cwmp_main->deviceid.softwareversion) == 0) {
		cwmp_get_parameter_value("Device.DeviceInfo.SoftwareVersion", &dm_param);
		snprintf(cwmp_main->deviceid.softwareversion, sizeof(cwmp_main->deviceid.softwareversion), "%s", dm_param.value ? dm_param.value : "");
	}

	return CWMP_OK;
}

int cwmp_config_reload()
{
	CWMP_MEMSET(&cwmp_main->env, 0, sizeof(struct env));

	int err = global_conf_init();
	if (err != CWMP_OK)
		return err;

	return CWMP_OK;
}
