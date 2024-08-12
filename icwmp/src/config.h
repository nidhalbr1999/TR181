/*
 * config.h - load/store icwmp application configuration
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *	  Author Anis Ellouze <anis.ellouze@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef _CONFIG_H__
#define _CONFIG_H__

#define UCI_CPE_LOG_FILE_NAME "cwmp.cpe.log_file_name"
#define UCI_CPE_LOG_MAX_SIZE "cwmp.cpe.log_max_size"
#define UCI_CPE_ENABLE_STDOUT_LOG "cwmp.cpe.log_to_console"
#define UCI_CPE_ENABLE_FILE_LOG "cwmp.cpe.log_to_file"
#define UCI_LOG_SEVERITY_PATH "cwmp.cpe.log_severity"
#define UCI_CPE_ENABLE_SYSLOG "cwmp.cpe.log_to_syslog"
#define UCI_CPE_DEFAULT_WAN_IFACE "cwmp.cpe.default_wan_interface"
#define UCI_CPE_INCOMING_RULE "cwmp.cpe.incoming_rule"
#define UCI_CPE_AMD_VERSION "cwmp.cpe.amd_version"

int cwmp_get_deviceid();
int cwmp_config_reload();
int get_preinit_config();
void cwmp_config_load();
#endif
