/*
 * diagnostic.h - Manage Diagnostics parameters from icwmp
 *
 * Copyright (C) 2021-2023, IOPSYS Software Solutions AB.
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *	  Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef __DIAGNOSTIC__H
#define __DIAGNOSTIC__H

bool set_diagnostic_parameter_structure_value(char *parameter_name, char *value);
void set_diagnostic_state_end_session_flag(char *parameter_name, char *value);

int cwmp_wifi_neighboring__diagnostics(void);
int cwmp_download_diagnostics(void);
int cwmp_upload_diagnostics(void);
int cwmp_ip_ping_diagnostics(void);
int cwmp_nslookup_diagnostics(void);
int cwmp_traceroute_diagnostics(void);
int cwmp_udp_echo_diagnostics(void);
int cwmp_serverselection_diagnostics(void);
int cwmp_ip_layer_capacity_diagnostics(void);
int cwmp_packet_capture_diagnostics(void);
int cwmp_selftest_diagnostics(void);

#endif
