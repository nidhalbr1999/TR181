/*
 * diagnostic.c - Manage Diagnostics parameters from icwmp
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

#include <string.h>

#include "common.h"
#include "diagnostic.h"
#include "ubus_utils.h"
#include "log.h"
#include "event.h"
#include "session.h"

struct diagnostic_input {
	char *input_name;
	char *parameter_name;
	char *value;
};

#define DOWNLOAD_DIAG_CMD "Device.IP.Diagnostics.DownloadDiagnostics()"
#define UPLOAD_DIAG_CMD "Device.IP.Diagnostics.UploadDiagnostics()"
#define IPPING_DIAG_CMD "Device.IP.Diagnostics.IPPing()"
#define SERVER_SELECTION_DIAG_CMD "Device.IP.Diagnostics.ServerSelectionDiagnostics()"
#define TRACE_ROUTE_DIAG_CMD "Device.IP.Diagnostics.TraceRoute()"
#define UDPECHO_DIAG_CMD "Device.IP.Diagnostics.UDPEchoDiagnostics()"
#define IPLAYER_CAPACITY_DIAG_CMD "Device.IP.Diagnostics.IPLayerCapacity()"
#define NSLOOKUP_DIAG_CMD "Device.DNS.Diagnostics.NSLookupDiagnostics()"
#define WIFINEIBORING_DIAG_CMD "Device.WiFi.NeighboringWiFiDiagnostic()"
#define PACKET_CAPTURE_DIAG_CMD "Device.PacketCaptureDiagnostics()"
#define SELF_TEST_DIAG_CMD "Device.SelfTestDiagnostics()"

struct diagnostic_input packet_capture[] = {
	{ "Interface", "Device.PacketCaptureDiagnostics.Interface", NULL },
	{ "Format", "Device.PacketCaptureDiagnostics.Format", NULL },
	{ "Duration", "Device.PacketCaptureDiagnostics.Duration", NULL },
	{ "PacketCount", "Device.PacketCaptureDiagnostics.PacketCount", NULL },
	{ "FileTarget", "Device.PacketCaptureDiagnostics.FileTarget", NULL },
	{ "FilterExpression", "Device.PacketCaptureDiagnostics.FilterExpression", NULL },
	{ "Username", "Device.PacketCaptureDiagnostics.Username", NULL },
	{ "Password", "Device.PacketCaptureDiagnostics.Password", NULL },
};

struct diagnostic_input iplayer_capacity[] = {
	{ "Interface", "Device.IP.Diagnostics.IPLayerCapacityMetrics.Interface", NULL },
	{ "Role", "Device.IP.Diagnostics.IPLayerCapacityMetrics.Role", NULL },
	{ "Host", "Device.IP.Diagnostics.IPLayerCapacityMetrics.Host", NULL },
	{ "Port", "Device.IP.Diagnostics.IPLayerCapacityMetrics.Port", NULL },
	{ "JumboFramesPermitted", "Device.IP.Diagnostics.IPLayerCapacityMetrics.JumboFramesPermitted", NULL },
	{ "DSCP", "Device.IP.Diagnostics.IPLayerCapacityMetrics.DSCP", NULL },
	{ "ProtocolVersion", "Device.IP.Diagnostics.IPLayerCapacityMetrics.ProtocolVersion", NULL },
	{ "UDPPayloadContent", "Device.IP.Diagnostics.IPLayerCapacityMetrics.UDPPayloadContent", NULL },
	{ "TestType", "Device.IP.Diagnostics.IPLayerCapacityMetrics.TestType", NULL },
	{ "IPDVEnable", "Device.IP.Diagnostics.IPLayerCapacityMetrics.IPDVEnable", NULL },
	{ "StartSendingRateIndex", "Device.IP.Diagnostics.IPLayerCapacityMetrics.StartSendingRateIndex", NULL },
	{ "NumberTestSubIntervals", "Device.IP.Diagnostics.IPLayerCapacityMetrics.NumberTestSubIntervals", NULL },
	{ "NumberFirstModeTestSubIntervals", "Device.IP.Diagnostics.IPLayerCapacityMetrics.NumberFirstModeTestSubIntervals", NULL },
	{ "TestSubInterval", "Device.IP.Diagnostics.IPLayerCapacityMetrics.TestSubInterval", NULL },
	{ "StatusFeedbackInterval", "Device.IP.Diagnostics.IPLayerCapacityMetrics.StatusFeedbackInterval", NULL },
	{ "SeqErrThresh", "Device.IP.Diagnostics.IPLayerCapacityMetrics.SeqErrThresh", NULL },
	{ "ReordDupIgnoreEnable", "Device.IP.Diagnostics.IPLayerCapacityMetrics.ReordDupIgnoreEnable", NULL },
	{ "LowerThresh", "Device.IP.Diagnostics.IPLayerCapacityMetrics.LowerThresh", NULL },
	{ "UpperThresh", "Device.IP.Diagnostics.IPLayerCapacityMetrics.UpperThresh", NULL },
	{ "HighSpeedDelta", "Device.IP.Diagnostics.IPLayerCapacityMetrics.HighSpeedDelta", NULL },
	{ "SlowAdjThresh", "Device.IP.Diagnostics.IPLayerCapacityMetrics.SlowAdjThresh", NULL },
	{ "RateAdjAlgorithm", "Device.IP.Diagnostics.IPLayerCapacityMetrics.RateAdjAlgorithm", NULL },
};

struct diagnostic_input download_diagnostics[] = {
	{ "Interface", "Device.IP.Diagnostics.DownloadDiagnostics.Interface", NULL },
	{ "DownloadURL", "Device.IP.Diagnostics.DownloadDiagnostics.DownloadURL", NULL },
	{ "DSCP", "Device.IP.Diagnostics.DownloadDiagnostics.DSCP", NULL },
	{ "EthernetPriority", "Device.IP.Diagnostics.DownloadDiagnostics.EthernetPriority", NULL },
	{ "ProtocolVersion", "Device.IP.Diagnostics.DownloadDiagnostics.ProtocolVersion", NULL },
	{ "NumberOfConnections", "Device.IP.Diagnostics.DownloadDiagnostics.NumberOfConnections", NULL },
	{ "EnablePerConnectionResults", "Device.IP.Diagnostics.DownloadDiagnostics.EnablePerConnectionResults", NULL },
	//{"TimeBasedTestDuration","Device.IP.Diagnostics.DownloadDiagnostics.TimeBasedTestDuration",NULL},
	//{"TimeBasedTestMeasurementInterval","Device.IP.Diagnostics.DownloadDiagnostics.TimeBasedTestMeasurementInterval",NULL},
	//{"TimeBasedTestMeasurementOffset","Device.IP.Diagnostics.DownloadDiagnostics.TimeBasedTestMeasurementOffset",NULL}
};

struct diagnostic_input upload_diagnostics[] = {
	{ "Interface", "Device.IP.Diagnostics.UploadDiagnostics.Interface", NULL },
	{ "UploadURL", "Device.IP.Diagnostics.UploadDiagnostics.UploadURL", NULL },
	{ "TestFileLength", "Device.IP.Diagnostics.UploadDiagnostics.TestFileLength", NULL },
	{ "DSCP", "Device.IP.Diagnostics.UploadDiagnostics.DSCP", NULL },
	{ "EthernetPriority", "Device.IP.Diagnostics.UploadDiagnostics.EthernetPriority", NULL },
	{ "ProtocolVersion", "Device.IP.Diagnostics.UploadDiagnostics.ProtocolVersion", NULL },
	{ "NumberOfConnections", "Device.IP.Diagnostics.UploadDiagnostics.NumberOfConnections", NULL },
	{ "EnablePerConnectionResults", "Device.IP.Diagnostics.UploadDiagnostics.EnablePerConnectionResults", NULL },
	//{"TimeBasedTestDuration","Device.IP.Diagnostics.UploadDiagnostics.TimeBasedTestDuration",NULL},
	//{"TimeBasedTestMeasurementInterval","Device.IP.Diagnostics.UploadDiagnostics.TimeBasedTestMeasurementInterval",NULL},
	//{"TimeBasedTestMeasurementOffset","Device.IP.Diagnostics.UploadDiagnostics.TimeBasedTestMeasurementOffset",NULL}
};

struct diagnostic_input ipping_diagnostics[] = {
	{ "Host", "Device.IP.Diagnostics.IPPing.Host", NULL },
	{ "NumberOfRepetitions", "Device.IP.Diagnostics.IPPing.NumberOfRepetitions", NULL },
	{ "Timeout", "Device.IP.Diagnostics.IPPing.Timeout", NULL },
	{ "Interface", "Device.IP.Diagnostics.IPPing.Interface", NULL },
	{ "ProtocolVersion", "Device.IP.Diagnostics.IPPing.ProtocolVersion", NULL },
	{ "DSCP", "Device.IP.Diagnostics.IPPing.DSCP", NULL },
	{ "DataBlockSize", "Device.IP.Diagnostics.IPPing.DataBlockSize", NULL }
};

struct diagnostic_input serverselection_diagnostics[] = {
	{ "Interface", "Device.IP.Diagnostics.ServerSelectionDiagnostics.Interface", NULL },
	{ "Protocol", "Device.IP.Diagnostics.ServerSelectionDiagnostics.Protocol", NULL },
	{ "HostList", "Device.IP.Diagnostics.ServerSelectionDiagnostics.HostList", NULL },
	{ "ProtocolVersion", "Device.IP.Diagnostics.ServerSelectionDiagnostics.ProtocolVersion", NULL },
	{ "NumberOfRepetitions", "Device.IP.Diagnostics.ServerSelectionDiagnostics.NumberOfRepetitions", NULL },
	{ "Timeout", "Device.IP.Diagnostics.ServerSelectionDiagnostics.Timeout", NULL }
};

struct diagnostic_input traceroute_diagnostics[] = {
	{ "Interface", "Device.IP.Diagnostics.TraceRoute.Interface", NULL },
	{ "Host", "Device.IP.Diagnostics.TraceRoute.Host", NULL },
	{ "NumberOfTries", "Device.IP.Diagnostics.TraceRoute.NumberOfTries", NULL },
	{ "ProtocolVersion", "Device.IP.Diagnostics.TraceRoute.ProtocolVersion", NULL },
	{ "Timeout", "Device.IP.Diagnostics.TraceRoute.Timeout", NULL },
	{ "DataBlockSize", "Device.IP.Diagnostics.TraceRoute.DataBlockSize", NULL },
	{ "DSCP", "Device.IP.Diagnostics.TraceRoute.DSCP", NULL },
	{ "MaxHopCount", "Device.IP.Diagnostics.TraceRoute.MaxHopCount", NULL }
};

struct diagnostic_input udpecho_diagnostics[] = {
	{ "Interface", "Device.IP.Diagnostics.UDPEchoDiagnostics.Interface", NULL },
	{ "Host", "Device.IP.Diagnostics.UDPEchoDiagnostics.Host", NULL },
	{ "Port", "Device.IP.Diagnostics.UDPEchoDiagnostics.Port", NULL },
	{ "NumberOfRepetitions", "Device.IP.Diagnostics.UDPEchoDiagnostics.NumberOfRepetitions", NULL },
	{ "Timeout", "Device.IP.Diagnostics.UDPEchoDiagnostics.Timeout", NULL },
	{ "DataBlockSize", "Device.IP.Diagnostics.UDPEchoDiagnostics.DataBlockSize", NULL },
	{ "DSCP", "Device.IP.Diagnostics.UDPEchoDiagnostics.DSCP", NULL },
	{ "InterTransmissionTime", "Device.IP.Diagnostics.UDPEchoDiagnostics.InterTransmissionTime", NULL },
	{ "ProtocolVersion", "Device.IP.Diagnostics.UDPEchoDiagnostics.ProtocolVersion", NULL },
	//{"EnableIndividualPacketResults","Device.IP.Diagnostics.UDPEchoDiagnostics.EnableIndividualPacketResults",NULL}
};

struct diagnostic_input nslookup_diagnostics[] = {
	{ "Interface", "Device.DNS.Diagnostics.NSLookupDiagnostics.Interface", NULL },
	{ "HostName", "Device.DNS.Diagnostics.NSLookupDiagnostics.HostName", NULL },
	{ "DNSServer", "Device.DNS.Diagnostics.NSLookupDiagnostics.DNSServer", NULL },
	{ "NumberOfRepetitions", "Device.DNS.Diagnostics.NSLookupDiagnostics.NumberOfRepetitions", NULL },
	{ "Timeout", "Device.DNS.Diagnostics.NSLookupDiagnostics.Timeout", NULL }
};

void set_diagnostic_state_end_session_flag(char *parameter_name, char *value)
{
	if (CWMP_STRLEN(parameter_name) == 0 || CWMP_STRLEN(value) == 0)
		return;

	if (strcmp(value, "Requested") != 0)
		return;

	if (strcmp(parameter_name, "Device.IP.Diagnostics.DownloadDiagnostics.DiagnosticsState") == 0) {
		cwmp_set_end_session(END_SESSION_DOWNLOAD_DIAGNOSTIC);
		return;
	}

	if (strcmp(parameter_name, "Device.IP.Diagnostics.UploadDiagnostics.DiagnosticsState") == 0) {
		cwmp_set_end_session(END_SESSION_UPLOAD_DIAGNOSTIC);
		return;
	}

	if (strcmp(parameter_name, "Device.IP.Diagnostics.IPPing.DiagnosticsState") == 0) {
		cwmp_set_end_session(END_SESSION_IPPING_DIAGNOSTIC);
		return;
	}

	if (strcmp(parameter_name, "Device.IP.Diagnostics.ServerSelectionDiagnostics.DiagnosticsState") == 0) {
		cwmp_set_end_session(END_SESSION_SERVERSELECTION_DIAGNOSTIC);
		return;
	}

	if (strcmp(parameter_name, "Device.IP.Diagnostics.TraceRoute.DiagnosticsState") == 0) {
		cwmp_set_end_session(END_SESSION_TRACEROUTE_DIAGNOSTIC);
		return;
	}

	if (strcmp(parameter_name, "Device.IP.Diagnostics.UDPEchoDiagnostics.DiagnosticsState") == 0) {
		cwmp_set_end_session(END_SESSION_UDPECHO_DIAGNOSTIC);
		return;
	}

	if (strcmp(parameter_name, "Device.DNS.Diagnostics.NSLookupDiagnostics.DiagnosticsState") == 0) {
		cwmp_set_end_session(END_SESSION_NSLOOKUP_DIAGNOSTIC);
		return;
	}

	if (strcmp(parameter_name, "Device.IP.Diagnostics.IPLayerCapacityMetrics.DiagnosticsState") == 0) {
		cwmp_set_end_session(END_SESSION_IPLAYERCAPACITY_DIAGNOSTIC);
		return;
	}

	if (strcmp(parameter_name, "Device.WiFi.NeighboringWiFiDiagnostic.DiagnosticsState") == 0) {
		cwmp_set_end_session(END_SESSION_NEIGBORING_WIFI_DIAGNOSTIC);
		return;
	}

	if (strcmp(parameter_name, "Device.PacketCaptureDiagnostics.DiagnosticsState") == 0) {
		cwmp_set_end_session(END_SESSION_PACKETCAPTURE_DIAGNOSTIC);
		return;
	}

	if (strcmp(parameter_name, "Device.SelfTestDiagnostics.DiagnosticsState") == 0) {
		cwmp_set_end_session(END_SESSION_SELFTEST_DIAGNOSTIC);
		return;
	}
}

static bool set_specific_diagnostic_object_parameter_structure_value(struct diagnostic_input (*diagnostics_array)[], int number_inputs, char *parameter, char *value)
{
	if (CWMP_STRLEN(parameter) == 0)
		return false;

	for (int i = 0; i < number_inputs; i++) {
		if (CWMP_STRCMP((*diagnostics_array)[i].parameter_name, parameter) == 0) {
			FREE((*diagnostics_array)[i].value);
			(*diagnostics_array)[i].value = strdup(value ? value : "");
			return true;
		}
	}

	return false;
}

bool set_diagnostic_parameter_structure_value(char *parameter_name, char *value) //returns false in case the parameter is not among diagnostics parameters
{
	return set_specific_diagnostic_object_parameter_structure_value(&download_diagnostics, ARRAY_SIZE(download_diagnostics), parameter_name, value) ||
		   set_specific_diagnostic_object_parameter_structure_value(&upload_diagnostics, ARRAY_SIZE(upload_diagnostics), parameter_name, value) ||
	       set_specific_diagnostic_object_parameter_structure_value(&ipping_diagnostics, ARRAY_SIZE(ipping_diagnostics), parameter_name, value) ||
		   set_specific_diagnostic_object_parameter_structure_value(&nslookup_diagnostics, ARRAY_SIZE(nslookup_diagnostics), parameter_name, value) ||
	       set_specific_diagnostic_object_parameter_structure_value(&traceroute_diagnostics, ARRAY_SIZE(traceroute_diagnostics), parameter_name, value) ||
		   set_specific_diagnostic_object_parameter_structure_value(&udpecho_diagnostics, ARRAY_SIZE(udpecho_diagnostics), parameter_name, value) ||
	       set_specific_diagnostic_object_parameter_structure_value(&serverselection_diagnostics, ARRAY_SIZE(serverselection_diagnostics), parameter_name, value) ||
		   set_specific_diagnostic_object_parameter_structure_value(&iplayer_capacity, ARRAY_SIZE(iplayer_capacity), parameter_name, value) ||
	       set_specific_diagnostic_object_parameter_structure_value(&packet_capture, ARRAY_SIZE(packet_capture), parameter_name, value);

}

static int cwmp_diagnostics_operate(char *command, char *command_key, struct diagnostic_input diagnostics[], int number_inputs)
{
	struct blob_buf b = {0};

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	bb_add_string(&b, "command", command);
	bb_add_string(&b, "command_key", command_key);

	if (number_inputs > 0) {
		void *tbl = blobmsg_open_table(&b, "input");

		for (int i = 0; i < number_inputs; i++) {

			if (CWMP_STRLEN(diagnostics[i].value) == 0)
				continue;

			bb_add_string(&b, diagnostics[i].input_name, diagnostics[i].value);
		}

		blobmsg_close_table(&b, tbl);
	}

	int e = icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "operate", b.head, NULL, NULL);
	blob_buf_free(&b);

	return e;
}

int cwmp_wifi_neighboring__diagnostics(void)
{
	if (cwmp_diagnostics_operate(WIFINEIBORING_DIAG_CMD, "cwmp_wifi_neig_diag", NULL, 0) == -1)
		return -1;

	CWMP_LOG(INFO, "WiFi neighboring diagnostic is successfully executed");
	cwmp_main->diag_session = true;
	return 0;
}

int cwmp_packet_capture_diagnostics(void)
{
	if (cwmp_diagnostics_operate(PACKET_CAPTURE_DIAG_CMD, "cwmp_pack_capture_diag", packet_capture, ARRAY_SIZE(packet_capture)) == -1)
		return -1;

	CWMP_LOG(INFO, "packet capture diagnostic is successfully executed");
	cwmp_main->diag_session = true;
	return 0;
}

int cwmp_selftest_diagnostics(void)
{
	if (cwmp_diagnostics_operate(SELF_TEST_DIAG_CMD, "cwmp_self_test_diag", NULL, 0) == -1)
		return -1;

	CWMP_LOG(INFO, "self test diagnostic is successfully executed");
	cwmp_main->diag_session = true;
	return 0;
}

int cwmp_ip_layer_capacity_diagnostics(void)
{
	if (cwmp_diagnostics_operate(IPLAYER_CAPACITY_DIAG_CMD, "cwmp_ip_layer_diag", iplayer_capacity, ARRAY_SIZE(iplayer_capacity)) == -1)
		return -1;

	CWMP_LOG(INFO, "IP layer capacity diagnostic is successfully executed");
	cwmp_main->diag_session = true;
	return 0;
}

int cwmp_download_diagnostics(void)
{
	if (cwmp_diagnostics_operate(DOWNLOAD_DIAG_CMD, "cwmp_ip_download_diag", download_diagnostics, ARRAY_SIZE(download_diagnostics)) == -1)
		return -1;

	CWMP_LOG(INFO, "Download diagnostic is successfully executed");
	cwmp_main->diag_session = true;
	return 0;
}

int cwmp_upload_diagnostics(void)
{
	if (cwmp_diagnostics_operate(UPLOAD_DIAG_CMD, "cwmp_ip_upload_diag", upload_diagnostics, ARRAY_SIZE(upload_diagnostics)) == -1)
		return -1;

	CWMP_LOG(INFO, "Upload diagnostic is successfully executed");
	cwmp_main->diag_session = true;
	return 0;
}

int cwmp_ip_ping_diagnostics(void)
{
	if (cwmp_diagnostics_operate(IPPING_DIAG_CMD, "cwmp_ip_ping_diag", ipping_diagnostics, ARRAY_SIZE(ipping_diagnostics)) == -1)
		return -1;

	CWMP_LOG(INFO, "IPPing diagnostic is successfully executed");
	cwmp_main->diag_session = true;
	return 0;
}

int cwmp_nslookup_diagnostics(void)
{
	if (cwmp_diagnostics_operate(NSLOOKUP_DIAG_CMD, "cwmp_dns_nslookup_diag", nslookup_diagnostics, ARRAY_SIZE(nslookup_diagnostics)) == -1)
		return -1;

	CWMP_LOG(INFO, "Nslookup diagnostic is successfully executed");
	cwmp_main->diag_session = true;
	return 0;
}

int cwmp_traceroute_diagnostics(void)
{
	if (cwmp_diagnostics_operate(TRACE_ROUTE_DIAG_CMD, "cwmp_ip_trace_route_diag", traceroute_diagnostics, ARRAY_SIZE(traceroute_diagnostics)) == -1)
		return -1;

	CWMP_LOG(INFO, "Trace Route diagnostic is successfully executed");
	cwmp_main->diag_session = true;
	return 0;
}

int cwmp_udp_echo_diagnostics(void)
{
	if (cwmp_diagnostics_operate(UDPECHO_DIAG_CMD, "cwmp_ip_udpecho_diag", udpecho_diagnostics, ARRAY_SIZE(udpecho_diagnostics)) == -1)
		return -1;

	CWMP_LOG(INFO, "UDPEcho diagnostic is successfully executed");
	cwmp_main->diag_session = true;
	return 0;
}

int cwmp_serverselection_diagnostics(void)
{
	if (cwmp_diagnostics_operate(SERVER_SELECTION_DIAG_CMD, "cwmp_ip_srv_selection_diag", serverselection_diagnostics, ARRAY_SIZE(serverselection_diagnostics)) == -1)
		return -1;

	CWMP_LOG(INFO, "Server Selection diagnostic is successfully executed");
	cwmp_main->diag_session = true;
	return 0;
}
