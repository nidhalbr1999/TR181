/*
 * xml.c - XML and SOAP functions
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

#include "xml.h"
#include "log.h"
#include "notifications.h"
#include "http.h"
#include "cwmp_zlib.h"
#include "common.h"
#include "event.h"
#include "cwmp_event.h"
#include "datamodel_interface.h"

static const char *soap_env_url = "http://schemas.xmlsoap.org/soap/envelope/";
static const char *soap_enc_url = "http://schemas.xmlsoap.org/soap/encoding/";
static const char *xsd_url = "http://www.w3.org/2001/XMLSchema";
static const char *xsi_url = "http://www.w3.org/2001/XMLSchema-instance";

char *g_tab_space = NULL;

const char *cwmp_urls[] = { "urn:dslforum-org:cwmp-1-0", "urn:dslforum-org:cwmp-1-1", "urn:dslforum-org:cwmp-1-2", "urn:dslforum-org:cwmp-1-2", "urn:dslforum-org:cwmp-1-2", "urn:dslforum-org:cwmp-1-2", NULL };

struct xml_node_data xml_nodes_data[] = {
		/*
		 * SOAP Requests
		 */
		[SOAP_REQ_SPV] = {XML_SINGLE, 0, NULL, {{"ParameterList", XML_REC, SOAP_REQ_SPV_LIST, NULL}, {"ParameterKey", XML_STRING, 0, NULL}}},
		[SOAP_REQ_GPV] = {XML_LIST, SOAP_REQ_GPV_REF, "string", {}},
		[SOAP_REQ_GPN] = {XML_SINGLE, 0, NULL, {{"ParameterPath", XML_STRING, 0, NULL}, {"NextLevel", XML_BOOL, 0, NULL}}},
		[SOAP_REQ_SPA] = {XML_LIST, SOAP_REQ_SPA_REF, "SetParameterAttributesStruct", {}},
		[SOAP_REQ_GPA] = {XML_LIST, SOAP_REQ_GPA_REF, "string", {}},
		[SOAP_REQ_ADDOBJ] = {XML_SINGLE, 0, NULL, {{"ObjectName", XML_STRING, 0, NULL}, {"ParameterKey", XML_STRING, 0, NULL}}},
		[SOAP_REQ_DELOBJ] = {XML_SINGLE, 0, NULL, {{"ObjectName", XML_STRING, 0, NULL}, {"ParameterKey", XML_STRING, 0, NULL}}},
		[SOAP_REQ_REBOOT] = {XML_SINGLE, 0, NULL, {{"CommandKey", XML_STRING, 0, NULL}}},
		[SOAP_REQ_DOWNLOAD] = {XML_SINGLE, 0, NULL, {{"CommandKey", XML_STRING, 0, NULL}, {"FileType", XML_FUNC, 0, load_download_filetype}, {"URL", XML_STRING, 0, NULL}, {"Username", XML_STRING, 0, NULL}, {"Password", XML_STRING, 0, NULL}, {"FileSize", XML_INTEGER, 0, NULL}, {"DelaySeconds", XML_INTEGER, 0, NULL}}},
		[SOAP_REQ_UPLOAD] = {XML_SINGLE, 0, NULL, {{"CommandKey", XML_STRING, 0, NULL}, {"FileType", XML_FUNC, 0, load_upload_filetype}, {"URL", XML_STRING, 0, NULL}, {"Username", XML_STRING, 0, NULL}, {"Password", XML_STRING, 0, NULL}, {"DelaySeconds", XML_INTEGER, 0, NULL}}},
		[SOAP_REQ_CANCELTRANSFER] = {XML_SINGLE, 0, NULL, {{"CommandKey", XML_STRING, 0, NULL}}},
		[SOAP_REQ_SCHEDINF] = {XML_SINGLE, 0, NULL, {{"CommandKey", XML_STRING, 0, NULL}, {"DelaySeconds", XML_INTEGER, 0, NULL}}},
		[SOAP_REQ_SCHEDDOWN] = {XML_SINGLE, 0, NULL, {{"CommandKey", XML_STRING, 0, NULL}, {"FileType", XML_STRING, 0, NULL}, {"URL", XML_STRING, 0, NULL}, {"Username", XML_STRING, 0, NULL}, {"Password", XML_STRING, 0, NULL}, {"FileSize", XML_STRING, 0, NULL}, {"TimeWindowList", XML_REC, SOAP_TIMEWINDOW_REF, NULL}}},
		[SOAP_REQ_CDU] = {XML_SINGLE, 0, NULL, {{"CommandKey", XML_STRING, 0, NULL}, {"Operations", XML_REC, SOAP_REQ_CDU_OPERATIONS, NULL}}},
		[SOAP_REQ_SPV_LIST] = {XML_LIST, SOAP_REQ_SPV_LIST_REF, "ParameterValueStruct", {}},
		[SOAP_REQ_SPV_LIST_REF] = {XML_SINGLE, 0, NULL, {{"Name", XML_STRING, 0, NULL}, {"Value", XML_STRING, 0, NULL}}},
		[SOAP_REQ_GPV_REF] = {XML_SINGLE, 0, NULL, {{"string", XML_STRING, 0, NULL}}},
		[SOAP_REQ_SPA_REF] = {XML_SINGLE, 0, NULL, {{"Name", XML_STRING, 0, NULL}, {"Notification", XML_INTEGER, 0, NULL}, {"NotificationChange", XML_BOOL, 0, NULL}}},
		[SOAP_REQ_GPA_REF] = {XML_SINGLE, 0, NULL, {{"string", XML_STRING, 0, NULL}}},
		[SOAP_TIMEWINDOW_REF] = {XML_LIST, SOAP_TIME_REF, NULL, {}},
		[SOAP_TIME_REF] = {XML_SINGLE, 0, NULL, {{"WindowStart", XML_LINTEGER, 0, NULL}, {"WindowEnd", XML_LINTEGER, 0, NULL}, {"WindowMode", XML_STRING, 0, NULL}, {"WindowMode", XML_FUNC, 0, load_sched_download_window_mode}, {"MaxRetries", XML_INTEGER, 0, NULL}}},
		[SOAP_REQ_CDU_OPERATIONS] = {XML_LIST, SOAP_REQ_CDU_OPS_REF, "Operations", {}},
		[SOAP_REQ_CDU_OPS_REF] = {XML_SINGLE, 0, NULL, {{"Operations", XML_FUNC, 0, load_change_du_state_operation}}},
		[SOAP_REQ_DU_INSTALL] = {XML_SINGLE, 0, NULL, {{"URL", XML_STRING, 0, NULL}, {"UUID", XML_STRING, 0, NULL}, {"Username", XML_STRING, 0, NULL}, {"Password", XML_STRING, 0, NULL}, {"ExecutionEnvRef", XML_STRING, 0, NULL}}},
		[SOAP_REQ_DU_UPDATE] = {XML_SINGLE, 0, NULL, {{"URL", XML_STRING, 0, NULL}, {"UUID", XML_STRING, 0, NULL}, {"Username", XML_STRING, 0, NULL}, {"Password", XML_STRING, 0, NULL}, {"Version", XML_STRING, 0, NULL}}},
		[SOAP_REQ_DU_UNINSTALL] = {XML_SINGLE, 0, NULL, {{"Version", XML_STRING, 0, NULL}, {"ExecutionEnvRef", XML_STRING, 0, NULL}, {"URL", XML_STRING, 0, NULL}}},

		 /*
		 * SOAP Responses
		 */
		[SOAP_RESP_GET] = {XML_SINGLE, 0, NULL, {{"ParameterList", XML_REC, SOAP_RESP_GET_LIST, NULL}}},
		[SOAP_RESP_GET_LIST] = {XML_LIST, SOAP_RESP_GET_LIST_REF, NULL, {{NULL, XML_REC, SOAP_RESP_GET_LIST_ATTRS, NULL}}},
		[SOAP_RESP_GET_LIST_REF] = {XML_SINGLE, 0, NULL, {{NULL, XML_FUNC, 0, build_parameter_structure}}},
		[SOAP_RESP_GET_LIST_ATTRS] = {XML_SINGLE, 0, NULL, {{NULL, XML_REC, GET_RPC_ATTR, NULL}}},
		[SOAP_PARAM_STRUCT] = {XML_LIST, SOAP_PARAM_STRUCT_REF, "ParameterValueStruct", {}},
		[SOAP_PARAM_STRUCT_REF] = {XML_SINGLE, 0, NULL, {{"Name", XML_STRING, 0, NULL}, {"Value", XML_STRING, ATTR_PARAM_STRUCT, NULL}}},
		[SOAP_VALUE_STRUCT] = {XML_SINGLE, 0, NULL, {{"Value", XML_STRING, ATTR_PARAM_STRUCT, NULL}}},
		[SOAP_RESP_SPV] = {XML_SINGLE, 0, NULL, {{"Status", XML_INTEGER, 0, NULL}}},
		[SOAP_RESP_GPN] = {XML_SINGLE, 0, NULL, {{"ParameterList", XML_REC, SOAP_RESP_GPN_LIST, NULL}}},
		[SOAP_RESP_GPN_LIST] = {XML_LIST, SOAP_RESP_GPN_REF, "ParameterInfoStruct", {{NULL, XML_REC, SOAP_RESP_GET_LIST_ATTRS, NULL}}},
		[SOAP_RESP_GPN_REF] = {XML_SINGLE, 0, NULL, {{"Name", XML_STRING, 0, NULL}, {"Writable", XML_BOOL, 0, NULL}}},
		[SOAP_GPA_STRUCT] = {XML_LIST, SOAP_GPA_STRUCT_REF, "ParameterAttributeStruct", {}},
		[SOAP_GPA_STRUCT_REF] = {XML_SINGLE, 0, NULL, {{"Name", XML_STRING, 0, NULL}, {"Notification", XML_INTEGER, 0, NULL}, {"AccessList", XML_STRING, 0, NULL}}},
		[SOAP_RESP_ADDOBJ] = {XML_SINGLE, 0, NULL, {{"InstanceNumber", XML_INTEGER, 0, NULL}, {"Status", XML_INTEGER, 0, NULL}}},
		[SOAP_RESP_DELOBJ] = {XML_SINGLE, 0, NULL, {{"Status", XML_INTEGER, 0, NULL}}},
		[SOAP_RESP_DOWNLOAD] = {XML_SINGLE, 0, NULL, {{"Status", XML_INTEGER, 0, NULL}, {"StartTime", XML_STRING, 0, NULL}, {"CompleteTime", XML_STRING, 0, NULL}}},
		[SOAP_RESP_UPLOAD] = {XML_SINGLE, 0, NULL, {{"Status", XML_INTEGER, 0, NULL}, {"StartTime", XML_STRING, 0, NULL}, {"CompleteTime", XML_STRING, 0, NULL}}},
		[SOAP_RESP_GETRPC] = {XML_SINGLE, 0, NULL, {{"MethodList", XML_REC, SOAP_RESP_GETRPC_LIST, NULL}}},
		[SOAP_RESP_GETRPC_LIST] = {XML_LIST, SOAP_RESP_GETRPC_REF, NULL, {{NULL, XML_REC, SOAP_RESP_GET_LIST_ATTRS, NULL}}},
		[SOAP_RESP_GETRPC_REF] = {XML_SINGLE, 0, NULL, {{"string", XML_STRING, 0, NULL}}},
		[SOAP_RESP_ACS_GETRPC] = {XML_LIST, SOAP_RESP_ACS_GETRPC_REF, "string", {}},
		[SOAP_RESP_ACS_GETRPC_REF] = {XML_SINGLE, 0, NULL, {{"string", XML_FUNC, 0, load_get_rpc_method_acs_resp_string}}},
		[SOAP_ACS_TRANSCOMPLETE] = {XML_SINGLE, 0, NULL, {{"CommandKey", XML_STRING, 0, NULL}, {"FaultStruct", XML_REC, SOAP_CWMP_FAULT, NULL}, {"StartTime", XML_STRING, 0, NULL}, {"CompleteTime", XML_STRING, 0, NULL}}},
		[SOAP_ROOT_FAULT] = {XML_SINGLE, 0, NULL, {{"soap_env:Fault", XML_REC, SOAP_RPC_FAULT, NULL}}},
		[SOAP_RPC_FAULT] = {XML_SINGLE, 0, NULL, {{"faultcode", XML_STRING, 0, NULL}, {"faultstring", XML_STRING, 0, NULL}, {"detail", XML_REC, SOAP_FAULT_DETAIL, NULL}}},
		[SOAP_FAULT_DETAIL] = {XML_SINGLE, 0, NULL, {{"cwmp:Fault", XML_REC, SOAP_CWMP_FAULT, NULL}}},
		[SOAP_CWMP_FAULT] = {XML_SINGLE, 0, NULL, {{"FaultCode", XML_INTEGER, 0, NULL}, {"FaultString", XML_STRING, 0, NULL}}},
		[SOAP_SPV_FAULT] = {XML_LIST, SOAP_SPV_FAULT_REF, "SetParameterValuesFault", {}},
		[SOAP_SPV_FAULT_REF] = {XML_SINGLE, 0, NULL, {{"ParameterName", XML_STRING, 0, NULL}, {"FaultCode", XML_INTEGER, 0, NULL}, {"FaultString", XML_STRING, 0, NULL}}},

		/*
		 * SOAP RPC ACS
		 */
		[SOAP_ENV] = {XML_SINGLE, 0, NULL, {{"soap_env:Envelope", XML_FUNC, 0, build_inform_env_header}}},
		[SOAP_INFORM_CWMP] = {XML_SINGLE, 0, NULL, {{"DeviceId", XML_REC, SOAP_DEVID, NULL}, {"Event", XML_FUNC, 0, build_inform_events}, {"MaxEnvelopes", XML_INTEGER, 0, NULL}, {"CurrentTime", XML_STRING, 0, NULL}, {"RetryCount", XML_INTEGER, 0, NULL}}},
		[SOAP_DEVID] = {XML_SINGLE, 0, NULL, {{"Manufacturer", XML_STRING, 0, NULL}, {"OUI", XML_STRING, 0, NULL}, {"ProductClass", XML_STRING, 0, NULL}, {"SerialNumber", XML_STRING, 0, NULL}}},
		[SOAP_DU_CHANGE_COMPLETE] = {XML_SINGLE, 0, NULL, {{"CommandKey", XML_STRING, 0, NULL}, {"Results", XML_REC, SOAP_CDU_RESULTS_REF, NULL}}},
		[SOAP_AUTONOMOUS_DU_CHANGE_COMPLETE] = {XML_SINGLE, 0, NULL, {{"Results", XML_REC, SOAP_ACDU_OPTS_REF, NULL}}},
		[SOAP_AUTONOMOUS_TRANSFER_COMPLETE] = {XML_SINGLE, 0, NULL, {{"AnnounceURL", XML_STRING, 0, NULL}, {"TransferURL", XML_STRING, 0, NULL}, {"IsDownload", XML_BOOL, 0, NULL}, {"FileType", XML_STRING, 0, NULL}, {"FileSize", XML_INTEGER, 0, NULL}, {"TargetFileName", XML_STRING, 0, NULL}, {"FaultStruct", XML_REC, SOAP_CWMP_FAULT,  NULL}, {"StartTime", XML_STRING, 0, NULL}, {"CompleteTime", XML_STRING, 0, NULL}}},
		[SOAP_CDU_RESULTS_REF] = {XML_LIST, SOAP_CDU_OPTS_REF, "OpResultStruct", {}},
		[SOAP_CDU_OPTS_REF] = {XML_SINGLE, 0, NULL, {{"UUID", XML_STRING, 0, NULL}, {"DeploymentUnitRef", XML_STRING, 0, NULL}, {"Version", XML_STRING, 0, NULL}, {"CurrentState", XML_STRING, 0, NULL}, {"StartTime", XML_STRING, 0, NULL}, {"CompleteTime", XML_STRING, 0, NULL}, {"FaultStruct", XML_REC, SOAP_CWMP_FAULT, NULL}}},
		[SOAP_ACDU_OPTS_REF] = {XML_SINGLE, 0, NULL, {{"UUID", XML_STRING, 0, NULL}, {"Version", XML_STRING, 0, NULL}, {"CurrentState", XML_STRING, 0, NULL}, {"Resolved", XML_BOOL, 0, NULL}, {"StartTime", XML_STRING, 0, NULL}, {"CompleteTime", XML_STRING, 0, NULL}, {"FaultStruct", XML_REC, SOAP_CWMP_FAULT, NULL}, {"OperationPerformed", XML_STRING, 0, NULL}}},

		/*
		 * XML Backup Session
		 */
		[BKP_EVT_LOAD] = {XML_SINGLE, 0, NULL, {{"id", XML_INTEGER, 0, NULL}, {"index", XML_INTEGER, 0, NULL}, {"CommandKey", XML_FUNC, XML_SWITCH, load_backup_event_command_key}, {"parameter", XML_REC, BKP_EVT_PARAM_REF, NULL}}},
		[BKP_EVT_PARAM_REF] = {XML_LIST, BKP_EVT_SINGLE_PARAM, "parameter", {}},
		[BKP_EVT_SINGLE_PARAM] = {XML_SINGLE, 0, NULL, {{"string", XML_FUNC, 0, load_backup_event_parameter}}},
		[BKP_EVT_BUILD] = {XML_SINGLE, 0, NULL, {{"cwmp_event", XML_REC, BKP_EVT_BUILD_REF, NULL}}},
		[BKP_EVT_BUILD_REF] = {XML_SINGLE, 0, NULL, {{"id", XML_INTEGER, 0, NULL}, {"index", XML_INTEGER, 0, NULL}, {"CommandKey", XML_STRING, XML_SWITCH, NULL}}},
		[BKP_SCHEDULE_INFORM_BUILD] = {XML_SINGLE, 0, NULL, {{"schedule_inform", XML_REC, BKP_SCHEDULE_INFORM, NULL}}},
		[BKP_SCHEDULE_INFORM] = {XML_SINGLE, 0, NULL, {{"id", XML_INTEGER, 0, NULL}, {"CommandKey", XML_STRING, XML_SWITCH, NULL}, {"time", XML_INTEGER, 0, NULL}}},
		[BKP_DOWNLOAD_BUILD] = {XML_SINGLE, 0, NULL, {{"download", XML_REC, BKP_DOWNLOAD, NULL}}},
		[BKP_DOWNLOAD] = {XML_SINGLE, 0, NULL, {{"id", XML_INTEGER, 0, NULL}, {"URL", XML_STRING, XML_SWITCH, NULL}, {"CommandKey", XML_STRING, XML_SWITCH, NULL}, {"FileType", XML_STRING, XML_SWITCH, NULL}, {"Username", XML_STRING, XML_SWITCH, NULL}, {"Password", XML_STRING, XML_SWITCH, NULL}, {"FileSize", XML_INTEGER, XML_SWITCH, NULL}, {"time", XML_INTEGER, 0, NULL}}},
		[BKP_SCHED_DOWNLOAD_BUILD] = {XML_SINGLE, 0, NULL, {{"schedule_download", XML_REC, BKP_SCHED_DOWNLOAD, NULL}}},
		[BKP_SCHED_DOWNLOAD] = {XML_SINGLE, 0, NULL, {{"id", XML_INTEGER, 0, NULL}, {"URL", XML_STRING, XML_SWITCH, NULL}, {"CommandKey", XML_STRING, XML_SWITCH, NULL}, {"FileType", XML_STRING, XML_SWITCH, NULL}, {"Username", XML_STRING, XML_SWITCH, NULL}, {"Password", XML_STRING, XML_SWITCH, NULL}, {"FileSize", XML_INTEGER, XML_SWITCH, NULL}, {"windowstart1", XML_INTEGER, 0, NULL}, {"windowstart2", XML_INTEGER, 0, NULL}, {"windowend1", XML_INTEGER, 0, NULL}, {"windowend2", XML_INTEGER, 0, NULL}, {"windowmode1", XML_STRING, 0, NULL}, {"windowmode2", XML_STRING, 0, NULL}, {"usermessage1", XML_STRING, 0, NULL}, {"usermessage2", XML_STRING, 0, NULL}, {"maxretrie1", XML_INTEGER, 0, NULL}, {"maxretrie2", XML_INTEGER, 0, NULL}}},
		[BKP_UPLOAD_BUILD] = {XML_SINGLE, 0, NULL, {{"upload", XML_REC, BKP_UPLOAD, NULL}}},
		[BKP_UPLOAD] = {XML_SINGLE, 0, NULL, {{"id", XML_INTEGER, 0, NULL}, {"URL", XML_STRING, XML_SWITCH, NULL}, {"CommandKey", XML_STRING, XML_SWITCH, NULL}, {"FileType", XML_STRING, XML_SWITCH, NULL}, {"Username", XML_STRING, XML_SWITCH, NULL}, {"Password", XML_STRING, XML_SWITCH, NULL}, {"time", XML_INTEGER, 0, NULL}}},
		[BKP_CDU_BUILD] = {XML_SINGLE, 0, NULL, {{"change_du_state", XML_REC, BKP_CDU_BUILD_REF, NULL}}},
		[BKP_CDU_BUILD_REF] = {XML_SINGLE, 0, NULL, {{"id", XML_INTEGER, 0, NULL}, {"CommandKey", XML_STRING, XML_SWITCH, NULL}, {"time", XML_INTEGER, 0, NULL}, {NULL, XML_REC, BKP_CDU_OPS_REF, NULL}}},
		[BKP_CDU_OPS_REF] = {XML_LIST, BKP_CDU_OPTION, NULL, {}},
		[BKP_CDU_OPTION] = {XML_SINGLE, 0, NULL, {{NULL, XML_FUNC, 0, build_backup_cdu_option}}},
		[BKP_CDU] = {XML_SINGLE, 0, NULL, {{"id", XML_INTEGER, 0, NULL}, {"CommandKey", XML_STRING, XML_SWITCH, NULL}, {"time", XML_INTEGER, 0, NULL}, {"update", XML_FUNC, 0, load_cdu_backup_operation}, {"install", XML_FUNC, 0, load_cdu_backup_operation}, {"uninstall", XML_FUNC, 0, load_cdu_backup_operation}}},
		[BKP_CDU_UPDATE] = {XML_SINGLE, 0, NULL, {{"UUID", XML_STRING, XML_SWITCH, NULL}, {"Version", XML_STRING, XML_SWITCH, NULL}, {"URL", XML_STRING, 0, NULL}, {"Username", XML_STRING, 0, NULL}, {"Password", XML_INTEGER, 0, NULL}}},
		[BKP_CDU_INSTALL] = {XML_SINGLE, 0, NULL, {{"UUID", XML_STRING, XML_SWITCH, NULL}, {"ExecutionEnvRef", XML_STRING, XML_SWITCH, NULL}, {"URL", XML_STRING, XML_SWITCH, NULL}, {"Username", XML_STRING, XML_SWITCH, NULL}, {"Password", XML_INTEGER, XML_SWITCH, NULL}}},
		[BKP_CDU_UNINSTALL] = {XML_SINGLE, 0, NULL, {{"UUID", XML_STRING, XML_SWITCH, NULL}, {"ExecutionEnvRef", XML_STRING, XML_SWITCH, NULL}, {"Version", XML_STRING, XML_SWITCH, NULL}}},
		[BKP_CDU_COMPLETE_BUILD] = {XML_SINGLE, 0, NULL, {{"du_state_change_complete", XML_REC, BKP_CDU_COMPLETE, NULL}}},
		[BKP_CDU_COMPLETE] = {XML_SINGLE, 0, NULL, {{"id", XML_INTEGER, 0, NULL}, {"CommandKey", XML_STRING, XML_SWITCH, NULL}, {"time", XML_INTEGER, 0, NULL}, {"opresult", XML_FUNC, 0, load_cdu_complete_backup_operation}}},
		[BKP_CDU_COMPLETE_OPRES] = {XML_SINGLE, 0, NULL, {{"UUID", XML_STRING, XML_SWITCH, NULL}, {"execution_unit_ref", XML_STRING, 0, NULL}, {"Version", XML_STRING, XML_SWITCH, NULL}, {"CurrentState", XML_STRING, XML_SWITCH, NULL}, {"Resolved", XML_STRING, XML_SWITCH, NULL}, {"StartTime", XML_STRING, XML_SWITCH, NULL}, {"CompleteTime", XML_STRING, XML_SWITCH, NULL}, {"FaultCode", XML_INTEGER, XML_SWITCH, NULL}, {"FaultString", XML_STRING, XML_SWITCH, NULL}}},
		[BKP_TRANSFER_COMPLETE_BUILD] = {XML_SINGLE, 0, NULL, {{"transfer_complete", XML_REC, BKP_TRANSFER_COMPLETE, NULL}}},
		[BKP_TRANSFER_COMPLETE] = {XML_SINGLE, 0, NULL, {{"CommandKey", XML_STRING, XML_SWITCH, NULL}, {"StartTime", XML_STRING, XML_SWITCH, NULL}, {"CompleteTime", XML_STRING, XML_SWITCH, NULL}, {"old_software_version", XML_STRING, 0, NULL}, {"FaultCode", XML_INTEGER, XML_SWITCH, NULL}, {"FaultString", XML_STRING, XML_SWITCH, NULL}, {"type", XML_LINTEGER, 0, NULL}}},
		[BKP_AUTO_CDU_BUILD] = {XML_SINGLE, 0, NULL, {{"autonomous_du_state_change_complete", XML_REC, BKP_AUTO_CDU, NULL}}},
		[BKP_AUTO_CDU] = {XML_SINGLE, 0, NULL, {{"id", XML_INTEGER, 0, NULL}, {"UUID", XML_STRING, XML_SWITCH, NULL}, {"Version", XML_STRING, XML_SWITCH, NULL}, {"CurrentState", XML_STRING, XML_SWITCH, NULL}, {"StartTime", XML_STRING, XML_SWITCH, NULL}, {"CompleteTime", XML_STRING, XML_SWITCH, NULL}, {"operation", XML_STRING, 0, NULL}, {"FaultCode", XML_INTEGER, XML_SWITCH, NULL}, {"FaultString", XML_STRING, XML_SWITCH, NULL}}},
		[BKP_AUTO_TRANSFER_COMPLETE_BUILD] = {XML_SINGLE, 0, NULL, {{"autonomous_transfer_complete", XML_REC, BKP_AUTO_TRANSFER_COMPLETE, NULL}}},
		[BKP_AUTO_TRANSFER_COMPLETE] = {XML_SINGLE, 0, NULL, {{"id", XML_INTEGER, 0, NULL}, {"AnnounceURL", XML_STRING, XML_SWITCH, NULL}, {"TransferURL", XML_STRING, XML_SWITCH, NULL}, {"IsDownload", XML_BOOL, 0, NULL}, {"StartTime", XML_STRING, XML_SWITCH, NULL}, {"CompleteTime", XML_STRING, XML_SWITCH, NULL}, {"FileType", XML_STRING, XML_SWITCH, NULL}, {"FileSize", XML_INTEGER, XML_SWITCH, NULL}, {"FaultCode", XML_INTEGER, XML_SWITCH, NULL}, {"FaultString", XML_STRING, XML_SWITCH, NULL}}},

		/*
		 * XML node attributes
		 */
		[ATTR_PARAM_STRUCT] = {XML_SINGLE, 0, NULL, {{"xsi:type", XML_STRING, 0, NULL}}},
		[ATTR_SOAP_ENV] = {XML_SINGLE, 0, NULL, {{"xmlns:soap_env", XML_STRING, 0, NULL}, {"xmlns:soap_enc", XML_STRING, 0, NULL}, {"xmlns:xsd", XML_STRING, 0, NULL}, {"xmlns:xsi", XML_STRING, 0, NULL}}},
		[GET_RPC_ATTR] = {XML_SINGLE, 0, NULL, {{"xsi:type", XML_STRING, 0, NULL}, {"soap_enc:arrayType", XML_FUNC, 0, get_soap_enc_array_type}}}
};

struct xml_switch xml_nodes_names_switches[] = {{"URL", "url"}, {"UUID", "uuid"}, {"IsDownload", "isdownload"}, {"AnnounceURL", "announceurl"}, {"TransferURL", "transferurl"}, {"ExecutionEnvRef", "executionenvref"}, {"Resolved", "resolved"}, {"CurrentState", "uuid"}, {"FileType", "file_type"}, {"CommandKey", "command_key"}, {"Username", "username"}, {"Version", "version"}, {"Password", "password"}, {"StartTime", "start_time"}, {"CompleteTime", "complete_time"}, {"FileSize", "file_size"}, {"FaultCode", "fault_code"}, {"FaultString", "fault_string"}};

char* xml_tags_names[] = {
		"ParameterList",
		"Name",
		"Value",
		"string",
		"ParameterPath",
		"ParameterName",
		"ObjectName",
		"ParameterKey",
		"CommandKey",
		"FileType",
		"URL",
		"AnnounceURL",
		"TransferURL",
		"Username",
		"Password",
		"UUID",
		"ExecutionEnvRef",
		"DeploymentUnitRef",
		"execution_unit_ref",
		"CurrentState",
		"Version",
		"OperationPerformed",
		"Resolved",
		"WindowMode",
		"UserMessage",
		"StartTime",
		"CompleteTime",
		"AccessList",
		"FaultString",
		"faultcode",
		"faultstring",
		"Manufacturer",
		"OUI",
		"SerialNumber",
		"CurrentTime",
		"ProductClass",
		"windowmode1",
		"windowmode2",
		"usermessage1",
		"usermessage2",
		"operation",
		"old_software_version",
		"parameter",
		"xsi:type",
		"soap_enc:arrayType",
		"TargetFileName",
		"index",
		"id",
		"BKP_ID",
		"time",
		"FileSize",
		"Notification",
		"MaxRetries",
		"maxretrie1",
		"maxretrie2",
		"Status",
		"InstanceNumber",
		"FaultCode",
		"MaxEnvelopes",
		"RetryCount",
		"type",
		"DelaySeconds",
		"WindowStart",
		"WindowEnd",
		"windowstart1",
		"windowstart2",
		"windowend1",
		"windowend2",
		"NextLevel",
		"NotificationChange",
		"Writable",
		"IsDownload"
};

static char *convert_xml_node_to_string(mxml_node_t *node, mxml_save_cb_t cb)
{
	char *str = NULL;
	int bytes = 0;

	// Determine the size of the XML node
	bytes = mxmlSaveString(node, NULL, 0, cb);
	if (bytes <= 0) {
		CWMP_LOG(ERROR, "XML node received is empty");
		return NULL;
	}

	// Allocate a buffer of the required size
	str = (char *)malloc(bytes + 1);
	if (str == NULL) {
		CWMP_LOG(ERROR, "Failed to allocate %d bytes for the XML node string due to insufficient space", bytes + 1);
		return NULL;
	}

	// Save the XML node into the allocated buffer
	mxmlSaveString(node, str, bytes + 1, cb);

	// Return the allocated string
	return str;
}

int get_xml_tags_array_total_size(int tag_ref)
{
	int i;
	for (i = 0; i < 10; i++) {
		if (xml_nodes_data[tag_ref].xml_tags[i].rec_ref == 0 && xml_nodes_data[tag_ref].xml_tags[i].tag_name == NULL && xml_nodes_data[tag_ref].xml_tags[i].tag_type == 0)
			return i;
	}
	return 0;
}

void add_xml_data_list(struct list_head *data_list, struct xml_list_data *xml_data)
{
	list_add_tail(&xml_data->list, data_list);
}

void delete_xml_data_from_list(struct xml_list_data *xml_data)
{
	list_del(&xml_data->list);
	FREE(xml_data->param_name);
	FREE(xml_data->param_value);
	FREE(xml_data->param_type);
	FREE(xml_data->windowmode);
	FREE(xml_data->usermessage);
	FREE(xml_data->access_list);
	FREE(xml_data->fault_string);
	FREE(xml_data->command_key);
	FREE(xml_data->complete_time);
	FREE(xml_data->current_state);
	FREE(xml_data->execution_env_ref);
	FREE(xml_data->du_ref);
	FREE(xml_data->username);
	FREE(xml_data->password);
	FREE(xml_data->rpc_name);
	FREE(xml_data->url);
	FREE(xml_data->uuid);
	FREE(xml_data->start_time);
	FREE(xml_data->version);
	FREE(xml_data);
}

void cwmp_free_all_xml_data_list(struct list_head *list)
{
	while (list->next != list) {
		struct xml_list_data *xml_data;
		xml_data = list_entry(list->next, struct xml_list_data, list);
		delete_xml_data_from_list(xml_data);
	}
}

int load_backup_event_command_key(mxml_node_t *b __attribute__((unused)), struct xml_data_struct *xml_attrs)
{
	mxml_node_t *c = mxmlWalkNext(b, b, MXML_DESCEND);
	if (!c || mxmlGetType(c) != MXML_OPAQUE)
		return FAULT_CPE_INVALID_ARGUMENTS;
	const char *command_key = mxmlGetOpaque(c);
	if (xml_attrs->index && *(xml_attrs->index) > -1) {
		if (EVENT_CONST[*(xml_attrs->index)].RETRY & EVENT_RETRY_AFTER_REBOOT) {
			xml_attrs->event_save = cwmp_add_event_container(*(xml_attrs->index), ((command_key != NULL) ? (char *)command_key : ""));
			if (xml_attrs->event_save != NULL)
				xml_attrs->event_save->id = *(xml_attrs->id);
		}
	}
	return FAULT_CPE_NO_FAULT;
}

int load_backup_event_parameter(mxml_node_t *b, struct xml_data_struct *xml_attrs)
{
	mxml_node_t *c = mxmlWalkNext(b, b, MXML_DESCEND);
	if (c && mxmlGetType(c) == MXML_OPAQUE) {
		const char *op = mxmlGetOpaque(c);
		if (op != NULL) {
			if (xml_attrs->event_save != NULL)
				add_dm_parameter_to_list(&xml_attrs->event_save->head_dm_parameter, (char *)op, NULL, NULL, 0, false);
		}
	}
	return FAULT_CPE_NO_FAULT;
}

int load_upload_filetype(mxml_node_t *b, struct xml_data_struct *xml_attrs)
{
	if (b == NULL)
		return FAULT_CPE_INTERNAL_ERROR;
	mxml_node_t *t = mxmlWalkNext(b, b, MXML_DESCEND);
	if (t == NULL)
		return FAULT_CPE_INTERNAL_ERROR;
	const char *node_opaque = mxmlGetOpaque(t);
	if (node_opaque == NULL)
		return FAULT_CPE_INVALID_ARGUMENTS;
	char log_config[16]={0};
	int ftype, instance = 0;

	sscanf(node_opaque, "%1d Vendor %15s File %8d", &ftype, log_config, &instance);
	if (strcmp(log_config, "Configuration") != 0 && strcmp(log_config, "Log") != 0)
		return FAULT_CPE_INVALID_ARGUMENTS;
	else if (strcmp(log_config, "Configuration") == 0 && ftype != 1 && ftype != 3)
		return FAULT_CPE_INVALID_ARGUMENTS;
	else if (strcmp(log_config, "Log") == 0 && ftype != 2 && ftype != 4)
		return FAULT_CPE_INVALID_ARGUMENTS;
	if ((ftype == 3 || ftype == 4) && (instance == 0))
		return FAULT_CPE_INVALID_ARGUMENTS;
	if (ftype !=1 && ftype != 2 && ftype != 3 && ftype != 4)
		return FAULT_CPE_INVALID_ARGUMENTS;
	*xml_attrs->file_type = strdup(node_opaque);
	*xml_attrs->instance = instance;
	return FAULT_CPE_NO_FAULT;
}

int load_get_rpc_method_acs_resp_string(mxml_node_t *b, struct xml_data_struct *xml_attrs __attribute__((unused)))
{
	if (b == NULL)
		return FAULT_CPE_INTERNAL_ERROR;

	mxml_node_t *t = mxmlWalkNext(b, b, MXML_DESCEND);
	if (t == NULL)
		return FAULT_CPE_INTERNAL_ERROR;
	const char *node_opaque = mxmlGetOpaque(t);
	if (node_opaque == NULL)
		return FAULT_CPE_INVALID_ARGUMENTS;

	set_rpc_acs_to_supported(node_opaque);

	return FAULT_CPE_NO_FAULT;
}

int load_download_filetype(mxml_node_t *b, struct xml_data_struct *xml_attrs)
{
	mxml_node_t *t = mxmlWalkNext(b, b, MXML_DESCEND);
	if (t == NULL)
		return FAULT_CPE_INTERNAL_ERROR;
	const char *node_opaque = mxmlGetOpaque(t);
	if (node_opaque == NULL)
		return FAULT_CPE_INVALID_ARGUMENTS;
	if (*(xml_attrs->file_type) == NULL) {
		*(xml_attrs->file_type) = strdup(node_opaque);
	} else {
		char tmp[128];
		snprintf(tmp, sizeof(tmp), "%s", *(xml_attrs->file_type));
		FREE(*(xml_attrs->file_type));
		if (cwmp_asprintf(xml_attrs->file_type, "%s %s", tmp, node_opaque) == -1)
			return FAULT_CPE_INTERNAL_ERROR;
	}
	return FAULT_CPE_NO_FAULT;
}

int load_sched_download_window_mode(mxml_node_t *b, struct xml_data_struct *xml_attrs)
{
	mxml_node_t *t = mxmlWalkNext(b, b, MXML_DESCEND);
	if (t == NULL)
		return FAULT_CPE_INTERNAL_ERROR;
	const char *node_opaque = mxmlGetOpaque(t);
	if (*(xml_attrs->window_mode) == NULL)
		*(xml_attrs->window_mode) = strdup(node_opaque ? node_opaque : "");
	else {
		static char *tmp = NULL;
		tmp = *(xml_attrs->window_mode);
		if (cwmp_asprintf(xml_attrs->window_mode, "%s %s", tmp, node_opaque ? node_opaque : "") == -1)
			return FAULT_CPE_INTERNAL_ERROR;
	}
	return FAULT_CPE_NO_FAULT;
}

int load_change_du_state_operation(mxml_node_t *b, struct xml_data_struct *xml_attrs)
{
	char *operation = (char *)mxmlElementGetAttr(b, "xsi:type");
	int cdu_ref = 0;
	int type = 0;

	if (operation == NULL)
		return FAULT_CPE_INVALID_ARGUMENTS;

	if (xml_attrs->cdu_type == NULL) {
		CWMP_LOG(ERROR, "Not able to load CDU operation");
		return FAULT_CPE_INTERNAL_ERROR;

	}
	if (CWMP_STRCMP(operation, "cwmp:InstallOpStruct") == 0) {
		cdu_ref = SOAP_REQ_DU_INSTALL;
		type = DU_INSTALL;
	}
	else if (CWMP_STRCMP(operation, "cwmp:UpdateOpStruct") == 0) {
		cdu_ref = SOAP_REQ_DU_UPDATE;
		type = DU_UPDATE;
	}

	else if (CWMP_STRCMP(operation, "cwmp:UninstallOpStruct") == 0) {
		cdu_ref = SOAP_REQ_DU_UNINSTALL;
		type = DU_UNINSTALL;
	}

	*(xml_attrs->cdu_type) = type;

	if (cdu_ref == 0)
		return FAULT_CPE_INVALID_ARGUMENTS;
	int fault = load_xml_node_data(cdu_ref, b, xml_attrs);
	if (fault)
		return fault;

	return FAULT_CPE_NO_FAULT;
}

int load_cdu_backup_operation(mxml_node_t *b, struct xml_data_struct *xml_attrs)
{
	int fault = FAULT_CPE_NO_FAULT;
	if (b == NULL)
		return FAULT_CPE_INTERNAL_ERROR;

	struct operations *operat =  (operations *)calloc(1, sizeof(operations));
	list_add_tail(&(operat->list), &(xml_attrs->cdu->list_operation));
	const char *element = mxmlGetElement(b);

	struct xml_data_struct bkp_xml_cdu_backup = {0};
	bkp_xml_cdu_backup.uuid = &operat->uuid;
	bkp_xml_cdu_backup.exec_env_ref = &operat->executionenvref;
	bkp_xml_cdu_backup.version = &operat->version;
	bkp_xml_cdu_backup.url = &operat->url;
	bkp_xml_cdu_backup.username = &operat->username;
	bkp_xml_cdu_backup.password = &operat->password;
	if (CWMP_STRCMP(element, "update") == 0) {
		operat->type = DU_UPDATE;
		fault = load_xml_node_data(BKP_CDU_UPDATE, b, &bkp_xml_cdu_backup);
	} else if (CWMP_STRCMP(element, "install") == 0) {
		operat->type = DU_INSTALL;
		fault = load_xml_node_data(BKP_CDU_INSTALL, b, &bkp_xml_cdu_backup);
	} else if (CWMP_STRCMP(element, "uninstall") == 0) {
		operat->type = DU_UNINSTALL;
		fault = load_xml_node_data(BKP_CDU_UNINSTALL, b, &bkp_xml_cdu_backup);
	}
	return fault;
}

int load_cdu_complete_backup_operation(mxml_node_t *b, struct xml_data_struct *xml_attrs)
{
	if (b == NULL)
		return FAULT_CPE_INTERNAL_ERROR;
	struct opresult *elem = (opresult *)calloc(1, sizeof(opresult));
	list_add_tail(&(elem->list), &(xml_attrs->cdu_complete->list_opresult));
	struct xml_data_struct opresult_bkp = {0};
	opresult_bkp.uuid = &elem->uuid;
	opresult_bkp.version = &elem->version;
	opresult_bkp.du_ref = &elem->du_ref;
	opresult_bkp.current_state = &elem->current_state;
	opresult_bkp.resolved = &elem->resolved;
	opresult_bkp.start_time = &elem->start_time;
	opresult_bkp.complete_time = &elem->complete_time;
	opresult_bkp.fault_code = &elem->fault;
	opresult_bkp.exec_unit_ref = &elem->execution_unit_ref;
	int fault = load_xml_node_data(BKP_CDU_COMPLETE_OPRES, b, &opresult_bkp);
	return fault;
}

int build_inform_env_header(mxml_node_t *b, struct xml_data_struct *xml_attrs)
{
	if (b == NULL || xml_attrs == NULL)
		return FAULT_CPE_INTERNAL_ERROR;
	int amd_version = cwmp_main->conf.supported_amd_version ? cwmp_main->conf.supported_amd_version : DEFAULT_AMD_VERSION;
	mxml_node_t **envelope = xml_attrs->xml_env;

	*envelope = b;

	mxmlElementSetAttr(*envelope, "xmlns:soap_env", "http://schemas.xmlsoap.org/soap/envelope/");
	mxmlElementSetAttr(*envelope, "xmlns:soap_enc", "http://schemas.xmlsoap.org/soap/encoding/");
	mxmlElementSetAttr(*envelope, "xmlns:xsd", "http://www.w3.org/2001/XMLSchema");
	mxmlElementSetAttr(*envelope, "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
	mxmlElementSetAttr(*envelope, "xmlns:cwmp", cwmp_urls[amd_version - 1]);

	mxml_node_t *header = mxmlNewElement(*envelope, "soap_env:Header");
	if (header == NULL)
		return FAULT_CPE_INTERNAL_ERROR;

	mxml_node_t *id = mxmlNewElement(header, "cwmp:ID");
	if (id == NULL)
		return FAULT_CPE_INTERNAL_ERROR;

	mxmlElementSetAttr(id, "soap_env:mustUnderstand", "1");

	mxml_node_t *node = NULL;
	if (amd_version >= 4) {
		node = mxmlNewElement(header, "cwmp:SessionTimeout");
		if (!node)
			return FAULT_CPE_INTERNAL_ERROR;

		mxmlElementSetAttr(node, "soap_env:mustUnderstand", "0");
		node = mxmlNewInteger(node, cwmp_main->conf.session_timeout ? cwmp_main->conf.session_timeout : 60);
		if (!node)
			return FAULT_CPE_INTERNAL_ERROR;
	}

	if (amd_version >= 5) {
		node = mxmlNewElement(header, "cwmp:SupportedCWMPVersions");
		if (!node)
			return FAULT_CPE_INTERNAL_ERROR;

		mxmlElementSetAttr(node, "soap_env:mustUnderstand", "0");
		node = mxmlNewOpaque(node, xml_get_cwmp_version(amd_version));
		if (!node)
			return FAULT_CPE_INTERNAL_ERROR;
	}

	mxml_node_t *body = mxmlNewElement(*envelope, "soap_env:Body");
	if (body == NULL)
		return FAULT_CPE_INTERNAL_ERROR;

	return FAULT_CPE_NO_FAULT;
}

int build_inform_events(mxml_node_t *event, struct xml_data_struct *xml_attrs)
{
	mxml_node_t *node, *b2;
	char c[128];
	unsigned int n = 0;

	if (!event)
		return -1;

	mxmlElementSetAttr(event, "soap_enc:arrayType", "cwmp:EventStruct[0]");
	struct xml_list_data *xml_data;

	list_for_each_entry (xml_data, xml_attrs->data_list, list) {
		node = mxmlNewElement(event, "EventStruct");
		if (!node)
			goto error;
		b2 = mxmlNewElement(node, "EventCode");
		if (!b2)
			goto error;

		b2 = mxmlNewOpaque(b2, EVENT_CONST[xml_data->event_code].CODE);
		if (!b2)
			goto error;
		b2 = mxmlNewElement(node, "CommandKey");
		if (!b2)
			goto error;
		if (xml_data->command_key) {
			b2 = mxmlNewOpaque(b2, xml_data->command_key);
			if (!b2)
				goto error;
		}
		mxmlAdd(event, MXML_ADD_AFTER, MXML_ADD_TO_PARENT, node);
		n++;
	}
	if (n) {
		if (snprintf(c, sizeof(c), "cwmp:EventStruct[%u]", n) == -1)
			return -1;
		mxmlElementSetAttr(event, "xsi:type", "soap_enc:Array");
		mxmlElementSetAttr(event, "soap_enc:arrayType", c);
	}
	return 0;

error:
	return FAULT_CPE_INTERNAL_ERROR;
}


int build_parameter_structure(mxml_node_t *param_list, struct xml_data_struct *xml_attrs)
{
	char *err = NULL;

	LIST_HEAD(parameters_list);

	if (xml_attrs->parameter_name == NULL)
		return CWMP_OK;

	if (xml_attrs->rpc_enum == SOAP_PARAM_STRUCT)
		err = cwmp_get_parameter_values(*(xml_attrs->parameter_name), &parameters_list);
	else if (xml_attrs->rpc_enum == SOAP_GPA_STRUCT)
		err = cwmp_get_parameter_attributes(*(xml_attrs->parameter_name), &parameters_list);
	else
		return FAULT_CPE_INTERNAL_ERROR;

	if (err) {
		int fault_code = cwmp_get_fault_code_by_string(err);
		cwmp_free_all_dm_parameter_list(&parameters_list);
		return fault_code;
	}

	LIST_HEAD(prameters_xml_list);
	dm_parameter_list_to_xml_data_list(&parameters_list, &prameters_xml_list);

	struct xml_data_struct prmvalstrct_resp_xml_attrs = {0};
	prmvalstrct_resp_xml_attrs.data_list = &prameters_xml_list;
	prmvalstrct_resp_xml_attrs.counter = xml_attrs->counter;
	prmvalstrct_resp_xml_attrs.inc_counter = true;

	int fault = build_xml_node_data(xml_attrs->rpc_enum, param_list, &prmvalstrct_resp_xml_attrs);

	cwmp_free_all_dm_parameter_list(&parameters_list);
	cwmp_free_all_xml_data_list(&prameters_xml_list);

	return (fault != CWMP_OK) ? fault : FAULT_CPE_NO_FAULT;
}

int build_backup_cdu_option(mxml_node_t *cdu, struct xml_data_struct *xml_attrs)
{
	mxml_node_t *cdu_opt = NULL;
	if (*(xml_attrs->cdu_type) == DU_INSTALL) {
		cdu_opt = mxmlNewElement(cdu, "install");
		return build_xml_node_data(BKP_CDU_INSTALL, cdu_opt, xml_attrs);
	} else if (*(xml_attrs->cdu_type) == DU_UPDATE) {
		cdu_opt = mxmlNewElement(cdu, "update");
		return build_xml_node_data(BKP_CDU_UPDATE, cdu_opt, xml_attrs);
	} else if (*(xml_attrs->cdu_type) == DU_UNINSTALL) {
		cdu_opt = mxmlNewElement(cdu, "uninstall");
		return build_xml_node_data(BKP_CDU_UNINSTALL, cdu_opt, xml_attrs);
	}
	return FAULT_CPE_INTERNAL_ERROR;
}
int get_soap_enc_array_type(mxml_node_t *node __attribute__((unused)), struct xml_data_struct *xml_attrs)
{
	if (xml_attrs->soap_enc_array_type == NULL)
		return FAULT_CPE_INTERNAL_ERROR;
	if (xml_attrs->rpc_enum == SOAP_PARAM_STRUCT) {
		if (icwmp_asprintf(xml_attrs->soap_enc_array_type, "cwmp:ParameterValueStruct[%d]", xml_attrs->counter ? *(xml_attrs->counter) : 0) == -1)
			return FAULT_CPE_INTERNAL_ERROR;
		return FAULT_CPE_NO_FAULT;
	} else if (xml_attrs->rpc_enum == SOAP_GPA_STRUCT) {
		if (icwmp_asprintf(xml_attrs->soap_enc_array_type, "cwmp:ParameterAttributeStruct[%d]", xml_attrs->counter ? *(xml_attrs->counter) : 0) == -1)
			return FAULT_CPE_INTERNAL_ERROR;
		return FAULT_CPE_NO_FAULT;
	} else if (xml_attrs->rpc_enum == SOAP_RESP_GETRPC) {
		if (icwmp_asprintf(xml_attrs->soap_enc_array_type, "xsd:string[%d]", xml_attrs->counter ? *(xml_attrs->counter) : 0) == -1)
			return FAULT_CPE_INTERNAL_ERROR;
		return FAULT_CPE_NO_FAULT;
	} else if (xml_attrs->rpc_enum == SOAP_RESP_GPN) {
		if (icwmp_asprintf(xml_attrs->soap_enc_array_type, "cwmp:ParameterInfoStruct[%d]", xml_attrs->counter ? *(xml_attrs->counter) : 0) == -1)
			return FAULT_CPE_INTERNAL_ERROR;
		return FAULT_CPE_NO_FAULT;
	}
	else
		return FAULT_CPE_INTERNAL_ERROR;
}

int get_xml_type(int node_ref, int soap_idx)
{
	return xml_nodes_data[node_ref].xml_tags[soap_idx].tag_type;
}

char *get_xml_node_name_switch(char *node_name)
{
	unsigned int i;
	if (node_name == NULL)
		return NULL;

	size_t total_size = sizeof(xml_nodes_names_switches) / sizeof(struct xml_switch);
	for (i = 0; i < total_size; i++)
	{
		if (xml_nodes_names_switches[i].node_name == NULL)
			continue;

		if (CWMP_STRCMP(node_name, xml_nodes_names_switches[i].node_name) == 0)
			return xml_nodes_names_switches[i].switch_node_name;
	}
	return NULL;
}

char *get_xml_node_name_by_switch_name(char *switch_node_name)
{
	unsigned int i;
	if (switch_node_name == NULL)
		return NULL;

	size_t total_size = sizeof(xml_nodes_names_switches) / sizeof(struct xml_switch);
	for (i = 0; i < total_size; i++)
	{
		if (xml_nodes_names_switches[i].switch_node_name == NULL)
			continue;

		if (CWMP_STRCMP(switch_node_name, xml_nodes_names_switches[i].switch_node_name) == 0)
			return xml_nodes_names_switches[i].node_name;
	}
	return NULL;
}

int get_xml_tag_index(const char *name)
{
	unsigned int i;
	if (name == NULL)
		return -1;

	size_t total_size = sizeof(xml_tags_names) / sizeof(char*);
	for (i = 0; i < total_size; i++) {
		if (xml_tags_names[i] == NULL)
			continue;

		if (CWMP_STRCMP(name, xml_tags_names[i]) == 0)
			return i;
	}
	return -1;
}


int get_xml_soap_tag_index(int soap_ref, const char *name)
{
	unsigned int i = 0;
	if (name == NULL)
		return -1;

	size_t total_size = sizeof(xml_nodes_data[soap_ref].xml_tags) / sizeof(struct xml_tag);
	for (i = 0; i < total_size; i++) {
		if (xml_nodes_data[soap_ref].xml_tags[i].tag_name == NULL)
			continue;

		if (CWMP_STRCMP(name, xml_nodes_data[soap_ref].xml_tags[i].tag_name) == 0)
			return i;
	}
	return -1;
}

int load_xml_list_node_data(int node_ref, mxml_node_t *node, struct xml_data_struct *xml_attrs)
{
	mxml_node_t *b;

	b = mxmlWalkNext(node, node, MXML_DESCEND);
	while (b) {
		if (mxmlGetType(b) == MXML_ELEMENT) {
			const char *b_name = b ? mxmlGetElement(b) : NULL;
			if (b_name && CWMP_STRCMP(xml_nodes_data[node_ref].tag_list_name, b_name) == 0) {
				struct xml_list_data *xml_data = calloc(1, sizeof(struct xml_list_data));

				struct xml_data_struct xml_attrs_args = {0};
				xml_attrs_args.name = &xml_data->param_name;
				xml_attrs_args.string = &xml_data->param_name;
				xml_attrs_args.parameter_path = &xml_data->param_name;
				xml_attrs_args.value = &xml_data->param_value;
				xml_attrs_args.window_mode = &xml_data->windowmode;
				xml_attrs_args.user_message = &xml_data->usermessage;
				xml_attrs_args.notification = &xml_data->notification;
				xml_attrs_args.scheddown_max_retries = &xml_data->max_retries;
				xml_attrs_args.window_start = &xml_data->windowstart;
				xml_attrs_args.window_end = &xml_data->windowend;
				xml_attrs_args.notification_change = &xml_data->notification_change;
				xml_attrs_args.access_list = &xml_data->access_list;

				xml_attrs_args.url = &xml_data->url;
				xml_attrs_args.uuid = &xml_data->uuid;
				xml_attrs_args.username = &xml_data->username;
				xml_attrs_args.password = &xml_data->password;
				xml_attrs_args.exec_env_ref = &xml_data->execution_env_ref;
				xml_attrs_args.version = &xml_data->version;
				xml_attrs_args.cdu_type = &xml_data->cdu_type;

				xml_attrs_args.validations = xml_attrs->validations;
				xml_attrs_args.nbre_validations = xml_attrs->nbre_validations;
				xml_attrs_args.data_list = xml_attrs->data_list;
				if (xml_attrs->data_list == NULL) {
					CWMP_LOG(WARNING, "the data list attribute of the corresponding node is null");
					return FAULT_CPE_INTERNAL_ERROR;
				}
				list_add(&(xml_data->list), xml_attrs->data_list);
				int fault = load_xml_node_data(xml_nodes_data[node_ref].tag_node_ref, b, &xml_attrs_args);
				if (fault)
					return fault;
			}
		}
		b = mxmlWalkNext(b, node, MXML_DESCEND);
	}
	return CWMP_OK;
}

bool validate_xml_node_opaque_value(char *node_name, char *opaque, struct xml_tag_validation *validations, int nbre_validations)
{
	int i;
	if (node_name == NULL) {
		CWMP_LOG(ERROR, "Node Validation ERROR: node name is null");
		return false;
	}
	for (i = 0; i < nbre_validations; i++) {
		if (validations[i].tag_name == NULL)
			continue;

		if (CWMP_STRCMP(node_name, validations[i].tag_name) == 0) {
			if (validations[i].validation_type == VALIDATE_STR_SIZE) {
				if (!icwmp_validate_string_length(opaque, validations[i].max))
					return false;
			}
			if (validations[i].validation_type == VALIDATE_UNINT) {
				if (!icwmp_validate_unsignedint(opaque))
					return false;
			}
			if (validations[i].validation_type == VALIDATE_BOOLEAN) {
				if (!icwmp_validate_boolean_value(opaque))
					return false;
			}
			if (validations[i].validation_type == VALIDATE_INT_RANGE) {
				if (!icwmp_validate_int_in_range(opaque, validations[i].min, validations[i].max)) {
					return false;
				}
			}
		}
	}
	return true;
}

bool check_node_is_switch_by_node_name(int node_ref, char *node_name)
{
	unsigned int i;
	if (node_name == NULL)
		return false;
	size_t total_size = sizeof(xml_nodes_data[node_ref].xml_tags) / sizeof(struct xml_tag);
	for (i = 0; i < total_size; i++)
	{
		if (xml_nodes_data[node_ref].xml_tags[i].tag_name == NULL)
			continue;

		if (CWMP_STRCMP(xml_nodes_data[node_ref].xml_tags[i].tag_name, node_name) == 0 && xml_nodes_data[node_ref].xml_tags[i].rec_ref == XML_SWITCH)
			return true;
	}
	return false;
}

int load_single_xml_node_data(int node_ref, mxml_node_t *node, struct xml_data_struct *xml_attrs)
{
	mxml_node_t *b = node;
	int idx, xml_type = -1, soap_idx;
	void **ptr = NULL;
	int error = FAULT_CPE_NO_FAULT;
	while (b) {
		const char *xml_node_name = mxmlGetElement(b);
		mxml_type_t node_type = mxmlGetType(b);
		mxml_node_t *firstchild = mxmlGetFirstChild(b);

		char *node_name = get_xml_node_name_by_switch_name((char *)xml_node_name);
		if (!check_node_is_switch_by_node_name(node_ref, node_name))
			node_name = (char *)xml_node_name;

		if (node_type == MXML_ELEMENT) {
			soap_idx = get_xml_soap_tag_index(node_ref, (char *)node_name);
			if (soap_idx == -1) {
				b = mxmlWalkNext(b, node, MXML_DESCEND);
				continue;
			}

			xml_type = get_xml_type(node_ref, soap_idx);
			if (xml_type == XML_FUNC) {
				if ((error = xml_nodes_data[node_ref].xml_tags[soap_idx].xml_func(b, xml_attrs)) != FAULT_CPE_NO_FAULT)
					return error;
				b = mxmlWalkNext(b, node, MXML_DESCEND);
				continue;
			}

			if (xml_type == XML_REC) {
				if ((error = load_xml_node_data(xml_nodes_data[node_ref].xml_tags[soap_idx].rec_ref, node, xml_attrs)) != FAULT_CPE_NO_FAULT)
						return error;
				b = mxmlWalkNext(b, node, MXML_DESCEND);
				continue;
			}
			idx = get_xml_tag_index((char *)node_name);

			// cppcheck-suppress knownConditionTrueFalse
			/*
			 * xml_type value can be modified when calling the function get_xml_type
			 */
			if ((idx == -1) && (xml_type != XML_FUNC) && (xml_type != XML_REC)) {
				b = mxmlWalkNext(b, node, MXML_DESCEND);
				continue;
			}

			char *opaque = NULL;
			if (firstchild)
				opaque = (char*) mxmlGetOpaque(firstchild);

			if (opaque != NULL && !validate_xml_node_opaque_value(b ? (char*)mxmlGetElement(b) : NULL, opaque, xml_attrs->validations, xml_attrs->nbre_validations))
				return FAULT_CPE_INVALID_ARGUMENTS;

			if ((xml_type != XML_FUNC) && (xml_type != XML_REC))
				ptr = (void **)((char *)xml_attrs + idx * sizeof(char *));

			char **str;
			int *intgr;
			bool *bol;
			long int *lint;
			time_t *time;

			switch (xml_type) {
			case XML_STRING:
				str = (char **)(*ptr);
				*str = strdup(opaque ? opaque : "");
				break;
			case XML_INTEGER:
				intgr = (int *)(*ptr);
				*intgr = opaque ? atoi(opaque) : 0;
				break;
			case XML_BOOL:
				bol = (bool *)(*ptr);
				*bol = opaque && ((strcmp(opaque, "1") == 0) || (strcasecmp(opaque, "true") == 0));
				break;
			case XML_LINTEGER:
				lint = (long int *)(*ptr);
				*lint = opaque ? atol(opaque) : 0;
				break;
			case XML_TIME:
				time = (time_t *)(*ptr);
				*time = opaque ? atol(opaque) : 0;
				break;
			default:
				break;
			}
		}
		b = mxmlWalkNext(b, node, MXML_DESCEND);
	}
	return CWMP_OK;
}

int load_xml_node_data(int node_ref, mxml_node_t *node, struct xml_data_struct *xml_attrs)
{
	if (!node || node_ref >= SOAP_MAX)
		return FAULT_CPE_INTERNAL_ERROR;
	if (xml_nodes_data[node_ref].node_ms == XML_LIST) {
		return load_xml_list_node_data(node_ref, node, xml_attrs);
	} else {
		return load_single_xml_node_data(node_ref, node, xml_attrs);
	}
	return CWMP_OK;
}

void cwmp_param_fault_list_to_xml_data_list(struct list_head *param_fault_list, struct list_head *xml_data_list)
{
	struct cwmp_param_fault *param_fault = NULL;

	list_for_each_entry (param_fault, param_fault_list, list) {
		struct xml_list_data *xml_data = NULL;

		xml_data = calloc(1, sizeof(struct xml_list_data));
		list_add_tail(&xml_data->list, xml_data_list);

		int idx = cwmp_get_fault_code(param_fault->fault_code);

		xml_data->param_name = CWMP_STRDUP(param_fault->path_name);
		xml_data->fault_code = atoi(FAULT_CPE_ARRAY[idx].CODE);
		xml_data->fault_string = CWMP_STRLEN(param_fault->fault_msg) ? strdup(param_fault->fault_msg) : strdup(FAULT_CPE_ARRAY[idx].DESCRIPTION);
	}
}

void dm_parameter_list_to_xml_data_list(struct list_head *dm_parameter_list, struct list_head *xml_data_list)
{
	struct cwmp_dm_parameter *param_value = NULL;
	list_for_each_entry (param_value, dm_parameter_list, list) {
		if (!param_value->name)
			continue;
		struct xml_list_data *xml_data;
		xml_data = calloc(1, sizeof(struct xml_list_data));
		list_add_tail(&xml_data->list, xml_data_list);
		xml_data->param_name = CWMP_STRDUP(param_value->name);
		xml_data->param_value = strdup(param_value->value ? param_value->value : "");
		xml_data->param_type = strdup(param_value->type ? param_value->type : "");
		xml_data->access_list = strdup(param_value->access_list ? param_value->access_list : "");
		xml_data->notification = param_value->notification;
		xml_data->writable = param_value->writable;
	}
}

void xml_data_list_to_dm_parameter_list(struct list_head *xml_data_list, struct list_head *dm_parameter_list)
{
	struct xml_list_data *xml_data;
	list_for_each_entry (xml_data, xml_data_list, list) {
		struct cwmp_dm_parameter *dm_parameter;
		dm_parameter = calloc(1, sizeof(struct cwmp_dm_parameter));
		list_add_tail(&dm_parameter->list, dm_parameter_list);
		dm_parameter->name = strdup(xml_data->param_name ? xml_data->param_name : "");
		dm_parameter->value = strdup(xml_data->param_value ? xml_data->param_value : "");
		dm_parameter->type = strdup(xml_data->param_type ? xml_data->param_type : "");
		dm_parameter->access_list = strdup(xml_data->access_list ? xml_data->access_list : "");
		dm_parameter->notification = xml_data->notification;
		dm_parameter->writable =xml_data->notification;
	}
}

void xml_data_list_to_cdu_operations_list(struct list_head *xml_data_list, struct list_head *cdu_operations_list)
{
	struct xml_list_data *xml_data;
	list_for_each_entry (xml_data, xml_data_list, list) {
		struct operations *operation;
		operation = calloc(1, sizeof(struct operations));
		list_add_tail(&operation->list, cdu_operations_list);
		operation->url = strdup(xml_data->url ? xml_data->url : "");
		operation->uuid = strdup(xml_data->uuid ? xml_data->uuid : "");
		operation->username = strdup(xml_data->username ? xml_data->username : "");
		operation->password = strdup(xml_data->password ? xml_data->password : "");
		operation->executionenvref = strdup(xml_data->execution_env_ref ? xml_data->execution_env_ref : "");
		operation->version = strdup(xml_data->version ? xml_data->version : "");
		operation->type = xml_data->cdu_type;
	}
}

void cdu_operations_result_list_to_xml_data_list(struct list_head *du_op_res_list, struct list_head *xml_data_list)
{
	struct opresult *du_op_res_data = NULL, *tmp = NULL;
	list_for_each_entry_safe (du_op_res_data, tmp, du_op_res_list, list) {
		struct xml_list_data *xml_data =  calloc(1, sizeof(struct xml_list_data));
		list_add_tail(&xml_data->list, xml_data_list);
		xml_data->uuid = strdup(du_op_res_data->uuid ? du_op_res_data->uuid : "");
		xml_data->du_ref = strdup(du_op_res_data->du_ref ? du_op_res_data->du_ref : "");
		xml_data->version = strdup(du_op_res_data->version ? du_op_res_data->version : "");
		xml_data->current_state = strdup(du_op_res_data->current_state ? du_op_res_data->current_state : "");
		xml_data->start_time = strdup(du_op_res_data->start_time ? du_op_res_data->start_time : "");
		xml_data->complete_time = strdup(du_op_res_data->complete_time ? du_op_res_data->complete_time : "");
		xml_data->fault_code = du_op_res_data->fault ? atoi(FAULT_CPE_ARRAY[du_op_res_data->fault].CODE) : 0;
		xml_data->fault_string = du_op_res_data->fault_msg ? strdup(du_op_res_data->fault_msg) : strdup("");
	}
}

void cdu_operations_list_to_xml_data_list(struct list_head *du_op_list, struct list_head *xml_data_list)
{
	struct operations *du_opt_data = NULL;
	list_for_each_entry (du_opt_data, du_op_list, list) {
		struct xml_list_data *xml_data =  calloc(1, sizeof(struct xml_list_data));
		list_add_tail(&xml_data->list, xml_data_list);
		xml_data->uuid = strdup(du_opt_data->uuid ? du_opt_data->uuid : "");
		xml_data->du_ref = strdup(du_opt_data->url ? du_opt_data->url : "");
		xml_data->username = strdup(du_opt_data->username ? du_opt_data->username : "");
		xml_data->password = strdup(du_opt_data->password ? du_opt_data->password : "");
		xml_data->execution_env_ref = strdup(du_opt_data->executionenvref ? du_opt_data->executionenvref : "");
		xml_data->version = strdup(du_opt_data->version ? du_opt_data->version : "");
		xml_data->cdu_type = du_opt_data->type;
	}
}

void event_container_list_to_xml_data_list(struct list_head *event_container_list, struct list_head *xml_data_list)
{
	struct event_container *event_container;

	list_for_each_entry (event_container, event_container_list, list) {
		// cppcheck-suppress uninitvar
		if (cwmp_main->session->session_status.is_heartbeat && event_container->code != EVENT_IDX_14HEARTBEAT)
			continue;
		if ((!cwmp_main->session->session_status.is_heartbeat) && (event_container->code == EVENT_IDX_14HEARTBEAT))
			continue;
		struct xml_list_data *xml_data =  calloc(1, sizeof(struct xml_list_data));
		list_add_tail(&xml_data->list, xml_data_list);
		xml_data->event_code = event_container->code;
		xml_data->command_key = strdup(event_container->command_key ? event_container->command_key : "");
	}
}

void get_xml_data_value_by_name(int type, int idx, struct xml_data_struct *xml_attrs, char **data_value)
{
	char **str;
	int *intgr;
	bool *bol;
	long int *lint;
	time_t *time;
	void **ptr = (void **)((char *)xml_attrs + idx * sizeof(char *));
	switch(type) {
	case XML_STRING:
		str = (char **)(*ptr);
		*data_value = icwmp_strdup((str && *str) ? *str : "");
		break;
	case XML_INTEGER:
		intgr = (int *)(*ptr);
		icwmp_asprintf(data_value, "%d", intgr ? *intgr : 0);
		break;
	case XML_LINTEGER:
		lint = (long int *)(*ptr);
		icwmp_asprintf(data_value, "%ld", lint ? *lint : 0);
		break;
	case XML_BOOL:
		bol = (bool *)(*ptr);
		*data_value = icwmp_strdup((bol && *bol) ? "1" : "0");
		break;
	case XML_TIME:
		time = (time_t *)(*ptr);
		icwmp_asprintf(data_value, "%ld", time ? *time : 0);
		break;
	case XML_NODE:
		*data_value = *ptr;
		break;
	default:
		break;
	}
}

void set_node_attributes(int attr_ref, mxml_node_t *node, struct xml_data_struct *xml_attrs)
{
	int i = 0;
	int total_size = get_xml_tags_array_total_size(attr_ref);

	for(i =0; i < total_size; i++) {
		char *attr_value = NULL;
		int idx = get_xml_tag_index(xml_nodes_data[attr_ref].xml_tags[i].tag_name);
		if (idx == -1)
			continue;
		int tag_type = xml_nodes_data[attr_ref].xml_tags[i].tag_type;
		if (xml_nodes_data[attr_ref].xml_tags[i].tag_type == XML_FUNC) {
			xml_nodes_data[attr_ref].xml_tags[i].xml_func(node, xml_attrs);
			tag_type = XML_STRING;
		}
		get_xml_data_value_by_name(tag_type, idx, xml_attrs, &attr_value);
		if (!attr_value)
			continue;
		mxmlElementSetAttr(node, xml_nodes_data[attr_ref].xml_tags[i].tag_name, attr_value);
	}
}

int build_single_xml_node_data(int node_ref, mxml_node_t *node, struct xml_data_struct *xml_attrs)
{
	int i = 0, idx = 0;
	mxml_node_t *n = node;
	int total_size = get_xml_tags_array_total_size(node_ref);
	for(i =0; i < total_size; i++) {
		if (xml_nodes_data[node_ref].xml_tags[i].tag_name != NULL) {
			char *node_name = NULL;
			if (xml_nodes_data[node_ref].xml_tags[i].rec_ref == XML_SWITCH)
				node_name = get_xml_node_name_switch(xml_nodes_data[node_ref].xml_tags[i].tag_name);
			else
				node_name = xml_nodes_data[node_ref].xml_tags[i].tag_name;
			n = mxmlNewElement(node, node_name);
			if (!n)
				return FAULT_CPE_INTERNAL_ERROR;
		}

		if ((xml_nodes_data[node_ref].xml_tags[i].rec_ref >= ATTR_PARAM_STRUCT) && (xml_nodes_data[node_ref].xml_tags[i].rec_ref < XML_SWITCH)) {
			set_node_attributes(xml_nodes_data[node_ref].xml_tags[i].rec_ref, n, xml_attrs);
			if (xml_nodes_data[node_ref].xml_tags[i].tag_type == XML_REC)
				continue;
		}

		if (xml_nodes_data[node_ref].xml_tags[i].tag_type == XML_REC) {
			if (xml_nodes_data[node_ref].xml_tags[i].rec_ref > 0){
				int error = build_xml_node_data(xml_nodes_data[node_ref].xml_tags[i].rec_ref, n, xml_attrs);
				if (error)
					return error;
			}
			continue;
		}

		if (xml_nodes_data[node_ref].xml_tags[i].tag_type == XML_FUNC) {
			if (xml_nodes_data[node_ref].xml_tags[i].xml_func) {
				int err = xml_nodes_data[node_ref].xml_tags[i].xml_func(n, xml_attrs);
				if (err)
					return err;
			}
			continue;
		}

		idx = get_xml_tag_index(xml_nodes_data[node_ref].xml_tags[i].tag_name);
		if (idx == -1)
			continue;

		if (xml_nodes_data[node_ref].xml_tags[i].tag_type == XML_NODE) {
			mxml_node_t **t = NULL;
			get_xml_data_value_by_name(xml_nodes_data[node_ref].xml_tags[i].tag_type, idx, xml_attrs, (char **)&t);
			if (t != NULL)
				*t = n;
			continue;
		}

		char *opaque = NULL;
		get_xml_data_value_by_name(xml_nodes_data[node_ref].xml_tags[i].tag_type, idx, xml_attrs, &opaque);

		n = mxmlNewOpaque(n, opaque ? opaque : "");
		if (!n)
			return FAULT_CPE_INTERNAL_ERROR;
	}
	return CWMP_OK;
}

int build_xml_list_node_data(int node_ref, mxml_node_t *node, struct xml_data_struct *xml_attrs)
{
	mxml_node_t *n = node;
	struct xml_list_data *xml_data;
	list_for_each_entry (xml_data, xml_attrs->data_list, list) {
		if (xml_nodes_data[node_ref].tag_list_name) {
			n = mxmlNewElement(node, xml_nodes_data[node_ref].tag_list_name);
			if (!n)
				return FAULT_CPE_INTERNAL_ERROR;
		} else
			n = node;
		if (xml_nodes_data[node_ref].tag_node_ref > 0) {
			struct xml_data_struct xml_ref_data = {0};
			xml_ref_data.name = &xml_data->param_name;
			xml_ref_data.parameter_name = &xml_data->param_name;
			xml_ref_data.value = &xml_data->param_value;
			xml_ref_data.string = &xml_data->rpc_name;
			xml_ref_data.xsi_type = &xml_data->param_type;
			xml_ref_data.notification = &xml_data->notification;
			xml_ref_data.writable = &xml_data->writable;
			xml_ref_data.access_list = &xml_data->access_list;
			xml_ref_data.fault_string = &xml_data->fault_string;
			xml_ref_data.fault_code = &xml_data->fault_code;
			xml_ref_data.current_state = &xml_data->current_state;
			xml_ref_data.du_ref = &xml_data->du_ref;
			xml_ref_data.uuid = &xml_data->uuid;
			xml_ref_data.version = &xml_data->version;
			xml_ref_data.start_time = &xml_data->start_time;
			xml_ref_data.complete_time = &xml_data->complete_time;
			xml_ref_data.rpc_enum = xml_attrs->rpc_enum;
			xml_ref_data.counter = xml_attrs->counter;

			int fault = build_xml_node_data(xml_nodes_data[node_ref].tag_node_ref, n, &xml_ref_data);
			if (fault != CWMP_OK)
				return fault;
		}
		if (xml_attrs->counter != NULL && xml_attrs->inc_counter)
			*(xml_attrs->counter)+=1;
	}

	int i;
	int nbre_refs = get_xml_tags_array_total_size(node_ref);
	for (i = 0; i < nbre_refs; i++) {
		if (xml_nodes_data[node_ref].xml_tags[i].rec_ref > 0) {
			int fault = build_xml_node_data(xml_nodes_data[node_ref].xml_tags[i].rec_ref, node, xml_attrs);
			if (fault != CWMP_OK)
				return fault;
		}
	}
	return 0;
}

int build_xml_node_data(int node_ref, mxml_node_t *node, struct xml_data_struct *xml_attrs)
{
	if (node_ref >= SOAP_MAX)
		return FAULT_CPE_INTERNAL_ERROR;

	if (xml_nodes_data[node_ref].node_ms == XML_LIST )
		return build_xml_list_node_data(node_ref, node, xml_attrs);
	else
		return build_single_xml_node_data(node_ref, node, xml_attrs);
	return CWMP_OK;
}

mxml_node_t * build_top_body_soap_response(mxml_node_t *node, char *method)
{
	mxml_node_t *n = mxmlFindElement(node, node, "soap_env:Body", NULL, NULL, MXML_DESCEND);

	if (!n)
		return NULL;

	char method_resp[128];
	snprintf(method_resp, sizeof(method_resp), "cwmp:%sResponse", method);
	n = mxmlNewElement(n, method_resp);

	if (!n)
		return NULL;

	return n;
}

mxml_node_t * build_top_body_soap_request(mxml_node_t *node, char *method)
{
	mxml_node_t *n = mxmlFindElement(node, node, "soap_env:Body", NULL, NULL, MXML_DESCEND);

	if (!n)
		return NULL;

	char method_resp[128];
	snprintf(method_resp, sizeof(method_resp), "cwmp:%s", method);
	n = mxmlNewElement(n, method_resp);

	if (!n)
		return NULL;

	return n;
}

mxml_node_t * /* O - Element node or NULL */
mxmlFindElementOpaque(mxml_node_t *node, /* I - Current node */
		      mxml_node_t *top, /* I - Top node */
		      const char *text, /* I - Element text, if NULL return NULL */
		      int descend) /* I - Descend into tree - MXML_DESCEND, MXML_NO_DESCEND, or MXML_DESCEND_FIRST */
{
	if (!node || !top || !text)
		return (NULL);

	node = mxmlWalkNext(node, top, descend);

	while (node != NULL) {
		const char *op = mxmlGetOpaque(node);
		if (mxmlGetType(node) == MXML_OPAQUE && (!CWMP_STRCMP(op, text))) {
			return node;
		}

		if (descend == MXML_DESCEND)
			node = mxmlWalkNext(node, top, MXML_DESCEND);
		else
			node = mxmlGetNextSibling(node);
	}
	return (NULL);
}

char *xml__get_attribute_name_by_value(mxml_node_t *node,	const char  *value)
{
	if (node == NULL || value == NULL)
		return NULL;
	int attributes_nbre = mxmlElementGetAttrCount(node);
	int i;
	for (i = 0; i < attributes_nbre; i++) {
		char *attr_name = NULL;
		const char *attr_value = mxmlElementGetAttrByIndex(node, i, (const char **)&attr_name);
		if (attr_value && CWMP_STRCMP(attr_value, value) == 0)
			return attr_name;
	}
	return NULL;
}

int xml_recreate_namespace(mxml_node_t *tree)
{
	mxml_node_t *b = tree;

	FREE(ns.soap_env);
	FREE(ns.soap_enc);
	FREE(ns.xsd);
	FREE(ns.xsi);
	FREE(ns.cwmp);

	if (tree) {
		do {
			char *c;

			c = (char *)xml__get_attribute_name_by_value(b, soap_env_url);
			if (c && *(c + 5) == ':') {
				FREE(ns.soap_env);
				ns.soap_env = strdup((c + 6));
			}

			c = (char *)xml__get_attribute_name_by_value(b, soap_enc_url);
			if (c && *(c + 5) == ':') {
				FREE(ns.soap_enc);
				ns.soap_enc = strdup((c + 6));
			}

			c = (char *)xml__get_attribute_name_by_value(b, xsd_url);
			if (c && *(c + 5) == ':') {
				FREE(ns.xsd);
				ns.xsd = strdup((c + 6));
			}

			c = (char *)xml__get_attribute_name_by_value(b, xsi_url);
			if (c && *(c + 5) == ':') {
				FREE(ns.xsi);
				ns.xsi = strdup((c + 6));
			}

			int i;
			for (i = 0; cwmp_urls[i] != NULL; i++) {
				const char *cwmp_urn = cwmp_urls[i];

				c = (char *)xml__get_attribute_name_by_value(b, cwmp_urn);
				if (c && *(c + 5) == ':') {
					FREE(ns.cwmp);
					ns.cwmp = strdup((c + 6));
					break;
				}
			}

		} while ((b = mxmlWalkNext(b, tree, MXML_DESCEND)));
		return 0;
	}
	return -1;
}

void xml_exit(void)
{
	FREE(ns.soap_env);
	FREE(ns.soap_enc);
	FREE(ns.xsd);
	FREE(ns.xsi);
	FREE(ns.cwmp);
}

int xml_send_message(struct rpc *rpc)
{
	char *s, *msg_out = NULL, *msg_in = NULL;
	char c[512];
	int msg_out_len = 0, f, r = 0;
	mxml_node_t *b;

	if (cwmp_main->session == NULL) {
		CWMP_LOG(ERROR, "cwmp session not exist");
		return -1;
	}

	if (cwmp_main->session->tree_out) {
		unsigned char *zmsg_out;

		msg_out = convert_xml_node_to_string(cwmp_main->session->tree_out, whitespace_cb);
		FREE(g_tab_space);
		if (msg_out == NULL) {
			CWMP_LOG(ERROR, "%s: msg_out is null", __FUNCTION__);
			return -1;
		}

		CWMP_LOG_XML_MSG(DEBUG, msg_out, XML_MSG_OUT);
		if (cwmp_main->conf.compression != COMP_NONE) {
			if (zlib_compress(msg_out, &zmsg_out, &msg_out_len, cwmp_main->conf.compression)) {
				return -1;
			}
			FREE(msg_out);
			msg_out = (char *)zmsg_out;
		} else {
			msg_out_len = strlen(msg_out);
		}
	}
	while (1) {
		f = 0;
		if (icwmp_http_send_message(msg_out, msg_out_len, &msg_in)) {
			goto error;
		}
		if (msg_in) {
			CWMP_LOG_XML_MSG(DEBUG, msg_in, XML_MSG_IN);
			if ((s = CWMP_STRSTR(msg_in, "<FaultCode>")))
				sscanf(s, "<FaultCode>%d</FaultCode>", &f);
			if (f) {
				if (f == 8005) {
					r++;
					if (r < 5) {
						FREE(msg_in);
						continue;
					}
					goto error;
				} else if (rpc && rpc->type != RPC_ACS_INFORM) {
					break;
				} else {
					goto error;
				}
			} else {
				break;
			}
		} else {
			goto end;
		}
	}

	cwmp_main->session->tree_in = mxmlLoadString(NULL, msg_in, MXML_OPAQUE_CALLBACK);
	if (!cwmp_main->session->tree_in)
		goto error;
	if (xml_recreate_namespace(cwmp_main->session->tree_in) == -1) {
		CWMP_LOG(ERROR, "Failed to get ns parameters");
		goto error;
	}
	/* get NoMoreRequests or HolRequest*/
	cwmp_main->session->hold_request = false;

	if (snprintf(c, sizeof(c), "%s:%s", ns.cwmp, "NoMoreRequests") == -1)
		goto error;
	b = mxmlFindElement(cwmp_main->session->tree_in, cwmp_main->session->tree_in, c, NULL, NULL, MXML_DESCEND);
	if (b) {
		b = mxmlWalkNext(b, cwmp_main->session->tree_in, MXML_DESCEND_FIRST);
		const char *bname = b ? mxmlGetOpaque(b) : NULL;
		if (b && mxmlGetType(b) == MXML_OPAQUE && bname)
			cwmp_main->session->hold_request = atoi(bname);
	} else {
		if (snprintf(c, sizeof(c), "%s:%s", ns.cwmp, "HoldRequests") == -1)
			goto error;

		b = mxmlFindElement(cwmp_main->session->tree_in, cwmp_main->session->tree_in, c, NULL, NULL, MXML_DESCEND);
		const char *bname = b ? mxmlGetOpaque(b) : NULL;
		if (b) {
			b = mxmlWalkNext(b, cwmp_main->session->tree_in, MXML_DESCEND_FIRST);
			if (b && mxmlGetType(b) == MXML_OPAQUE && bname)
				cwmp_main->session->hold_request = atoi(bname);
		}
	}

end:
	FREE(msg_out);
	FREE(msg_in);
	return 0;

error:
	FREE(msg_out);
	FREE(msg_in);
	return -1;
}

int xml_prepare_msg_out()
{
	struct config *conf = &(cwmp_main->conf);
	mxml_node_t *n;

	load_response_xml_schema(&cwmp_main->session->tree_out);
	if (!cwmp_main->session->tree_out)
		return -1;

	n = mxmlFindElement(cwmp_main->session->tree_out, cwmp_main->session->tree_out, "soap_env:Envelope", NULL, NULL, MXML_DESCEND);
	if (!n) {
		return -1;
	}

	mxmlElementSetAttr(n, "xmlns:cwmp", cwmp_urls[(conf->amd_version) - 1]);
	if (!cwmp_main->session->tree_out)
		return -1;

	return 0;
}

int xml_set_cwmp_id()
{
	char c[32];
	mxml_node_t *b;
	int pid_t = getpid();

	/* define cwmp id */
	if (snprintf(c, sizeof(c), "%d.%u", pid_t, ++(cwmp_main->cwmp_id)) == -1)
		return -1;

	b = mxmlFindElement(cwmp_main->session->tree_out, cwmp_main->session->tree_out, "cwmp:ID", NULL, NULL, MXML_DESCEND);
	if (!b)
		return -1;

	b = mxmlNewOpaque(b, c);
	if (!b)
		return -1;

	return 0;
}

int xml_set_cwmp_id_rpc_cpe()
{
	char c[512];
	mxml_node_t *b;

	/* handle cwmp:ID */
	if (snprintf(c, sizeof(c), "%s:%s", ns.cwmp, "ID") == -1)
		return -1;

	b = mxmlFindElement(cwmp_main->session->tree_in, cwmp_main->session->tree_in, c, NULL, NULL, MXML_DESCEND);

	if (b) {
		/* ACS send ID parameter */
		b = mxmlWalkNext(b, cwmp_main->session->tree_in, MXML_DESCEND_FIRST);
		if (!b || mxmlGetType(b) != MXML_OPAQUE || !mxmlGetOpaque(b))
			return 0;
		snprintf(c, sizeof(c), "%s", mxmlGetOpaque(b));

		b = mxmlFindElement(cwmp_main->session->tree_out, cwmp_main->session->tree_out, "cwmp:ID", NULL, NULL, MXML_DESCEND);
		if (!b)
			return -1;

		b = mxmlNewOpaque(b, c);
		if (!b)
			return -1;
	} else {
		/* ACS does not send ID parameter */
		int r = xml_set_cwmp_id();
		return r;
	}
	return 0;
}

char *xml_get_cwmp_version(int version)
{
	static char versions[60];
	unsigned pos = 0;
	int k;

	versions[0] = '\0';
	for (k = 0; k < version; k++) {
		pos += snprintf(&versions[pos], sizeof(versions) - pos, "1.%d, ", k);
	}

	if (pos)
		versions[pos - 2] = 0;

	return versions;
}

static int xml_prepare_lwnotifications(mxml_node_t *parameter_list)
{
	mxml_node_t *b, *n;

	struct list_head *p;
	struct cwmp_dm_parameter *lw_notification;
	list_for_each (p, &list_lw_value_change) {
		lw_notification = list_entry(p, struct cwmp_dm_parameter, list);

		n = mxmlNewElement(parameter_list, "Param");
		if (!n)
			goto error;

		b = mxmlNewElement(n, "Name");
		if (!b)
			goto error;

		b = mxmlNewOpaque(b, lw_notification->name);
		if (!b)
			goto error;

		b = mxmlNewElement(n, "Value");
		if (!b)
			goto error;
		mxmlElementSetAttr(b, "xsi:type", lw_notification->type);
		b = mxmlNewOpaque(b, lw_notification->value);
		if (!b)
			goto error;
	}
	return 0;

error:
	return -1;
}

int xml_prepare_lwnotification_message(char **msg_out)
{
	mxml_node_t *lw_tree;

	load_notification_xml_schema(&lw_tree);
	if (!lw_tree)
		return -1;;

	*msg_out = convert_xml_node_to_string(lw_tree, MXML_NO_CALLBACK);

	mxmlDelete(lw_tree);
	return 0;
}

void load_notification_xml_schema(mxml_node_t **tree)
{
	char declaration[1024] = {0};
	struct config *conf = &(cwmp_main->conf);
	char *c = NULL;

	if (tree == NULL)
		return;

	*tree = NULL;

	snprintf(declaration, sizeof(declaration), "?xml version=\"1.0\" encoding=\"UTF-8\"?");
	mxml_node_t *xml = mxmlNewElement(NULL, declaration);
	if (xml == NULL)
		return;

	mxml_node_t *notification = mxmlNewElement(xml, "Notification");
	if (notification == NULL) {
		MXML_DELETE(xml);
		return;
	}

	mxmlElementSetAttr(notification, "xmlns", "urn:broadband-forum-org:cwmp:lwnotif-1-0");
	mxmlElementSetAttr(notification, "xmlns:xs", xsd_url);
	mxmlElementSetAttr(notification, "xmlns:xsi", xsi_url);
	mxmlElementSetAttr(notification, "xsi:schemaLocation", "urn:broadband-forum-org:cwmp:lxnotif-1-0 http://www.broadband-forum.org/cwmp/cwmp-UDPLightweightNotification-1-0.xsd");

	mxml_node_t *ts = mxmlNewElement(notification, "TS");
	if (ts == NULL) {
		MXML_DELETE(xml);
		return;
	}

	if (cwmp_asprintf(&c, "%ld", time(NULL)) == -1) {
		MXML_DELETE(xml);
		return;
	}

	if (NULL == mxmlNewOpaque(ts, c)) {
		FREE(c);
		MXML_DELETE(xml);
		return;
	}

	FREE(c);

	mxml_node_t *un = mxmlNewElement(notification, "UN");
	if (un == NULL) {
		MXML_DELETE(xml);
		return;
	}

	if (NULL == mxmlNewOpaque(un, conf->acs_userid)) {
		MXML_DELETE(xml);
		return;
	}

	mxml_node_t *cn = mxmlNewElement(notification, "CN");
	if (cn == NULL) {
		MXML_DELETE(xml);
		return;
	}

	c = (char *)calculate_lwnotification_cnonce();
	if (!c) {
		MXML_DELETE(xml);
		return;
	}

	if (NULL == mxmlNewOpaque(cn, c)) {
		FREE(c);
		MXML_DELETE(xml);
		return;
	}

	FREE(c);

	mxml_node_t *oui = mxmlNewElement(notification, "OUI");
	if (oui == NULL) {
		MXML_DELETE(xml);
		return;
	}

	if (NULL == mxmlNewOpaque(oui, cwmp_main->deviceid.oui)) {
		MXML_DELETE(xml);
		return;
	}

	mxml_node_t *pclass = mxmlNewElement(notification, "ProductClass");
	if (pclass == NULL) {
		MXML_DELETE(xml);
		return;
	}

	if (NULL == mxmlNewOpaque(pclass, cwmp_main->deviceid.productclass)) {
		MXML_DELETE(xml);
		return;
	}

	mxml_node_t *slno = mxmlNewElement(notification, "SerialNumber");
	if (slno == NULL) {
		MXML_DELETE(xml);
		return;
	}

	if (NULL == mxmlNewOpaque(slno, cwmp_main->deviceid.serialnumber)) {
		MXML_DELETE(xml);
		return;
	}

	if (xml_prepare_lwnotifications(notification)) {
		MXML_DELETE(xml);
		return;
	}

	*tree = xml;
}

void load_response_xml_schema(mxml_node_t **schema)
{
	char declaration[1024] = {0};

	if (schema == NULL)
		return;

	*schema = NULL;

	snprintf(declaration, sizeof(declaration), "?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?");
	mxml_node_t *xml = mxmlNewElement(NULL, declaration);
	if (xml == NULL)
		return;

	mxml_node_t *envlp = mxmlNewElement(xml, "soap_env:Envelope");
	if (envlp == NULL) {
		MXML_DELETE(xml);
		return;
	}

	mxmlElementSetAttr(envlp, "xmlns:soap_env", soap_env_url);
	mxmlElementSetAttr(envlp, "xmlns:soap_enc", soap_enc_url);
	mxmlElementSetAttr(envlp, "xmlns:xsd", xsd_url);
	mxmlElementSetAttr(envlp, "xmlns:xsi", xsi_url);

	mxml_node_t *header = mxmlNewElement(envlp, "soap_env:Header");
	if (header == NULL) {
		MXML_DELETE(xml);
		return;
	}

	mxml_node_t *id = mxmlNewElement(header, "cwmp:ID");
	if (id == NULL) {
		MXML_DELETE(xml);
		return;
	}

	mxmlElementSetAttr(id, "soap_env:mustUnderstand", "1");

	if (NULL == mxmlNewElement(envlp, "soap_env:Body")) {
		MXML_DELETE(xml);
		return;
	}

	*schema = xml;
}

const char *get_node_tab_space(mxml_node_t *node)
{
	int count = 0;

	while ((node = mxmlGetParent(node))) {
		count = count + 1;
	}

	if (!count)
		return "";

	FREE(g_tab_space);
	unsigned int size = count * sizeof(CWMP_MXML_TAB_SPACE) + 1;
	g_tab_space = (char *)malloc(size);
	if (!g_tab_space) {
		CWMP_LOG(ERROR, "Not able to allocate memory of size %u", size);
		return "";
	}

	memset(g_tab_space, 0, size);
	snprintf(g_tab_space, size, "%*s", size - 1, "");

	return g_tab_space;
}

const char *whitespace_cb(mxml_node_t *node, int where)
{
	if (mxmlGetType(node) != MXML_ELEMENT)
		return NULL;

	switch (where) {
	case MXML_WS_BEFORE_CLOSE:
		if (mxmlGetFirstChild(node) && mxmlGetType(mxmlGetFirstChild(node)) != MXML_ELEMENT)
			return NULL;

		return get_node_tab_space(node);
	case MXML_WS_BEFORE_OPEN:
		if (where == MXML_WS_BEFORE_CLOSE && mxmlGetFirstChild(node) && mxmlGetType(mxmlGetFirstChild(node)) != MXML_ELEMENT)
			return NULL;

		return get_node_tab_space(node);
	case MXML_WS_AFTER_OPEN:
		return ((mxmlGetFirstChild(node) == NULL || mxmlGetType(mxmlGetFirstChild(node)) == MXML_ELEMENT) ? "\n" : NULL);
	case MXML_WS_AFTER_CLOSE:
		return "\n";
	default:
		return NULL;
	}

	return NULL;
}
