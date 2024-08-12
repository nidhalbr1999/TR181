/*
 * rpc.c - CWMP RPC methods
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

#include "rpc.h"

#include "download.h"
#include "cwmp_du_state.h"
#include "log.h"
#include "event.h"
#include "datamodel_interface.h"
#include "event.h"
#include "xml.h"
#include "backupSession.h"
#include "notifications.h"
#include "upload.h"
#include "sched_inform.h"
#include "diagnostic.h"
#include "uci_utils.h"
#include "cwmp_event.h"
#include "autonomous_complpolicy.h"

#define PROCESSING_DELAY (1) // In download/upload the message enqueued before sending the response, which cause the download/upload
			     // to start just before the time. This delay is to compensate the time lapsed during the message enqueue and response

struct cwmp_namespaces ns;
const struct rpc_cpe_method rpc_cpe_methods[] = {
		[RPC_CPE_GET_RPC_METHODS] = { "GetRPCMethods", cwmp_handle_rpc_cpe_get_rpc_methods, AMD_1 },
		[RPC_CPE_SET_PARAMETER_VALUES] = { "SetParameterValues", cwmp_handle_rpc_cpe_set_parameter_values, AMD_1 },
		[RPC_CPE_GET_PARAMETER_VALUES] = { "GetParameterValues", cwmp_handle_rpc_cpe_get_parameter_values, AMD_1 },
		[RPC_CPE_GET_PARAMETER_NAMES] = { "GetParameterNames", cwmp_handle_rpc_cpe_get_parameter_names, AMD_1 },
		[RPC_CPE_SET_PARAMETER_ATTRIBUTES] = { "SetParameterAttributes", cwmp_handle_rpc_cpe_set_parameter_attributes, AMD_1 },
		[RPC_CPE_GET_PARAMETER_ATTRIBUTES] = { "GetParameterAttributes", cwmp_handle_rpc_cpe_get_parameter_attributes, AMD_1 },
		[RPC_CPE_ADD_OBJECT] = { "AddObject", cwmp_handle_rpc_cpe_add_object, AMD_1 },
		[RPC_CPE_DELETE_OBJECT] = { "DeleteObject", cwmp_handle_rpc_cpe_delete_object, AMD_1 },
		[RPC_CPE_REBOOT] = { "Reboot", cwmp_handle_rpc_cpe_reboot, AMD_1 },
		[RPC_CPE_DOWNLOAD] = { "Download", cwmp_handle_rpc_cpe_download, AMD_1 },
		[RPC_CPE_UPLOAD] = { "Upload", cwmp_handle_rpc_cpe_upload, AMD_1 },
		[RPC_CPE_FACTORY_RESET] = { "FactoryReset", cwmp_handle_rpc_cpe_factory_reset, AMD_1 },
		[RPC_CPE_CANCEL_TRANSFER] = { "CancelTransfer", cwmp_handle_rpc_cpe_cancel_transfer, AMD_3 },
		[RPC_CPE_SCHEDULE_INFORM] = { "ScheduleInform", cwmp_handle_rpc_cpe_schedule_inform, AMD_1 },
		[RPC_CPE_SCHEDULE_DOWNLOAD] = { "ScheduleDownload", cwmp_handle_rpc_cpe_schedule_download, AMD_3 },
		[RPC_CPE_CHANGE_DU_STATE] = { "ChangeDUState", cwmp_handle_rpc_cpe_change_du_state, AMD_3 },
		[RPC_CPE_X_FACTORY_RESET_SOFT] = { "X_FactoryResetSoft", cwmp_handle_rpc_cpe_x_factory_reset_soft, AMD_1 },
		[RPC_CPE_FAULT] = { "Fault", cwmp_handle_rpc_cpe_fault, AMD_1 }
};

struct rpc_acs_method rpc_acs_methods[] = {
		[RPC_ACS_INFORM] = { "Inform", cwmp_rpc_acs_prepare_message_inform, cwmp_rpc_acs_parse_response_inform, NULL, NOT_KNOWN },
		[RPC_ACS_GET_RPC_METHODS] = { "GetRPCMethods", cwmp_rpc_acs_prepare_get_rpc_methods, cwmp_rpc_acs_parse_response_get_rpc_methods, NULL, NOT_KNOWN },
		[RPC_ACS_TRANSFER_COMPLETE] = { "TransferComplete", cwmp_rpc_acs_prepare_transfer_complete, NULL, cwmp_rpc_acs_destroy_data_transfer_complete, NOT_KNOWN },
		[RPC_ACS_AUTONOMOUS_TRANSFER_COMPLETE] = { "AutonomousTransferComplete", cwmp_rpc_acs_prepare_autonomous_transfer_complete, NULL, cwmp_rpc_acs_destroy_data_autonomous_transfer_complete, NOT_KNOWN },
		[RPC_ACS_DU_STATE_CHANGE_COMPLETE] = { "DUStateChangeComplete", cwmp_rpc_acs_prepare_du_state_change_complete, NULL, cwmp_rpc_acs_destroy_data_du_state_change_complete, NOT_KNOWN },
		[RPC_ACS_AUTONOMOUS_DU_STATE_CHANGE_COMPLETE] = { "AutonomousDUStateChangeComplete", cwmp_rpc_acs_prepare_autonomous_du_state_change_complete, NULL, cwmp_rpc_acs_destroy_data_autonomous_du_state_change_complete, NOT_KNOWN }
};

static char *forced_inform_parameters[] = {
	"Device.RootDataModelVersion",
	"Device.DeviceInfo.HardwareVersion",
	"Device.DeviceInfo.SoftwareVersion",
	"Device.DeviceInfo.ProvisioningCode",
	"Device.ManagementServer.ParameterKey",
	"Device.ManagementServer.ConnectionRequestURL",
	"Device.ManagementServer.AliasBasedAddressing"
};

int xml_handle_message()
{
	char buf[128] = {0};
	int i;
	mxml_node_t *b;
	struct config *conf = &(cwmp_main->conf);

	/* get method */
	snprintf(buf, sizeof(buf), "%s:%s", ns.soap_env, "Body");

	if (strlen(buf) == 0) {
		cwmp_main->session->fault_code = FAULT_CPE_INTERNAL_ERROR;
		goto fault;
	}

	b = mxmlFindElement(cwmp_main->session->tree_in, cwmp_main->session->tree_in, buf, NULL, NULL, MXML_DESCEND);

	if (!b) {
		CWMP_LOG(INFO, "Invalid received message");
		cwmp_main->session->fault_code = FAULT_CPE_REQUEST_DENIED;
		goto fault;
	}
	cwmp_main->session->body_in = b;

	while (1) {
		b = mxmlWalkNext(b, cwmp_main->session->body_in, MXML_DESCEND_FIRST);
		if (!b)
			goto error;
		if (mxmlGetType(b) == MXML_ELEMENT)
			break;
	}

	char *c = (char *)mxmlGetElement(b);

	if (c == NULL) {
		CWMP_LOG(INFO, "Could not get element from received message");
		goto error;
	}


	/* convert QName to localPart, check that ns is the expected one */
	if (c && strchr(c, ':')) {
		char *tmp = strchr(c, ':');
		size_t ns_len = tmp - c;

		if (CWMP_STRLEN(ns.cwmp) != ns_len) {
			CWMP_LOG(INFO, "Namespace length is not matched in string (%s) and expected (%s)", c, ns.cwmp);
			cwmp_main->session->fault_code = FAULT_CPE_REQUEST_DENIED;
			goto fault;
		}

		if (CWMP_STRNCMP(ns.cwmp, c, ns_len)) {
			CWMP_LOG(INFO, "Namespace in string (%s) is not the expected (%s) one", c, ns.cwmp);
			cwmp_main->session->fault_code = FAULT_CPE_REQUEST_DENIED;
			goto fault;
		}

		c = tmp + 1;
	} else {
		CWMP_LOG(INFO, "Can not convert QName to local part with received string (%s)", c);
		cwmp_main->session->fault_code = FAULT_CPE_REQUEST_DENIED;
		goto fault;
	}
	CWMP_LOG(INFO, "SOAP RPC message: %s", c);
	for (i = 1; i < __RPC_CPE_MAX; i++) {
		if (i != RPC_CPE_FAULT && c && CWMP_STRCMP(c, rpc_cpe_methods[i].name) == 0 && rpc_cpe_methods[i].amd <= conf->supported_amd_version) {
			CWMP_LOG(INFO, "%s RPC is supported", c);
			cwmp_main->session->rpc_cpe = build_sessin_rcp_cpe(i);
			if (cwmp_main->session->rpc_cpe == NULL)
				goto error;
			break;
		}
	}
	if (!cwmp_main->session->rpc_cpe) {
		CWMP_LOG(INFO, "%s RPC is not supported", c);
		cwmp_main->session->fault_code = FAULT_CPE_METHOD_NOT_SUPPORTED;
		goto fault;
	}
	return 0;
fault:
	cwmp_main->session->rpc_cpe = build_sessin_rcp_cpe(RPC_CPE_FAULT);
	if (cwmp_main->session->rpc_cpe == NULL)
		goto error;
	return 0;
error:
	return -1;
}

/*
 * [RPC ACS]: Inform
 */
static int xml_prepare_parameters_inform(struct cwmp_dm_parameter *dm_parameter, mxml_node_t *parameter_list, int *size)
{
	mxml_node_t *node = NULL, *b;
	b = mxmlFindElementOpaque(parameter_list, parameter_list, dm_parameter->name, MXML_DESCEND);
	if (b && dm_parameter->value != NULL) {
		node = mxmlGetParent(b);
		b = mxmlFindElement(node, node, "Value", NULL, NULL, MXML_DESCEND_FIRST);
		if (!b)
			return 0;
		mxml_node_t *c = mxmlGetFirstChild(b);
		const char *c_opaque = c ? mxmlGetOpaque(c) : NULL;
		if (c && c_opaque && CWMP_STRCMP(dm_parameter->value, c_opaque) == 0)
			return 0;
		mxmlDelete(b);
		(*size)--;
	} else if (dm_parameter->value == NULL)
		return 0;

	char *type = (dm_parameter->type && dm_parameter->type[0] != '\0') ? dm_parameter->type : "xsd:string";
	if (node == NULL) {
		if (dm_parameter->name == NULL)
			return -1;
		struct xml_data_struct inform_params_xml_attrs = {0};
		struct xml_list_data *xml_data = calloc(1, sizeof(struct xml_list_data));
		xml_data->param_name = CWMP_STRDUP(dm_parameter->name);
		xml_data->param_value = CWMP_STRDUP(dm_parameter->value);
		xml_data->param_type = CWMP_STRDUP(type);
		LIST_HEAD(prameters_xml_list);
		list_add_tail(&xml_data->list, &prameters_xml_list);
		inform_params_xml_attrs.data_list = &prameters_xml_list;
		int fault = build_xml_node_data(SOAP_PARAM_STRUCT, parameter_list, &inform_params_xml_attrs);
		if (fault != CWMP_OK)
			return -1;

		cwmp_free_all_xml_data_list(&prameters_xml_list);
	} else {
		struct xml_data_struct inform_param_value_xml_attrs = {0};
		inform_param_value_xml_attrs.value = &dm_parameter->value;
		inform_param_value_xml_attrs.xsi_type = &type;

		int fault = build_xml_node_data(SOAP_VALUE_STRUCT, node, &inform_param_value_xml_attrs);
		if (fault != CWMP_OK)
			return -1;
	}

	(*size)++;
	return 0;
}

bool event_in_session_event_list(char *event, struct list_head *list_evts)
{
	struct event_container *event_container = NULL;

	if (event == NULL)
		return false;
	list_for_each_entry (event_container, list_evts, list) {
		if (CWMP_STRCMP(event, EVENT_CONST[event_container->code].CODE) == 0)
			return true;
	}
	return false;
}

bool check_inform_parameter_events_list_corresponding(char *events_str_list, struct list_head *list_evts)
{
	char *evt = NULL;

	if (CWMP_STRLEN(events_str_list) == 0) {
		/* Need to check and if only '4 VALUE CHANGE' event in session event list,
		 * then this parameter should not be added in inform param */
		bool add_param = false;
		struct event_container *event_container = NULL;

		list_for_each_entry(event_container, list_evts, list) {
			if (event_container->code != EVENT_IDX_4VALUE_CHANGE) {
				add_param = true;
				break;
			}
		}

		return add_param;
	}

	foreach_elt_in_strlist(evt, events_str_list, ",") {
		if (event_in_session_event_list(evt, list_evts))
			return true;
	}
	return false;
}

static void load_inform_xml_schema(mxml_node_t **tree)
{
	LIST_HEAD(local_inform_list);
	char declaration[1024] = {0};
	char c[256] = {0};

	mxml_node_t *xml = NULL, *envelope = NULL;
	if (tree == NULL)
		return;

	*tree = NULL;

	snprintf(declaration, sizeof(declaration), "?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?");

	xml= mxmlNewElement(NULL, declaration);
	if (xml == NULL)
		return;

	struct xml_data_struct env_xml_attrs = {0};

	env_xml_attrs.xml_env = &envelope;

	int fault = build_xml_node_data(SOAP_ENV, xml, &env_xml_attrs);

	if (envelope == NULL || fault != CWMP_OK)
		goto error;

	mxml_node_t *inform = build_top_body_soap_request(envelope, "Inform");
	if (inform == NULL)
		goto error;

	struct xml_data_struct inform_xml_attrs = {0};

	char *manufacturer = cwmp_main->deviceid.manufacturer;
	char *oui = cwmp_main->deviceid.oui;
	char *product_class = cwmp_main->deviceid.productclass;
	char *serial_number = cwmp_main->deviceid.serialnumber;
	int max_env = 1;
	char *current_time = get_time(time(NULL));

	inform_xml_attrs.manufacturer = &manufacturer;
	inform_xml_attrs.oui = &oui;
	inform_xml_attrs.product_class = &product_class;
	inform_xml_attrs.serial_number = &serial_number;
	inform_xml_attrs.max_envelopes = &max_env;
	inform_xml_attrs.current_time = &current_time;
	inform_xml_attrs.retry_count = &cwmp_main->retry_count_session;

	LIST_HEAD(xml_events_list);
	event_container_list_to_xml_data_list(&(cwmp_main->session->events), &xml_events_list);
	inform_xml_attrs.data_list = &xml_events_list;

	fault = build_xml_node_data(SOAP_INFORM_CWMP, inform, &inform_xml_attrs);
	if (fault != CWMP_OK)
		goto error;

	move_next_session_events_to_actual_session();
	cwmp_free_all_xml_data_list(&xml_events_list);
	mxml_node_t *param_list = mxmlNewElement(inform, "ParameterList");
	if (param_list == NULL)
		goto error;

	mxmlElementSetAttr(param_list, "soap_enc:arrayType", "cwmp:ParameterValueStruct[0]");
	struct list_head *ilist, *jlist;
	struct cwmp_dm_parameter *dm_parameter;
	int size = 0;

	list_for_each (ilist, &(cwmp_main->session->events)) {
		struct event_container *event_container = list_entry(ilist, struct event_container, list);
		list_for_each (jlist, &(event_container->head_dm_parameter)) {
			dm_parameter = list_entry(jlist, struct cwmp_dm_parameter, list);
			if (xml_prepare_parameters_inform(dm_parameter, param_list, &size))
				goto error;
		}
	}

	struct cwmp_dm_parameter cwmp_dm_param = {0};
	force_inform_node *iter = NULL, *node = NULL;

	list_for_each_entry_safe(iter, node, &force_inform_list, list) {
		if (!cwmp_get_parameter_value(iter->path, &cwmp_dm_param))
			continue;

		// An empty connection url cause CDR test to break
		if (strcmp(iter->path, "Device.ManagementServer.ConnectionRequestURL") == 0 &&
				CWMP_STRLEN(cwmp_dm_param.value) == 0) {
			CWMP_LOG(ERROR, "# Empty CR URL[%s] value", iter->path);
			goto error;
		}

		if (xml_prepare_parameters_inform(&cwmp_dm_param, param_list, &size))
			goto error;
	}

	//only forced inform parameters are included in heartbeat inform session
	if (cwmp_main->session->session_status.is_heartbeat)
		goto end;

	struct cwmp_dm_parameter *param_iter = NULL;

	get_inform_parameters_uci(&local_inform_list);
	list_for_each_entry(param_iter, &local_inform_list, list) {
		bool enable = param_iter->writable;

		if (enable == false)
			continue;

		char *parameter_name = param_iter->name;
		if (CWMP_STRLEN(parameter_name) == 0)
			continue;

		LIST_HEAD(parameters_list);
		char *err = cwmp_get_parameter_values(parameter_name, &parameters_list);
		if (err || list_empty(&parameters_list))
			continue;

		char *events_str_list = param_iter->value;
		if (!check_inform_parameter_events_list_corresponding(events_str_list, &(cwmp_main->session->events)))
			continue;

		struct list_head *data_list = &parameters_list;
		struct cwmp_dm_parameter *dm_param = NULL;
		list_for_each_entry(dm_param, data_list, list) {
			if (xml_prepare_parameters_inform(dm_param, param_list, &size)) {
				cwmp_free_all_dm_parameter_list(&parameters_list);
				goto error;
			}
		}
		cwmp_free_all_dm_parameter_list(&parameters_list);
	}
	cwmp_free_all_dm_parameter_list(&local_inform_list);
	goto end;

error:
	cwmp_free_all_dm_parameter_list(&local_inform_list);
	MXML_DELETE(xml);
	return;

end:
	if (snprintf(c, sizeof(c), "cwmp:ParameterValueStruct[%d]", size) == -1) {
		MXML_DELETE(xml);
		return;
	}

	mxmlElementSetAttr(param_list, "xsi:type", "soap_enc:Array");
	mxmlElementSetAttr(param_list, "soap_enc:arrayType", c);

	*tree = xml;
}

static int validate_inform_parameter_name(struct list_head *parameters_values_list)
{
	struct cwmp_dm_parameter *param_value = NULL;
	char reg_exp[128] = {0};

	snprintf(reg_exp, sizeof(reg_exp), "^Device\\.ManagementServer\\.InformParameter\\.[0-9]+\\.ParameterName$");

	list_for_each_entry(param_value, parameters_values_list, list) {

		if (param_value->name == NULL || param_value->value == NULL)
			continue;

		if (match_reg_exp(reg_exp, param_value->name) == false)
			continue;

		force_inform_node *iter = NULL, *node = NULL;
		list_for_each_entry_safe(iter, node, &force_inform_list, list) {
			if (strcmp(iter->path, param_value->value) == 0)
				return FAULT_CPE_INVALID_PARAMETER_VALUE;
		}
	}

	return FAULT_CPE_NO_FAULT;
}

int cwmp_rpc_acs_prepare_message_inform(struct rpc *this __attribute__((unused)))
{
	mxml_node_t *tree;

	if (cwmp_main->session == NULL)
		return -1;

	load_inform_xml_schema(&tree);

	if (!tree)
		goto error;

	cwmp_main->session->tree_out = tree;

	return 0;

error:
	CWMP_LOG(ERROR, "Unable Prepare Message Inform", CWMP_BKP_FILE);
	return -1;
}

int cwmp_rpc_acs_parse_response_inform(struct rpc *this __attribute__((unused)))
{
	mxml_node_t *tree, *b;
	int i = -1;
	char *c;
	const char *cwmp_urn;

	tree = cwmp_main->session->tree_in;
	if (!tree)
		goto error;
	b = mxmlFindElement(tree, tree, "MaxEnvelopes", NULL, NULL, MXML_DESCEND);
	if (!b)
		goto error;
	b = mxmlWalkNext(b, tree, MXML_DESCEND_FIRST);
	if (!b || mxmlGetType(b) != MXML_OPAQUE || !mxmlGetOpaque(b))
		goto error;
	if (cwmp_main->conf.supported_amd_version == 1) {
		cwmp_main->conf.amd_version = 1;
		return 0;
	}
	b = mxmlFindElement(tree, tree, "UseCWMPVersion", NULL, NULL, MXML_DESCEND);
	if (b && cwmp_main->conf.supported_amd_version >= 5) { //IF supported version !=5 acs response dosen't contain UseCWMPVersion
		b = mxmlWalkNext(b, tree, MXML_DESCEND_FIRST);
		if (!b || mxmlGetType(b) != MXML_OPAQUE || !mxmlGetOpaque(b))
			goto error;
		c = (char *) mxmlGetOpaque(b);
		if (c && *(c + 1) == '.') {
			c += 2;
			cwmp_main->conf.amd_version = atoi(c) + 1;
			return 0;
		}
		goto error;
	}
	for (i = 0; cwmp_urls[i] != NULL; i++) {
		cwmp_urn = cwmp_urls[i];
		c = (char *)xml__get_attribute_name_by_value(tree, cwmp_urn);
		if (c && *(c + 5) == ':') {
			break;
		}
	}
	if (i == 0) {
		cwmp_main->conf.amd_version = i + 1;
	} else if (i >= 1 && i <= 3) {
		switch (cwmp_main->conf.supported_amd_version) {
		case 1:
			cwmp_main->conf.amd_version = 1; //Already done
			break;
		case 2:
		case 3:
		case 4:
			//MIN ACS CPE
			if (cwmp_main->conf.supported_amd_version <= i + 1)
				cwmp_main->conf.amd_version = cwmp_main->conf.supported_amd_version;
			else
				cwmp_main->conf.amd_version = i + 1;
			break;
		case 5:
			cwmp_main->conf.amd_version = i + 1;
			break;
		}
	} else if (i >= 4) {
		cwmp_main->conf.amd_version = cwmp_main->conf.supported_amd_version;
	}
	return 0;

error:
	return -1;
}

int set_rpc_acs_to_supported(const char *rpc_name)
{
	int i;

	if (rpc_name == NULL)
		return -1;
	for (i=1; i < __RPC_ACS_MAX; i++) {
		if (strcmp(rpc_acs_methods[i].name, rpc_name) == 0) {
			rpc_acs_methods[i].acs_support = RPC_ACS_SUPPORT;
			return i;
		}
	}
	return -1;
}

void set_not_known_acs_support()
{
	int i;
	for (i=1; i < __RPC_ACS_MAX; i++) {
		if ((i != RPC_ACS_INFORM) && (rpc_acs_methods[i].acs_support == NOT_KNOWN))
			rpc_acs_methods[i].acs_support = RPC_ACS_NOT_SUPPORT;
	}
}

int cwmp_rpc_acs_parse_response_get_rpc_methods(struct rpc *this __attribute__((unused)))
{
	mxml_node_t *tree, *b;
	tree = cwmp_main->session->tree_in;

	b = mxmlFindElement(tree, tree, "cwmp:GetRPCMethodsResponse", NULL, NULL, MXML_DESCEND);
	if (!b)
		goto error;

	LIST_HEAD(getrpcs_acs_list);
	struct xml_data_struct getrpcs_xml_attrs = {0};
	getrpcs_xml_attrs.data_list = &getrpcs_acs_list;
	struct xml_tag_validation getrpcs_validation[] = {{"string", VALIDATE_STR_SIZE, 0, 256}};
	getrpcs_xml_attrs.validations = getrpcs_validation;
	getrpcs_xml_attrs.nbre_validations = 1;

	int err = load_xml_node_data(SOAP_RESP_ACS_GETRPC, b, &getrpcs_xml_attrs);
	cwmp_free_all_xml_data_list(&getrpcs_acs_list);
	if (err) {
		CWMP_LOG(INFO, "# Failed to load GetRPCMethodsResp");
		goto error;
	}

	set_not_known_acs_support();
	return 0;
error:
	return -1;
}

/*
 * [RPC ACS]: GetRPCMethods
 */
int cwmp_rpc_acs_prepare_get_rpc_methods(struct rpc *rpc __attribute__((unused)))
{
	mxml_node_t *tree = NULL, *n;

	load_response_xml_schema(&tree);
	if (!tree)
		return -1;

	n = mxmlFindElement(tree, tree, "soap_env:Envelope", NULL, NULL, MXML_DESCEND);
	if (!n)
		return -1;
	mxmlElementSetAttr(n, "xmlns:cwmp", cwmp_urls[(cwmp_main->conf.amd_version) - 1]);

	n = build_top_body_soap_request(tree, "GetRPCMethods");
	if (!n)
		return -1;

	cwmp_main->session->tree_out = tree;

	return 0;
}

/*
 * [RPC ACS]: TransferComplete
 */
int cwmp_rpc_acs_prepare_transfer_complete(struct rpc *rpc)
{
	mxml_node_t *tree, *n;
	struct transfer_complete *p;
	char *faultstring = NULL;

	p = (struct transfer_complete *)rpc->extra_data;
	load_response_xml_schema(&tree);
	if (!tree)
		goto error;

	n = mxmlFindElement(tree, tree, "soap_env:Envelope", NULL, NULL, MXML_DESCEND);
	if (!n)
		goto error;
	mxmlElementSetAttr(n, "xmlns:cwmp", cwmp_urls[(cwmp_main->conf.amd_version) - 1]);

	n = build_top_body_soap_request(tree, "TransferComplete");
	if (!n)
		goto error;

	struct xml_data_struct transfer_complete_xml_attrs = {0};

	transfer_complete_xml_attrs.command_key = p ? &p->command_key : NULL;
	if (p) {
		transfer_complete_xml_attrs.start_time = &p->start_time;
		transfer_complete_xml_attrs.complete_time = &p->complete_time;

		if (CWMP_STRLEN(p->fault_string) != 0)
			faultstring = strdup(p->fault_string);
	}

	int faultcode = (p && p->fault_code && (p->fault_code < __FAULT_CPE_MAX)) ? atoi(FAULT_CPE_ARRAY[p->fault_code].CODE) : 0;
	transfer_complete_xml_attrs.fault_code = &faultcode;

	if (faultstring == NULL)
		faultstring = strdup((p && p->fault_code) ? FAULT_CPE_ARRAY[p->fault_code].DESCRIPTION : "");
	transfer_complete_xml_attrs.fault_string = &faultstring;

	int fault = build_xml_node_data(SOAP_ACS_TRANSCOMPLETE, n, &transfer_complete_xml_attrs);
	if (fault != CWMP_OK)
		goto error;

	FREE(faultstring);
	cwmp_main->session->tree_out = tree;

	return 0;

error:
	return -1;
}

int cwmp_rpc_acs_prepare_autonomous_transfer_complete(struct rpc *rpc)
{
	mxml_node_t *tree = NULL, *n;
	auto_transfer_complete *p;

	p = (auto_transfer_complete *)rpc->extra_data;
	load_response_xml_schema(&tree);
	if (!tree)
		goto error;

	n = mxmlFindElement(tree, tree, "soap_env:Envelope", NULL, NULL, MXML_DESCEND);
	if (!n)
		goto error;

	mxmlElementSetAttr(n, "xmlns:cwmp", cwmp_urls[(cwmp_main->conf.amd_version) - 1]);

	n = build_top_body_soap_request(tree, "AutonomousTransferComplete");
	if (!n)
		goto error;

	struct xml_data_struct auto_trsfr_complete_xml_attrs = {0};

	if (p) {
		auto_trsfr_complete_xml_attrs.start_time = &p->start_time;
		auto_trsfr_complete_xml_attrs.complete_time = &p->complete_time;
		auto_trsfr_complete_xml_attrs.fault_code = &p->fault_code;
		auto_trsfr_complete_xml_attrs.fault_string = &p->fault_string;
		auto_trsfr_complete_xml_attrs.announce_url = &p->announce_url;
		auto_trsfr_complete_xml_attrs.transfer_url = &p->transfer_url;
		auto_trsfr_complete_xml_attrs.file_size = &p->file_size;
		auto_trsfr_complete_xml_attrs.file_type = &p->file_type;
		auto_trsfr_complete_xml_attrs.target_file_name = &p->target_file_name;
		auto_trsfr_complete_xml_attrs.is_download = &p->is_download;
	}

	int fault = build_xml_node_data(SOAP_AUTONOMOUS_TRANSFER_COMPLETE, n, &auto_trsfr_complete_xml_attrs);
	if (fault != CWMP_OK) {
		goto error;
	}

	cwmp_main->session->tree_out = tree;
	return 0;

error:
	return -1;
}
/*
 * [RPC ACS]: DUStateChangeComplete
 */
int cwmp_rpc_acs_prepare_du_state_change_complete(struct rpc *rpc)
{
	mxml_node_t *tree = NULL, *n;
	struct du_state_change_complete *p;

	if (rpc == NULL)
		goto error;

	p = (struct du_state_change_complete *)rpc->extra_data;
	if (p == NULL)
		goto error;

	load_response_xml_schema(&tree);
	if (!tree)
		goto error;

	n = mxmlFindElement(tree, tree, "soap_env:Envelope", NULL, NULL, MXML_DESCEND);
	if (!n)
		goto error;

	mxmlElementSetAttr(n, "xmlns:cwmp", cwmp_urls[(cwmp_main->conf.amd_version) - 1]);

	n = build_top_body_soap_request(tree, "DUStateChangeComplete");
	if (!n)
		goto error;

	LIST_HEAD(opt_result_list);
	cdu_operations_result_list_to_xml_data_list(&p->list_opresult, &opt_result_list);

	struct xml_data_struct cdu_complete_xml_attrs = {0};

	cdu_complete_xml_attrs.command_key = &p->command_key;
	cdu_complete_xml_attrs.data_list = &opt_result_list;

	int fault = build_xml_node_data(SOAP_DU_CHANGE_COMPLETE, n, &cdu_complete_xml_attrs);
	if (fault != CWMP_OK) {
		cwmp_free_all_xml_data_list(&opt_result_list);
		goto error;
	}

	cwmp_free_all_xml_data_list(&opt_result_list);
	cwmp_main->session->tree_out = tree;
	return 0;

error:
	return -1;
}

/*
 * [RPC ACS]: AutonomousDUStateChangeComplete
 */
int cwmp_rpc_acs_prepare_autonomous_du_state_change_complete(struct rpc *rpc)
{
	mxml_node_t *tree = NULL, *n;
	auto_du_state_change_compl *p;

	p = (auto_du_state_change_compl *)rpc->extra_data;
	load_response_xml_schema(&tree);
	if (!tree)
		goto error;

	n = mxmlFindElement(tree, tree, "soap_env:Envelope", NULL, NULL, MXML_DESCEND);
	if (!n)
		goto error;

	mxmlElementSetAttr(n, "xmlns:cwmp", cwmp_urls[(cwmp_main->conf.amd_version) - 1]);

	n = build_top_body_soap_request(tree, "AutonomousDUStateChangeComplete");
	if (!n)
		goto error;

	struct xml_data_struct acdu_complete_xml_attrs = {0};

	acdu_complete_xml_attrs.command_key = NULL;
	if (p) {
		acdu_complete_xml_attrs.start_time = &p->start_time;
		acdu_complete_xml_attrs.complete_time = &p->complete_time;
		acdu_complete_xml_attrs.fault_code = &p->fault_code;
		acdu_complete_xml_attrs.fault_string = &p->fault_string;
		acdu_complete_xml_attrs.version = &p->ver;
		acdu_complete_xml_attrs.uuid = &p->uuid;
		acdu_complete_xml_attrs.current_state = &p->current_state;
		acdu_complete_xml_attrs.operation = &p->operation;
		acdu_complete_xml_attrs.resolved = &p->resolved;
	}

	int fault = build_xml_node_data(SOAP_AUTONOMOUS_DU_CHANGE_COMPLETE, n, &acdu_complete_xml_attrs);
	if (fault != CWMP_OK) {
		goto error;
	}

	cwmp_main->session->tree_out = tree;
	return 0;

error:
	return -1;
}

/*
 * [RPC CPE]: GetParameterValues
 */
int cwmp_handle_rpc_cpe_get_parameter_values(struct rpc *rpc)
{
	mxml_node_t *b = NULL;
	int fault_code = FAULT_CPE_INTERNAL_ERROR;
	int counter = 0;
	char *err_msg = NULL;

	if (cwmp_main->session->tree_out == NULL) {
		err_msg = "Output xml tree does not exist";
		goto fault;
	}

	b = build_top_body_soap_response(cwmp_main->session->tree_out, "GetParameterValues");
	if (b == NULL) {
		err_msg = "Failed to populate the SOAP message for GPV response";
		goto fault;
	}

	LIST_HEAD(gpv_xml_data_list);

	struct xml_data_struct gpv_xml_attrs = {0};
	gpv_xml_attrs.data_list = &gpv_xml_data_list;
	struct xml_tag_validation gpv_validation[] = {{"string", VALIDATE_STR_SIZE, 0, 256}};
	gpv_xml_attrs.validations = gpv_validation;
	gpv_xml_attrs.nbre_validations = 1;

	fault_code = load_xml_node_data(SOAP_REQ_GPV, cwmp_main->session->body_in, &gpv_xml_attrs);
	if (fault_code) {
		err_msg = "Failed to load the attributes from GPV requests message";
		goto fault;
	}

	gpv_xml_attrs.rpc_enum = SOAP_PARAM_STRUCT;
	gpv_xml_attrs.counter = &counter;
	gpv_xml_attrs.inc_counter = false;
	char *xsi_type = "soap_enc:Array";
	char *soap_array_type = NULL;
	gpv_xml_attrs.xsi_type = &xsi_type;
	gpv_xml_attrs.soap_enc_array_type = &soap_array_type;

	fault_code = build_xml_node_data(SOAP_RESP_GET, b, &gpv_xml_attrs);

	cwmp_free_all_xml_data_list(&gpv_xml_data_list);

	if (fault_code)
		goto fault;

	return 0;

fault:
	if (cwmp_create_fault_message(rpc, fault_code, err_msg))
		return -1;
	return 0;
}

/*
 * [RPC CPE]: GetParameterNames
 */
int cwmp_handle_rpc_cpe_get_parameter_names(struct rpc *rpc)
{
	mxml_node_t *n;
	char *parameter_name = NULL;
	bool next_level = true;
	int counter = 0, fault_code = FAULT_CPE_INTERNAL_ERROR;
	char *err_msg = NULL;
	LIST_HEAD(parameters_list);

	struct xml_data_struct gpn_xml_attrs = {0};

	gpn_xml_attrs.next_level = &next_level;
	gpn_xml_attrs.parameter_path = &parameter_name;
	struct xml_tag_validation gpn_validation[] = {{"ParameterPath", VALIDATE_STR_SIZE, 0, 256}, {"NextLevel", VALIDATE_BOOLEAN, 0, 0}};
	gpn_xml_attrs.validations = gpn_validation;
	gpn_xml_attrs.nbre_validations = 2;

	fault_code = load_xml_node_data(SOAP_REQ_GPN, cwmp_main->session->body_in, &gpn_xml_attrs);
	if (fault_code != CWMP_OK) {
		err_msg = "Failed to load attributes from GPN request message";
		goto fault;
	}

	char *err = cwmp_get_parameter_names(parameter_name ? parameter_name : "", next_level, &parameters_list);
	if (err) {
		fault_code = cwmp_get_fault_code_by_string(err);
		FREE(parameter_name);
		goto fault;
	}
	FREE(parameter_name);

	if (cwmp_main->session->tree_out == NULL) {
		err_msg = "Output xml tree does not exist";
		goto fault;
	}

	n = build_top_body_soap_response(cwmp_main->session->tree_out, "GetParameterNames");

	if (!n) {
		fault_code = FAULT_CPE_INTERNAL_ERROR;
		err_msg = "Failed to populate the SOAP message for GPN response";
		goto fault;
	}


	LIST_HEAD(prameters_xml_list);
	dm_parameter_list_to_xml_data_list(&parameters_list, &prameters_xml_list);

	struct xml_data_struct gpv_resp_xml_attrs = {0};
	gpv_resp_xml_attrs.data_list = &prameters_xml_list;
	gpv_resp_xml_attrs.counter = &counter;
	gpv_resp_xml_attrs.inc_counter = true;
	char *xsi_type = "soap_enc:Array";
	char *soap_array_type = NULL;
	gpv_resp_xml_attrs.xsi_type = &xsi_type;
	gpv_resp_xml_attrs.soap_enc_array_type = &soap_array_type;
	gpv_resp_xml_attrs.rpc_enum = SOAP_RESP_GPN;

	fault_code = build_xml_node_data(SOAP_RESP_GPN, n, &gpv_resp_xml_attrs);
	cwmp_free_all_dm_parameter_list(&parameters_list);
	cwmp_free_all_xml_data_list(&prameters_xml_list);

	if (fault_code != CWMP_OK) {
		err_msg = "Failed to build the xml data nodes for GPN response message";
		goto fault;
	}

	return 0;

fault:
	cwmp_free_all_dm_parameter_list(&parameters_list);
	if (cwmp_create_fault_message(rpc, fault_code, err_msg))
		return -1;
	return 0;
}

/*
 * [RPC CPE]: GetParameterAttributes
 */
int cwmp_handle_rpc_cpe_get_parameter_attributes(struct rpc *rpc)
{
	mxml_node_t *n, *b;
	int counter = 0, fault_code = FAULT_CPE_INTERNAL_ERROR;
	char *err_msg = NULL;

	b = cwmp_main->session->body_in;

	n = build_top_body_soap_response(cwmp_main->session->tree_out, "GetParameterAttributes");
	if (!n) {
		err_msg = "Failed to build SOAP message for GetParameterAttributes response";
		goto fault;
	}

	LIST_HEAD(gpa_xml_data_list);


	struct xml_data_struct gpa_xml_attrs = {0};
	gpa_xml_attrs.data_list = &gpa_xml_data_list;
	struct xml_tag_validation gpa_validation[] = {{"string", VALIDATE_STR_SIZE, 0, 256}};
	gpa_xml_attrs.validations = gpa_validation;
	gpa_xml_attrs.nbre_validations = 1;

	int fault = load_xml_node_data(SOAP_REQ_GPA, b, &gpa_xml_attrs);
	if (fault) {
		fault_code = fault;
		err_msg = "Failed to load data from GetParameterAttributes request message";
		goto fault;
	}
	gpa_xml_attrs.rpc_enum = SOAP_GPA_STRUCT;
	gpa_xml_attrs.counter = &counter;
	gpa_xml_attrs.inc_counter = false;
	char *soap_array_type = NULL;
	char *xsi_type = "soap_enc:Array";
	gpa_xml_attrs.xsi_type = &xsi_type;
	gpa_xml_attrs.soap_enc_array_type = &soap_array_type;
	mxml_node_t *resp = n;
	fault_code = build_xml_node_data(SOAP_RESP_GET, resp, &gpa_xml_attrs);

	cwmp_free_all_xml_data_list(&gpa_xml_data_list);

	if (fault_code)
		goto fault;

	return 0;

fault:
	if (cwmp_create_fault_message(rpc, fault_code, err_msg))
		return -1;
	return 0;
}

/*
 * [RPC CPE]: SetParameterValues
 */
int is_duplicated_parameter(mxml_node_t *param_node)
{
	mxml_node_t *b = param_node;
	const char *node_name = param_node ? mxmlGetElement(param_node) : NULL;
	while ((b = mxmlWalkNext(b, cwmp_main->session->body_in, MXML_DESCEND))) {
		const char *node_opaque = mxmlGetOpaque(b);
		mxml_node_t *parent = mxmlGetParent(b);
		mxml_type_t node_type = mxmlGetType(b);
		const char *parent_name = parent ? mxmlGetElement(parent) : NULL;

		if (node_type == MXML_OPAQUE && node_opaque && mxmlGetType(parent) == MXML_ELEMENT && node_name && !CWMP_STRCMP(parent_name, "Name")) {
			if (strcmp(node_opaque, mxmlGetOpaque(param_node)) == 0)
				return -1;
		}
	}
	return 0;
}

int cwmp_handle_rpc_cpe_set_parameter_values(struct rpc *rpc)
{
	mxml_node_t *b = NULL;
	char *parameter_key = NULL;
	int fault_code = FAULT_CPE_INTERNAL_ERROR, ret = 0;
	char *err_msg = NULL;

	LIST_HEAD(xml_list_set_param_value);
	LIST_HEAD(list_set_param_value);
	LIST_HEAD(list_fault_param);

	rpc->list_set_value_fault = &list_fault_param;
	struct xml_tag_validation spv_validation[] = {{"ParameterKey", VALIDATE_STR_SIZE, 0, 32}, {"Name", VALIDATE_STR_SIZE, 0, 256}};
	struct xml_data_struct spv_xml_attrs = {0};
	spv_xml_attrs.parameter_key = &parameter_key;
	spv_xml_attrs.data_list = &xml_list_set_param_value;
	spv_xml_attrs.validations = spv_validation;
	spv_xml_attrs.nbre_validations = 2;

	fault_code = load_xml_node_data(SOAP_REQ_SPV, cwmp_main->session->body_in, &spv_xml_attrs);
	if (fault_code) {
		err_msg = "Failed to load attributes from SPV request message";
		goto fault;
	}

	xml_data_list_to_dm_parameter_list(&xml_list_set_param_value, &list_set_param_value);

	if (!cwmp_transaction("start")) {
		fault_code = FAULT_CPE_INTERNAL_ERROR;
		err_msg = "Failed to start new transaction";
		goto fault;
	}

	/* Before set check if exists Device.ManagementServer.InformParameter.{i}.ParameterName with ForcedInform Parameter */
	fault_code = validate_inform_parameter_name(&list_set_param_value);
	if (fault_code != FAULT_CPE_NO_FAULT) {
		err_msg = "Forced inform parameter can not be configured in Device.ManagementServer.InformParameter";
		goto fault;
	}

	fault_code = cwmp_set_multi_parameters_value(&list_set_param_value, rpc->list_set_value_fault);
	if (fault_code != FAULT_CPE_NO_FAULT)
		goto fault;

	set_rpc_parameter_key(parameter_key);
	FREE(parameter_key);

	struct cwmp_dm_parameter *param_value = NULL;
	list_for_each_entry (param_value, &list_set_param_value, list) {
		set_interface_reset_request(param_value->name, param_value->value);
		set_diagnostic_parameter_structure_value(param_value->name, param_value->value);
		set_diagnostic_state_end_session_flag(param_value->name, param_value->value);
	}

	cwmp_free_all_xml_data_list(&xml_list_set_param_value);
	cwmp_free_all_dm_parameter_list(&list_set_param_value);

	b = build_top_body_soap_response(cwmp_main->session->tree_out, "SetParameterValues");

	if (!b) {
		fault_code = FAULT_CPE_INTERNAL_ERROR;
		err_msg = "Failed to prepare SOAP response message of SPV request";
		goto fault;
	}

	int status = 1;

	struct xml_data_struct spv_resp_xml_attrs = {.status = &status};
	fault_code = build_xml_node_data(SOAP_RESP_SPV, b, &spv_resp_xml_attrs);
	if (fault_code) {
		err_msg = "Failed to build xml data nodes for SPV response message";
		goto fault;
	}

	if (!cwmp_transaction("commit")) {
		fault_code = FAULT_CPE_INTERNAL_ERROR;
		err_msg = "Failed to commit the transaction";
		goto fault;
	}

	cwmp_set_end_session(END_SESSION_RESTART_SERVICES | END_SESSION_SET_NOTIFICATION_UPDATE | END_SESSION_RELOAD);
	return 0;

fault:
	cwmp_free_all_dm_parameter_list(&list_set_param_value);
	if (cwmp_create_fault_message(rpc, fault_code, err_msg))
		ret = -1;

	cwmp_free_all_list_param_fault(rpc->list_set_value_fault);

	cwmp_transaction("abort");
	return ret;
}

/*
 * [RPC CPE]: SetParameterAttributes
 */
int cwmp_handle_rpc_cpe_set_parameter_attributes(struct rpc *rpc)
{
	mxml_node_t *n;
	int fault_code = FAULT_CPE_INTERNAL_ERROR, ret = 0;
	char c[256];
	char *err_msg = NULL;

	if (snprintf(c, sizeof(c), "%s:%s", ns.cwmp, "SetParameterAttributes") == -1) {
		err_msg = "Failed to write in buffer, string operation failure";
		goto fault;
	}

	n = mxmlFindElement(cwmp_main->session->tree_in, cwmp_main->session->tree_in, c, NULL, NULL, MXML_DESCEND);

	if (!n) {
		err_msg = "SetParameterAttributes element does not exist in xml input tree";
		goto fault;
	}

	LIST_HEAD(prameters_xml_list);
	struct xml_data_struct spa_xml_attrs = {0};
	spa_xml_attrs.data_list = &prameters_xml_list;
	struct xml_tag_validation spa_validation[] = {{"Name", VALIDATE_STR_SIZE, 0, 256}, {"NotificationChange", VALIDATE_BOOLEAN, 0, 0}, {"Notification", VALIDATE_INT_RANGE, 0, 6}};
	spa_xml_attrs.validations = spa_validation;
	spa_xml_attrs.nbre_validations = 3;

	fault_code = load_xml_node_data(SOAP_REQ_SPA, n, &spa_xml_attrs);
	if (fault_code) {
		err_msg = "Failed to load data from SetParameterAttributes request message";
		goto fault;
	}

	struct list_head *l = prameters_xml_list.next;
	struct xml_list_data *p = NULL;
	while (l != &prameters_xml_list) {
		p = list_entry(l, struct xml_list_data, list);
		if (p->param_name && p->notification_change) {
			char *err = cwmp_set_parameter_attributes(p->param_name, p->notification);
			if (err) {
				fault_code = cwmp_get_fault_code_by_string(err);
				goto fault;
			}
		}
		l = l->next;
	}
	cwmp_free_all_xml_data_list(&prameters_xml_list);

	mxml_node_t *resp = build_top_body_soap_response(cwmp_main->session->tree_out, "SetParameterAttributes");
	if (!resp) {
		err_msg = "Failed to populate SOAP response for SetParameterAttributes request";
		goto fault;
	}

	cwmp_set_end_session(END_SESSION_SET_NOTIFICATION_UPDATE | END_SESSION_RESTART_SERVICES | END_SESSION_INIT_NOTIFY);
	return 0;

fault:
	if (cwmp_create_fault_message(rpc, fault_code, err_msg))
		ret = -1;

	return ret;
}

/*
 * [RPC CPE]: AddObject
 */
int cwmp_handle_rpc_cpe_add_object(struct rpc *rpc)
{
	mxml_node_t *b = NULL;
	char *object_name = NULL;
	char *parameter_key = NULL;
	int fault_code = FAULT_CPE_INTERNAL_ERROR, ret = 0;
	struct object_result res = {0};
	char *err_msg = NULL;

	struct xml_data_struct add_obj_xml_attrs = {0};
	add_obj_xml_attrs.object_name = &object_name;
	add_obj_xml_attrs.parameter_key = &parameter_key;
	struct xml_tag_validation gpn_validation[] = {{"ParameterKey", VALIDATE_STR_SIZE, 0, 32}, {"ObjectName", VALIDATE_STR_SIZE, 0, 256}};
	add_obj_xml_attrs.validations = gpn_validation;
	add_obj_xml_attrs.nbre_validations = 2;

	fault_code = load_xml_node_data(SOAP_REQ_ADDOBJ, cwmp_main->session->body_in, &add_obj_xml_attrs);

	if (fault_code) {
		err_msg = "Failed to load data from AddObject request message";
		goto fault;
	}

	if (!cwmp_transaction("start")) {
		err_msg = "Failed to start new transaction";
		goto fault;
	}

	if (object_name) {
		bool err = cwmp_add_object(object_name, &res);
		if (!err) {
			fault_code = cwmp_get_fault_code(res.fault_code);
			err_msg = res.fault_msg;
			goto fault;
		}
	} else {
		fault_code = FAULT_CPE_INVALID_PARAMETER_NAME;
		err_msg = "No object name is found in AddObject request";
		goto fault;
	}

	set_rpc_parameter_key(parameter_key);

	if (res.instance == NULL) {
		err_msg = "No new instance number found after AddObject";
		goto fault;
	}

	b = build_top_body_soap_response(cwmp_main->session->tree_out, "AddObject");

	if (!b) {
		err_msg = "Failed to build SOAP message for AddObject response";
		goto fault;
	}

	struct xml_data_struct add_resp_xml_attrs = {0};
	int instance_int = atoi(res.instance);
	int status = 0;

	add_resp_xml_attrs.instance = &instance_int;
	add_resp_xml_attrs.status = &status;

	fault_code = build_xml_node_data(SOAP_RESP_ADDOBJ, b, &add_resp_xml_attrs);
	if (fault_code != CWMP_OK) {
		err_msg = "Failed to add xml data nodes in AddObject response message";
		goto fault;
	}

	if (!cwmp_transaction("commit")) {
		err_msg = "Failed to commit the transaction";
		goto fault;
	}

	char object_path[1024] = {0};
	snprintf(object_path, sizeof(object_path), "%s%s.", object_name, res.instance);
	cwmp_set_parameter_attributes(object_path, 0);
	FREE(object_name);
	FREE(parameter_key);
	FREE(res.instance);
	cwmp_set_end_session(END_SESSION_RESTART_SERVICES);
	return 0;

fault:
	FREE(object_name);
	FREE(parameter_key);
	FREE(res.instance);
	if (cwmp_create_fault_message(rpc, fault_code, err_msg))
		ret = -1;

	cwmp_transaction("abort");
	return ret;
}

/*
 * [RPC CPE]: DeleteObject
 */
int cwmp_handle_rpc_cpe_delete_object(struct rpc *rpc)
{
	mxml_node_t *b;
	char *object_name = NULL;
	char *parameter_key = NULL;
	int fault_code = FAULT_CPE_INTERNAL_ERROR, ret = 0;
	struct object_result res = {0};
	char *err_msg = NULL;

	struct xml_data_struct del_obj_xml_attrs = {0};
	del_obj_xml_attrs.object_name = &object_name;
	del_obj_xml_attrs.parameter_key = &parameter_key;
	struct xml_tag_validation gpn_validation[] = {{"ParameterKey", VALIDATE_STR_SIZE, 0, 32}, {"ObjectName", VALIDATE_STR_SIZE, 0, 256}};
	del_obj_xml_attrs.validations = gpn_validation;
	del_obj_xml_attrs.nbre_validations = 2;

	fault_code = load_xml_node_data(SOAP_REQ_DELOBJ, cwmp_main->session->body_in, &del_obj_xml_attrs);

	if (fault_code) {
		err_msg = "Failed to load data from DeleteObject request message";
		goto fault;
	}

	if (!cwmp_transaction("start")) {
		err_msg = "Failed to start new transaction";
		goto fault;
	}

	if (object_name) {
		bool err = cwmp_delete_object(object_name, &res);
		if (!err) {
			fault_code = cwmp_get_fault_code(res.fault_code);
			err_msg = res.fault_msg;
			goto fault;
		}
	} else {
		fault_code = FAULT_CPE_INVALID_PARAMETER_NAME;
		err_msg = "No object name found in DeleteObject request message";
		goto fault;
	}
	set_rpc_parameter_key(parameter_key);
	b = build_top_body_soap_response(cwmp_main->session->tree_out, "DeleteObject");

	if (!b) {
		fault_code = FAULT_CPE_INTERNAL_ERROR;
		err_msg = "Failed to build SOAP message for DeleteObject response";
		goto fault;
	}

	int status = 1;
	struct xml_data_struct add_resp_xml_attrs = {0};
	add_resp_xml_attrs.status = &status;

	fault_code = build_xml_node_data(SOAP_RESP_DELOBJ, b, &add_resp_xml_attrs);
	if (fault_code != CWMP_OK) {
		err_msg = "Failed to add xml data in DeleteObject response message";
		goto fault;
	}

	if (!cwmp_transaction("commit")) {
		fault_code = FAULT_CPE_INTERNAL_ERROR;
		err_msg = "Failed to commit the transaction";
		goto fault;
	}
	FREE(object_name);
	FREE(parameter_key);
	FREE(res.instance);
	cwmp_set_end_session(END_SESSION_RESTART_SERVICES);
	return 0;

fault:
	FREE(res.instance);
	FREE(object_name);
	FREE(parameter_key);
	if (cwmp_create_fault_message(rpc, fault_code, err_msg))
		ret = -1;

	cwmp_transaction("abort");
	return ret;
}

/*
 * [RPC CPE]: GetRPCMethods
 */
int cwmp_handle_rpc_cpe_get_rpc_methods(struct rpc *rpc)
{
	mxml_node_t *n;
	int i, counter = 0;
	int fault_code = FAULT_CPE_INTERNAL_ERROR;
	char *err_msg = NULL;

	n = build_top_body_soap_response(cwmp_main->session->tree_out, "GetRPCMethods");

	if (!n) {
		err_msg = "Failed to prepare SOAP response message for GetRPCMethods";
		goto fault;
	}


	LIST_HEAD(rpcs_list);

	for (i = 1; i < __RPC_CPE_MAX; i++) {
		if (i != RPC_CPE_FAULT) {
			struct xml_list_data *xml_data = calloc(1, sizeof(struct xml_list_data));
			xml_data->rpc_name = CWMP_STRDUP(rpc_cpe_methods[i].name);
			list_add(&(xml_data->list), &rpcs_list);
			counter++;
		}
	}

	struct xml_data_struct getrpc_resp_xml_attrs = {0};
	getrpc_resp_xml_attrs.data_list = &rpcs_list;
	getrpc_resp_xml_attrs.counter = &counter;
	getrpc_resp_xml_attrs.inc_counter = false;
	char *xsi_type = "soap_enc:Array";
	char *soap_array_type = NULL;
	getrpc_resp_xml_attrs.xsi_type = &xsi_type;
	getrpc_resp_xml_attrs.soap_enc_array_type = &soap_array_type;
	getrpc_resp_xml_attrs.rpc_enum = SOAP_RESP_GETRPC;

	fault_code = build_xml_node_data(SOAP_RESP_GETRPC, n, &getrpc_resp_xml_attrs);
	cwmp_free_all_xml_data_list(&rpcs_list);

	if (fault_code != CWMP_OK) {
		err_msg = "Failed to build xml data nodes for GetRPCMethods response";
		goto fault;
	}

	return 0;

fault:
	if (cwmp_create_fault_message(rpc, fault_code, err_msg))
		return -1;
	return 0;

}

/*
 * [RPC CPE]: FactoryReset
 */
int cwmp_handle_rpc_cpe_factory_reset(struct rpc *rpc)
{
	mxml_node_t *b;
	char *err_msg = NULL;

	b = build_top_body_soap_response(cwmp_main->session->tree_out, "FactoryReset");

	if (!b) {
		err_msg = "Failed to build SOAP message for FactoryReset response";
		goto fault;
	}

	cwmp_set_end_session(END_SESSION_FACTORY_RESET);

	return 0;

fault:
	if (cwmp_create_fault_message(rpc, FAULT_CPE_INTERNAL_ERROR, err_msg))
		goto error;
	return 0;

error:
	return -1;
}

/*
 * [RPC CPE]: X_FactoryResetSoft
 */
int cwmp_handle_rpc_cpe_x_factory_reset_soft(struct rpc *rpc)
{
	mxml_node_t *b;

	b = build_top_body_soap_response(cwmp_main->session->tree_out, "X_FactoryResetSoft");

	if (!b)
		goto fault;

	cwmp_set_end_session(END_SESSION_X_FACTORY_RESET_SOFT);

	return 0;

fault:
	if (cwmp_create_fault_message(rpc, FAULT_CPE_INTERNAL_ERROR, ""))
		goto error;
	return 0;

error:
	return -1;
}

/*
 * [RPC CPE]: CancelTransfer
 */
int cwmp_handle_rpc_cpe_cancel_transfer(struct rpc *rpc)
{
	mxml_node_t *b;
	char *command_key = NULL;
	int fault_code = FAULT_CPE_INTERNAL_ERROR;
	char *err_msg = NULL;

	b = cwmp_main->session->body_in;

	struct xml_data_struct canceltrancer_obj_xml_attrs = {0};
	canceltrancer_obj_xml_attrs.command_key = &command_key;
	struct xml_tag_validation canceltransfer_validation[] = {{"CommandKey", VALIDATE_STR_SIZE, 0, 32}};
	canceltrancer_obj_xml_attrs.validations = canceltransfer_validation;
	canceltrancer_obj_xml_attrs.nbre_validations = 1;

	fault_code = load_xml_node_data(SOAP_REQ_CANCELTRANSFER, cwmp_main->session->body_in, &canceltrancer_obj_xml_attrs);

	if (command_key)
		cancel_transfer(command_key);

	if (fault_code) {
		err_msg = "Failed to load data from CancelTransfer request message";
		goto fault;
	}

	b = build_top_body_soap_response(cwmp_main->session->tree_out, "CancelTransfer");

	if (!b) {
		fault_code = FAULT_CPE_INTERNAL_ERROR;
		err_msg = "Failed to build the SOAP message from CancelTransfer response";
		goto fault;
	}
	FREE(command_key);
	return 0;

fault:
	FREE(command_key);
	if (cwmp_create_fault_message(rpc, fault_code, err_msg))
		goto error;
	return 0;

error:
	return -1;
}

int cancel_transfer(char *key)
{
	struct list_head *ilist, *q;

	if (list_download.next != &(list_download)) {
		list_for_each_safe (ilist, q, &(list_download)) {
			struct download *pdownload = list_entry(ilist, struct download, list);
			if (CWMP_STRCMP(pdownload->command_key, key) == 0) {
				bkp_session_delete_element("download", pdownload->id);
				bkp_session_save();
				list_del(&(pdownload->list));
				if (pdownload->scheduled_time != 0)
					count_download_queue--;
				cwmp_free_download_request(pdownload);
			}
		}
	}
	if (list_upload.next != &(list_upload)) {
		list_for_each_safe (ilist, q, &(list_upload)) {
			struct upload *pupload = list_entry(ilist, struct upload, list);
			if (CWMP_STRCMP(pupload->command_key, key) == 0) {
				bkp_session_delete_element("upload", pupload->id);
				bkp_session_save();
				list_del(&(pupload->list));
				if (pupload->scheduled_time != 0)
					count_upload_queue--;
				cwmp_free_upload_request(pupload);
			}
		}
	}
	// Cancel schedule download
	return CWMP_OK;
}

/*
 * [RPC CPE]: Reboot
 */
int cwmp_handle_rpc_cpe_reboot(struct rpc *rpc)
{
	mxml_node_t *b;
	struct event_container *event_container;
	char *command_key = NULL;
	int fault_code = FAULT_CPE_INTERNAL_ERROR;
	b = cwmp_main->session->body_in;
	char *err_msg = NULL;

	struct xml_data_struct reboot_obj_xml_attrs = {0};
	reboot_obj_xml_attrs.command_key = &command_key;
	struct xml_tag_validation reboot_validation[] = {{"CommandKey", VALIDATE_STR_SIZE, 0, 32}};
	reboot_obj_xml_attrs.validations = reboot_validation;
	reboot_obj_xml_attrs.nbre_validations = 1;

	fault_code = load_xml_node_data(SOAP_REQ_REBOOT, cwmp_main->session->body_in, &reboot_obj_xml_attrs);

	if (fault_code) {
		err_msg = "Failed to load data from reboot request";
		goto fault;
	}

	commandKey = icwmp_strdup(command_key ? command_key : "");

	event_container = cwmp_add_event_container(EVENT_IDX_M_Reboot, command_key ? command_key : "");
	if (event_container == NULL) {
		err_msg = "Reboot failed due to memory allocation failure";
		goto fault;
	}

	cwmp_save_event_container(event_container);

	b = build_top_body_soap_response(cwmp_main->session->tree_out, "Reboot");

	if (!b) {
		err_msg = "Failed to build the SOAP message for reboot response";
		goto fault;
	}

	cwmp_set_end_session(END_SESSION_REBOOT);

	FREE(command_key);
	return 0;

fault:
	FREE(command_key);
	if (cwmp_create_fault_message(rpc, fault_code, err_msg))
		goto error;
	return 0;

error:
	return -1;
}

/*
 * [RPC CPE]: ScheduleInform
 */
int cwmp_handle_rpc_cpe_schedule_inform(struct rpc *rpc)
{
	mxml_node_t *n;
	char *command_key = NULL;
	struct schedule_inform *schedule_inform;
	time_t scheduled_time;
	struct list_head *ilist;
	int fault = FAULT_CPE_NO_FAULT;
	int delay_seconds = 0;
	char err_msg[256] = {0};


	struct xml_data_struct schedinform_obj_xml_attrs = {0};
	schedinform_obj_xml_attrs.command_key = &command_key;
	schedinform_obj_xml_attrs.delay_seconds = (long int*)&delay_seconds;
	struct xml_tag_validation schedinform_validation[] = {{"CommandKey", VALIDATE_STR_SIZE, 0, 32}, {"DelaySeconds", VALIDATE_UNINT, 0, 0}};
	schedinform_obj_xml_attrs.validations = schedinform_validation;
	schedinform_obj_xml_attrs.nbre_validations = 2;

	fault = load_xml_node_data(SOAP_REQ_SCHEDINF, cwmp_main->session->body_in, &schedinform_obj_xml_attrs);

	if (fault) {
		snprintf(err_msg, sizeof(err_msg), "Failed to load data from ScheduleInform request message");
		goto fault;
	}

	if (count_schedule_inform_queue >= MAX_SCHEDULE_INFORM_QUEUE) {
		fault = FAULT_CPE_RESOURCES_EXCEEDED;
		snprintf(err_msg, sizeof(err_msg), "ScheduleInform queue is full, Max queue size (%d) and current request count (%d)", MAX_SCHEDULE_INFORM_QUEUE, count_schedule_inform_queue+1);
		goto fault;
	}
	count_schedule_inform_queue++;

	scheduled_time = time(NULL) + delay_seconds;
	list_for_each (ilist, &(list_schedule_inform)) {
		schedule_inform = list_entry(ilist, struct schedule_inform, list);
		if (schedule_inform->scheduled_time >= scheduled_time) {
			break;
		}
	}

	n = build_top_body_soap_response(cwmp_main->session->tree_out, "ScheduleInform");

	if (!n) {
		snprintf(err_msg, sizeof(err_msg), "Failed to build SOAP message for ScheduleInform response");
		goto fault;
	}

	CWMP_LOG(INFO, "Schedule inform event will start in %us", delay_seconds);
	schedule_inform = calloc(1, sizeof(struct schedule_inform));
	if (schedule_inform == NULL) {
		snprintf(err_msg, sizeof(err_msg), "Memory allocation failed of %zu bytes", sizeof(struct schedule_inform));
		goto fault;
	}

	schedule_inform->handler_timer.cb = cwmp_start_schedule_inform;
	schedule_inform->commandKey = CWMP_STRDUP(command_key);
	schedule_inform->scheduled_time = scheduled_time;
	if ((cwmp_main->sched_inform_id < 0) || (cwmp_main->sched_inform_id >= MAX_INT_ID)) {
		cwmp_main->sched_inform_id = 0;
	}
	cwmp_main->sched_inform_id++;
	schedule_inform->id = cwmp_main->sched_inform_id;
	list_add(&(schedule_inform->list), ilist->prev);
	bkp_session_insert_schedule_inform(schedule_inform->id, schedule_inform->scheduled_time, schedule_inform->commandKey);
	bkp_session_save();

	FREE(command_key);
	cwmp_set_end_session(END_SESSION_SCHEDULE_INFORM);
	return 0;

fault:
	FREE(command_key);
	if (cwmp_create_fault_message(rpc, fault, err_msg))
		return -1;

	return 0;
}

/*
 * [RPC CPE]: ChangeDuState
 */
int cwmp_handle_rpc_cpe_change_du_state(struct rpc *rpc)
{
	mxml_node_t *n, *t;
	struct change_du_state *change_du_state = NULL;
	int error = FAULT_CPE_NO_FAULT;
	char c[256];
	char err_msg[256] = {0};

	if (snprintf(c, sizeof(c), "%s:%s", ns.cwmp, "ChangeDUState") == -1) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Failed to write in buffer, string operation failed");
		goto fault;
	}

	n = mxmlFindElement(cwmp_main->session->tree_in, cwmp_main->session->tree_in, c, NULL, NULL, MXML_DESCEND);
	if (!n) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "ChangeDUState element does not exist in input xml tree");
		goto fault;
	}

	change_du_state = calloc(1, sizeof(struct change_du_state));
	if (change_du_state == NULL) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Memory allocation failed of %zu bytes", sizeof(struct change_du_state));
		goto fault;
	}

	INIT_LIST_HEAD(&(change_du_state->list_operation));
	change_du_state->timeout = time(NULL);

	LIST_HEAD(xml_list_operations);
	struct xml_data_struct cdu_xml_attrs = {0};
	cdu_xml_attrs.command_key = &change_du_state->command_key;
	cdu_xml_attrs.data_list = &xml_list_operations;
	struct xml_tag_validation cdu_validation[] = {{"CommandKey", VALIDATE_STR_SIZE, 0, 32}, {"URL", VALIDATE_STR_SIZE, 0, 1024}, {"UUID", VALIDATE_STR_SIZE, 0, 36}, {"Username", VALIDATE_STR_SIZE, 0, 256}, {"Password", VALIDATE_STR_SIZE, 0, 256}, {"ExecutionEnvRef", VALIDATE_STR_SIZE, 0, 256}, {"Version", VALIDATE_STR_SIZE, 0, 32}};
	cdu_xml_attrs.validations = cdu_validation;
	cdu_xml_attrs.nbre_validations = 7;

	error = load_xml_node_data(SOAP_REQ_CDU, n, &cdu_xml_attrs);

	if (error) {
		snprintf(err_msg, sizeof(err_msg), "Failed to load data from ChangeDUState request message");
		goto fault;
	}

	xml_data_list_to_cdu_operations_list(&xml_list_operations, &change_du_state->list_operation);

	t = build_top_body_soap_response(cwmp_main->session->tree_out, "ChangeDUState");

	if (!t) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Failed to build ChangeDUState response SOAP message");
		goto fault;
	}


	change_du_state->handler_timer.cb = change_du_state_execute;
	list_add_tail(&(change_du_state->list), &(list_change_du_state));
	if ((cwmp_main->cdu_id < 0) || (cwmp_main->cdu_id >= MAX_INT_ID)) {
		cwmp_main->cdu_id = 0;
	}
	cwmp_main->cdu_id++;
	change_du_state->id = cwmp_main->cdu_id;
	bkp_session_insert_change_du_state(change_du_state);
	bkp_session_save();
	cwmp_set_end_session(END_SESSION_CDU);
	return 0;

fault:
	cwmp_free_change_du_state_request(change_du_state);
	if (cwmp_create_fault_message(rpc, error, err_msg))
		goto error;
	return 0;

error:
	return -1;
}

/*
 * [RPC CPE]: Download
 */
int cwmp_handle_rpc_cpe_download(struct rpc *rpc)
{
	mxml_node_t *n;
	char c[256];
	int error = FAULT_CPE_NO_FAULT;
	struct download *download = NULL, *idownload;
	struct list_head *ilist;
	time_t scheduled_time = 0;
	time_t download_delay = 0;
	char err_msg[256] = {0};

	if (snprintf(c, sizeof(c), "%s:%s", ns.cwmp, "Download") == -1) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Failure in buffer writting, string operation failed");
		goto fault;
	}

	n = mxmlFindElement(cwmp_main->session->tree_in, cwmp_main->session->tree_in, c, NULL, NULL, MXML_DESCEND);

	if (!n) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Download element not present in xml input tree");
		goto fault;
	}

	download = calloc(1, sizeof(struct download));
	if (download == NULL) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Memory outage, failed to allocate %zu bytes memory space", sizeof(struct download));
		goto fault;
	}

	struct xml_data_struct download_xml_attrs = {0};
	download_xml_attrs.command_key = &download->command_key;
	download_xml_attrs.url = &download->url;
	download_xml_attrs.username = &download->username;
	download_xml_attrs.password = &download->password;
	download_xml_attrs.delay_seconds = (long int*)&download_delay;
	download_xml_attrs.file_type = &download->file_type;
	download_xml_attrs.file_size = &download->file_size;

	struct xml_tag_validation download_validation[] = {{"CommandKey", VALIDATE_STR_SIZE, 0, 32}, {"FileType", VALIDATE_STR_SIZE, 0, 64}, {"URL", VALIDATE_STR_SIZE, 0, 256}, {"Username", VALIDATE_STR_SIZE, 0, 256}, {"Password", VALIDATE_STR_SIZE, 0, 256}, {"FileSize", VALIDATE_UNINT, 0, 0}, {"DelaySeconds", VALIDATE_UNINT, 0, 0}};
	download_xml_attrs.validations = download_validation;
	download_xml_attrs.nbre_validations = 7;

	error = load_xml_node_data(SOAP_REQ_DOWNLOAD, n, &download_xml_attrs);

	if (error) {
		snprintf(err_msg, sizeof(err_msg), "Failed to load download request attributes from SOAP message");
		goto fault;
	}

	if (CWMP_STRCMP(download->file_type, FIRMWARE_UPGRADE_IMAGE_FILE_TYPE) && CWMP_STRCMP(download->file_type, WEB_CONTENT_FILE_TYPE) && CWMP_STRCMP(download->file_type, VENDOR_CONFIG_FILE_TYPE) && CWMP_STRCMP(download->file_type, TONE_FILE_TYPE) && CWMP_STRCMP(download->file_type, RINGER_FILE_TYPE) && CWMP_STRCMP(download->file_type, STORED_FIRMWARE_IMAGE_FILE_TYPE)) {
		error = FAULT_CPE_INVALID_ARGUMENTS;
		snprintf(err_msg, sizeof(err_msg), "(%s) is an invalid file type in download request", download->file_type ? download->file_type : "");
	} else if (count_download_queue >= MAX_DOWNLOAD_QUEUE) {
		error = FAULT_CPE_RESOURCES_EXCEEDED;
		snprintf(err_msg, sizeof(err_msg), "Download queue is full, queue size: %d, current request count: %d", MAX_DOWNLOAD_QUEUE, count_download_queue+1);
	} else if (CWMP_STRLEN(download->url) == 0) {
		error = FAULT_CPE_REQUEST_DENIED;
		snprintf(err_msg, sizeof(err_msg), "URL is empty in download request");
	} else if (CWMP_STRSTR(download->url, "@") != NULL) {
		error = FAULT_CPE_INVALID_ARGUMENTS;
		snprintf(err_msg, sizeof(err_msg), "User credential is present in URL: (%s)", download->url);
	} else if (CWMP_STRNCMP(download->url, DOWNLOAD_PROTOCOL_HTTP, strlen(DOWNLOAD_PROTOCOL_HTTP)) != 0 && CWMP_STRNCMP(download->url, DOWNLOAD_PROTOCOL_HTTPS, strlen(DOWNLOAD_PROTOCOL_HTTPS)) != 0 && CWMP_STRNCMP(download->url, DOWNLOAD_PROTOCOL_FTP, strlen(DOWNLOAD_PROTOCOL_FTP)) != 0) {
		error = FAULT_CPE_FILE_TRANSFER_UNSUPPORTED_PROTOCOL;
		snprintf(err_msg, sizeof(err_msg), "Requested protocol (%s) is not supported", download->url);
	}
	if (error != FAULT_CPE_NO_FAULT)
		goto fault;

	mxml_node_t *t = build_top_body_soap_response(cwmp_main->session->tree_out, "Download");
	if (!t) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Failed to populate download response SOAP message");
		goto fault;
	}

	char *start_time = "0001-01-01T00:00:00+00:00";
	char *complete_time = "0001-01-01T00:00:00+00:00";
	int status = 1;

	struct xml_data_struct download_resp_xml_attrs = {0};
	download_resp_xml_attrs.status = &status;
	download_resp_xml_attrs.start_time = &start_time;
	download_resp_xml_attrs.complete_time = &complete_time;
	error = build_xml_node_data(SOAP_RESP_DOWNLOAD, t, &download_resp_xml_attrs);
	if (error != CWMP_OK) {
		snprintf(err_msg, sizeof(err_msg), "Failed to create xml data nodes in download response SOAP message");
		goto fault;
	}

	if (error == FAULT_CPE_NO_FAULT) {
		if (download_delay != 0)
			scheduled_time = time(NULL) + download_delay + PROCESSING_DELAY;

		list_for_each (ilist, &(list_download)) {
			idownload = list_entry(ilist, struct download, list);
			if (idownload->scheduled_time >= scheduled_time) {
				break;
			}
		}
		list_add(&(download->list), ilist->prev);
		if (download_delay != 0) {
			count_download_queue++;
			download->scheduled_time = scheduled_time;
		}
		download->handler_timer.cb = cwmp_start_download;
		if ((cwmp_main->download_id < 0) || (cwmp_main->download_id >= MAX_INT_ID)) {
			cwmp_main->download_id = 0;
		}
		cwmp_main->download_id++;
		download->id = cwmp_main->download_id;
		bkp_session_insert_download(download);
		bkp_session_save();
		if (download_delay != 0) {
			CWMP_LOG(INFO, "Download will start in %us", download_delay);
		} else {
			CWMP_LOG(INFO, "Download will start at the end of session");
		}
		cwmp_set_end_session(END_SESSION_DOWNLOAD);
	}

	return 0;

fault:
	cwmp_free_download_request(download);
	if (cwmp_create_fault_message(rpc, error, err_msg))
		return -1;
	return 0;
}

/*
 * [RPC CPE]: ScheduleDownload
 */
int cwmp_handle_rpc_cpe_schedule_download(struct rpc *rpc)
{
	mxml_node_t *n, *t;
	char c[256];
	int i = 0, j = 0;
	int error = FAULT_CPE_NO_FAULT;
	struct download *schedule_download = NULL;
	long int schedule_download_delay[4] = { 0, 0, 0, 0 };
	char err_msg[256] = {0};

	if (snprintf(c, sizeof(c), "%s:%s", ns.cwmp, "ScheduleDownload") == -1) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Failure in buffer writting, string operation failed");
		goto fault;
	}

	n = mxmlFindElement(cwmp_main->session->tree_in, cwmp_main->session->tree_in, c, NULL, NULL, MXML_DESCEND);

	if (!n) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "ScheduleDownload element does not exist in input xml tree");
		goto fault;
	}

	schedule_download = calloc(1, sizeof(struct download));
	if (schedule_download == NULL) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Memory allocation failed of %zu bytes", sizeof(struct download));
		goto fault;
	}

	struct xml_data_struct sched_download_xml_attrs = {0};
	sched_download_xml_attrs.command_key = &schedule_download->command_key;
	sched_download_xml_attrs.url = &schedule_download->url;
	sched_download_xml_attrs.username = &schedule_download->username;
	sched_download_xml_attrs.password = &schedule_download->password;
	sched_download_xml_attrs.file_type = &schedule_download->file_type;
	sched_download_xml_attrs.file_size = &schedule_download->file_size;

	struct xml_tag_validation scheddownload_validation[] = {{"CommandKey", VALIDATE_STR_SIZE, 0, 32}, {"FileType", VALIDATE_STR_SIZE, 0, 64}, {"URL", VALIDATE_STR_SIZE, 0, 256}, {"Username", VALIDATE_STR_SIZE, 0, 256}, {"Password", VALIDATE_STR_SIZE, 0, 256}, {"FileSize", VALIDATE_UNINT, 0, 0}};
	sched_download_xml_attrs.validations = scheddownload_validation;
	sched_download_xml_attrs.nbre_validations = 6;

	LIST_HEAD(time_window_intervals);
	sched_download_xml_attrs.data_list = &time_window_intervals;

	error = load_xml_node_data(SOAP_REQ_SCHEDDOWN, n, &sched_download_xml_attrs);

	if (error) {
		snprintf(err_msg, sizeof(err_msg), "Failed to load data from ScheduleDownload request message");
		goto fault;
	}

	struct xml_list_data *list_data = NULL;
	if (time_window_intervals.next) {
		i++;
		list_data = container_of(time_window_intervals.next, struct xml_list_data, list);
		schedule_download->timewindowstruct[0].windowmode = list_data->windowmode;
		schedule_download->timewindowstruct[0].usermessage = list_data->usermessage;
		schedule_download->timewindowstruct[0].maxretries = list_data->max_retries;
		schedule_download_delay[0] = list_data->windowstart;
		schedule_download_delay[1] = list_data->windowend;
		if (time_window_intervals.next->next) {
			i++;
			list_data = container_of(time_window_intervals.next->next, struct xml_list_data, list);
			schedule_download->timewindowstruct[1].windowmode = list_data->windowmode;
			schedule_download->timewindowstruct[1].usermessage = list_data->usermessage;
			schedule_download->timewindowstruct[1].maxretries = list_data->max_retries;
			schedule_download_delay[2] = list_data->windowstart;
			schedule_download_delay[3] = list_data->windowend;
		}
	}

	if (CWMP_STRCMP(schedule_download->file_type, FIRMWARE_UPGRADE_IMAGE_FILE_TYPE) && CWMP_STRCMP(schedule_download->file_type, WEB_CONTENT_FILE_TYPE) && CWMP_STRCMP(schedule_download->file_type, VENDOR_CONFIG_FILE_TYPE) && CWMP_STRCMP(schedule_download->file_type, TONE_FILE_TYPE) && CWMP_STRCMP(schedule_download->file_type, RINGER_FILE_TYPE) && CWMP_STRCMP(schedule_download->file_type, STORED_FIRMWARE_IMAGE_FILE_TYPE)) {
		error = FAULT_CPE_INVALID_ARGUMENTS;
		snprintf(err_msg, sizeof(err_msg), "Invalid file type: (%s)", schedule_download->file_type ? schedule_download->file_type : "");
	} else if ((CWMP_STRCMP(schedule_download->timewindowstruct[0].windowmode, "1 At Any Time") && CWMP_STRCMP(schedule_download->timewindowstruct[0].windowmode, "2 Immediately") && CWMP_STRCMP(schedule_download->timewindowstruct[0].windowmode, "3 When Idle")) || (CWMP_STRCMP(schedule_download->timewindowstruct[1].windowmode, "1 At Any Time") && CWMP_STRCMP(schedule_download->timewindowstruct[1].windowmode, "2 Immediately") && CWMP_STRCMP(schedule_download->timewindowstruct[1].windowmode, "3 When Idle"))) {
		error = FAULT_CPE_REQUEST_DENIED;
		snprintf(err_msg, sizeof(err_msg), "Invalid window mode => TimeWindowStruct[1].WindowMode (%s), TimeWindowStruct[2].WindowMode (%s)",
			schedule_download->timewindowstruct[0].windowmode ? schedule_download->timewindowstruct[0].windowmode : "",
			schedule_download->timewindowstruct[1].windowmode ? schedule_download->timewindowstruct[1].windowmode : "");
	} else if (count_download_queue >= MAX_DOWNLOAD_QUEUE) {
		error = FAULT_CPE_RESOURCES_EXCEEDED;
		snprintf(err_msg, sizeof(err_msg), "Download queue is full, Queue size: %d and current request count: %d",
			MAX_DOWNLOAD_QUEUE, count_download_queue+1);
	} else if (CWMP_STRLEN(schedule_download->url) == 0) {
		error = FAULT_CPE_REQUEST_DENIED;
		snprintf(err_msg, sizeof(err_msg), "No url found in ScheduleDownload request message");
	} else if (CWMP_STRSTR(schedule_download->url, "@") != NULL) {
		error = FAULT_CPE_INVALID_ARGUMENTS;
		snprintf(err_msg, sizeof(err_msg), "URL (%s) contains user credentials", schedule_download->url);
	} else if (CWMP_STRNCMP(schedule_download->url, DOWNLOAD_PROTOCOL_HTTP, strlen(DOWNLOAD_PROTOCOL_HTTP)) != 0 && CWMP_STRNCMP(schedule_download->url, DOWNLOAD_PROTOCOL_FTP, strlen(DOWNLOAD_PROTOCOL_FTP)) != 0) {
		error = FAULT_CPE_FILE_TRANSFER_UNSUPPORTED_PROTOCOL;
		snprintf(err_msg, sizeof(err_msg), "Invalid file type: (%s)", schedule_download->url);
	} else {
		for (j = 0; j < 3; j++) {
			if (schedule_download_delay[j] > schedule_download_delay[j + 1]) {
				error = FAULT_CPE_INVALID_ARGUMENTS;
				snprintf(err_msg, sizeof(err_msg), "Invalid window start-end=> TimeWindowStruct[1].WindowStart (%ld), \
					TimeWindowStruct[1].WindowEnd (%ld), TimeWindowStruct[2].WindowStart (%ld), \
					TimeWindowStruct[2].WindowEnd (%ld)", schedule_download_delay[0], schedule_download_delay[1],
					schedule_download_delay[2], schedule_download_delay[3]);
				break;
			}
		}
	}

	if (error != FAULT_CPE_NO_FAULT)
		goto fault;

	t = build_top_body_soap_response(cwmp_main->session->tree_out, "ScheduleDownload");

	if (!t) {
		error = FAULT_CPE_INTERNAL_ERROR;
		goto fault;
	}

	list_add_tail(&(schedule_download->list), &(list_schedule_download));
	if (schedule_download_delay[0] != 0) {
		count_download_queue++;
	}
	while (i > 0) {
		i--;
		schedule_download->timewindowstruct[i].windowstart = time(NULL) + schedule_download_delay[i * 2];
		schedule_download->timewindowstruct[i].windowend = time(NULL) + schedule_download_delay[i * 2 + 1];
	}
	schedule_download->handler_timer.cb = cwmp_start_schedule_download;
	if ((cwmp_main->sched_download_id < 0) || (cwmp_main->sched_download_id >= MAX_INT_ID)) {
		cwmp_main->sched_download_id = 0;
	}
	cwmp_main->sched_download_id++;
	schedule_download->id = cwmp_main->sched_download_id;
	bkp_session_insert_schedule_download(schedule_download);
	bkp_session_save();
	if (schedule_download_delay[0] != 0) {
		CWMP_LOG(INFO, "Schedule download will start in %us", schedule_download_delay[0]);
	} else {
		CWMP_LOG(INFO, "Schedule Download will start at the end of session");
	}
	time_t now = time(NULL);
	if ((schedule_download->timewindowstruct[0].windowstart < now) ||(schedule_download->timewindowstruct[0].windowend < now && (now < schedule_download->timewindowstruct[1].windowstart || schedule_download->timewindowstruct[1].windowend < now) )) {
		error = FAULT_CPE_INTERNAL_ERROR;
		goto fault;
	}
	cwmp_set_end_session(END_SESSION_SCHEDULE_DOWNLOAD);
	return 0;

fault:
	cwmp_free_schedule_download_request(schedule_download);
	if (cwmp_create_fault_message(rpc, error, err_msg))
		goto error;
	return 0;

error:
	return -1;
}

/*
 * [RPC CPE]: Upload
 */
int cwmp_handle_rpc_cpe_upload(struct rpc *rpc)
{
	mxml_node_t *n;
	int error = FAULT_CPE_NO_FAULT;
	struct upload *upload = NULL, *iupload;
	struct list_head *ilist;
	time_t scheduled_time = 0;
	time_t upload_delay = 0;
	char c[256];
	char err_msg[256] = {0};

	if (snprintf(c, sizeof(c), "%s:%s", ns.cwmp, "Upload") == -1) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Failed to write on buffer, string operation failure");
		goto fault;
	}

	n = mxmlFindElement(cwmp_main->session->tree_in, cwmp_main->session->tree_in, c, NULL, NULL, MXML_DESCEND);

	if (!n) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Upload element does not exist in input xml tree");
		goto fault;
	}

	upload = calloc(1, sizeof(struct upload));
	if (upload == NULL) {
		error = FAULT_CPE_INTERNAL_ERROR;
		snprintf(err_msg, sizeof(err_msg), "Memory allocation failed of %zu bytes", sizeof(struct upload));
		goto fault;
	}
	upload->f_instance = 0;

	struct xml_data_struct upload_xml_attrs = {0};
	upload_xml_attrs.command_key = &upload->command_key;
	upload_xml_attrs.url = &upload->url;
	upload_xml_attrs.username = &upload->username;
	upload_xml_attrs.password = &upload->password;
	upload_xml_attrs.delay_seconds = (long int*)&upload_delay;
	upload_xml_attrs.file_type = &upload->file_type;
	upload_xml_attrs.instance = &upload->f_instance;


	struct xml_tag_validation upload_validation[] = {{"CommandKey", VALIDATE_STR_SIZE, 0, 32}, {"FileType", VALIDATE_STR_SIZE, 0, 64}, {"URL", VALIDATE_STR_SIZE, 0, 256}, {"Username", VALIDATE_STR_SIZE, 0, 256}, {"Password", VALIDATE_STR_SIZE, 0, 256}, {"DelaySeconds", VALIDATE_UNINT, 0, 0}};
	upload_xml_attrs.validations = upload_validation;
	upload_xml_attrs.nbre_validations = 6;

	error = load_xml_node_data(SOAP_REQ_UPLOAD, n, &upload_xml_attrs);

	if (error) {
		snprintf(err_msg, sizeof(err_msg), "Failed to load data from upload request message");
		goto fault;
	}

	if (count_upload_queue >= MAX_UPLOAD_QUEUE) {
		error = FAULT_CPE_RESOURCES_EXCEEDED;
		snprintf(err_msg, sizeof(err_msg), "Maximum queue limit %d exceeded, current request number: %d", MAX_UPLOAD_QUEUE, count_upload_queue+1);
	} else if (CWMP_STRLEN(upload->url) == 0) {
		error = FAULT_CPE_REQUEST_DENIED;
		snprintf(err_msg, sizeof(err_msg), "No url found in upload request");
	} else if (CWMP_STRSTR(upload->url, "@") != NULL) {
		error = FAULT_CPE_INVALID_ARGUMENTS;
		snprintf(err_msg, sizeof(err_msg), "Request ignored due to user credential exist in upload url (%s)", upload->url);
	} else if (CWMP_STRNCMP(upload->url, DOWNLOAD_PROTOCOL_HTTPS, strlen(DOWNLOAD_PROTOCOL_HTTPS)) != 0  && CWMP_STRNCMP(upload->url, DOWNLOAD_PROTOCOL_HTTP, strlen(DOWNLOAD_PROTOCOL_HTTP)) != 0 && CWMP_STRNCMP(upload->url, DOWNLOAD_PROTOCOL_FTP, strlen(DOWNLOAD_PROTOCOL_FTP)) != 0) {
		error = FAULT_CPE_FILE_TRANSFER_UNSUPPORTED_PROTOCOL;
		snprintf(err_msg, sizeof(err_msg), "Requested protocol is not supported (%s)", upload->url);
	}

	if (error != FAULT_CPE_NO_FAULT)
		goto fault;

	mxml_node_t *t = build_top_body_soap_response(cwmp_main->session->tree_out, "Upload");
	if (t == NULL) {
		snprintf(err_msg, sizeof(err_msg), "Failed to build SOAP message for upload response");
		error = FAULT_CPE_INTERNAL_ERROR;
		goto fault;
	}

	char *start_time = "0001-01-01T00:00:00+00:00";
	char *complete_time = "0001-01-01T00:00:00+00:00";
	int status = 1;

	struct xml_data_struct upload_resp_xml_attrs = {0};
	upload_resp_xml_attrs.status = &status;
	upload_resp_xml_attrs.start_time = &start_time;
	upload_resp_xml_attrs.complete_time = &complete_time;
	error = build_xml_node_data(SOAP_RESP_UPLOAD, t, &upload_resp_xml_attrs);
	if (error != CWMP_OK) {
		snprintf(err_msg, sizeof(err_msg), "Failed to add xml node in upload response message");
		goto fault;
	}

	if (error == FAULT_CPE_NO_FAULT) {
		if (upload_delay != 0)
			scheduled_time = time(NULL) + upload_delay + PROCESSING_DELAY;

		list_for_each (ilist, &(list_upload)) {
			iupload = list_entry(ilist, struct upload, list);
			if (iupload->scheduled_time >= scheduled_time) {
				break;
			}
		}
		list_add(&(upload->list), ilist->prev);
		if (upload_delay != 0) {
			count_upload_queue++;
			upload->scheduled_time = scheduled_time;
		}
		if ((cwmp_main->upload_id < 0) || (cwmp_main->upload_id >= MAX_INT_ID)) {
			cwmp_main->upload_id = 0;
		}
		cwmp_main->upload_id++;
		upload->id = cwmp_main->upload_id;
		bkp_session_insert_upload(upload);
		bkp_session_save();
		upload->handler_timer.cb = cwmp_start_upload;
		if (upload_delay != 0) {
			CWMP_LOG(INFO, "Upload will start in %us", upload_delay);
		} else {
			CWMP_LOG(INFO, "Upload will start at the end of session");
		}
		cwmp_set_end_session(END_SESSION_UPLOAD);
	}
	return 0;

fault:
	cwmp_free_upload_request(upload);
	if (cwmp_create_fault_message(rpc, error, err_msg))
		return -1;
	return 0;
}

/*
 * [FAULT]: Fault
 */

int cwmp_handle_rpc_cpe_fault(struct rpc *rpc)
{
	mxml_node_t *body;

	body = mxmlFindElement(cwmp_main->session->tree_out, cwmp_main->session->tree_out, "soap_env:Body", NULL, NULL, MXML_DESCEND);
	struct xml_data_struct fault_xml_attrs = {0};

	char *faultcode = (FAULT_CPE_ARRAY[cwmp_main->session->fault_code].TYPE == FAULT_CPE_TYPE_CLIENT) ? "Client" : "Server";
	char *faultstring = "CWMP fault";

	int fault_code = atoi(cwmp_main->session->fault_code ? FAULT_CPE_ARRAY[cwmp_main->session->fault_code].CODE : "0");
	char *fault_string = CWMP_STRLEN(cwmp_main->session->fault_msg) ? strdup(cwmp_main->session->fault_msg) : strdup(FAULT_CPE_ARRAY[cwmp_main->session->fault_code].DESCRIPTION);

	fault_xml_attrs.fault_code = &fault_code;
	fault_xml_attrs.fault_string = &fault_string;
	fault_xml_attrs.faultcode = &faultcode;
	fault_xml_attrs.faultstring = &faultstring;

	int fault = build_xml_node_data(SOAP_ROOT_FAULT, body, &fault_xml_attrs);
	FREE(fault_string);
	if (fault)
		return -1;

	if (rpc->type == RPC_CPE_SET_PARAMETER_VALUES) {
		struct xml_data_struct spv_fault_xml_attrs = {0};
		LIST_HEAD(spv_fault_xml_data_list);

		cwmp_param_fault_list_to_xml_data_list(rpc->list_set_value_fault, &spv_fault_xml_data_list);

		spv_fault_xml_attrs.data_list = &spv_fault_xml_data_list;

		body = mxmlFindElement(cwmp_main->session->tree_out, cwmp_main->session->tree_out, "cwmp:Fault", NULL, NULL, MXML_DESCEND);
		if (body == NULL)
			return -1;

		fault = build_xml_node_data(SOAP_SPV_FAULT, body, &spv_fault_xml_attrs);
		if (fault)
			return -1;

		cwmp_free_all_xml_data_list(&spv_fault_xml_data_list);
	}

	return 0;
}

int cwmp_create_fault_message(struct rpc *rpc_cpe, int fault_code, char *fault_msg)
{
	CWMP_LOG(INFO, "Fault detected");

	cwmp_main->session->fault_code = fault_code;
	snprintf(cwmp_main->session->fault_msg, sizeof(cwmp_main->session->fault_msg), "%s", fault_msg ? fault_msg : "");

	MXML_DELETE(cwmp_main->session->tree_out);

	if (xml_prepare_msg_out(cwmp_main->session))
		return -1;

	CWMP_LOG(INFO, "Preparing the Fault message");
	if (rpc_cpe_methods[RPC_CPE_FAULT].handler(rpc_cpe))
		return -1;

	rpc_cpe->type = RPC_CPE_FAULT;

	return 0;
}

void load_default_forced_inform(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(forced_inform_parameters); i++) {
		force_inform_node *node = (force_inform_node *)malloc(sizeof(force_inform_node));
		if (node == NULL) {
			CWMP_LOG(ERROR, "Out of memory");
			break;
		}

		CWMP_MEMSET(node, 0, sizeof(force_inform_node));
		snprintf(node->path, sizeof(node->path), "%s", forced_inform_parameters[i]);
		INIT_LIST_HEAD(&node->list);
		list_add_tail(&node->list, &force_inform_list);
	}
}

void clean_force_inform_list(void)
{
	force_inform_node *iter = NULL, *node = NULL;

	list_for_each_entry_safe(iter, node, &force_inform_list, list) {
		list_del(&iter->list);
		free(iter);
	}
}

void load_forced_inform_json(void)
{
	struct blob_buf bbuf = {0};
	struct blob_attr *cur = NULL;
	struct blob_attr *forced_inform_list = NULL;
	int rem = 0;

	if (!file_exists(cwmp_main->conf.forced_inform_json))
		return;

	CWMP_MEMSET(&bbuf, 0, sizeof(struct blob_buf));
	blob_buf_init(&bbuf, 0);

	if (blobmsg_add_json_from_file(&bbuf, cwmp_main->conf.forced_inform_json) == false) {
		CWMP_LOG(WARNING, "The file %s is not a valid JSON file", cwmp_main->conf.forced_inform_json);
		blob_buf_free(&bbuf);
		return;
	}

	struct blob_attr *tb[1] = { NULL };
	const struct blobmsg_policy p[1] = { { "forced_inform", BLOBMSG_TYPE_ARRAY } };

	blobmsg_parse(p, 1, tb, blobmsg_data(bbuf.head), blobmsg_len(bbuf.head));
	if (tb[0] == NULL) {
		CWMP_LOG(WARNING, "The JSON file %s doesn't contain a forced inform parameters list", cwmp_main->conf.forced_inform_json);
		blob_buf_free(&bbuf);
		return;
	}

	forced_inform_list = tb[0];
	blobmsg_for_each_attr(cur, forced_inform_list, rem)
	{
		char parameter_path[1024];
		struct cwmp_dm_parameter cwmp_dm_param = {0};

		snprintf(parameter_path, sizeof(parameter_path), "%s", blobmsg_get_string(cur));
		if (parameter_path[strlen(parameter_path)-1] == '.') {
			CWMP_LOG(WARNING, "%s is rejected as inform parameter. Only leaf parameters are allowed.", parameter_path);
			continue;
		}

		if (!cwmp_get_parameter_value(parameter_path, &cwmp_dm_param)) {
			CWMP_LOG(WARNING, "%s is rejected as inform parameter. Wrong parameter path.", parameter_path);
			continue;
		}

		/* Add in forced inform list */
		force_inform_node *node = (force_inform_node *)malloc(sizeof(force_inform_node));
		if (node == NULL) {
			CWMP_LOG(ERROR, "Out of memory");
			break;
		}

		CWMP_MEMSET(node, 0, sizeof(force_inform_node));
		snprintf(node->path, sizeof(node->path), "%s", parameter_path);
		INIT_LIST_HEAD(&node->list);
		list_add_tail(&node->list, &force_inform_list);
	}
	blob_buf_free(&bbuf);
}
