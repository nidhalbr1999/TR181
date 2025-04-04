/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "device.h"
#include "deviceinfo.h"
#include "times.h"
#include "upnp.h"
#include "ip.h"
#include "bridging.h"
#include "wifi.h"
#include "dhcpv4.h"
#include "nat.h"
#include "ppp.h"
#include "routing.h"
#include "firewall.h"
#include "dhcpv6.h"
#include "interfacestack.h"
#include "qos.h"
#include "usb.h"
#include "gre.h"
#include "lanconfigsecurity.h"
#include "security.h"
#include "ieee1905.h"
#include "routeradvertisement.h"
#include "gatewayinfo.h"
#include "mqtt.h"
#include "ssh.h"
#include "userinterface.h"
#include "packetcapture.h"
#include "selftest.h"
#include "cellular.h"
#include "ethernet.h"
//#include "syslog.h"


#define BBFDM_JSON_FILTERS "/etc/bbfdm/filters.json"

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_Device_InterfaceStackNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseInterfaceStackInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Device_RootDataModelVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "2.17";
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_Device_Reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int res = dmubus_call_set("system", "reboot", UBUS_ARGS{0}, 0);
	if (res) bbfdm_set_fault_message(ctx, "Reboot: ubus 'system reboot' method doesn't exist");
	return !res ? 0 : USP_FAULT_COMMAND_FAILURE;
}

static int operate_Device_FactoryReset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int res = dmcmd_no_wait("/sbin/defaultreset", 0);
	if (res) bbfdm_set_fault_message(ctx, "FactoryReset: '/sbin/defaultreset' command doesn't exist");
	return !res ? 0 : USP_FAULT_COMMAND_FAILURE;
}

static int bbfdm_check_filter(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *json_obj = NULL;

	if (!BBFDM_JSON_FILTERS || !strlen(BBFDM_JSON_FILTERS)){
		syslog(LOG_INFO, "No filter file");
		return -1;
	}
		

	json_obj = json_object_from_file(BBFDM_JSON_FILTERS);
	if (!json_obj) {
		syslog(LOG_INFO, "No object in filter file");
		return -1;
	}

	struct uci_section *dmmap_sect = NULL;
	json_object *arr_obj = NULL, *mem_obj = NULL;
	int i = 0;

	json_object_object_foreach(json_obj, key, val) {
		dmjson_foreach_obj_in_array(json_obj, arr_obj, mem_obj, i, 1, key) {

			char *invisible = NULL;

			char *dmmap = dmjson_get_value(mem_obj, 1, "dmmap");
			char *section_type = dmjson_get_value(mem_obj, 1, "section_type");
			char *option_name = dmjson_get_value(mem_obj, 1, "option_name");
			char *option_value = dmjson_get_value(mem_obj, 1, "option_value");
		
			if ((dmmap_sect = get_dup_section_in_dmmap_opt(dmmap, section_type, option_name, option_value)) != NULL) {
				
				dmuci_get_value_by_section_string(dmmap_sect, "invisible", &invisible);
				if ((DM_STRLEN(invisible) != 0) && (DM_LSTRCMP(invisible, "1") == 0)){
					continue;
				}else{
					dmuci_set_value_by_section_bbfdm(dmmap_sect, "invisible", "1");
					dmuci_commit_package_bbfdm(dmmap);
				}
			}
		}
	}
	
	return 0;

}


/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** BBFDM *** */
DM_MAP_OBJ tDynamicObj[] = {
/* parentobj, nextobject, parameter */
{"Device.", tDeviceObj, tDeviceParams},
{0}
};

/* *** Device. *** */
DMOBJ tDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"DeviceInfo", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoObj, tDeviceInfoParams, NULL, BBFDM_BOTH, NULL},
{"Time", &DMREAD, NULL, NULL, "file:/etc/config/system", NULL, NULL, NULL, NULL, tTimeParams, NULL, BBFDM_BOTH, NULL},
{"UPnP", &DMREAD, NULL, NULL, "file:/etc/init.d/ssdpd", NULL, NULL, NULL, tUPnPObj, NULL, NULL, BBFDM_BOTH, NULL},
{"WiFi", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiObj, tWiFiParams, NULL, BBFDM_BOTH, NULL},
{"Bridging", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tBridgingObj, tBridgingParams, NULL, BBFDM_BOTH, NULL},
{"IP", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tIPObj, tIPParams, NULL, BBFDM_BOTH, NULL},
{"DHCPv4", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcp.sh,/etc/config/dhcp", NULL, NULL, NULL, tDHCPv4Obj, tDHCPv4Params, NULL, BBFDM_BOTH, NULL},
{"DHCPv6", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcpv6.sh,/etc/config/dhcp", NULL, NULL, NULL, tDHCPv6Obj, tDHCPv6Params, NULL, BBFDM_BOTH, NULL},
{"NAT", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, NULL, tNATObj, tNATParams, NULL, BBFDM_BOTH, NULL},
{"PPP", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/ppp.sh,/etc/config/network", NULL, NULL, NULL, tPPPObj, tPPPParams, NULL, BBFDM_BOTH, NULL},
{"Routing", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, tRoutingObj, tRoutingParams, NULL, BBFDM_BOTH, NULL},
{"Firewall", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, NULL, tFirewallObj, tFirewallParams, NULL, BBFDM_BOTH, NULL},
{"IEEE1905", &DMREAD, NULL, NULL, "file:/etc/config/ieee1905", NULL, NULL, NULL, tIEEE1905Obj, tIEEE1905Params, NULL, BBFDM_BOTH, NULL},
{"InterfaceStack", &DMREAD, NULL, NULL, "file:/etc/config/network", browseInterfaceStackInst, NULL, NULL, NULL, tInterfaceStackParams, NULL, BBFDM_BOTH, NULL},
{"USB", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tUSBObj, tUSBParams, NULL, BBFDM_BOTH, NULL},
{"GRE", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/gre.sh,/etc/config/network", NULL, NULL, NULL, tGREObj, tGREParams, NULL, BBFDM_BOTH, NULL},
{"QoS", &DMREAD, NULL, NULL, "file:/etc/config/qos", NULL, NULL, NULL, tQoSObj, tQoSParams, NULL, BBFDM_BOTH, NULL},
{"LANConfigSecurity", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, NULL, NULL, tLANConfigSecurityParams, NULL, BBFDM_BOTH, NULL},
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tSecurityObj, tSecurityParams, NULL, BBFDM_BOTH, NULL},
{"RouterAdvertisement", &DMREAD, NULL, NULL, "file:/etc/config/dhcp", NULL, NULL, NULL, tRouterAdvertisementObj, tRouterAdvertisementParams, NULL, BBFDM_BOTH, NULL},
{"Services", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, BBFDM_BOTH, NULL},
{"GatewayInfo", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tGatewayInfoParams, NULL, BBFDM_CWMP, NULL},
{"MQTT", &DMREAD, NULL, NULL, "file:/etc/config/mosquitto", NULL, NULL, NULL, tMQTTObj, tMQTTParams, NULL, BBFDM_BOTH, NULL},
{"SSH", &DMREAD, NULL, NULL, "file:/etc/config/dropbear", NULL, NULL, NULL, tSSHObj, tSSHParams, NULL, BBFDM_BOTH, NULL},
{"UserInterface", &DMREAD, NULL, NULL, "file:/etc/config/userinterface", NULL, NULL, NULL, tUIHTTPAccessObj, tUIParams, NULL, BBFDM_BOTH, NULL},
{"PacketCaptureDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tPacketCaptureObj, tPacketCaptureParams, NULL, BBFDM_CWMP, NULL},
{"SelfTestDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tSelfTestParams, NULL, BBFDM_CWMP, NULL},
{"Cellular", &DMREAD, NULL, NULL,"file:/etc/config/network", NULL, NULL, NULL, tCellularObj, tCellularParams, NULL, BBFDM_BOTH, NULL},
{"Ethernet", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetObj, tEthernetParams, NULL, BBFDM_BOTH, NULL},
//{"Syslog", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tSyslogObj, tSyslogParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceStackNumberOfEntries", &DMREAD, DMT_UNINT, get_Device_InterfaceStackNumberOfEntries, NULL, BBFDM_BOTH},
{"RootDataModelVersion", &DMREAD, DMT_STRING, get_Device_RootDataModelVersion, NULL, BBFDM_BOTH},
{"Reboot()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_Reboot, BBFDM_USP},
{"FactoryReset()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_FactoryReset, BBFDM_USP},
{"PacketCaptureDiagnostics()", &DMASYNC, DMT_COMMAND, get_operate_args_packetCapture, operate_Device_packetCapture, BBFDM_USP},
{"SelfTestDiagnostics()", &DMASYNC, DMT_COMMAND, get_operate_args_SelfTest, operate_Device_SelfTest, BBFDM_USP},
{"FilterParameters()", &DMSYNC, DMT_COMMAND, NULL, bbfdm_check_filter, BBFDM_USP},
//{"Boot!", &DMREAD, DMT_EVENT, NULL, NULL, BBFDM_USP},
{0}
};

