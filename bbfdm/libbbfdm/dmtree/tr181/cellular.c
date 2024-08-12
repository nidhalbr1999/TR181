/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: <Name> <Surname> <name.surname@iopsys.eu>
 */

#include "cellular.h"


char *PINCheck[] = {"OnNetworkAccess", "Reboot", "Off", NULL};

struct cellular_iface
{
	struct uci_section *dm_cellular_iface;
	struct uci_section *config_section;
};

struct cellular_ap
{
	struct uci_section *dm_cellular_ap;
	struct uci_section *config_section;
};

/*************************************************************
* INIT
**************************************************************/

static void init_cellular_iface(struct uci_section *dm, struct cellular_iface *iface)
{
	iface->dm_cellular_iface = dm;
}

static void init_cellular_ap(struct uci_section *dm, struct uci_section *conf_sec, struct cellular_ap *ap)
{
	ap->dm_cellular_ap = dm;
	ap->config_section = conf_sec;
}

/*************************************************************
* COMMON Functions
**************************************************************/


static char *find_net_sys_device(struct uci_section *s)
{
	char *device = NULL, *dev = NULL;

	dmuci_get_value_by_section_string(s, "device", &dev);
	if (dev == NULL)
		return NULL;

	while(!isdigit(*dev++));
	(dev--);
	dmasprintf(&device, "wwan%s", dev);

	return device;
}

static int check_ip_private(char *ipaddr)
{
	unsigned value_addr;

	inet_pton(AF_INET, ipaddr, &value_addr);

	// 10.0.0.0/8
    if ((ntohl(value_addr) & 0xFF000000) == 0x0A000000) {
        return 0;
    }
    
    // 172.16.0.0/12
    if ((ntohl(value_addr) & 0xFFF00000) == 0xAC100000) {
        return 0;
    }
    
    // 192.168.0.0/16
    if ((ntohl(value_addr) & 0xFFFF0000) == 0xC0A80000) {
        return true;
    }

	return -1;
}


static int dmmap_sysfs_synchronize_CellularInterface(char *dmmap_package, char *dmmap_section, char *opt_name, struct list_head *dup_list)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_sect = NULL;
	char sysfs_rep_path[512];
	char section_name[512];
	DIR *dir;
	struct dirent *ent;
	char *v = NULL;
	char index[8]= {'\0'};

	sysfs_foreach_file("/dev", dir, ent) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;
		if (DM_STRNCMP(ent->d_name, "cdc-wdm",strlen("cdc-wdm")) == 0){

		snprintf(sysfs_rep_path, sizeof(sysfs_rep_path), "%s/%s", "/dev", ent->d_name);
		if ((dmmap_sect = get_dup_section_in_dmmap_opt(dmmap_package, dmmap_section, opt_name, sysfs_rep_path)) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, dmmap_section, &dmmap_sect);
			int index_len = strlen(ent->d_name)-strlen("cdc-wdm");
			strncpy( index, (ent->d_name)+strlen("cdc-wdm"),index_len);
			snprintf(section_name, sizeof(section_name), "cellular_%s", index);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, opt_name, sysfs_rep_path);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "enabled", "0");
		}

		//refresh from config
		v = get_dup_section_in_config_opt("network", "interface", "device", sysfs_rep_path) ? "1" : "0" ;
		dmuci_set_value_by_section_bbfdm(dmmap_sect, "enabled", v);

		add_sysfs_section_list(dup_list, dmmap_sect, ent->d_name, sysfs_rep_path);
		}
	}
	if (dir)
		closedir(dir);

	uci_path_foreach_sections_safe(bbfdm, dmmap_package, dmmap_section, stmp, s) {
		char *opt_val = NULL;

		dmuci_get_value_by_section_string(s, opt_name, &opt_val);
		if (!file_exists(opt_val))
			dmuci_delete_by_section(s, NULL, NULL);
	}
	return 0;
}

static void dmmap_synchronize_CellularAccessPoint(char *package, char *dmmap_package, char *section, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	char *apn = NULL, *device = NULL;

	uci_foreach_option_eq(package, "interface", "proto", "qmi", s) {

		dmuci_get_value_by_section_string(s, "apn", &apn);
		dmuci_get_value_by_section_string(s, "device", &device);

		if ((DM_STRLEN(apn) == 0 ) && (DM_STRLEN(device) == 0 ))
			continue;
		
		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, section, section_name(s))) == NULL){
			dmuci_add_section_bbfdm(dmmap_package, section, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(s));
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "enabled", "1");
		}
		
		dmuci_set_value_by_section_bbfdm(dmmap_sect, "apn", apn);
		dmuci_set_value_by_section_bbfdm(dmmap_sect, "device", device);

		//refresh interface name
		if (DM_STRLEN(device) != 0){
			char *inst = NULL, *ifname = NULL;

			struct uci_section *if_dmmap_sec = get_dup_section_in_dmmap_opt("dmmap_cellular", "interface", "device", device);
			dmuci_get_value_by_section_string(if_dmmap_sec, "cellular_iface_instance", &inst);
			dmasprintf(&ifname, "Device.Cellular.Interface.%s", inst);
			dmuci_set_value_by_section(dmmap_sect, "interface_name", ifname);
		}
		
		add_dmmap_config_dup_list(dup_list, s, dmmap_sect);

	}
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section, stmp, s) {
		
		char *apn_val = NULL, *device_val = NULL;

		dmuci_get_value_by_section_string(s, "apn", &apn_val);
		dmuci_get_value_by_section_string(s, "device", &device_val);
		if ((get_dup_section_in_config_opt(package, "interface", "apn", apn_val) == NULL) && (get_dup_section_in_config_opt(package, "interface", "device", device_val) == NULL) )
			dmuci_delete_by_section(s, NULL, NULL);
	}
	
}


static int browseCellularInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct cellular_iface iface = {0};
	LIST_HEAD(dup_list);
	struct sysfs_dmsection *p = NULL;
	

	dmmap_sysfs_synchronize_CellularInterface("dmmap_cellular", "interface", "device", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char netfolderpath[256] = {0};

		snprintf(netfolderpath, sizeof(netfolderpath), "%s", p->sysfs_folder_path);
		
		if (!file_exists(netfolderpath))
			continue;

		init_cellular_iface(p->dmmap_section, &iface);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "cellular_iface_instance", "cellular_iface_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &iface, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}


static int browseCellularAccessPointInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dm_data *curr_data = NULL;
	char *inst = NULL;
	struct cellular_ap ap = {0};
	LIST_HEAD(dup_list);

	dmmap_synchronize_CellularAccessPoint("network", "dmmap_cellular", "access_point", &dup_list);
	list_for_each_entry(curr_data, &dup_list, list) {

		init_cellular_ap(curr_data->dmmap_section, curr_data->config_section, &ap);

		inst = handle_instance(dmctx, parent_node, curr_data->dmmap_section, "cellular_ap_instance", "cellular_ap_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &ap, inst) == DM_STOP)
		break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/

static int addObjCellularAccessPoint(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *conf = NULL, *dmmap = NULL;
	char s_name[32] = {0};
	char ap_name[32] = {0};

	snprintf(s_name, sizeof(s_name), "cellular_ap_%s", *instance);
	snprintf(ap_name, sizeof(ap_name), "cellular_ap_%s", *instance);

	//network
	dmuci_add_section("network", "interface", &conf);
	dmuci_rename_section_by_section(conf, s_name);
	dmuci_set_value_by_section(conf, "proto", "qmi");
	dmuci_set_value_by_section(conf, "apn", "internet");
	dmuci_set_value_by_section(conf, "auth", "none");
	dmuci_set_value_by_section(conf, "pdptype", "ipv4");
	//dmmap
	dmuci_add_section_bbfdm("dmmap_cellular", "access_point", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", ap_name);
	dmuci_set_value_by_section(dmmap, "enabled", "1");
	dmuci_set_value_by_section(dmmap, "cellular_instance", *instance);
	return 0;
}

static int delObjCellularAccessPoint(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
	case DEL_INST:
		// Remove dmmap section
		dmuci_delete_by_section(((struct cellular_ap *)data)->dm_cellular_ap, NULL, NULL);

		// Remove config section
		dmuci_delete_by_section(((struct cellular_ap *)data)->config_section, NULL, NULL);
		break;
	case DEL_ALL:
		//TODO
		break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_Cellular_RoamingEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	/*char *enabled;

	struct uci_section *s=get_dup_section_in_dmmap("dmmap_cellular", "interface", "CellularInterface");
	*value = (dmuci_get_value_by_section_string(s, "Roaming_enabled", &enabled)== 0) ? enabled : "1";*/
	return 0;
}

static int set_Cellular_RoamingEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	//bool b;

	//struct uci_section *s=get_dup_section_in_dmmap("dmmap_cellular", "interface", "CellularInterface");
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//string_to_bool(value, &b);
			//dmuci_set_value_by_section(s, "Roaming_enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_Cellular_RoamingStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_Cellular_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseCellularInterfaceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Cellular_AccessPointNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseCellularAccessPointInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_CellularInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_CellularInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//nothing to do here
			break;
	}
	return 0;
}

static int get_CellularInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char *device = NULL;

	device = find_net_sys_device(((struct cellular_iface *)data)->dm_cellular_iface);
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", device, String}}, 1, &res);
	DM_ASSERT(res, *value = "Down");

	char *isup = dmjson_get_value(res, 1, "up");
	*value = (DM_STRCMP(isup, "true") == 0) ? "Up" : "Down";
	return 0;
}

static int get_CellularInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct cellular_iface *)data)->dm_cellular_iface, "if_alias", instance, value);
}

static int set_CellularInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			return bbf_set_alias(ctx, ((struct cellular_iface *)data)->dm_cellular_iface, "if_alias", instance, value);
			break;
	}
	return 0;
}

static int get_CellularInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{	
	char *name = NULL;
	dmuci_get_value_by_section_string((((struct cellular_iface *)data)->dm_cellular_iface), "section_name", &name);
	dmasprintf(value, "%s", name);
	return 0;
}

static int get_CellularInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char *if_name = NULL;

	dmuci_get_value_by_section_string((((struct cellular_iface *)data)->dm_cellular_iface), "section_name", &if_name);
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
	//DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	return 0;
}

static int get_CellularInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_CellularInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_CellularInterface_Upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char *if_name = NULL;

	dmuci_get_value_by_section_string((((struct cellular_iface *)data)->dm_cellular_iface), "section_name", &if_name);
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
	char *isup = dmjson_get_value(res, 1, "up");
	
	if (DM_STRCMP(isup, "true") == 0){
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		json_object *jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
		char *ipaddr = dmjson_get_value(jobj, 1, "address");
		*value = check_ip_private(ipaddr)? "0" : "1";
	}else{
		*value = "0";
	}
	
	return 0;
}

static int get_CellularInterface_IMEI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterface_SupportedAccessTechnologies(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterface_PreferredAccessTechnology(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_CellularInterface_PreferredAccessTechnology(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_CellularInterface_CurrentAccessTechnology(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterface_AvailableNetworks(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterface_NetworkRequested(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_CellularInterface_NetworkRequested(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_CellularInterface_NetworkInUse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterface_RSSI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterface_RSRP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterface_RSRQ(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterface_UpstreamMaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterface_DownstreamMaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterfaceUSIM_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterfaceUSIM_IMSI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterfaceUSIM_ICCID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterfaceUSIM_MSISDN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterfaceUSIM_PINCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_CellularInterfaceUSIM_PINCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, PINCheck, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_CellularInterfaceUSIM_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_CellularInterfaceUSIM_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 4, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_CellularInterfaceStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct cellular_iface *)data)->dm_cellular_iface);
	if (device == NULL)
		return 0;
	
	return get_net_device_sysfs(device, "statistics/tx_bytes", value);
}

static int get_CellularInterfaceStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct cellular_iface *)data)->dm_cellular_iface);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/rx_bytes", value);
}

static int get_CellularInterfaceStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct cellular_iface *)data)->dm_cellular_iface);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/tx_packets", value);
}

static int get_CellularInterfaceStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct cellular_iface *)data)->dm_cellular_iface);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/rx_packets", value);
}

static int get_CellularInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct cellular_iface *)data)->dm_cellular_iface);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/tx_errors", value);
}

static int get_CellularInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct cellular_iface *)data)->dm_cellular_iface);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/rx_errors", value);
}

static int get_CellularInterfaceStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterfaceStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct cellular_iface *)data)->dm_cellular_iface);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/rx_unicast_packets", value);
}

static int get_CellularInterfaceStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct cellular_iface *)data)->dm_cellular_iface);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/tx_dropped", value);
}

static int get_CellularInterfaceStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct cellular_iface *)data)->dm_cellular_iface);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/rx_dropped", value);
}

static int get_CellularInterfaceStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterfaceStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct cellular_iface *)data)->dm_cellular_iface);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/multicast", value);
}

static int get_CellularInterfaceStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterfaceStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularInterfaceStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_CellularAccessPoint_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = NULL;
	
	dmuci_get_value_by_section_string(((struct cellular_ap *)data)->config_section, "disabled", &disabled);
	*value = ((DM_LSTRCMP(disabled, "1") == 0)) ? "0" : "1";
	return 0;
}

static int set_CellularAccessPoint_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b)  {
				dmuci_delete_by_section(((struct cellular_ap *)data)->config_section, "disabled", NULL);
				dmuci_commit_package("network");
			}else {
				dmuci_set_value_by_section(((struct cellular_ap *)data)->config_section, "disabled", "1");
				dmuci_commit_package("network");
			}
			dmubus_call_set("network", "reload", UBUS_ARGS{0}, 0);
			break;
	}
	return 0;
}

static int get_CellularAccessPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct cellular_ap *)data)->dm_cellular_ap, "ap_alias", instance, value);
}

static int set_CellularAccessPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			return bbf_set_alias(ctx, ((struct cellular_ap *)data)->dm_cellular_ap, "ap_alias", instance, value);
			break;
	}
	return 0;
}

static int get_CellularAccessPoint_APN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct cellular_ap *)data)->config_section, "apn", "");
	return 0;
}

static int set_CellularAccessPoint_APN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct cellular_ap *)data)->config_section, "apn", value);
			break;
	}
	return 0;
}

static int get_CellularAccessPoint_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct cellular_ap *)data)->config_section, "username", value);
	return 0;
}

static int set_CellularAccessPoint_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct cellular_ap *)data)->config_section, "username", value);
			break;
	}
	return 0;
}

static int get_CellularAccessPoint_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct cellular_ap *)data)->config_section, "password", value);
	return 0;
}

static int set_CellularAccessPoint_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct cellular_ap *)data)->config_section, "password", value);
			break;
	}
	return 0;
}

static int get_CellularAccessPoint_Proxy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_CellularAccessPoint_Proxy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 45, NULL, IPAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_CellularAccessPoint_ProxyPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_CellularAccessPoint_ProxyPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_CellularAccessPoint_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct cellular_ap *)data)->dm_cellular_ap, "interface_name", "");
	return 0;
}

static int set_CellularAccessPoint_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.Cellular.Interface.",NULL};
	struct dm_reference reference = {0};
	char *device = NULL;

	char *inst = (DM_STRRCHR(value, '.')+1);
	
	bbf_get_reference_args(value, &reference);

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
				return FAULT_9007;
			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;
			if (!isdigit_str(inst))
				return FAULT_9007;
			break;
		case VALUESET:
			// Store LowerLayers value under dmmap_network section;
			dmuci_set_value_by_section_bbfdm(((struct cellular_ap *)data)->dm_cellular_ap, "interface_name", value);
			
			struct uci_section *s = get_dup_section_in_dmmap_opt("dmmap_cellular", "interface", "cellular_iface_instance", inst);
			dmuci_get_value_by_section_string(s, "device", &device);
			// Store LowerLayers value under config section;
			dmuci_set_value_by_section(((struct cellular_ap *)data)->config_section, "device", device);

			dmuci_commit_package("network");
			dmubus_call_set("network", "reload", UBUS_ARGS{0}, 0);
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Cellular. *** */
DMOBJ tCellularObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys */
{"Interface", &DMREAD, NULL, NULL, NULL, browseCellularInterfaceInst, NULL, NULL, tCellularInterfaceObj, tCellularInterfaceParams, NULL, BBFDM_BOTH, NULL},
{"AccessPoint", &DMWRITE, addObjCellularAccessPoint, delObjCellularAccessPoint, NULL, browseCellularAccessPointInst, NULL, NULL, NULL, tCellularAccessPointParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tCellularParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"RoamingEnabled", &DMWRITE, DMT_BOOL, get_Cellular_RoamingEnabled, set_Cellular_RoamingEnabled, BBFDM_BOTH},
{"RoamingStatus", &DMREAD, DMT_STRING, get_Cellular_RoamingStatus, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_Cellular_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{"AccessPointNumberOfEntries", &DMREAD, DMT_UNINT, get_Cellular_AccessPointNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Cellular.Interface.{i}. *** */
DMOBJ tCellularInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys */
{"USIM", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tCellularInterfaceUSIMParams, NULL, BBFDM_BOTH, NULL},
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tCellularInterfaceStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tCellularInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"Enable", &DMWRITE, DMT_BOOL, get_CellularInterface_Enable, set_CellularInterface_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_CellularInterface_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_CellularInterface_Alias, set_CellularInterface_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_CellularInterface_Name, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_CellularInterface_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_CellularInterface_LowerLayers, set_CellularInterface_LowerLayers, BBFDM_BOTH},
{"Upstream", &DMREAD, DMT_BOOL, get_CellularInterface_Upstream, NULL, BBFDM_BOTH},
{"IMEI", &DMREAD, DMT_STRING, get_CellularInterface_IMEI, NULL, BBFDM_BOTH},
{"SupportedAccessTechnologies", &DMREAD, DMT_STRING, get_CellularInterface_SupportedAccessTechnologies, NULL, BBFDM_BOTH},
{"PreferredAccessTechnology", &DMWRITE, DMT_STRING, get_CellularInterface_PreferredAccessTechnology, set_CellularInterface_PreferredAccessTechnology, BBFDM_BOTH},
{"CurrentAccessTechnology", &DMREAD, DMT_STRING, get_CellularInterface_CurrentAccessTechnology, NULL, BBFDM_BOTH},
{"AvailableNetworks", &DMREAD, DMT_STRING, get_CellularInterface_AvailableNetworks, NULL, BBFDM_BOTH},
{"NetworkRequested", &DMWRITE, DMT_STRING, get_CellularInterface_NetworkRequested, set_CellularInterface_NetworkRequested, BBFDM_BOTH},
{"NetworkInUse", &DMREAD, DMT_STRING, get_CellularInterface_NetworkInUse, NULL, BBFDM_BOTH},
{"RSSI", &DMREAD, DMT_INT, get_CellularInterface_RSSI, NULL, BBFDM_BOTH},
{"RSRP", &DMREAD, DMT_INT, get_CellularInterface_RSRP, NULL, BBFDM_BOTH},
{"RSRQ", &DMREAD, DMT_INT, get_CellularInterface_RSRQ, NULL, BBFDM_BOTH},
{"UpstreamMaxBitRate", &DMREAD, DMT_UNINT, get_CellularInterface_UpstreamMaxBitRate, NULL, BBFDM_BOTH},
{"DownstreamMaxBitRate", &DMREAD, DMT_UNINT, get_CellularInterface_DownstreamMaxBitRate, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Cellular.Interface.{i}.USIM. *** */
DMLEAF tCellularInterfaceUSIMParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"Status", &DMREAD, DMT_STRING, get_CellularInterfaceUSIM_Status, NULL, BBFDM_BOTH},
{"IMSI", &DMREAD, DMT_STRING, get_CellularInterfaceUSIM_IMSI, NULL, BBFDM_BOTH},
{"ICCID", &DMREAD, DMT_STRING, get_CellularInterfaceUSIM_ICCID, NULL, BBFDM_BOTH},
{"MSISDN", &DMREAD, DMT_STRING, get_CellularInterfaceUSIM_MSISDN, NULL, BBFDM_BOTH},
{"PINCheck", &DMWRITE, DMT_STRING, get_CellularInterfaceUSIM_PINCheck, set_CellularInterfaceUSIM_PINCheck, BBFDM_BOTH},
{"PIN", &DMWRITE, DMT_STRING, get_CellularInterfaceUSIM_PIN, set_CellularInterfaceUSIM_PIN, BBFDM_BOTH},
{0}
};

/* *** Device.Cellular.Interface.{i}.Stats. *** */
DMLEAF tCellularInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"BytesSent", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNLONG, get_CellularInterfaceStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Cellular.AccessPoint.{i}. *** */
DMLEAF tCellularAccessPointParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"Enable", &DMWRITE, DMT_BOOL, get_CellularAccessPoint_Enable, set_CellularAccessPoint_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_CellularAccessPoint_Alias, set_CellularAccessPoint_Alias, BBFDM_BOTH},
{"APN", &DMWRITE, DMT_STRING, get_CellularAccessPoint_APN, set_CellularAccessPoint_APN, BBFDM_BOTH},
{"Username", &DMWRITE, DMT_STRING, get_CellularAccessPoint_Username, set_CellularAccessPoint_Username, BBFDM_BOTH},
{"Password", &DMWRITE, DMT_STRING, get_CellularAccessPoint_Password, set_CellularAccessPoint_Password, BBFDM_BOTH},
{"Proxy", &DMWRITE, DMT_STRING, get_CellularAccessPoint_Proxy, set_CellularAccessPoint_Proxy, BBFDM_BOTH},
{"ProxyPort", &DMWRITE, DMT_UNINT, get_CellularAccessPoint_ProxyPort, set_CellularAccessPoint_ProxyPort, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_CellularAccessPoint_Interface, set_CellularAccessPoint_Interface, BBFDM_BOTH},
{0}
};

