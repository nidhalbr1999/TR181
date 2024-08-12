/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: <Name> <Surname> <name.surname@iopsys.eu>
 */

#include "ethernet.h"

#define SYSFS_NET_DEVICES_PATH "/sys/class/net"


char *DuplexMode[] = {"Half", "Full", "Auto", NULL};
char *MACAddress[] = {"^$", "^([0-9A-Fa-f][0-9A-Fa-f]:){5}([0-9A-Fa-f][0-9A-Fa-f])$", NULL};


struct ethernet_interface
{
	struct uci_section *dm_ethernet_iface;
	struct uci_section *config_section;
	char *iface_name;
	char *iface_path;
	char *statistics_path;
	char *portlink;
};

struct ethernet_link
{
	struct uci_section *dm_ethernet_link;
	struct uci_section *config_section;
};

struct ethernet_vlan
{
	struct uci_section *dm_ethernet_vlan;
	struct uci_section *config_section;
};



/*************************************************************
* INIT
*************************************************************/

static void init_ethernet_interface(struct uci_section *dm, char *iface_name, char *iface_path, char *statistics_path, char *portlink, struct ethernet_interface *iface)
{
	iface->dm_ethernet_iface = dm;
	iface->iface_name = dmstrdup(iface_name);
	iface->iface_path = dmstrdup(iface_path);
}

static void init_ethernet_link(struct uci_section *dm, struct uci_section *conf_sec, struct ethernet_link *link)
{
	link->dm_ethernet_link = dm;
	link->config_section = conf_sec;
}

static void init_ethernet_vlan(struct uci_section *dm, struct uci_section *conf_sec, struct ethernet_vlan *vlan)
{
	vlan->dm_ethernet_vlan = dm;
	vlan->config_section = conf_sec;
}
/*************************************************************
* COMMON Functions
**************************************************************/

static int read_sysfs_file(const char *file, char **value)
{
	char buf[128];
	int rc;

	rc =  dm_read_sysfs_file(file, buf, sizeof(buf));
	*value = dmstrdup(buf);

	return rc;
}


static int read_sysfs(const char *path, const char *name, char **value)
{
	char file[256];

	snprintf(file, sizeof(file), "%s/%s", path, name);
	return read_sysfs_file(file, value);
}

static int read_sysfs_ethernet_net_iface(const struct ethernet_interface *iface, const char *name, char **value)
{
	return get_net_device_sysfs(iface->iface_name, name, value);
}

static int read_sysfs_ethernet_iface(const struct ethernet_interface *iface, const char *name, char **value)
{
	return read_sysfs(iface->iface_path, name, value);
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


static char *find_vlan_iface_conf(struct ethernet_vlan *vlan)
{
	char *device = NULL, *id = NULL;
	char vlan_d[16] = {0};

	dmuci_get_value_by_section_string(vlan->config_section, "device", &device);
	dmuci_get_value_by_section_string(vlan->config_section, "vlan", &id);
	snprintf(vlan_d,sizeof(vlan_d),"%s.%s",device,id);
	
	return dmstrdup(vlan_d);
}


static char *get_wifi_device(struct uci_section *s)
{
	struct uci_section *wifi_iface = NULL;
	char *mode = NULL, *inst = NULL, *sec_name = NULL, *wl_device = NULL;
	char sysfs_path[64] = {0};

	dmuci_get_value_by_section_string(s, "device", &inst);
	while(!isdigit(*inst++));
	(inst--);

	dmuci_get_value_by_section_string(s, "ap_section_name", &sec_name);
	

	wifi_iface = get_dup_section_in_dmmap_opt("dmmap_wireless","wifi-iface", "section_name",sec_name);

	if (wifi_iface == NULL){
		dmasprintf(&wl_device, "wlan%s", inst);
		return wl_device;
	}

	dmuci_get_value_by_section_string(s, "ap_instance", &mode);
	if (DM_STRLEN(mode) != 0 )
		dmasprintf(&wl_device, "phy%s-ap0", inst);
	else 
		dmasprintf(&wl_device, "phy%s-sta0", inst);

	snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/net/%s", wl_device);
	if(folder_exists(sysfs_path)) 
		return wl_device;
	
	return sec_name;
			
}

static int synchronize_ethernet_sysfs_with_dmmap(char *sysfsrep, char *dmmap_package, char *dmmap_section, char *opt_name, struct list_head *dup_list)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_sect = NULL;
	char sysfs_rep_path[512];
	DIR *dir;
	struct dirent *ent;
	bool lan_wan_found = false;
	char *invisible = NULL;

	//check lan wan ports

	lan_wan_found = ((folder_exists("/sys/class/net/lan")) || (folder_exists("/sys/class/net/lan1")) || (folder_exists("/sys/class/net/wan")) || (folder_exists("/sys/class/net/wan1")));

	sysfs_foreach_file(sysfsrep, dir, ent) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;
		if ((DM_STRNCMP(ent->d_name, "lan",strlen("lan")) == 0) || (DM_STRNCMP(ent->d_name, "wan",strlen("wan")) == 0) || 
		((DM_STRNCMP(ent->d_name, "eth",strlen("eth")) == 0) && !lan_wan_found )){

		snprintf(sysfs_rep_path, sizeof(sysfs_rep_path), "%s/%s", sysfsrep, ent->d_name);
		if ((dmmap_sect = get_dup_section_in_dmmap_opt(dmmap_package, dmmap_section, opt_name, ent->d_name)) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, dmmap_section, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, opt_name, ent->d_name);
		}

		//check if it is hidden
		dmuci_get_value_by_section_string(dmmap_sect, "invisible", &invisible);
		if (DM_LSTRCMP(invisible, "1") == 0)
			continue;

		add_sysfs_section_list(dup_list, dmmap_sect, ent->d_name, sysfs_rep_path);
		}

	}

	if (dir)
		closedir(dir);

	uci_path_foreach_sections_safe(bbfdm, dmmap_package, dmmap_section, stmp, s) {
		char *opt_val = NULL;

		dmuci_get_value_by_section_string(s, opt_name, &opt_val);
		snprintf(sysfs_rep_path, sizeof(sysfs_rep_path), "%s/%s", sysfsrep, opt_val);
		if (!folder_exists(sysfs_rep_path))
			dmuci_delete_by_section(s, NULL, NULL);
	}
	return 0;
}

static void dmmap_synchronize_EthernetLink_from_dmmap_bridge_port(struct dmctx *ctx, char *dmmap_package, char *section, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	struct uci_section *conf_sec = NULL;
	char *lowerlayer = NULL;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_bridge_port", "bridge_port", stmp, s) {

		char *op_value = NULL, *manage = NULL;

		dmuci_get_value_by_section_string(s, "management", &manage);
		if (DM_LSTRCMP(manage, "0") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "port", &op_value);
		
		if ((dmmap_sect = get_dup_section_in_dmmap_opt(dmmap_package, section, "device", op_value)) == NULL){
			dmuci_add_section_bbfdm(dmmap_package, section, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "package", "dmmap_bridge_port");
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "name", op_value);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "device", op_value);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "enabled", "1");
			adm_entry_get_reference_param(ctx, "Device.Bridging.Bridge.*.Port.1.Name", op_value, &lowerlayer);
			if (lowerlayer != NULL)
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "LowerLayers", lowerlayer);
			
		}
		conf_sec = get_dup_section_in_config_opt("network", "device", "name", op_value);

		add_dmmap_config_dup_list(dup_list, conf_sec, dmmap_sect);
	}

	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section, stmp, s) {

		char *v = NULL, *package = NULL;

		dmuci_get_value_by_section_string(s, "added_by_user", &v);
		if(DM_LSTRCMP(v, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "package", &package);
		if (DM_STRNCMP(package, "dmmap_bridge_port",strlen("dmmap_bridge_port")) != 0)
			continue;
			
		dmuci_get_value_by_section_string(s, "device", &v);
		if (get_dup_section_in_dmmap_opt(package, "bridge_port", "port", v) == NULL)
			dmuci_delete_by_section(s, NULL, NULL);
	}

}


static void dmmap_synchronize_EthernetLink_from_dmmap_wireless(struct dmctx *ctx, char *dmmap_package, char *section, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	struct uci_section *conf_sec = NULL;
	char *lowerlayer = NULL;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_wireless", "ssid", stmp, s) {

		char *name = NULL, *device = NULL, *ifname = NULL;

		name = get_wifi_device(s);
		dmuci_get_value_by_section_string(s, "device", &device);
		dmuci_get_value_by_section_string(s, "ap_section_name", &ifname);


		if (get_section_in_dmmap_with_options_eq("dmmap_bridge_port", "bridge_port", "port", ifname,"management","0"))
			continue;
		
		if ((dmmap_sect = get_dup_section_in_dmmap_opt(dmmap_package, section, "name", name)) == NULL){
			dmuci_add_section_bbfdm(dmmap_package, section, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "package", "dmmap_wireless");
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "name", name);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "device", device);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "enabled", "1");
			adm_entry_get_reference_param(ctx, "Device.WiFi.SSID.*.Name", ifname, &lowerlayer);
			if (lowerlayer != NULL)
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "LowerLayers", lowerlayer);

		}
		
		conf_sec = get_origin_section_from_config("wireless", "wifi-iface", ifname);

		add_dmmap_config_dup_list(dup_list, conf_sec, dmmap_sect);
	}

	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section, stmp, s) {

		char *v = NULL, *package = NULL;
		char sysfs_path[64] = {0};

		dmuci_get_value_by_section_string(s, "added_by_user", &v);
		if(DM_LSTRCMP(v, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "package", &package);
		if (DM_STRNCMP(package, "dmmap_wireless",strlen("dmmap_wireless")) != 0)
			continue;
			
		dmuci_get_value_by_section_string(s, "name", &v);
		snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/net/%s", v);
		if ((get_dup_section_in_dmmap_opt(package, "ssid", "ap_section_name", v) == NULL) && (!folder_exists(sysfs_path)))
			dmuci_delete_by_section(s, NULL, NULL);
	}

}

static void dmmap_synchronize_EthernetLink_from_dmmap_cellular(struct dmctx *ctx, char *dmmap_package, char *section, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	struct uci_section *conf_sec = NULL;
	char *lowerlayer = NULL;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_cellular", "interface", stmp, s) {

		char *name = NULL, *device = NULL;

		dmuci_get_value_by_section_string(s, "section_name", &name);
		dmuci_get_value_by_section_string(s, "device", &device);
		
		if ((dmmap_sect = get_dup_section_in_dmmap_opt(dmmap_package, section, "name", name)) == NULL){
			dmuci_add_section_bbfdm(dmmap_package, section, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "package", "dmmap_cellular");
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "name", name);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "device", device);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "enabled", "1");
			adm_entry_get_reference_param(ctx, "Device.Cellular.Interface.*.Name", name, &lowerlayer);
			if (lowerlayer != NULL)
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "LowerLayers", lowerlayer);

		}

		conf_sec = get_dup_section_in_config_opt("network", "interface", "device", device);

		add_dmmap_config_dup_list(dup_list, conf_sec, dmmap_sect);
	}

	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section, stmp, s) {

		char *v = NULL, *package = NULL;

		dmuci_get_value_by_section_string(s, "added_by_user", &v);
		if(DM_LSTRCMP(v, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "package", &package);
		if (DM_STRNCMP(package, "dmmap_cellular",strlen("dmmap_cellular")) != 0)
			continue;
			
		dmuci_get_value_by_section_string(s, "name", &v);
		if (get_dup_section_in_dmmap_opt(package, "interface", "section_name", v) == NULL)
			dmuci_delete_by_section(s, NULL, NULL);
	}

}

static void dmmap_synchronize_EthernetLink_from_dmmap_ethernet(struct dmctx *ctx, char *dmmap_package, char *section, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	struct uci_section *conf_sec = NULL;
	char *lowerlayer = NULL;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_ethernet", "interface", stmp, s) {

		char *op_value = NULL;

		dmuci_get_value_by_section_string(s, "ethernet_iface_name", &op_value);

		if (get_section_in_dmmap_with_options_eq("dmmap_bridge_port", "bridge_port", "port", op_value,"management","0"))
			continue;
		
		if ((dmmap_sect = get_dup_section_in_dmmap_opt(dmmap_package, section, "device", op_value)) == NULL){
			dmuci_add_section_bbfdm(dmmap_package, section, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "package", "dmmap_ethernet");
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "name", op_value);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "device", op_value);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "enabled", "1");
			adm_entry_get_reference_param(ctx, "Device.Ethernet.Interface.*.Name", op_value, &lowerlayer);
			if (lowerlayer != NULL)
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "LowerLayers", lowerlayer);

		}

		conf_sec = get_dup_section_in_config_opt("network", "device", "name", op_value);

		add_dmmap_config_dup_list(dup_list, conf_sec, dmmap_sect);

	}

	//add the user added links
	uci_path_foreach_sections_safe(bbfdm, "dmmap_ethernet", "link", stmp, s) {

		char *added = NULL;

		dmuci_get_value_by_section_string(s, "added_by_user", &added);
		if(DM_LSTRCMP(added, "1") == 0)
			add_dmmap_config_dup_list(dup_list, s, s);
	}

	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section, stmp, s) {

		char *v = NULL, *package = NULL;

		dmuci_get_value_by_section_string(s, "added_by_user", &v);
		if(DM_LSTRCMP(v, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "package", &package);
		if (DM_STRNCMP(package, "dmmap_ethernet",strlen("dmmap_ethernet")) != 0)
			continue;
			
		dmuci_get_value_by_section_string(s, "device", &v);
		if (get_dup_section_in_dmmap_opt(package, "interface", "ethernet_iface_name", v) == NULL)
			dmuci_delete_by_section(s, NULL, NULL);
		if (get_section_in_dmmap_with_options_eq("dmmap_bridge_port", "bridge_port", "port", v,"management","0"))
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

static char *find_net_sys_device(struct uci_section *s)
{
	char *package = NULL, *device = NULL, *inst = NULL;

	dmuci_get_value_by_section_string(s, "package", &package);

	if (DM_LSTRNCMP(package, "dmmap_ethernet", 14) == 0){

		dmuci_get_value_by_section_string(s, "device", &device);
		return device;
		
	}else if (DM_LSTRNCMP(package, "dmmap_bridge", 12) == 0){

		dmuci_get_value_by_section_string(s, "device", &device);
		return device;
		
	}else if (DM_LSTRNCMP(package, "dmmap_wireless", 14) == 0){

		dmuci_get_value_by_section_string(s, "name", &device);
		return device;

	}else if (DM_LSTRNCMP(package, "dmmap_cellular", 14) == 0){
				
		dmuci_get_value_by_section_string(s, "device", &inst);
		while(!isdigit(*inst++));
		(inst--);
		dmasprintf(&device, "wwan%s", inst);
		return device;
		
	}
	return NULL;
}

static char *find_l3_interface(struct uci_section *s)
{
	struct uci_section *if_dmmap_sec = NULL;
	char *link_inst = NULL, *ifname = NULL;
	char eth_link[64] = {0};

	dmuci_get_value_by_section_string(s, "link_instance", &link_inst);
	snprintf(eth_link, sizeof(eth_link), "Device.Ethernet.Link.%s", link_inst);

	if_dmmap_sec = get_dup_section_in_dmmap_opt("dmmap_network", "interface", "LowerLayers", eth_link);
	
	if (if_dmmap_sec == NULL)
		return NULL;
				
	dmuci_get_value_by_section_string(if_dmmap_sec, "section_name", &ifname);

	return ifname;
}



/*************************************************************
* ENTRY METHOD
**************************************************************/

static int browseEthernetInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DIR *dir = NULL;
	struct dirent *ent = NULL;
	char *inst = NULL;
	size_t length;
	char **foldersplit;
	struct ethernet_interface iface = {0};
	LIST_HEAD(dup_list);
	struct sysfs_dmsection *p = NULL;
	

	synchronize_ethernet_sysfs_with_dmmap(SYSFS_NET_DEVICES_PATH, "dmmap_ethernet", "interface", "ethernet_iface_name", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char statistics_path[652] = {0};
		char iface_path[620] = {0};
		char netfolderpath[256] = {0};
		char iface_name[260] = {0};
		char port_link[128] = {0};

		snprintf(netfolderpath, sizeof(netfolderpath), "%s", p->sysfs_folder_path);
		
		if (!folder_exists(netfolderpath))
			continue;

		if (p->dmmap_section) {
			foldersplit= strsplit(p->sysfs_folder_name, ":", &length);
			snprintf(port_link, sizeof(port_link), "%s", foldersplit[0]);
		}
		sysfs_foreach_file(netfolderpath, dir, ent) {
			if(DM_LSTRCMP(ent->d_name, ".")==0 || DM_LSTRCMP(ent->d_name, "..")==0)
				continue;
			foldersplit= strsplit(p->sysfs_folder_name, ":", &length);
			snprintf(iface_name, sizeof(iface_name), "%s", foldersplit[0]);
			break;
		}
		if (dir)
			closedir(dir);

		strncpy(iface_path, netfolderpath,sizeof(iface_path));
		if (p->dmmap_section)
			dmuci_set_value_by_section_bbfdm(p->dmmap_section, "ethernet_iface_path", iface_path);

		snprintf(statistics_path, sizeof(statistics_path), "%s/statistics", iface_path);
		init_ethernet_interface(p->dmmap_section, iface_name, iface_path, statistics_path, port_link, &iface);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "ethernet_iface_instance", "ethernet_iface_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, &iface, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseEthernetLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dm_data *curr_data = NULL;
	char *inst = NULL;
	struct ethernet_link link = {0};
	LIST_HEAD(dup_list);
	
	dmmap_synchronize_EthernetLink_from_dmmap_bridge_port(dmctx, "dmmap_ethernet", "link", &dup_list);
	dmmap_synchronize_EthernetLink_from_dmmap_wireless(dmctx, "dmmap_ethernet", "link", &dup_list);
	dmmap_synchronize_EthernetLink_from_dmmap_cellular(dmctx, "dmmap_ethernet", "link", &dup_list);
	dmmap_synchronize_EthernetLink_from_dmmap_ethernet(dmctx, "dmmap_ethernet", "link", &dup_list);

	list_for_each_entry(curr_data, &dup_list, list) {
		
		init_ethernet_link(curr_data->dmmap_section, curr_data->config_section, &link);
		inst = handle_instance(dmctx, parent_node, curr_data->dmmap_section, "link_instance", "link_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &link, inst) == DM_STOP)
		break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseEthernetVLANTerminationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dm_data *curr_data = NULL;
	char *inst = NULL;
	struct ethernet_vlan vlan = {0};
	LIST_HEAD(dup_list);

	//dmmap_synchronize_EthernetVLAN(dmctx, "network", "dmmap_ethernet_vlan", "VLAN_Termination", &dup_list);
	list_for_each_entry(curr_data, &dup_list, list) {
		
		init_ethernet_vlan(curr_data->dmmap_section, curr_data->config_section, &vlan);
		inst = handle_instance(dmctx, parent_node, curr_data->dmmap_section, "vlan_instance", "vlan_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &vlan, inst) == DM_STOP)
		break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseEthernetRMONStatsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

static int browseEthernetLAGInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjEthernetLink(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL;
	char s_name[32] = {0};

	snprintf(s_name, sizeof(s_name), "link_%s", *instance);

	dmuci_add_section_bbfdm("dmmap_ethernet", "link", &dmmap);
	dmuci_set_value_by_section(dmmap, "name", s_name);
	dmuci_set_value_by_section(dmmap, "enabled", "0");
	dmuci_set_value_by_section(dmmap, "added_by_user", "1");
	dmuci_set_value_by_section(dmmap, "link_instance", *instance);

	return 0;
}

static int delObjEthernetLink(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{

	switch (del_action) {
		case DEL_INST:
			
			// Remove dmmap section
			dmuci_delete_by_section(((struct ethernet_link *)data)->dm_ethernet_link, NULL, NULL);
			break;
		case DEL_ALL:
			//TODO
			break;
	}
	return 0;
}

static int addObjEthernetVLANTermination(char *refparam, struct dmctx *ctx, void *data, char **instance)
{

	return 0;
}

static int delObjEthernetVLANTermination(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			//TODO
			
			break;
		case DEL_ALL:
			//TODO
			break;
	}
	return 0;
}

static int addObjEthernetRMONStats(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

static int delObjEthernetRMONStats(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			//TODO
			break;
		case DEL_ALL:
			//TODO
			break;
	}
	return 0;
}

static int addObjEthernetLAG(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

static int delObjEthernetLAG(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			//TODO
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
static int get_Ethernet_WoLSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_Ethernet_FlowControlSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_Ethernet_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseEthernetInterfaceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Ethernet_LinkNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseEthernetLinkInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Ethernet_VLANTerminationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseEthernetVLANTerminationInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Ethernet_RMONStatsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseEthernetRMONStatsInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Ethernet_LAGNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseEthernetLAGInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_EthernetInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *carrier;

	read_sysfs_ethernet_iface(data, "carrier", &carrier);

	if (carrier[0] == '1')
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_EthernetInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//Should be empty
			break;
	}
	return 0;
}

static int get_EthernetInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *carrier;

	read_sysfs_ethernet_iface(data, "carrier", &carrier);

	if (carrier[0] == '1')
		*value = "Up";
	else
		*value = "Down";
	return 0;
}

static int get_EthernetInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct ethernet_interface *)data)->dm_ethernet_iface, "ethernet_interface_alias", instance, value);
}

static int set_EthernetInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			return bbf_set_alias(ctx, ((struct ethernet_interface *)data)->dm_ethernet_iface, "ethernet_interface_alias", instance, value);
			break;
	}
	return 0;
}

static int get_EthernetInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct ethernet_interface *ethiface= (struct ethernet_interface *)data;
	dmasprintf(value, "%s", ethiface->iface_name);
	return 0;
}

static int get_EthernetInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char ubus_call[32];

	snprintf(ubus_call, sizeof(ubus_call), "network.interface.%s",((struct ethernet_interface *)data)->iface_name);
	dmubus_call(ubus_call, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	return 0;
}

static int get_EthernetInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_EthernetInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//Should be empty
			break;
	}
	return 0;
}

static int get_EthernetInterface_Upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char *carrier;

	read_sysfs_ethernet_iface(data, "carrier", &carrier);
	if (carrier[0] == '1'){
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", ((struct ethernet_interface *)data)->iface_name, String}}, 1, &res);
		json_object *jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
		char *ipaddr = dmjson_get_value(jobj, 1, "address");
		*value = check_ip_private(ipaddr)? "0" : "1";
	}else{
		*value = "0";
	}
	
	return 0;
}

static int get_EthernetInterface_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_iface(data, "address", value);
}

static int get_EthernetInterface_SupportedLinkModes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_iface(data, "link_mode", value);
}

static int get_EthernetInterface_MaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetInterface_MaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetInterface_CurrentBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_iface(data, "speed", value);

}

static int get_EthernetInterface_DuplexMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_iface(data, "duplex", value);
}

static int set_EthernetInterface_DuplexMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, DuplexMode, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetInterface_EEECapability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetInterface_EEEEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetInterface_EEEEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetInterface_EEEStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetInterfaceStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_net_iface(data, "statistics/tx_bytes", value);
}

static int get_EthernetInterfaceStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_net_iface(data, "statistics/rx_bytes", value);
}

static int get_EthernetInterfaceStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_net_iface(data, "statistics/tx_packets", value);
}

static int get_EthernetInterfaceStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_net_iface(data, "statistics/rx_packets", value);
}

static int get_EthernetInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_net_iface(data, "statistics/tx_errors", value);
}

static int get_EthernetInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_net_iface(data, "statistics/rx_errors", value);
}

static int get_EthernetInterfaceStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetInterfaceStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetInterfaceStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_net_iface(data, "statistics/tx_dropped", value);
}

static int get_EthernetInterfaceStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_net_iface(data, "statistics/rx_dropped", value);
}

static int get_EthernetInterfaceStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetInterfaceStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return read_sysfs_ethernet_net_iface(data, "statistics/multicast", value);
}

static int get_EthernetInterfaceStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetInterfaceStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetInterfaceStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLink_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct ethernet_link *)data)->dm_ethernet_link, "enabled", value);
	*value = ((*value)[0] == '1') ? "1" : "0";
	return 0;	
}

static int set_EthernetLink_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	struct uci_section *if_conf_sec = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);

			if (!if_conf_sec)
				return 0;	

			if (b){
				dmuci_delete_by_section(if_conf_sec, "disabled", NULL);
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "enabled", "1");
			}else{
				dmuci_set_value_by_section(if_conf_sec, "disabled", "1");
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "enabled", "0");
			}
			dmubus_call_set("network", "reload", UBUS_ARGS{0}, 0);
			return 0;
	}
	return 0;
}

static int get_EthernetLink_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char *device = NULL;

	device = find_net_sys_device(((struct ethernet_link *)data)->dm_ethernet_link);
	
	if (device == NULL){
		*value = "Down";
		return 0;
	}

	dmubus_call("network.device", "status", UBUS_ARGS{{"name", device, String}}, 1, &res);
	DM_ASSERT(res, *value = "Down");

	char *isup = dmjson_get_value(res, 1, "up");
	*value = (DM_STRCMP(isup, "true") == 0) ? "Up" : "Down";
	return 0;
}

static int get_EthernetLink_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct ethernet_link *)data)->dm_ethernet_link, "ethernet_link_alias", instance, value);
}

static int set_EthernetLink_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			return bbf_set_alias(ctx, ((struct ethernet_interface *)data)->dm_ethernet_iface, "ethernet_link_alias", instance, value);
			break;
	}
	return 0;
}

static int get_EthernetLink_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct ethernet_link *)data)->dm_ethernet_link, "name", value);
	return 0;
}

static int get_EthernetLink_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char *interface_name = NULL;
	char ubus_call[32];

	interface_name = find_l3_interface(((struct ethernet_link *)data)->dm_ethernet_link);

	if (interface_name == NULL){
		*value = "0";
		return 0;
	}

	snprintf(ubus_call, sizeof(ubus_call), "network.interface.%s", interface_name);
	dmubus_call(ubus_call, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");

	return 0;
}

static int get_EthernetLink_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct ethernet_link *)data)->dm_ethernet_link, "LowerLayers", "");
	return 0;
}

static int set_EthernetLink_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {
			"Device.Ethernet.Interface.",
			"Device.WiFi.SSID.",
			"Device.Bridging.Bridge.*.Port.",
			NULL
	};
	struct dm_reference reference = {0};

	char *inst = NULL, *name = NULL;

	bbf_get_reference_args(value, &reference);

	inst = strrchr(value, '.')+1;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;	
			if (!isdigit_str(inst))
				return FAULT_9007;

			break;
		case VALUESET:

			// Store LowerLayers value under dmmap_network section;
			dmuci_set_value_by_section_bbfdm(((struct ethernet_link *)data)->dm_ethernet_link, "LowerLayers", value);

			if (DM_LSTRNCMP(value, "Device.Ethernet.Interface.", 26) == 0){
				
				struct uci_section *if_dmmap_sec = get_dup_section_in_dmmap_opt("dmmap_ethernet", "interface", "ethernet_iface_instance", inst);
				dmuci_get_value_by_section_string(if_dmmap_sec, "ethernet_iface_name", &name);
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "package", "dmmap_ethernet");
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "device", name);
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "enabled", "1");
			}else if (DM_LSTRNCMP(value, "Device.Bridging.Bridge.", 23) == 0){

				struct uci_section *if_dmmap_sec = get_dup_section_in_dmmap_opt("dmmap_bridge_port", "bridge_port", "br_inst", inst);
				dmuci_get_value_by_section_string(if_dmmap_sec, "port", &name);
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "package", "dmmap_bridge_port");
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "device", name);
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "enabled", "1");
			}else if (DM_LSTRNCMP(value, "Device.WiFi.SSID.", 17) == 0){
				
				struct uci_section *if_dmmap_sec = get_dup_section_in_dmmap_opt("dmmap_wireless", "ssid", "ssid_instance", inst);
				dmuci_get_value_by_section_string(if_dmmap_sec, "name", &name);
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "package", "dmmap_wireless");
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "device", name);
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "enabled", "1");
			}else if (DM_LSTRNCMP(value, "dmmap_cellular", 14) == 0){
				
				struct uci_section *if_dmmap_sec = get_dup_section_in_dmmap_opt("dmmap_cellular", "interface", "cellular_iface_instance", inst);
				dmuci_get_value_by_section_string(if_dmmap_sec, "section_name", &name);
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "package", "dmmap_cellular");
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "device", name);
				dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "enabled", "1");
			}

			dmuci_commit_package("network");
			
			break;
	}
	return 0;
}

static int get_EthernetLink_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct ethernet_link *)data)->dm_ethernet_link, "macaddr", value);
	if (*value[0] == '\0'){
		char *device = find_net_sys_device(((struct ethernet_link *)data)->dm_ethernet_link);
		if (device){
			get_net_device_sysfs(device, "address", value);
			dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link,"macaddr", *value);
		}
	}
	return 0;
}

static int set_EthernetLink_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 17, NULL, MACAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct ethernet_link *)data)->dm_ethernet_link, "macaddr", value);
			dmuci_set_value_by_section(((struct ethernet_link *)data)->config_section, "macaddr", value);
			dmuci_commit_package("network");
			dmubus_call_set("network", "reload", UBUS_ARGS{0}, 0);
			break;
	}
	return 0;
}

static int get_EthernetLink_PriorityTagging(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetLink_PriorityTagging(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetLink_FlowControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetLink_FlowControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetLinkStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct ethernet_link *)data)->dm_ethernet_link);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/tx_bytes", value);
}

static int get_EthernetLinkStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct ethernet_link *)data)->dm_ethernet_link);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/rx_bytes", value);
}

static int get_EthernetLinkStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct ethernet_link *)data)->dm_ethernet_link);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/tx_packets", value);
}

static int get_EthernetLinkStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct ethernet_link *)data)->dm_ethernet_link);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/rx_packets", value);
}

static int get_EthernetLinkStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct ethernet_link *)data)->dm_ethernet_link);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/tx_errors", value);
}

static int get_EthernetLinkStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct ethernet_link *)data)->dm_ethernet_link);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/rx_errors", value);
}

static int get_EthernetLinkStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLinkStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLinkStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct ethernet_link *)data)->dm_ethernet_link);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/tx_dropped", value);
}

static int get_EthernetLinkStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct ethernet_link *)data)->dm_ethernet_link);
	if (device == NULL)
		return 0;

	return get_net_device_sysfs(device, "statistics/rx_dropped", value);
}

static int get_EthernetLinkStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLinkStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = find_net_sys_device(((struct ethernet_link *)data)->dm_ethernet_link);
	if (device == NULL)
		return 0;
	
	return get_net_device_sysfs(device, "statistics/multicast", value);
}

static int get_EthernetLinkStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLinkStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLinkStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetVLANTermination_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int set_EthernetVLANTermination_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//noyhing to do
			return 0;
	}
	return 0;
}

static int get_EthernetVLANTermination_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char *name = NULL;

	dmuci_get_value_by_section_string(((struct ethernet_vlan *)data)->config_section, "name", &name);
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", name, String}}, 1, &res);
	DM_ASSERT(res, *value = "Down");

	char *isup = dmjson_get_value(res, 1, "up");
	*value = (DM_STRCMP(isup, "false") == 0) ? "Down" : "Up";
	return 0;
}

static int get_EthernetVLANTermination_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct ethernet_vlan *)data)->dm_ethernet_vlan, "ethernet_vlan_alias", instance, value);
}

static int set_EthernetVLANTermination_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			return bbf_set_alias(ctx, ((struct ethernet_vlan *)data)->dm_ethernet_vlan, "ethernet_vlan_alias", instance, value);
			break;
	}
	return 0;
}

static int get_EthernetVLANTermination_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct ethernet_vlan *)data)->config_section, "name", value);
	return 0;
}

static int get_EthernetVLANTermination_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	struct uci_section *dmmap_sect;
	char *name = NULL;

	dmuci_get_value_by_section_string(((struct ethernet_vlan *)data)->config_section, "name", &name);
	dmmap_sect = get_dup_section_in_config_opt("network", "interface", "device", name);
	if (dmmap_sect == NULL){
		*value = "0";
		return 0;
	}
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(dmmap_sect), String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	return 0;
}

static int get_EthernetVLANTermination_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifname = NULL;
	dmuci_get_value_by_section_string(((struct ethernet_vlan *)data)->config_section, "ifname", &ifname);
	adm_entry_get_reference_param(ctx, "Device.Ethernet.Link.*.Name", ifname, value);
	return 0;
}

static int set_EthernetVLANTermination_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetVLANTermination_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct ethernet_link *)data)->dm_ethernet_link, "vlan_id", value);
	return 0;
}

static int set_EthernetVLANTermination_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_sect;
	char *device = NULL, *vlan_d = NULL;
	char new_vlan_d[16] = {0};

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			struct uci_section *s = (((struct ethernet_vlan *)data)->config_section);
			dmuci_get_value_by_section_string(((struct ethernet_vlan *)data)->config_section, "device", &device);
			vlan_d = find_vlan_iface_conf(((struct ethernet_vlan *)data));
			dmmap_sect = get_dup_section_in_config_opt("network", "interface", "device", vlan_d);

			snprintf(new_vlan_d,sizeof(new_vlan_d),"%s.%s",device,value);
			dmuci_set_value_by_section(s, "vlan", value);
			dmuci_set_value_by_section(dmmap_sect, "device", new_vlan_d);
			dmuci_commit_package("network");
			dmubus_call_set("network", "reload", UBUS_ARGS{0}, 0);
			break;
	}
	return 0;
}

static int get_EthernetVLANTermination_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetVLANTermination_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetVLANTerminationStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vlan_d = NULL;

	vlan_d = find_vlan_iface_conf(((struct ethernet_vlan *)data));
	return get_net_device_sysfs(vlan_d,"statistics/tx_bytes", value);
}

static int get_EthernetVLANTerminationStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vlan_d = NULL;
	
	vlan_d = find_vlan_iface_conf(((struct ethernet_vlan *)data));
	return get_net_device_sysfs(vlan_d,"statistics/rx_bytes", value);
}

static int get_EthernetVLANTerminationStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vlan_d = NULL;
	
	vlan_d = find_vlan_iface_conf(((struct ethernet_vlan *)data));
	return get_net_device_sysfs(vlan_d,"statistics/tx_packets", value);
}

static int get_EthernetVLANTerminationStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vlan_d = NULL;
	
	vlan_d = find_vlan_iface_conf(((struct ethernet_vlan *)data));
	return get_net_device_sysfs(vlan_d,"statistics/rx_packets", value);
}

static int get_EthernetVLANTerminationStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vlan_d = NULL;
	
	vlan_d = find_vlan_iface_conf(((struct ethernet_vlan *)data));
	return get_net_device_sysfs(vlan_d,"statistics/tx_errors", value);
}

static int get_EthernetVLANTerminationStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vlan_d = NULL;
	
	vlan_d = find_vlan_iface_conf(((struct ethernet_vlan *)data));
	return get_net_device_sysfs(vlan_d,"statistics/rx_errors", value);
}

static int get_EthernetVLANTerminationStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetVLANTerminationStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vlan_d = NULL;
	
	vlan_d = find_vlan_iface_conf(((struct ethernet_vlan *)data));
	return get_net_device_sysfs(vlan_d,"statistics/rx_unicast_packets", value);
}

static int get_EthernetVLANTerminationStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vlan_d = NULL;
	
	vlan_d = find_vlan_iface_conf(((struct ethernet_vlan *)data));
	return get_net_device_sysfs(vlan_d,"statistics/tx_dropped", value);
}

static int get_EthernetVLANTerminationStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vlan_d = NULL;
	
	vlan_d = find_vlan_iface_conf(((struct ethernet_vlan *)data));
	return get_net_device_sysfs(vlan_d,"statistics/rx_dropped", value);
}

static int get_EthernetVLANTerminationStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetVLANTerminationStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vlan_d = NULL;
	
	vlan_d = find_vlan_iface_conf(((struct ethernet_vlan *)data));
	return get_net_device_sysfs(vlan_d,"statistics/multicast", value);
}

static int get_EthernetVLANTerminationStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetVLANTerminationStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetVLANTerminationStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetRMONStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetRMONStats_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetRMONStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_EthernetRMONStats_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetRMONStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_EthernetRMONStats_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetRMONStats_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"0","4094"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetRMONStats_Queue(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetRMONStats_Queue(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_EthernetRMONStats_AllQueues(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetRMONStats_AllQueues(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetRMONStats_DropEvents(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_Packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_BroadcastPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_MulticastPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_CRCErroredPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_UndersizePackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_OversizePackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_Packets64Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_Packets65to127Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_Packets128to255Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_Packets256to511Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_Packets512to1023Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetRMONStats_Packets1024to1518Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetWoL_SendMagicPacket(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetWoL_SendMagicPacket(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetWoL_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetWoL_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 17, NULL, MACAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetWoL_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetWoL_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_EthernetLAG_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetLAG_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetLAG_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAG_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetLAG_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_EthernetLAG_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAG_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAG_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetLAG_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetLAG_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetLAG_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 17, NULL, MACAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetLAGStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_EthernetLAGStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*************************************************************
* OPERATE COMMANDS
**************************************************************/
static operation_args ethernetwol_sendmagicpacket_args = {
    .in = (const char *[]) {
        "MACAddress",
        "Password",
        NULL
    }
};

static int get_operate_args_EthernetWoL_SendMagicPacket(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    *value = (char *)&ethernetwol_sendmagicpacket_args;
    return 0;
}

static int operate_EthernetWoL_SendMagicPacket(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
    //TODO
    return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Ethernet. *** */
DMOBJ tEthernetObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys */
{"Interface", &DMREAD, NULL, NULL, NULL, browseEthernetInterfaceInst, NULL, NULL, tEthernetInterfaceObj, tEthernetInterfaceParams, NULL, BBFDM_BOTH, NULL},
{"Link", &DMWRITE, addObjEthernetLink, delObjEthernetLink, NULL, browseEthernetLinkInst, NULL, NULL, tEthernetLinkObj, tEthernetLinkParams, NULL, BBFDM_BOTH, NULL},
{"VLANTermination", &DMWRITE, addObjEthernetVLANTermination, delObjEthernetVLANTermination, NULL, browseEthernetVLANTerminationInst, NULL, NULL, tEthernetVLANTerminationObj, tEthernetVLANTerminationParams, NULL, BBFDM_BOTH, NULL},
{"RMONStats", &DMWRITE, addObjEthernetRMONStats, delObjEthernetRMONStats, NULL, browseEthernetRMONStatsInst, NULL, NULL, NULL, tEthernetRMONStatsParams, NULL, BBFDM_BOTH, NULL},
{"WoL", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetWoLParams, NULL, BBFDM_BOTH, NULL},
{"LAG", &DMWRITE, addObjEthernetLAG, delObjEthernetLAG, NULL, browseEthernetLAGInst, NULL, NULL, tEthernetLAGObj, tEthernetLAGParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tEthernetParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"WoLSupported", &DMREAD, DMT_BOOL, get_Ethernet_WoLSupported, NULL, BBFDM_BOTH},
{"FlowControlSupported", &DMREAD, DMT_BOOL, get_Ethernet_FlowControlSupported, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{"LinkNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_LinkNumberOfEntries, NULL, BBFDM_BOTH},
{"VLANTerminationNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_VLANTerminationNumberOfEntries, NULL, BBFDM_BOTH},
{"RMONStatsNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_RMONStatsNumberOfEntries, NULL, BBFDM_BOTH},
{"LAGNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_LAGNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Interface.{i}. *** */
DMOBJ tEthernetInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys */
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetInterfaceStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tEthernetInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetInterface_Enable, set_EthernetInterface_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetInterface_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetInterface_Alias, set_EthernetInterface_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetInterface_Name, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_EthernetInterface_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetInterface_LowerLayers, set_EthernetInterface_LowerLayers, BBFDM_BOTH},
{"Upstream", &DMREAD, DMT_BOOL, get_EthernetInterface_Upstream, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_EthernetInterface_MACAddress, NULL, BBFDM_BOTH},
{"SupportedLinkModes", &DMREAD, DMT_STRING, get_EthernetInterface_SupportedLinkModes, NULL, BBFDM_BOTH},
{"MaxBitRate", &DMWRITE, DMT_INT, get_EthernetInterface_MaxBitRate, set_EthernetInterface_MaxBitRate, BBFDM_BOTH},
{"CurrentBitRate", &DMREAD, DMT_UNINT, get_EthernetInterface_CurrentBitRate, NULL, BBFDM_BOTH},
{"DuplexMode", &DMWRITE, DMT_STRING, get_EthernetInterface_DuplexMode, set_EthernetInterface_DuplexMode, BBFDM_BOTH},
{"EEECapability", &DMREAD, DMT_BOOL, get_EthernetInterface_EEECapability, NULL, BBFDM_BOTH},
{"EEEEnable", &DMWRITE, DMT_BOOL, get_EthernetInterface_EEEEnable, set_EthernetInterface_EEEEnable, BBFDM_BOTH},
{"EEEStatus", &DMREAD, DMT_STRING, get_EthernetInterface_EEEStatus, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Interface.{i}.Stats. *** */
DMLEAF tEthernetInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Link.{i}. *** */
DMOBJ tEthernetLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys */
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetLinkStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tEthernetLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetLink_Enable, set_EthernetLink_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetLink_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetLink_Alias, set_EthernetLink_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetLink_Name, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_EthernetLink_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetLink_LowerLayers, set_EthernetLink_LowerLayers, BBFDM_BOTH},
{"MACAddress", &DMWRITE, DMT_STRING, get_EthernetLink_MACAddress, set_EthernetLink_MACAddress, BBFDM_BOTH},
{"PriorityTagging", &DMWRITE, DMT_BOOL, get_EthernetLink_PriorityTagging, set_EthernetLink_PriorityTagging, BBFDM_BOTH},
{"FlowControl", &DMWRITE, DMT_BOOL, get_EthernetLink_FlowControl, set_EthernetLink_FlowControl, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Link.{i}.Stats. *** */
DMLEAF tEthernetLinkStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetLinkStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetLinkStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetLinkStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetLinkStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetLinkStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.VLANTermination.{i}. *** */
DMOBJ tEthernetVLANTerminationObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys */
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetVLANTerminationStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tEthernetVLANTerminationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetVLANTermination_Enable, set_EthernetVLANTermination_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetVLANTermination_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetVLANTermination_Alias, set_EthernetVLANTermination_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetVLANTermination_Name, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_EthernetVLANTermination_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetVLANTermination_LowerLayers, set_EthernetVLANTermination_LowerLayers, BBFDM_BOTH},
{"VLANID", &DMWRITE, DMT_UNINT, get_EthernetVLANTermination_VLANID, set_EthernetVLANTermination_VLANID, BBFDM_BOTH},
{"TPID", &DMWRITE, DMT_UNINT, get_EthernetVLANTermination_TPID, set_EthernetVLANTermination_TPID, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.VLANTermination.{i}.Stats. *** */
DMLEAF tEthernetVLANTerminationStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.RMONStats.{i}. *** */
DMLEAF tEthernetRMONStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetRMONStats_Enable, set_EthernetRMONStats_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetRMONStats_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetRMONStats_Alias, set_EthernetRMONStats_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetRMONStats_Name, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_EthernetRMONStats_Interface, set_EthernetRMONStats_Interface, BBFDM_BOTH},
{"VLANID", &DMWRITE, DMT_UNINT, get_EthernetRMONStats_VLANID, set_EthernetRMONStats_VLANID, BBFDM_BOTH},
{"Queue", &DMWRITE, DMT_STRING, get_EthernetRMONStats_Queue, set_EthernetRMONStats_Queue, BBFDM_BOTH},
{"AllQueues", &DMWRITE, DMT_BOOL, get_EthernetRMONStats_AllQueues, set_EthernetRMONStats_AllQueues, BBFDM_BOTH},
{"DropEvents", &DMREAD, DMT_UNINT, get_EthernetRMONStats_DropEvents, NULL, BBFDM_BOTH},
{"Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Bytes, NULL, BBFDM_BOTH},
{"Packets", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets, NULL, BBFDM_BOTH},
{"BroadcastPackets", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_BroadcastPackets, NULL, BBFDM_BOTH},
{"MulticastPackets", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_MulticastPackets, NULL, BBFDM_BOTH},
{"CRCErroredPackets", &DMREAD, DMT_UNINT, get_EthernetRMONStats_CRCErroredPackets, NULL, BBFDM_BOTH},
{"UndersizePackets", &DMREAD, DMT_UNINT, get_EthernetRMONStats_UndersizePackets, NULL, BBFDM_BOTH},
{"OversizePackets", &DMREAD, DMT_UNINT, get_EthernetRMONStats_OversizePackets, NULL, BBFDM_BOTH},
{"Packets64Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets64Bytes, NULL, BBFDM_BOTH},
{"Packets65to127Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets65to127Bytes, NULL, BBFDM_BOTH},
{"Packets128to255Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets128to255Bytes, NULL, BBFDM_BOTH},
{"Packets256to511Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets256to511Bytes, NULL, BBFDM_BOTH},
{"Packets512to1023Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets512to1023Bytes, NULL, BBFDM_BOTH},
{"Packets1024to1518Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets1024to1518Bytes, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.WoL. *** */
DMLEAF tEthernetWoLParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"SendMagicPacket", &DMWRITE, DMT_BOOL, get_EthernetWoL_SendMagicPacket, set_EthernetWoL_SendMagicPacket, BBFDM_CWMP},
{"MACAddress", &DMWRITE, DMT_STRING, get_EthernetWoL_MACAddress, set_EthernetWoL_MACAddress, BBFDM_CWMP},
{"Password", &DMWRITE, DMT_STRING, get_EthernetWoL_Password, set_EthernetWoL_Password, BBFDM_CWMP},
{"SendMagicPacket()", &DMASYNC, DMT_COMMAND, get_operate_args_EthernetWoL_SendMagicPacket, operate_EthernetWoL_SendMagicPacket, BBFDM_USP},
{0}
};

/* *** Device.Ethernet.LAG.{i}. *** */
DMOBJ tEthernetLAGObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys */
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetLAGStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tEthernetLAGParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetLAG_Enable, set_EthernetLAG_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetLAG_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetLAG_Alias, set_EthernetLAG_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetLAG_Name, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_EthernetLAG_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetLAG_LowerLayers, set_EthernetLAG_LowerLayers, BBFDM_BOTH},
{"MACAddress", &DMWRITE, DMT_STRING, get_EthernetLAG_MACAddress, set_EthernetLAG_MACAddress, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.LAG.{i}.Stats. *** */
DMLEAF tEthernetLAGStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type */
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetLAGStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetLAGStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLAGStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLAGStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetLAGStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetLAGStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLAGStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLAGStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetLAGStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetLAGStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLAGStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLAGStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLAGStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLAGStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetLAGStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

