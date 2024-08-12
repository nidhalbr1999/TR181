/*
 * uci_utils.h - API to manage UCI packages/sections/options
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 * See LICENSE file for license related information.
 *
 */


#ifndef __UCI_UTILS_H
#define __UCI_UTILS_H

#include <uci.h>
#include <libubox/list.h>

#define ETC_DB_CONFIG "/etc/board-db/config"
#define UCI_CONFIG_DIR "/etc/config/"
#define VARSTATE_CONFIG "/var/state"
#define ICWMPD_CONFIG "/etc/icwmpd"

#define DHCP_OPTION_READ_MAX_RETRY 5
#define UCI_OPTION_READ_INTERVAL 5

#define section_name(s) s ? (s)->e.name : ""
struct strNode {
	struct list_head list;
	char path[BUF_SIZE_256];
};

void add_str_list(struct list_head *head, char *str);
void free_str_list(struct list_head *head);
int export_uci_package(char *package, const char *output_path);
int export_std_uci(const char *output_path);
int import_uci_package(char *package_name, const char *input_path);
int get_uci_path_value(const char *conf_dir, char *path, char *value, size_t max_value_len);
int get_uci_dm_list(const char *conf_dir, char *path, struct list_head *head, int notif_type);
int set_uci_path_value(const char *conf_dir, char *path, char *value);
int set_uci_list_value(const char *conf_dir, char *path, char *value);
int del_uci_list_value(const char *conf_dir, char *path, char *value);
int get_inform_parameters_uci(struct list_head *inform_head);
int commit_uci_package(char *package);
int get_global_config();


#endif
