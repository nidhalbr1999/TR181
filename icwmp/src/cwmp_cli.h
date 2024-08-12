/*
 * cwmp_cli.h - icwmp CLI
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef CWMP_CLI
#define CWMP_CLI

#include "datamodel_interface.h"

union cmd_result {
	struct list_head *param_list;
	struct object_result obj_res;
};

struct cmd_input {
	char *first_input;
	char *second_input;
	char *third_input;
};

char *cmd_get_exec_func(struct cmd_input in, union cmd_result *res);
char *cmd_set_exec_func(struct cmd_input in, union cmd_result *res);
char *cmd_add_exec_func(struct cmd_input in, union cmd_result *res);
char *cmd_del_exec_func(struct cmd_input in, union cmd_result *res);
char *cmd_get_notif_exec_func(struct cmd_input in, union cmd_result *res);
char *cmd_set_notif_exec_func(struct cmd_input in, union cmd_result *res __attribute__((unused)));
char *cmd_get_names_exec_func(struct cmd_input in, union cmd_result *res);
char *execute_cwmp_cli_command(char *cmd, char *args[]);
#endif
