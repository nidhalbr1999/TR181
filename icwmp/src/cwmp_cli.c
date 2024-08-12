/*
 * cwmp_cli.c - icwmp CLI
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#include <string.h>

#include "common.h"
#include "cwmp_cli.h"
#include "notifications.h"

LIST_HEAD(parameters_list);

struct fault_resp {
	int fault_index;
	char *fault_code;
	char *fault_message;
};

struct cwmp_cli_command_struct {
	char *command_name;
	char *(*cmd_exec_func)(struct cmd_input in, union cmd_result *out);
	void (*display_cmd_result)(struct cmd_input in, union cmd_result res, char *fault);
};

const struct fault_resp faults_array[] = {
		{ FAULT_CPE_INTERNAL_ERROR, "9002", "Internal error" }, //Internal error
		{ FAULT_CPE_INVALID_PARAMETER_NAME, "9003", "Invalid arguments" }, //Invalid arguments
		{ FAULT_CPE_INVALID_PARAMETER_NAME, "9005", "Invalid parameter name" }, //Invalid parameter name
		{ FAULT_CPE_INVALID_PARAMETER_VALUE, "9007", "Invalid parameter value" }, //Invalid Parameter value
		{ FAULT_CPE_NON_WRITABLE_PARAMETER, "9008", "Attempt to set a non-writable parameter" }, //Non writable parameter
		{ FAULT_CPE_NOTIFICATION_REJECTED, "9009", "Notification request rejected" }
};

static char *get_fault_message_by_fault_code(char *fault_code)
{
	for (size_t i = 0; i < ARRAY_SIZE(faults_array); i++) {
		if (CWMP_STRCMP(faults_array[i].fault_code, fault_code) == 0)
			return faults_array[i].fault_message;
	}
	return NULL;
}

/*
 * Get_Values
 */
char *cmd_get_exec_func(struct cmd_input in, union cmd_result *res)
{
	res->param_list = &parameters_list;
	char *fault = cwmp_get_parameter_values(in.first_input, res->param_list);
	return fault;
}

static void display_get_cmd_result(struct cmd_input in __attribute__((unused)), union cmd_result res, char *fault)
{
	if (fault != NULL) {
		fprintf(stderr, "Fault %s: %s\n", fault, get_fault_message_by_fault_code(fault));
		return;
	}

	struct cwmp_dm_parameter *param_value = NULL;
	list_for_each_entry (param_value, res.param_list, list) {
		fprintf(stdout, "%s => %s\n", param_value->name, param_value->value);
	}
	cwmp_free_all_dm_parameter_list(&parameters_list);
}

/*
 * Set_Values
 */
char *cmd_set_exec_func(struct cmd_input in, union cmd_result *res)
{
	if (CWMP_STRLEN(in.first_input) == 0)
		return "9003";

	LIST_HEAD(faults_list);

	int fault_idx = cwmp_set_parameter_value(in.first_input, in.second_input, &faults_list);
	if (fault_idx != FAULT_CPE_NO_FAULT) {
		struct cwmp_param_fault *param_fault = NULL;
		char *fault = NULL;

		list_for_each_entry (param_fault, &faults_list, list) {
			res->obj_res.fault_code = param_fault->fault_code;
			snprintf(res->obj_res.fault_msg, sizeof(res->obj_res.fault_msg), "%s", param_fault->fault_msg);
			break;
		}
		cwmp_free_all_list_param_fault(&faults_list);

		icwmp_asprintf(&fault, "%d", res->obj_res.fault_code);
		return fault;
	}

	set_rpc_parameter_key(in.third_input);

	return NULL;
}

static void display_set_cmd_result(struct cmd_input in, union cmd_result res, char *fault)
{
	if (fault == NULL) {
		fprintf(stdout, "Set value is successfully done\n");
		fprintf(stdout, "%s => %s\n", in.first_input, in.second_input);
		return;
	}

	fprintf(stderr, "Fault %s: %s\n", fault, res.obj_res.fault_msg);
}

/*
 * Add_Object
 */
char *cmd_add_exec_func(struct cmd_input in, union cmd_result *res)
{
	if (in.first_input == NULL)
		return "9003";

	bool status = cwmp_add_object(in.first_input, &res->obj_res);
	if (!status) {
		char *fault = NULL;

		icwmp_asprintf(&fault, "%d", res->obj_res.fault_code);
		return fault;
	}

	set_rpc_parameter_key(in.second_input);

	return NULL;
}

static void display_add_cmd_result(struct cmd_input in, union cmd_result res, char *fault)
{
	if (fault != NULL) {
		fprintf(stderr, "Fault %s: %s\n", fault, strlen(res.obj_res.fault_msg) ? res.obj_res.fault_msg : get_fault_message_by_fault_code(fault));
		return;
	}

	if (in.first_input[strlen(in.first_input) - 1] == '.')
		fprintf(stdout, "Added %s%s.\n", in.first_input, res.obj_res.instance);
	else
		fprintf(stdout, "Added %s.%s.\n", in.first_input, res.obj_res.instance);

	FREE(res.obj_res.instance);
}

/*
 * Delete_Object
 */
char *cmd_del_exec_func(struct cmd_input in, union cmd_result *res)
{
	if (in.first_input == NULL)
		return "9003";

	bool status = cwmp_delete_object(in.first_input, &res->obj_res);
	if (!status) {
		char *fault = NULL;

		icwmp_asprintf(&fault, "%d", res->obj_res.fault_code);
		return fault;
	}

	set_rpc_parameter_key(in.second_input);

	return NULL;
}

static void display_del_cmd_result(struct cmd_input in, union cmd_result res, char *fault)
{
	if (fault != NULL) {
		fprintf(stderr, "Fault %s: %s\n", fault, strlen(res.obj_res.fault_msg) ? res.obj_res.fault_msg : get_fault_message_by_fault_code(fault));
		return;
	}

	fprintf(stdout, "Deleted %s\n", in.first_input);
}

/*
 * Get_Notifications
 */
char *cmd_get_notif_exec_func(struct cmd_input in, union cmd_result *res)
{
	if (in.first_input == NULL)
		in.first_input = "";

	res->param_list = &parameters_list;

	return cwmp_get_parameter_attributes(in.first_input, res->param_list);
}

static void display_get_notif_cmd_result(struct cmd_input in __attribute__((unused)), union cmd_result res, char *fault)
{
	if (fault != NULL) {
		fprintf(stderr, "Fault %s: %s\n", fault, get_fault_message_by_fault_code(fault));
		return;
	}
	struct cwmp_dm_parameter *param_value = NULL;
	list_for_each_entry (param_value, res.param_list, list) {
		fprintf(stdout, "%s => %s\n", param_value->name, param_value->notification == 2 ? "active" : param_value->notification == 1 ? "passive" : "off");
	}
	cwmp_free_all_dm_parameter_list(&parameters_list);
}

/*
 * Set_Notifications
 */
char *cmd_set_notif_exec_func(struct cmd_input in, union cmd_result *res __attribute__((unused)))
{
	if (in.first_input == NULL || CWMP_STRLEN(in.second_input) == 0)
		return "9003";

	if (!icwmp_validate_int_in_range(in.second_input, 0, 6))
		return "9003";

	char *fault = cwmp_set_parameter_attributes(in.first_input, atoi(in.second_input));
	if (fault != NULL)
		return fault;

	return NULL;
}

static void display_set_notif_cmd_result(struct cmd_input in, union cmd_result res __attribute__((unused)), char *fault)
{
	if (fault != NULL) {
		fprintf(stderr, "Fault %s: %s\n", fault, get_fault_message_by_fault_code(fault));
		return;
	}
	fprintf(stdout, "%s => %s\n", in.first_input, in.second_input);
}

/*
 * Get_Names
 */
char *cmd_get_names_exec_func(struct cmd_input in, union cmd_result *res)
{
	if (in.first_input == NULL)
		in.first_input = "";
	res->param_list = &parameters_list;
	bool next_level = (CWMP_STRCMP(in.second_input, "1") == 0 || CWMP_LSTRCASECMP(in.second_input, "true") == 0) ? true : false;
	char *fault = cwmp_get_parameter_names(in.first_input, next_level, res->param_list);
	return fault;
}

static void display_get_names_cmd_result(struct cmd_input in __attribute__((unused)), union cmd_result res, char *fault)
{
	if (fault != NULL) {
		fprintf(stderr, "Fault %s: %s\n", fault, get_fault_message_by_fault_code(fault));
		return;
	}
	struct cwmp_dm_parameter *param_value = NULL;
	list_for_each_entry (param_value, res.param_list, list) {
		fprintf(stdout, "%s => %s\n", param_value->name, param_value->writable ? "writable" : "not-writable");
	}
	cwmp_free_all_dm_parameter_list(&parameters_list);
}

/*
 * Main
 */
static void cwmp_cli_help()
{
	printf("Valid commands:\n");
	printf("	help 					=> show this help\n");
	printf("	get [path-expr] 			=> get parameter values\n");
	printf("	get_names [path-expr] [next-level] 	=> get parameter names\n");
	printf("	set [path-expr] [value] [pkey]		=> set parameter value\n");
	printf("	add [object] [pkey] 				=> add object\n");
	printf("	del [object] [pkey]				=> delete object\n");
	printf("	get_notif [path-expr]			=> get parameter notifications\n");
	printf("	set_notif [path-expr] [notification]	=> set parameter notifications\n");
}

const struct cwmp_cli_command_struct icwmp_commands[] = {
	{ "get", cmd_get_exec_func, display_get_cmd_result }, //get_values
	{ "get_names", cmd_get_names_exec_func, display_get_names_cmd_result }, //get_names
	{ "set", cmd_set_exec_func, display_set_cmd_result }, //set_values
	{ "add", cmd_add_exec_func, display_add_cmd_result }, //add_object
	{ "del", cmd_del_exec_func, display_del_cmd_result }, //delete_object
	{ "get_notif", cmd_get_notif_exec_func, display_get_notif_cmd_result }, //get_notifications
	{ "set_notif", cmd_set_notif_exec_func, display_set_notif_cmd_result }, //set_notifications
};

char *execute_cwmp_cli_command(char *cmd, char *args[])
{
	if (CWMP_STRLEN(cmd) == 0) {
		printf("You must add a command as input: \n\n");
		goto cli_help;
	}

	if (CWMP_STRCMP(cmd, "help") == 0)
		goto cli_help;

	struct cmd_input cmd_in = {
			args[0] ? args[0] : NULL,
			args[0] && args[1] ? args[1] : "",
			args[0] && args[1] && args[2] ? args[2] : NULL
	};
	union cmd_result cmd_out = {0};
	char *fault = NULL, *fault_ret = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(icwmp_commands); i++) {
		if (CWMP_STRCMP(icwmp_commands[i].command_name, cmd) == 0) {
			fault = icwmp_commands[i].cmd_exec_func(cmd_in, &cmd_out);
			if (fault)
				fault_ret = strdup(fault);
			icwmp_commands[i].display_cmd_result(cmd_in, cmd_out, fault);
			goto cli_end;
		}
	}

	printf("Wrong cwmp cli command: %s\n", cmd);

cli_help:
	cwmp_cli_help();

cli_end:
	icwmp_cleanmem();

	return fault_ret;
}
