/*
 * datamodel_interface.h - API to call BBF datamodel functions (set, get, add, delete, setattributes, getattributes, getnames, ...)
 *
 * Copyright (C) 2021-2023, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef SRC_DATAMODELIFACE_H_
#define SRC_DATAMODELIFACE_H_

#include "common.h"

struct object_result {
	char *instance;
	char fault_msg[256];
	int fault_code;
};

extern unsigned int transaction_id;

bool cwmp_transaction(const char *cmd);

bool cwmp_get_parameter_value(const char *parameter_name, struct cwmp_dm_parameter *dm_parameter);

char *cwmp_get_parameter_values(const char *parameter_name, struct list_head *parameters_list);
char *cwmp_get_parameter_names(const char *parameter_name, bool next_level, struct list_head *parameters_list);
char *cwmp_validate_parameter_name(const char *param_name, bool next_level, struct list_head *param_list);

int cwmp_set_parameter_value(const char *parameter_name, const char *parameter_value, struct list_head *faults_list);
int cwmp_set_multi_parameters_value(struct list_head *parameters_values_list, struct list_head *faults_list);

bool cwmp_add_object(const char *object_name, struct object_result *res);
bool cwmp_delete_object(const char *object_name, struct object_result *res);

#endif /* SRC_DATAMODELIFACE_H_ */
