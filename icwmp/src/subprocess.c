/*
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Copyright (C) 2013-2021 iopsys Software Solutions AB
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#include <stdbool.h>

#include "common.h"
#include "subprocess.h"
#include "log.h"

#define END_TASK "{\"task\":\"end\"}"
#define EXIT_TASK "{\"task\":\"exit\"}"

static int pipefd1[2], pipefd2[2];

bool check_task_name(char *task, char *name)
{
	struct blob_buf bbuf;

	if (task && strcmp(task, "{}") == 0)
		return false;

	CWMP_MEMSET(&bbuf, 0, sizeof(struct blob_buf));
	blob_buf_init(&bbuf, 0);

	if (blobmsg_add_json_from_string(&bbuf, task) == false) {
		blob_buf_free(&bbuf);
		return false;
	}

	const struct blobmsg_policy p[1] = { { "task", BLOBMSG_TYPE_STRING } };

	struct blob_attr *tb[1] = { NULL };
	blobmsg_parse(p, 1, tb, blobmsg_data(bbuf.head), blobmsg_len(bbuf.head));
	if (tb[0] == NULL)
		return false;

	char *task_name = blobmsg_get_string(tb[0]);

	if (CWMP_STRCMP(task_name, name) == 0) {
		blob_buf_free(&bbuf);
		return true;
	}
	blob_buf_free(&bbuf);
	return false;
}

bool check_task_is_end(char *task)
{
	return check_task_name(task, "end");
}

bool check_task_is_exit(char *task)
{
	return check_task_name(task, "exit");
}

int subprocess_start(task_function task_fun)
{
	if(task_fun == NULL)
		return CWMP_GEN_ERR;

	pid_t p;

    if (pipe(pipefd1) == -1) {
            CWMP_LOG(ERROR, "pipefd1 failed\n");
            return CWMP_GEN_ERR;
    }

    if (pipe(pipefd2) == -1) {
        CWMP_LOG(ERROR, "pipefd2 failed\n");
        return CWMP_GEN_ERR;
    }

	p = fork();
	if (p == 0) {
		while(1) {
			char from_parent[512];
			int ret = 0;

			read(pipefd1[0], from_parent, 512); //The received string should has the form {"task":"TaskName", "arg1_name":"xxx", "arg2_name":"xxxx"}
			if (strlen(from_parent) == 0)
				continue;

			//get the task name if the task name is end
			if (check_task_is_end(from_parent)) {
				exit((write(pipefd2[1], EXIT_TASK, strlen(EXIT_TASK)+1) == -1)
						? EXIT_FAILURE : EXIT_SUCCESS);
			}

			char *to_child = task_fun(from_parent);

			struct blob_buf bbuf;
			CWMP_MEMSET(&bbuf, 0, sizeof(struct blob_buf));
			blob_buf_init(&bbuf, 0);
			blobmsg_add_string(&bbuf, "ret", to_child ? to_child : "500");
			char *to_child_json = blobmsg_format_json(bbuf.head, true);

			ret = write(pipefd2[1], to_child_json, CWMP_STRLEN(to_child_json)+1);

			FREE(to_child);
			FREE(to_child_json);
			blob_buf_free(&bbuf);

			if (ret == -1) {
				exit(EXIT_FAILURE);
			}
		}
	}
    return CWMP_OK;
}

char *execute_task_in_subprocess(char *task)
{
	char *ret = NULL;
	int len = 0;

	len = CWMP_STRLEN(task);
	if (len == 0) {
		task = END_TASK;
		len = strlen(END_TASK);
	}

	if (write(pipefd1[1], task, len + 1) == -1) {
		CWMP_LOG(ERROR, "write to child failed\n");
		goto out;
	}

	while(1) {
		char from_child[512];
		read(pipefd2[0], from_child, 512);
		if(strlen(from_child) == 0)
			continue;
		//The received string from the child should has the format {"task":"exit"} or {"ret":"exit"}
		if (check_task_is_exit(from_child)){
			break;
		}

		struct blob_buf bbuf;
		CWMP_MEMSET(&bbuf, 0, sizeof(struct blob_buf));
		blob_buf_init(&bbuf, 0);
		if (blobmsg_add_json_from_string(&bbuf, from_child) == false) {
			blob_buf_free(&bbuf);
			continue;
		}
		const struct blobmsg_policy p[1] = { { "ret", BLOBMSG_TYPE_STRING } };
		struct blob_attr *tb[1] = { NULL };
		blobmsg_parse(p, 1, tb, blobmsg_data(bbuf.head), blobmsg_len(bbuf.head));
		if (tb[0] == NULL) {
			blob_buf_free(&bbuf);
			continue;
		}
		ret = blobmsg_get_string(tb[0]);
		if (write(pipefd1[1], END_TASK, strlen(END_TASK) +1) == -1) {
			CWMP_LOG(ERROR, "write to child failed\n");
			goto out;
		}
	}

out:
	close(pipefd2[1]);
	close(pipefd2[0]);
	close(pipefd1[0]);
	close(pipefd1[1]);

	return ret;
}
