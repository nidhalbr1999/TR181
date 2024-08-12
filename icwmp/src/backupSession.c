/*
 * backupSession.c - API to store/load CWMP session in/from backup XML files
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

#include <unistd.h>

#include "backupSession.h"
#include "log.h"
#include "event.h"
#include "sched_inform.h"
#include "download.h"
#include "upload.h"
#include "cwmp_du_state.h"
#include "notifications.h"
#include "xml.h"
#include "cwmp_event.h"

static mxml_node_t *bkp_tree = NULL;

int cwmp_init_backup_session(char **ret, enum backup_loading load)
{
	if (bkp_session_check_file())
		return 0;

	return cwmp_load_saved_session(ret, load);
}

void bkp_tree_clean(void)
{
	if (bkp_tree != NULL)
		MXML_DELETE(bkp_tree);
	return;
}

void bkp_session_save()
{
	FILE *fp;
	if (!bkp_tree)
		return;
	fp = fopen(CWMP_BKP_FILE, "w");
	mxmlSaveFile(bkp_tree, fp, MXML_NO_CALLBACK);
	fclose(fp);
	sync();
}

void bkp_session_create_file()
{
	FILE *pFile;

	pFile = fopen(CWMP_BKP_FILE, "w");
	if (pFile == NULL) {
		CWMP_LOG(ERROR, "Unable to create %s file", CWMP_BKP_FILE);
		return;
	}
	fprintf(pFile, "%s", CWMP_BACKUP_SESSION);
	if (bkp_tree != NULL)
		MXML_DELETE(bkp_tree);
	bkp_tree = mxmlLoadString(NULL, CWMP_BACKUP_SESSION, MXML_OPAQUE_CALLBACK);
	fclose(pFile);
}

int bkp_session_check_file()
{
	if (!file_exists(CWMP_BKP_FILE)) {
		bkp_session_create_file();
		return -1;
	}

	if (bkp_tree == NULL) {
		FILE *pFile;
		pFile = fopen(CWMP_BKP_FILE, "r");
		bkp_tree = mxmlLoadFile(NULL, pFile, MXML_OPAQUE_CALLBACK);
		fclose(pFile);
	}

	if (bkp_tree == NULL) {
		bkp_session_create_file();
		return -1;
	}
	bkp_session_save();
	return 0;
}

int save_acs_bkp_config()
{
	CWMP_LOG(DEBUG, "%s:%d entry", __func__, __LINE__);
	bkp_session_simple_insert("acs", "URL", cwmp_main->conf.acs_url);
	bkp_session_save();
	CWMP_LOG(DEBUG, "%s:%d exit", __func__, __LINE__);
	return CWMP_OK;
}

mxml_node_t *bkp_session_node_found(mxml_node_t *tree, char *name, struct search_keywords *keys, int size)
{
	mxml_node_t *b = tree, *c, *d;
	struct search_keywords;
	int i = 0;
	if (!tree)
		return NULL;
	b = mxmlFindElement(b, b, name, NULL, NULL, MXML_DESCEND_FIRST);
	while (b) {
		c = mxmlGetFirstChild(b);
		if (c) {
			i = 0;
			while (c && i < size) {
				if (mxmlGetType(c) == MXML_ELEMENT && CWMP_STRCMP(keys[i].name, (char *) mxmlGetElement(c)) == 0) {
					d = c;
					d = mxmlWalkNext(d, c, MXML_DESCEND);
					if ((keys[i].value == NULL) || (d && mxmlGetType(d) == MXML_OPAQUE && CWMP_STRCMP(keys[i].value, mxmlGetOpaque(d)) == 0))
						i++;
				}
				c = mxmlWalkNext(c, b, MXML_NO_DESCEND);
			}
		}
		if (i == size)
			break;

		b = mxmlWalkNext(b, tree, MXML_NO_DESCEND);
	}
	return b;
}

mxml_node_t *get_bkp_session_node_by_id(mxml_node_t *tree, char *name, int id)
{
	struct search_keywords keys[1];
	char bkp_id[32];

	snprintf(bkp_id, sizeof(bkp_id), "%d", id);
	keys[0].name = "id";
	keys[0].value = bkp_id;

	return bkp_session_node_found(tree, name, keys, 1);
}

mxml_node_t *get_bkp_session_node_by_key(mxml_node_t *tree, char *name, char *key_name, char *key_value)
{
	struct search_keywords keys[1];

	keys[0].name = key_name;
	keys[0].value = key_value;

	return bkp_session_node_found(tree, name, keys, 1);
}
/*
 * Insert Backup Session
 */
mxml_node_t *bkp_session_insert(mxml_node_t *tree, char *name, char *value)
{
	mxml_node_t *b;
	if (tree == NULL || name == NULL) {
		CWMP_LOG(ERROR, "backup %s: tree or name is null: %p %p", __FUNCTION__, tree, name);
		return NULL;
	}
	b = mxmlNewElement(tree, name);
	if (b == NULL)
		return NULL;

	if (value != NULL)
		mxmlNewOpaque(b, value);

	return b;
}

void bkp_session_simple_insert(char *parent, char *child, char *value)
{
	mxml_node_t *b = bkp_tree;

	if (parent == NULL || child == NULL) {
		CWMP_LOG(ERROR, "backup %s: parent or child is null %p %p", __FUNCTION__, parent, child);
		return;
	}
	b = mxmlFindElement(b, b, parent, NULL, NULL, MXML_DESCEND);
	if (b)
		mxmlDelete(b);
	b = bkp_session_insert(bkp_tree, parent, NULL);
	bkp_session_insert(b, child, value);
}

void bkp_session_simple_insert_in_parent(char *parent, char *child, char *value)
{
	mxml_node_t *n, *b = bkp_tree;

	if (parent == NULL || child == NULL) {
		CWMP_LOG(ERROR, "backup %s: parent or child is null %p %p", __FUNCTION__, parent, child);
		return;
	}
	n = mxmlFindElement(b, b, parent, NULL, NULL, MXML_DESCEND);
	if (!n)
		n = bkp_session_insert(bkp_tree, parent, NULL);
	b = mxmlFindElement(n, n, child, NULL, NULL, MXML_DESCEND);
	if (b)
		mxmlDelete(b);
	bkp_session_insert(n, child, value);
}

mxml_node_t *bkp_session_insert_event(int index, char *command_key, int id)
{
	char event_idx[32];
	mxml_node_t *b;

	snprintf(event_idx, sizeof(event_idx), "%d", index);
	b = get_bkp_session_node_by_id(bkp_tree, "cwmp_event", id);
	if (!b) {
		struct xml_data_struct bkp_xml_event = {0};
		bkp_xml_event.command_key = command_key ? &command_key : NULL;
		bkp_xml_event.id = &id;
		bkp_xml_event.index = &index;
		int fault = build_xml_node_data(BKP_EVT_BUILD, bkp_tree, &bkp_xml_event);
		if (fault != CWMP_OK)
			return NULL;
	}
	b = get_bkp_session_node_by_id(bkp_tree, "cwmp_event", id);
	return b;
}

void bkp_session_insert_schedule_inform(int id, time_t time, char *command_key)
{
	mxml_node_t *b;

	b = get_bkp_session_node_by_id(bkp_tree, "schedule_inform", id);
	if (!b) {
		struct xml_data_struct bkp_xml_sched_inform = {0};
		bkp_xml_sched_inform.command_key = command_key ? &command_key : NULL;
		bkp_xml_sched_inform.time = (int *)&time;
		bkp_xml_sched_inform.id = &id;
		build_xml_node_data(BKP_SCHEDULE_INFORM_BUILD, bkp_tree, &bkp_xml_sched_inform);
	}
}

void bkp_session_insert_download(struct download *pdownload)
{
	mxml_node_t *b;

	b = get_bkp_session_node_by_id(bkp_tree, "download", pdownload->id);
	if (!b) {
		struct xml_data_struct bkp_xml_download = {0};
		bkp_xml_download.url = pdownload->url ? &pdownload->url : NULL;
		bkp_xml_download.command_key = pdownload->command_key ? &pdownload->command_key : NULL;
		bkp_xml_download.file_type = pdownload->file_type ? &pdownload->file_type : NULL;
		bkp_xml_download.username = pdownload->username ? &pdownload->username : NULL;
		bkp_xml_download.password = pdownload->password ? &pdownload->password : NULL;
		bkp_xml_download.file_size = &pdownload->file_size;
		bkp_xml_download.time = (int *)&pdownload->scheduled_time;
		bkp_xml_download.id = &pdownload->id;
		build_xml_node_data(BKP_DOWNLOAD_BUILD, bkp_tree, &bkp_xml_download);
	}
}

void bkp_session_insert_schedule_download(struct download *pschedule_download)
{
	mxml_node_t *b;

	b = get_bkp_session_node_by_id(bkp_tree, "schedule_download", pschedule_download->id);
	if (!b) {
		struct xml_data_struct bkp_xml_sched_download = {0};
		bkp_xml_sched_download.url = pschedule_download->url ? &pschedule_download->url : NULL;
		bkp_xml_sched_download.command_key = pschedule_download->command_key ? &pschedule_download->command_key : NULL;
		bkp_xml_sched_download.file_type = pschedule_download->file_type ? &pschedule_download->file_type : NULL;
		bkp_xml_sched_download.username = pschedule_download->username ? &pschedule_download->username : NULL;
		bkp_xml_sched_download.password = pschedule_download->password ? &pschedule_download->password : NULL;
		bkp_xml_sched_download.file_size = &pschedule_download->file_size;

		bkp_xml_sched_download.window_start1 = &pschedule_download->timewindowstruct[0].windowstart;
		bkp_xml_sched_download.window_start2 = &pschedule_download->timewindowstruct[1].windowstart;
		bkp_xml_sched_download.window_end1 = &pschedule_download->timewindowstruct[0].windowend;
		bkp_xml_sched_download.window_end2 = &pschedule_download->timewindowstruct[1].windowend;
		bkp_xml_sched_download.user_message1 = &pschedule_download->timewindowstruct[0].usermessage;
		bkp_xml_sched_download.user_message2 = &pschedule_download->timewindowstruct[1].usermessage;
		bkp_xml_sched_download.window_mode1 = &pschedule_download->timewindowstruct[0].windowmode;
		bkp_xml_sched_download.window_mode2 = &pschedule_download->timewindowstruct[1].windowmode;
		bkp_xml_sched_download.max_retries1 = &pschedule_download->timewindowstruct[0].maxretries;
		bkp_xml_sched_download.max_retries2 = &pschedule_download->timewindowstruct[1].maxretries;
		bkp_xml_sched_download.id = &pschedule_download->id;
		build_xml_node_data(BKP_SCHED_DOWNLOAD_BUILD, bkp_tree, &bkp_xml_sched_download);
	}
}

void bkp_session_insert_change_du_state(struct change_du_state *pchange_du_state)
{
	LIST_HEAD(cdu_operations_xml_list);
	struct xml_data_struct bkp_xml_cdu = {0};
	bkp_xml_cdu.time = (int *)&pchange_du_state->timeout;
	bkp_xml_cdu.command_key = &pchange_du_state->command_key;
	bkp_xml_cdu.id = &pchange_du_state->id;
	cdu_operations_list_to_xml_data_list(&(pchange_du_state->list_operation), &cdu_operations_xml_list);
	bkp_xml_cdu.data_list = &cdu_operations_xml_list;
	build_xml_node_data(BKP_CDU_BUILD, bkp_tree, &bkp_xml_cdu);
}

void bkp_session_insert_upload(struct upload *pupload)
{
	mxml_node_t *b;

	b = get_bkp_session_node_by_id(bkp_tree, "upload", pupload->id);
	if (!b) {
		struct xml_data_struct bkp_xml_upload = {0};
		bkp_xml_upload.command_key = &pupload->command_key;
		bkp_xml_upload.file_type = &pupload->file_type;
		bkp_xml_upload.username = &pupload->username;
		bkp_xml_upload.password = &pupload->password;
		bkp_xml_upload.time = (int *)&pupload->scheduled_time;
		bkp_xml_upload.url = &pupload->url;
		bkp_xml_upload.id = &pupload->id;
		build_xml_node_data(BKP_UPLOAD_BUILD, bkp_tree, &bkp_xml_upload);
	}
}

void bkp_session_insert_autonomous_du_state_change(auto_du_state_change_compl *data)
{
	mxml_node_t *b;

	if (data == NULL)
		return;

	b = get_bkp_session_node_by_id(bkp_tree, "autonomous_du_state_change_complete", data->id);
	if (!b) {
		struct xml_data_struct bkp_xml_auto_cdu = {0};
		bkp_xml_auto_cdu.uuid = &data->uuid;
		bkp_xml_auto_cdu.version = data->ver ? &data->ver : NULL;
		bkp_xml_auto_cdu.current_state = data->current_state ? &data->current_state : NULL;
		bkp_xml_auto_cdu.resolved = &data->resolved;
		bkp_xml_auto_cdu.start_time = data->start_time ? &data->start_time : NULL;
		bkp_xml_auto_cdu.complete_time = data->complete_time ? &data->complete_time : NULL;
		bkp_xml_auto_cdu.fault_code = &data->fault_code;
		bkp_xml_auto_cdu.fault_string = data->fault_string ? &data->fault_string : NULL;
		bkp_xml_auto_cdu.operation = data->operation ? &data->operation : NULL;
		bkp_xml_auto_cdu.id = &data->id;
		build_xml_node_data(BKP_AUTO_CDU_BUILD, bkp_tree, &bkp_xml_auto_cdu);
	}
}

void bkp_session_insert_autonomous_transfer_complete(auto_transfer_complete *data)
{
	mxml_node_t *b;

	if (data == NULL)
		return;

	b = get_bkp_session_node_by_id(bkp_tree, "autonomous_transfer_complete", data->id);
	if (!b) {
		struct xml_data_struct bkp_xml_auto_tc = {0};
		bkp_xml_auto_tc.announce_url = data->announce_url ? &data->announce_url : NULL;
		bkp_xml_auto_tc.transfer_url = data->transfer_url ? &data->transfer_url : NULL;
		bkp_xml_auto_tc.is_download = &data->is_download;
		bkp_xml_auto_tc.file_type = data->file_type ? &data->file_type : NULL;
		bkp_xml_auto_tc.file_size = &data->file_size;
		bkp_xml_auto_tc.start_time = data->start_time ? &data->start_time : NULL;
		bkp_xml_auto_tc.complete_time = data->complete_time ? &data->complete_time : NULL;
		bkp_xml_auto_tc.fault_code = &data->fault_code;
		bkp_xml_auto_tc.fault_string = data->fault_string ? &data->fault_string : NULL;
		bkp_xml_auto_tc.id = &data->id;
		build_xml_node_data(BKP_AUTO_TRANSFER_COMPLETE_BUILD, bkp_tree, &bkp_xml_auto_tc);
	}
}

void bkp_session_insert_du_state_change_complete(struct du_state_change_complete *pdu_state_change_complete)
{
	struct xml_data_struct bkp_xml_auto_cdu_complete = {0};
	LIST_HEAD(opresult_xml_data_list);
	cdu_operations_result_list_to_xml_data_list(&(pdu_state_change_complete->list_opresult), &opresult_xml_data_list);
	bkp_xml_auto_cdu_complete.command_key = &pdu_state_change_complete->command_key;
	bkp_xml_auto_cdu_complete.time = (int *)&pdu_state_change_complete->timeout;
	bkp_xml_auto_cdu_complete.data_list = &opresult_xml_data_list;
	bkp_xml_auto_cdu_complete.id = &pdu_state_change_complete->id;
	build_xml_node_data(BKP_CDU_COMPLETE_BUILD, bkp_tree, &bkp_xml_auto_cdu_complete);
}

void bkp_session_insert_transfer_complete(struct transfer_complete *ptransfer_complete)
{
	mxml_node_t *b;

	b = get_bkp_session_node_by_key(bkp_tree, "transfer_complete", "start_time", ptransfer_complete->start_time);
	if (!b) {
		struct xml_data_struct bkp_xml_tc = {0};

		bkp_xml_tc.command_key = ptransfer_complete->command_key ? &ptransfer_complete->command_key : NULL;
		bkp_xml_tc.start_time = ptransfer_complete->start_time ? &ptransfer_complete->start_time : NULL;
		bkp_xml_tc.complete_time = ptransfer_complete->complete_time ? &ptransfer_complete->complete_time : NULL;
		bkp_xml_tc.old_software_version = ptransfer_complete->old_software_version ? &ptransfer_complete->old_software_version : NULL;
		bkp_xml_tc.fault_code = &ptransfer_complete->fault_code;
		bkp_xml_tc.fault_string = ptransfer_complete->fault_string ? &ptransfer_complete->fault_string : NULL;
		bkp_xml_tc.type = &ptransfer_complete->type;
		build_xml_node_data(BKP_TRANSFER_COMPLETE_BUILD, bkp_tree, &bkp_xml_tc);
	}
}

/*
 * Load backup session
 */
static char *load_child_value(mxml_node_t *tree, char *sub_name)
{
	char *value = NULL;
	mxml_node_t *b = tree;

	if (b) {
		b = mxmlFindElement(b, b, sub_name, NULL, NULL, MXML_DESCEND);
		if (b) {
			b = mxmlWalkNext(b, tree, MXML_DESCEND);
			if (b && mxmlGetType(b) == MXML_OPAQUE) {
				const char *opaque = mxmlGetOpaque(b);
				if (opaque != NULL) {
					value = strdup(opaque);
				}
			}
		}
	}

	return value;
}

static void load_queue_event(mxml_node_t *tree)
{
	int idx = -1, id = -1;

	struct xml_data_struct bkp_xml_evt = {0};
	bkp_xml_evt.index = &idx;
	bkp_xml_evt.id = &id;
	load_xml_node_data(BKP_EVT_LOAD, tree, &bkp_xml_evt);
}

static void load_schedule_inform(mxml_node_t *tree)
{
	char *command_key = NULL;
	time_t scheduled_time = 0;
	struct schedule_inform *schedule_inform = NULL;
	struct list_head *ilist = NULL;

	struct xml_data_struct bkp_xml_schedule_inform = {0};
	bkp_xml_schedule_inform.command_key = &command_key;
	bkp_xml_schedule_inform.time = (int *)&scheduled_time;
	load_xml_node_data(BKP_SCHEDULE_INFORM, tree, &bkp_xml_schedule_inform);

	list_for_each (ilist, &(list_schedule_inform)) {
		schedule_inform = list_entry(ilist, struct schedule_inform, list);
		if (schedule_inform->scheduled_time > scheduled_time) {
			break;
		}
	}
	schedule_inform = calloc(1, sizeof(struct schedule_inform));
	if (schedule_inform != NULL) {
		schedule_inform->commandKey = command_key;
		schedule_inform->scheduled_time = scheduled_time;
		list_add(&(schedule_inform->list), ilist->prev);
	}
}

static void load_download(mxml_node_t *tree)
{
	struct download *download_request = NULL;
	struct list_head *ilist = NULL;
	struct download *idownload_request = NULL;

	if (tree == NULL) {
		CWMP_LOG(ERROR, "backup %s: tree is null", __FUNCTION__);
		return;
	}
	download_request = calloc(1, sizeof(struct download));
	if (download_request == NULL) {
		CWMP_LOG(ERROR, "backup %s: download_request is null", __FUNCTION__);
		return;
	}

	struct xml_data_struct bkp_xml_download = {0};
	bkp_xml_download.command_key = &download_request->command_key;
	bkp_xml_download.url = &download_request->url;
	bkp_xml_download.file_type = &download_request->file_type;
	bkp_xml_download.username = &download_request->username;
	bkp_xml_download.password = &download_request->password;
	bkp_xml_download.file_size = &download_request->file_size;
	bkp_xml_download.time = (int *)&download_request->scheduled_time;
	bkp_xml_download.id = &download_request->id;
	load_xml_node_data(BKP_DOWNLOAD, tree, &bkp_xml_download);

	download_request->handler_timer.cb = cwmp_start_download;

	list_for_each (ilist, &(list_download)) {
		idownload_request = list_entry(ilist, struct download, list);
		if (idownload_request->scheduled_time > download_request->scheduled_time) {
			break;
		}
	}
	list_add(&(download_request->list), ilist->prev);
	if (download_request->scheduled_time != 0)
		count_download_queue++;
	cwmp_set_end_session(END_SESSION_DOWNLOAD);
}

static void load_schedule_download(mxml_node_t *tree)
{
	struct download *download_request = NULL;
	struct list_head *ilist = NULL;
	struct download *idownload_request = NULL;

	if (tree == NULL) {
		CWMP_LOG(ERROR, "backup %s: tree is null", __FUNCTION__);
		return;
	}
	download_request = calloc(1, sizeof(struct download));
	if (download_request == NULL) {
		CWMP_LOG(ERROR, "backup %s: download_request is null", __FUNCTION__);
		return;
	}

	struct xml_data_struct bkp_xml_sched_download = {0};
	bkp_xml_sched_download.command_key = &download_request->command_key;
	bkp_xml_sched_download.url = &download_request->url;
	bkp_xml_sched_download.file_type = &download_request->file_type;
	bkp_xml_sched_download.username = &download_request->username;
	bkp_xml_sched_download.password = &download_request->password;
	bkp_xml_sched_download.file_size = &download_request->file_size;

	bkp_xml_sched_download.window_start1 = &download_request->timewindowstruct[0].windowstart;
	bkp_xml_sched_download.window_start2 = &download_request->timewindowstruct[1].windowstart;
	bkp_xml_sched_download.window_end1 = &download_request->timewindowstruct[0].windowend;
	bkp_xml_sched_download.window_end2 = &download_request->timewindowstruct[1].windowend;
	bkp_xml_sched_download.window_mode1 = &download_request->timewindowstruct[0].windowmode;
	bkp_xml_sched_download.window_mode2 = &download_request->timewindowstruct[1].windowmode;
	bkp_xml_sched_download.user_message1 = &download_request->timewindowstruct[0].usermessage;
	bkp_xml_sched_download.user_message2 = &download_request->timewindowstruct[1].usermessage;
	bkp_xml_sched_download.max_retries1 = &download_request->timewindowstruct[0].maxretries;
	bkp_xml_sched_download.max_retries2 = &download_request->timewindowstruct[1].maxretries;
	bkp_xml_sched_download.id = &download_request->id;
	load_xml_node_data(BKP_SCHED_DOWNLOAD, tree, &bkp_xml_sched_download);

	list_for_each (ilist, &(list_schedule_download)) {
		idownload_request = list_entry(ilist, struct download, list);
		if (idownload_request->timewindowstruct[0].windowstart > download_request->timewindowstruct[0].windowstart) {
			break;
		}
	}
	list_add(&(download_request->list), ilist->prev);
	if (download_request->timewindowstruct[0].windowstart != 0)
		count_download_queue++;
	cwmp_set_end_session(END_SESSION_SCHEDULE_DOWNLOAD);
}

static void load_upload(mxml_node_t *tree)
{
	struct upload *upload_request = NULL;
	struct list_head *ilist = NULL;
	struct upload *iupload_request = NULL;

	if (tree == NULL) {
		CWMP_LOG(ERROR, "backup %s: tree is null", __FUNCTION__);
		return;
	}
	upload_request = calloc(1, sizeof(struct upload));
	if (upload_request == NULL) {
		CWMP_LOG(ERROR, "backup %s: download_request is null", __FUNCTION__);
		return;
	}

	struct xml_data_struct bkp_xml_upload = {0};
	bkp_xml_upload.url = &upload_request->url;
	bkp_xml_upload.command_key = &upload_request->command_key;
	bkp_xml_upload.file_type = &upload_request->file_type;
	bkp_xml_upload.username = &upload_request->username;
	bkp_xml_upload.password = &upload_request->password;
	bkp_xml_upload.time = (int *)&upload_request->scheduled_time;
	bkp_xml_upload.id = &upload_request->id;
	load_xml_node_data(BKP_UPLOAD, tree, &bkp_xml_upload);

	list_for_each (ilist, &(list_upload)) {
		iupload_request = list_entry(ilist, struct upload, list);
		if (iupload_request->scheduled_time > upload_request->scheduled_time) {
			break;
		}
	}
	list_add(&(upload_request->list), ilist->prev);
	if (upload_request->scheduled_time != 0)
		count_upload_queue++;
	cwmp_set_end_session(END_SESSION_UPLOAD);
}

static void load_change_du_state(mxml_node_t *tree)
{
	if (tree == NULL) {
		CWMP_LOG(ERROR, "backup %s: tree is null", __FUNCTION__);
		return;
	}

	struct change_du_state *change_du_state_request = NULL;
	change_du_state_request = calloc(1, sizeof(struct change_du_state));
	INIT_LIST_HEAD(&(change_du_state_request->list_operation));

	struct xml_data_struct bkp_xml_cdu = {0};
	bkp_xml_cdu.command_key = &change_du_state_request->command_key;
	bkp_xml_cdu.time = (int *)&change_du_state_request->timeout;
	bkp_xml_cdu.cdu = change_du_state_request;
	bkp_xml_cdu.id = &change_du_state_request->id;
	load_xml_node_data(BKP_CDU, tree, &bkp_xml_cdu);

	list_add_tail(&(change_du_state_request->list_operation), &(list_change_du_state));
	cwmp_set_end_session(END_SESSION_CDU);
}

void load_du_state_change_complete(mxml_node_t *tree)
{
	struct du_state_change_complete *du_state_change_complete_request = NULL;

	du_state_change_complete_request = calloc(1, sizeof(struct du_state_change_complete));
	INIT_LIST_HEAD(&(du_state_change_complete_request->list_opresult));

	struct xml_data_struct bkp_xml_cdu_complete = {0};
	bkp_xml_cdu_complete.command_key = &du_state_change_complete_request->command_key;
	bkp_xml_cdu_complete.time = (int *)&du_state_change_complete_request->timeout;
	bkp_xml_cdu_complete.id = &du_state_change_complete_request->id;
	bkp_xml_cdu_complete.cdu_complete = du_state_change_complete_request;
	load_xml_node_data(BKP_CDU_COMPLETE, tree, &bkp_xml_cdu_complete);

	cwmp_root_cause_changedustate_complete(du_state_change_complete_request);
}

static void load_transfer_complete(mxml_node_t *tree)
{
	struct transfer_complete *ptransfer_complete;

	ptransfer_complete = calloc(1, sizeof(struct transfer_complete));

	struct xml_data_struct bkp_xml_transfer_complete = {0};
	bkp_xml_transfer_complete.command_key = &ptransfer_complete->command_key;
	bkp_xml_transfer_complete.start_time = &ptransfer_complete->start_time;
	bkp_xml_transfer_complete.complete_time = &ptransfer_complete->complete_time;
	bkp_xml_transfer_complete.old_software_version = &ptransfer_complete->old_software_version;
	bkp_xml_transfer_complete.fault_code = &ptransfer_complete->fault_code;
	bkp_xml_transfer_complete.fault_string = &ptransfer_complete->fault_string;
	bkp_xml_transfer_complete.type = &ptransfer_complete->type;

	load_xml_node_data(BKP_TRANSFER_COMPLETE, tree, &bkp_xml_transfer_complete);

	cwmp_root_cause_transfer_complete(ptransfer_complete);
	sotfware_version_value_change(ptransfer_complete);
}

static void load_autonomous_du_state_change_complete(mxml_node_t *tree)
{
	auto_du_state_change_compl *p;

	p = calloc(1, sizeof(auto_du_state_change_compl));

	struct xml_data_struct bkp_xml_auto_change_complete = {0};
	bkp_xml_auto_change_complete.uuid = &p->uuid;
	bkp_xml_auto_change_complete.version = &p->ver;
	bkp_xml_auto_change_complete.current_state = &p->current_state;
	bkp_xml_auto_change_complete.resolved = &p->resolved;
	bkp_xml_auto_change_complete.start_time = &p->start_time;
	bkp_xml_auto_change_complete.complete_time = &p->complete_time;
	bkp_xml_auto_change_complete.fault_code = &p->fault_code;
	bkp_xml_auto_change_complete.fault_string = &p->fault_string;
	bkp_xml_auto_change_complete.operation = &p->operation;
	bkp_xml_auto_change_complete.id = &p->id;
	load_xml_node_data(BKP_AUTO_CDU, tree, &bkp_xml_auto_change_complete);

	cwmp_root_cause_autonomous_cdu_complete(p);
}

static void load_autonomous_transfer_complete(mxml_node_t *tree)
{
	auto_transfer_complete *p;

	p = calloc(1, sizeof(auto_transfer_complete));

	struct xml_data_struct bkp_xml_auto_transfer_complete = {0};
	bkp_xml_auto_transfer_complete.announce_url = &p->announce_url;
	bkp_xml_auto_transfer_complete.transfer_url = &p->transfer_url;
	bkp_xml_auto_transfer_complete.is_download = &p->is_download;
	bkp_xml_auto_transfer_complete.file_type = &p->file_type;
	bkp_xml_auto_transfer_complete.file_size = &p->file_size;
	bkp_xml_auto_transfer_complete.start_time = &p->start_time;
	bkp_xml_auto_transfer_complete.complete_time = &p->complete_time;
	bkp_xml_auto_transfer_complete.fault_code = &p->fault_code;
	bkp_xml_auto_transfer_complete.fault_string = &p->fault_string;
	bkp_xml_auto_transfer_complete.id = &p->id;
	load_xml_node_data(BKP_AUTO_TRANSFER_COMPLETE, tree, &bkp_xml_auto_transfer_complete);

	cwmp_root_cause_autonomous_transfer_complete(p);
}

int cwmp_load_saved_session(char **ret, enum backup_loading load)
{
	mxml_node_t *b;

	b = bkp_tree;
	b = mxmlWalkNext(b, bkp_tree, MXML_DESCEND);
	while (b) {
		mxml_type_t ntype = mxmlGetType(b);
		const char *elem_name = mxmlGetElement(b);
		if (load == ACS) {
			if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "acs") == 0) {
				*ret = load_child_value(b, "URL");
				break;
			}
		}
		if (load == CR_IP) {
			if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "connection_request") == 0) {
				*ret = load_child_value(b, "ip");
				break;
			}
		}
		if (load == CR_IPv6) {
			if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "connection_request") == 0) {
				*ret = load_child_value(b, "ipv6");
				break;
			}
		}
		if (load == CR_PORT) {
			if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "connection_request") == 0) {
				*ret = load_child_value(b, "port");
				break;
			}
		}
		if (load == ALL) {
			if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "cwmp_event") == 0) {
				load_queue_event(b);
			} else if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "download") == 0) {
				load_download(b);
			} else if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "upload") == 0) {
				load_upload(b);
			} else if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "transfer_complete") == 0) {
				load_transfer_complete(b);
			} else if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "schedule_inform") == 0) {
				load_schedule_inform(b);
			} else if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "change_du_state") == 0) {
				load_change_du_state(b);
			} else if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "du_state_change_complete") == 0) {
				load_du_state_change_complete(b);
			} else if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "schedule_download") == 0) {
				load_schedule_download(b);
			} else if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "autonomous_du_state_change_complete") == 0) {
				load_autonomous_du_state_change_complete(b);
			} else if (ntype == MXML_ELEMENT && CWMP_STRCMP(elem_name, "autonomous_transfer_complete") == 0) {
				load_autonomous_transfer_complete(b);
			}
		}
		b = mxmlWalkNext(b, bkp_tree, MXML_NO_DESCEND);
	}

	return CWMP_OK;
}

/*
 * Delete Backup Session
 */
void bkp_session_delete_element(char *element_name, int id)
{
	mxml_node_t *b = get_bkp_session_node_by_id(bkp_tree, element_name, id);
	if (b)
		mxmlDelete(b);
}

void bkp_session_delete_element_by_key(char *element_name, char *key_name, char *key_value)
{
	mxml_node_t *b = get_bkp_session_node_by_key(bkp_tree, element_name, key_name, key_value);
	if (b)
		mxmlDelete(b);
}
