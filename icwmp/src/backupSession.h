/*
 * backupSession.h - API to store/load CWMP session in/from backup XML files
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

#ifndef _BACKUPSESSION_H__
#define _BACKUPSESSION_H__

#include <mxml.h>
#include "common.h"

#define RPC_NO_STATUS -1
#define RPC_QUEUE 0
#define RPC_SEND 1

#define CWMP_BACKUP_SESSION "<cwmp></cwmp>"
#define CWMP_BKP_FILE "/var/run/icwmpd/icwmpd_backup_session.xml"
typedef enum backup_loading
{
	ALL,
	ACS,
	CR_IP,
	CR_IPv6,
	CR_PORT
} backup_loading;

struct search_keywords {
	char *name;
	char *value;
};

int cwmp_init_backup_session(char **ret, enum backup_loading load);
int bkp_session_check_file();
void bkp_session_save();
int cwmp_load_saved_session(char **acsurl, enum backup_loading load);
int save_acs_bkp_config();
mxml_node_t *bkp_session_insert(mxml_node_t *tree, char *name, char *value);
void bkp_session_simple_insert_in_parent(char *parent, char *child, char *value);
void bkp_session_simple_insert(char *parent, char *child, char *value);
mxml_node_t *bkp_session_insert_event(int index, char *command_key, int id);
void bkp_session_insert_schedule_inform(int id, time_t schedule_time, char *command_key);
void bkp_session_insert_download(struct download *pdownload);
void bkp_session_insert_upload(struct upload *pupload);
void bkp_session_insert_change_du_state(struct change_du_state *pchange_du_state);
void bkp_session_insert_transfer_complete(struct transfer_complete *ptransfer_complete);

void bkp_session_insert_schedule_download(struct download *pschedule_download);
void bkp_session_insert_du_state_change_complete(struct du_state_change_complete *pdu_state_change_complete);
void bkp_session_insert_autonomous_du_state_change(auto_du_state_change_compl *data);
void bkp_session_insert_autonomous_transfer_complete(auto_transfer_complete *data);
void bkp_session_delete_element(char *element_name, int id);
void bkp_session_delete_element_by_key(char *element_name, char *key_name, char *key_value);
void bkp_tree_clean(void);
#endif /* _BACKUPSESSION_H__ */
