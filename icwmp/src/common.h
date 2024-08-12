/*
 * common.h - Some commun functions used by the application
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef __CCOMMON_H
#define __CCOMMON_H

#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <math.h>
#include <libubox/list.h>
#include <pthread.h>
#include <libubox/uloop.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef FREE
#define FREE(x) do { if(x) {free(x); x = NULL;} } while (0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

#define CWMP_STRCMP(S1, S2) cwmp_strcmp(S1, S2, __func__, __LINE__)
#define CWMP_STRNCMP(S1, S2, LEN) cwmp_strncmp(S1, S2, LEN, __func__, __LINE__)
#define CWMP_STRLEN(S1) cwmp_strlen(S1, __func__, __LINE__)
#define CWMP_STRSTR(S1, S2) cwmp_strstr(S1, S2, __func__, __LINE__)
#define CWMP_LSTRCASECMP(S1, S2) cwmp_strcasecmp(S1, S2, __func__, __LINE__)
#define CWMP_STRDUP(S1) cwmp_strdup(S1, __func__, __LINE__)
#define CWMP_STRNCPY(DST, SRC, SIZE) cwmp_strncpy(DST, SRC, SIZE, __func__, __LINE__)

#define CWMP_MEMSET(SRC, VAL, SIZE) cwmp_memset(SRC, VAL, SIZE, __func__, __LINE__)
#define CWMP_MEMCPY(DST, SRC, SIZE) cwmp_memcpy(DST, SRC, SIZE, __func__, __LINE__)

#define BBFDM_OBJECT_NAME "bbfdm"
#define MAX_EVENTS 64
#define MAX_INT32 2147483646
#define MAX_INT_ID MAX_INT32
#define MIN_INT_ID 836464
#define PERIOD_INFORM_MIN 60
#define PERIOD_INFORM_DEFAULT 86400
#define CONNECTION_REQUEST_RESTRICT_PERIOD 5
#define CONNECTION_REQUEST_RESTRICT_REQUEST 50
#define DEFAULT_CONNECTION_REQUEST_PORT 7547
#define DEFAULT_NOTIFY_PERIOD 10
#define DEFAULT_LWN_PORT 7547
#define DEFAULT_RETRY_MINIMUM_WAIT_INTERVAL 5
#define DEFAULT_RETRY_INITIAL_INTERVAL 60
#define DEFAULT_RETRY_INTERVAL_MULTIPLIER 2000
#define DEFAULT_RETRY_MAX_INTERVAL 60
#define DEFAULT_AMD_VERSION 5
#define DEFAULT_INSTANCE_MODE 0
#define DEFAULT_SESSION_TIMEOUT 60
#define MAX_NBRE_SERVICES 256

#define BUF_SIZE_8 (8 + 1)
#define BUF_SIZE_16 (16 + 1)
#define BUF_SIZE_32 (32 + 1)
#define BUF_SIZE_64 (64 + 1)
#define BUF_SIZE_256 (256 + 1)
#define BUF_SIZE_2048 (2048 + 1)

#define ICWMP_TMP_PATH "/tmp/icwmp"
#define FIREWALL_CWMP "/etc/firewall.cwmp"
#define DM_PPP_INTERFACE_PATH "Device\\.PPP\\.Interface\\."
#define DM_IP_INTERFACE_PATH "Device\\.IP\\.Interface\\."
#define DEFAULT_CR_TIMEOUT 5 /* In Seconds */

#define foreach_elt_in_strlist(elt, str, delim) \
        char *tmpchr; \
        char buffer_str[strlen(str) + 1]; \
        CWMP_STRNCPY(buffer_str, str, sizeof(buffer_str)); \
        for (elt = strtok_r(buffer_str, delim, &tmpchr); elt != NULL; elt = strtok_r(NULL, delim, &tmpchr))

extern char *commandKey;
extern bool cwmp_stop;
extern struct uloop_timeout session_timer;
extern struct uloop_timeout periodic_session_timer;
extern struct uloop_timeout retry_session_timer;
extern bool g_firewall_restart;
extern struct list_head intf_reset_list;
extern struct list_head force_inform_list;

typedef struct env {
	unsigned short boot;
	unsigned short periodic;
} env;

struct connection {
	char interface[BUF_SIZE_16];
	long ip_resolve;
	bool ipv6_status;
};

typedef struct config {
	char acs_url[BUF_SIZE_2048];
	char acs_userid[BUF_SIZE_256];
	char acs_passwd[BUF_SIZE_256];
	char acs_ssl_capath[BUF_SIZE_256];
	char cpe_userid[BUF_SIZE_256];
	char cpe_passwd[BUF_SIZE_256];
	char custom_notify_json[BUF_SIZE_256];
	char forced_inform_json[BUF_SIZE_256];
	char connection_request_path[BUF_SIZE_256];
	char auto_tc_transfer_type[BUF_SIZE_16];
	char auto_tc_result_type[BUF_SIZE_16];
	char auto_tc_file_type[BUF_SIZE_16];
	char auto_cdu_oprt_type[BUF_SIZE_16];
	char auto_cdu_result_type[BUF_SIZE_16];
	char auto_cdu_fault_code[BUF_SIZE_16];
	char default_wan_iface[BUF_SIZE_32];

	int connection_request_port;
	int period;
	int periodic_notify_interval;
	int compression;
	int delay_reboot;
	int heartbeat_interval;
	time_t schedule_reboot;
	time_t time;
	time_t heart_time;

	unsigned int active_notif_throttle;
	unsigned int md_notif_limit;

	bool dhcp_discovery;
	bool periodic_enable;
	bool periodic_notify_enable;
	bool insecure_enable;
	bool heart_beat_enable;
	bool acs_getrpc;
	bool auto_tc_enable;
	bool auto_cdu_enable;
	int retry_min_wait_interval;
	int retry_interval_multiplier;

	bool lwn_enable;
	char lwn_hostname[BUF_SIZE_256];
	int lwn_port;

	int amd_version;
	int supported_amd_version;
	unsigned int instance_mode;
	unsigned int session_timeout;
	bool http_disable_100continue;
	int cr_timeout;
	bool force_ipv4;
	bool fw_upgrade_keep_settings;
} config;

struct deviceid {
	char manufacturer[BUF_SIZE_64];
	char oui[BUF_SIZE_8];
	char serialnumber[BUF_SIZE_64];
	char productclass[BUF_SIZE_64];
	char softwareversion[BUF_SIZE_64];
};

enum firewall_cr_policy {
	CR_POLICY_Port_Only = 0,
	CR_POLICY_IP_Only,
	CR_POLICY_BOTH,
};

typedef struct cwmp {
	struct env env;
	struct config conf;
	struct deviceid deviceid;
	struct connection net;
	struct session *session;
	bool cwmp_cr_event;
	bool prev_periodic_enable;
	bool prev_heartbeat_enable;
	bool heart_session;
	bool diag_session;
	bool throttle_session;
	int prev_periodic_interval;
	int prev_heartbeat_interval;
	int retry_count_session;
	FILE *pid_file;
	time_t start_time;
	time_t prev_periodic_time;
	time_t prev_heartbeat_time;
	time_t md_value_change_last_time;
	unsigned int cwmp_id;
	int event_id;
	int sched_inform_id;
	int download_id;
	int sched_download_id;
	int cdu_id;
	int upload_id;
	int auto_cdu_id;
	int auto_tc_id;
	int cdu_complete_id;
	int tc_id;
	int cr_socket_desc;
	int cwmp_period;
	long int heart_session_interval;
	time_t cwmp_periodic_time;
	bool cwmp_periodic_enable;
	bool custom_notify_active;
	struct ubus_event_handler *ev;
	struct ubus_event_handler *intf_ev;
	bool throttle_session_triggered;
	enum firewall_cr_policy cr_policy;
	bool acs_changed;
} cwmp;

enum action {
	NONE = 0,
	START,
	STOP,
	RESTART,
};

enum auth_type_enum {
	AUTH_BASIC,
	AUTH_DIGEST
};

enum cwmp_start {
	CWMP_START_BOOT = 1,
	CWMP_START_PERIODIC = 2
};

enum cwmp_ret_err {
	CWMP_OK = 0, /* No Error */
	CWMP_GEN_ERR, /* General Error */
	CWMP_MEM_ERR, /* Memory Error */
	CWMP_RETRY_SESSION
};

enum http_compression {
	COMP_NONE,
	COMP_GZIP,
	COMP_DEFLATE
};

enum enum_ip_version {
	IPv4 = 4,
	IPv6 = 6
};

typedef struct rpc {
	struct list_head list;
	int type;
	void *extra_data;
	struct list_head *list_set_value_fault;
} rpc;

struct cwmp_param_fault {
	struct list_head list;
	char path_name[1024];
	char fault_msg[256];
	int fault_code;
};

struct cwmp_dm_parameter {
	struct list_head list;
	char *name;
	char *value;
	char *type;
	char *access_list;
	int notification;
	bool writable;
	bool forced_notification_param;
};

enum amd_version_enum {
	AMD_1 = 1,
	AMD_2,
	AMD_3,
	AMD_4,
	AMD_5,
};

enum instance_mode {
	INSTANCE_MODE_NUMBER,
	INSTANCE_MODE_ALIAS
};

struct cwmp_namespaces {
	char *soap_env;
	char *soap_enc;
	char *xsd;
	char *xsi;
	char *cwmp;
};

enum rpc_cpe_methods_idx {
	RPC_CPE_GET_RPC_METHODS = 1,
	RPC_CPE_SET_PARAMETER_VALUES,
	RPC_CPE_GET_PARAMETER_VALUES,
	RPC_CPE_GET_PARAMETER_NAMES,
	RPC_CPE_SET_PARAMETER_ATTRIBUTES,
	RPC_CPE_GET_PARAMETER_ATTRIBUTES,
	RPC_CPE_ADD_OBJECT,
	RPC_CPE_DELETE_OBJECT,
	RPC_CPE_REBOOT,
	RPC_CPE_DOWNLOAD,
	RPC_CPE_UPLOAD,
	RPC_CPE_FACTORY_RESET,
	RPC_CPE_SCHEDULE_INFORM,
	RPC_CPE_SCHEDULE_DOWNLOAD,
	RPC_CPE_CHANGE_DU_STATE,
	RPC_CPE_CANCEL_TRANSFER,
	RPC_CPE_X_FACTORY_RESET_SOFT,
	RPC_CPE_FAULT,
	__RPC_CPE_MAX
};

enum rpc_acs_methods_idx {
	RPC_ACS_INFORM = 1,
	RPC_ACS_GET_RPC_METHODS,
	RPC_ACS_TRANSFER_COMPLETE,
	RPC_ACS_AUTONOMOUS_TRANSFER_COMPLETE,
	RPC_ACS_DU_STATE_CHANGE_COMPLETE,
	RPC_ACS_AUTONOMOUS_DU_STATE_CHANGE_COMPLETE,
	__RPC_ACS_MAX
};

enum acs_support_idx {
	NOT_KNOWN,
	RPC_ACS_SUPPORT,
	RPC_ACS_NOT_SUPPORT
};

enum load_type {
	TYPE_DOWNLOAD = 0,
	TYPE_SCHEDULE_DOWNLOAD,
	TYPE_UPLOAD
};

enum dustate_type {
	DU_INSTALL = 1,
	DU_UPDATE,
	DU_UNINSTALL,
	__MAX_DU_STATE
};

enum fault_cpe_idx {
	FAULT_CPE_NO_FAULT,
	FAULT_CPE_METHOD_NOT_SUPPORTED,
	FAULT_CPE_REQUEST_DENIED,
	FAULT_CPE_INTERNAL_ERROR,
	FAULT_CPE_INVALID_ARGUMENTS,
	FAULT_CPE_RESOURCES_EXCEEDED,
	FAULT_CPE_INVALID_PARAMETER_NAME,
	FAULT_CPE_INVALID_PARAMETER_TYPE,
	FAULT_CPE_INVALID_PARAMETER_VALUE,
	FAULT_CPE_NON_WRITABLE_PARAMETER,
	FAULT_CPE_NOTIFICATION_REJECTED,
	FAULT_CPE_DOWNLOAD_FAILURE,
	FAULT_CPE_UPLOAD_FAILURE,
	FAULT_CPE_FILE_TRANSFER_AUTHENTICATION_FAILURE,
	FAULT_CPE_FILE_TRANSFER_UNSUPPORTED_PROTOCOL,
	FAULT_CPE_DOWNLOAD_FAIL_MULTICAST_GROUP,
	FAULT_CPE_DOWNLOAD_FAIL_CONTACT_SERVER,
	FAULT_CPE_DOWNLOAD_FAIL_ACCESS_FILE,
	FAULT_CPE_DOWNLOAD_FAIL_COMPLETE_DOWNLOAD,
	FAULT_CPE_DOWNLOAD_FAIL_FILE_CORRUPTED,
	FAULT_CPE_DOWNLOAD_FAIL_FILE_AUTHENTICATION,
	FAULT_CPE_DOWNLOAD_FAIL_WITHIN_TIME_WINDOW,
	FAULT_CPE_DUPLICATE_DEPLOYMENT_UNIT,
	FAULT_CPE_SYSTEM_RESOURCES_EXCEEDED,
	FAULT_CPE_UNKNOWN_DEPLOYMENT_UNIT,
	FAULT_CPE_INVALID_DEPLOYMENT_UNIT_STATE,
	FAULT_CPE_INVALID_DOWNGRADE_REJECTED,
	FAULT_CPE_INVALID_UPDATE_VERSION_UNSPECIFIED,
	FAULT_CPE_INVALID_UPDATE_VERSION_EXIST,
	__FAULT_CPE_MAX
};

enum fault_code_enum {
	FAULT_9000 = 9000, // Method not supported
	FAULT_9001, // Request denied
	FAULT_9002, // Internal error
	FAULT_9003, // Invalid arguments
	FAULT_9004, // Resources exceeded
	FAULT_9005, // Invalid parameter name
	FAULT_9006, // Invalid parameter type
	FAULT_9007, // Invalid parameter value
	FAULT_9008, // Attempt to set a non-writable parameter
	FAULT_9009, // Notification request rejected
	FAULT_9010, // Download failure
	FAULT_9011, // Upload failure
	FAULT_9012, // File transfer server authentication failure
	FAULT_9013, // Unsupported protocol for file transfer
	FAULT_9014, // Download failure: unable to join multicast group
	FAULT_9015, // Download failure: unable to contact file server
	FAULT_9016, // Download failure: unable to access file
	FAULT_9017, // Download failure: unable to complete download
	FAULT_9018, // Download failure: file corrupted
	FAULT_9019, // Download failure: file authentication failure
	FAULT_9020, // Download failure: unable to complete download
	FAULT_9021, // Cancelation of file transfer not permitted
	FAULT_9022, // Invalid UUID format
	FAULT_9023, // Unknown Execution Environment
	FAULT_9024, // Disabled Execution Environment
	FAULT_9025, // Diployment Unit to Execution environment mismatch
	FAULT_9026, // Duplicate Deployment Unit
	FAULT_9027, // System Ressources Exceeded
	FAULT_9028, // Unknown Deployment Unit
	FAULT_9029, // Invalid Deployment Unit State
	FAULT_9030, // Invalid Deployment Unit Update: Downgrade not permitted
	FAULT_9031, // Invalid Deployment Unit Update: Version not specified
	FAULT_9032, // Invalid Deployment Unit Update: Version already exist
	__FAULT_MAX
};

enum client_server_faults {
	FAULT_CPE_TYPE_CLIENT,
	FAULT_CPE_TYPE_SERVER
};

struct rpc_cpe_method {
	const char *name;
	int (*handler)(struct rpc *rpc);
	int amd;
};

struct rpc_acs_method {
	const char *name;
	int (*prepare_message)(struct rpc *rpc);
	int (*parse_response)(struct rpc *rpc);
	int (*extra_clean)(struct rpc *rpc);
	int acs_support;
};

typedef struct FAULT_CPE {
	char *CODE;
	int ICODE;
	int TYPE;
	char *DESCRIPTION;
} FAULT_CPE;

typedef struct schedule_inform {
	struct list_head list;
	struct uloop_timeout handler_timer ;
	time_t scheduled_time;
	char *commandKey;
	int id;
} schedule_inform;

typedef struct timewindow {
	time_t windowstart;
	time_t windowend;
	char *windowmode;
	char *usermessage;
	int maxretries;
} timewindow;

typedef struct download {
	struct list_head list;
	struct uloop_timeout handler_timer;
	time_t scheduled_time;
	unsigned int file_size;
	char *command_key;
	char *file_type;
	char *url;
	char *username;
	char *password;
	struct timewindow timewindowstruct[2];
	int id;
} download;

typedef struct timeinterval {
	time_t windowstart;
	time_t windowend;
	int maxretries;
} timeinterval;

typedef struct change_du_state {
	struct list_head list;
	struct uloop_timeout handler_timer;
	time_t timeout;
	char *command_key;
	struct list_head list_operation;
	int id;
} change_du_state;

typedef struct du_operational_uuid {
	struct list_head list;
	char uuid[37];
	char operation[10];
} du_op_uuid;

typedef struct operations {
	struct list_head list;
	int type;
	char *url;
	char *uuid;
	char *version;
	char *username;
	char *password;
	char *executionenvref;
} operations;

typedef struct upload {
	struct list_head list;
	struct uloop_timeout handler_timer ;
	time_t scheduled_time;
	char *file_type;
	char *command_key;
	char *url;
	char *username;
	char *password;
	int f_instance;
	int id;
} upload;

typedef struct transfer_complete {
	int fault_code;
	char *command_key;
	char *start_time;
	char *complete_time;
	char *old_software_version;
	char *file_type;
	char *fault_string;
	int type;
	int id;
} transfer_complete;

typedef struct autonomous_du_state_change_complete {
	char *uuid;
	char *ver;
	char *current_state;
	bool resolved;
	char *start_time;
	char *complete_time;
	int fault_code;
	char *fault_string;
	char *operation;
	int id;
} auto_du_state_change_compl;

typedef struct autonomous_transfer_complete {
	char *announce_url;
	char *transfer_url;
	char *file_type;
	char *target_file_name;
	char *start_time;
	char *complete_time;
	char *fault_string;
	int fault_code;
	bool is_download;
	unsigned int file_size;
	int id;

} auto_transfer_complete;

typedef struct du_state_change_complete {
	char *command_key;
	time_t timeout;
	struct list_head list_opresult;
	int id;
} du_state_change_complete;

typedef struct opresult {
	struct list_head list;
	char *uuid;
	char *du_ref;
	char *version;
	char *current_state;
	bool resolved;
	char *execution_unit_ref;
	char *start_time;
	char *complete_time;
	int fault;
	char *fault_msg;
} opresult;

typedef struct opfault {
	int fault_code;
	char *fault_string;
} opfault;

typedef struct intf_reset_node {
	char path[1024];
	struct list_head list;
} intf_reset_node;

typedef struct bin_list {
	uint8_t bin[1024];
	size_t len;
	struct list_head list;
} bin_list_t;

typedef struct force_inform_node {
	char path[1024];
	struct list_head list;
} force_inform_node;

extern struct cwmp *cwmp_main;
extern unsigned int flashsize;
extern struct FAULT_CPE FAULT_CPE_ARRAY[];
extern struct cwmp_namespaces ns;
extern struct session_timer_event *global_session_event;

void add_dm_parameter_to_list(struct list_head *head, char *param_name, char *param_data, char *param_type, int notification, bool writable);
void cwmp_free_all_dm_parameter_list(struct list_head *list);
int global_env_init(int argc, char **argv, struct env *env);
void cwmp_add_list_fault_param(char *param_name, char *fault_msg, int fault_code, struct list_head *list_set_value_fault);
void cwmp_free_all_list_param_fault(struct list_head *list_param_fault);
int cwmp_asprintf(char **s, const char *format, ...);
bool folder_exists(const char *path);
bool file_exists(const char *path);
void cwmp_reboot(char *command_key);
void cwmp_factory_reset();
void get_firewall_zone_name_by_wan_iface(char *if_wan, char **zone_name);
int download_file(const char *file_path, const char *url, const char *username, const char *password);
unsigned int get_file_size(char *file_name);
int cwmp_check_image();
int cwmp_apply_firmware();
bool cwmp_apply_web_content(char *filepath);
int opkg_install_package(char *package_path);
int copy(const char *from, const char *to);
int cwmp_get_fault_code(int fault_code);
int cwmp_get_fault_code_by_string(char *fault_code);
void *icwmp_malloc(size_t size);
void *icwmp_calloc(int n, size_t size);
void *icwmp_realloc(void *n, size_t size);
char *icwmp_strdup(const char *s);
int icwmp_asprintf(char **s, const char *format, ...);
void icwmp_free(void *m);
void icwmp_cleanmem();
void icwmp_init_list_services();
int icwmp_add_service(char *service);
void icwmp_free_list_services();
void icwmp_restart_services();
bool icwmp_validate_string_length(char *arg, int max_length);
bool icwmp_validate_boolean_value(char *arg);
bool icwmp_validate_unsignedint(char *arg);
bool icwmp_validate_int_in_range(char *arg, int min, int max);
char *string_to_hex(const unsigned char *str, size_t size);
int copy_file(char *source_file, char *target_file);
int icwmp_check_http_connection(void);
bool is_ipv6_enabled(void);
bool is_ipv6_status_changed(void);
char *get_time(time_t t_time);
bool is_reload_parameter(const char *object_name);
time_t convert_datetime_to_timestamp(char *value);
int run_session_end_func(void);
void set_interface_reset_request(char *param_name, char *value);
bool str_to_bool(char *value);
bool match_reg_exp(char *reg_exp, char *param_name);
void cwmp_invoke_intf_reset(char *path);
void check_firewall_restart_state();
void add_day_to_time(struct tm *time);
int set_rpc_acs_to_supported(const char *rpc_name);
void set_rpc_parameter_key(char *param_key);

void add_bin_list(struct list_head *list, uint8_t *str, size_t len);
void add_str_binlist(struct list_head *list, char *str);
void free_binlist(struct list_head *list);
int cwmp_strcmp(const char *s1, const char *s2, const char *origin, int pos);
int cwmp_strncmp(const char *s1, const char *s2, int len, const char *origin, int pos);
int cwmp_strlen(const char *s1, const char *origin, int pos);
int cwmp_strcasecmp(const char *s1, const char *s2, const char *origin, int pos);
char *cwmp_strstr(const char *s1, const char *s2, const char *origin, int pos);
char *cwmp_strncpy(char *dst, const char *src, int size, const char *origin, int pos);
char *cwmp_strdup(const char *s1, const char *origin, int pos);
void *cwmp_memset(void *src, int val, size_t size, const char *origin, int pos);
void *cwmp_memcpy(void *dst, const void *src, size_t size, const char *origin, int pos);
void cwmp_restart_service(struct uloop_timeout *timeout  __attribute__((unused)));
#endif
