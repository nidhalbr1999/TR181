/*
 * common.c - Some commun functions used by the application
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>
#include <regex.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <mxml.h>

#include "common.h"
#include "cwmp_cli.h"
#include "uci_utils.h"
#include "ubus_utils.h"
#include "log.h"

char *commandKey = NULL;
bool cwmp_stop = false;
unsigned int flashsize = 256000000;
struct cwmp *cwmp_main = NULL;
struct session_timer_event *global_session_event = NULL;
static int nbre_services = 0;
static char *list_services[MAX_NBRE_SERVICES] = { 0 };
LIST_HEAD(cwmp_memory_list);
extern bool g_firewall_restart;

struct cwmp_mem {
	struct list_head list;
	char mem[0];
};

struct option cwmp_long_options[] = {
	{ "boot-event", no_argument, NULL, 'b' },
	{ "get-rpc-methods", no_argument, NULL, 'g' },
	{ "command-input", no_argument, NULL, 'c' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'v' },
	{ NULL, 0, NULL, 0 }
};

struct FAULT_CPE FAULT_CPE_ARRAY[] = {
	[FAULT_CPE_METHOD_NOT_SUPPORTED] = { "9000", FAULT_9000, FAULT_CPE_TYPE_SERVER, "Method not supported" },
	[FAULT_CPE_REQUEST_DENIED] = { "9001", FAULT_9001, FAULT_CPE_TYPE_SERVER, "Request denied (no reason specified)" },
	[FAULT_CPE_INTERNAL_ERROR] = { "9002", FAULT_9002, FAULT_CPE_TYPE_SERVER, "Internal error" },
	[FAULT_CPE_INVALID_ARGUMENTS] = { "9003", FAULT_9003, FAULT_CPE_TYPE_CLIENT, "Invalid arguments" },
	[FAULT_CPE_RESOURCES_EXCEEDED] = { "9004", FAULT_9004, FAULT_CPE_TYPE_SERVER, "Resources exceeded" },
	[FAULT_CPE_INVALID_PARAMETER_NAME] = { "9005", FAULT_9005, FAULT_CPE_TYPE_CLIENT, "Invalid parameter name" },
	[FAULT_CPE_INVALID_PARAMETER_TYPE] = { "9006", FAULT_9006, FAULT_CPE_TYPE_CLIENT, "Invalid parameter type" },
	[FAULT_CPE_INVALID_PARAMETER_VALUE] = { "9007", FAULT_9007, FAULT_CPE_TYPE_CLIENT, "Invalid parameter value" },
	[FAULT_CPE_NON_WRITABLE_PARAMETER] = { "9008", FAULT_9008, FAULT_CPE_TYPE_CLIENT, "Attempt to set a non-writable parameter" },
	[FAULT_CPE_NOTIFICATION_REJECTED] = { "9009", FAULT_9009, FAULT_CPE_TYPE_SERVER, "Notification request rejected" },
	[FAULT_CPE_DOWNLOAD_FAILURE] = { "9010", FAULT_9010, FAULT_CPE_TYPE_SERVER, "Download failure" },
	[FAULT_CPE_UPLOAD_FAILURE] = { "9011", FAULT_9011, FAULT_CPE_TYPE_SERVER, "Upload failure" },
	[FAULT_CPE_FILE_TRANSFER_AUTHENTICATION_FAILURE] = { "9012", FAULT_9012, FAULT_CPE_TYPE_SERVER, "File transfer server authentication failure" },
	[FAULT_CPE_FILE_TRANSFER_UNSUPPORTED_PROTOCOL] = { "9013", FAULT_9013, FAULT_CPE_TYPE_SERVER, "Unsupported protocol for file transfer" },
	[FAULT_CPE_DOWNLOAD_FAIL_MULTICAST_GROUP] = { "9014", FAULT_9014, FAULT_CPE_TYPE_SERVER, "Download failure: unable to join multicast group" },
	[FAULT_CPE_DOWNLOAD_FAIL_CONTACT_SERVER] = { "9015", FAULT_9015, FAULT_CPE_TYPE_SERVER, "Download failure: unable to contact file server" },
	[FAULT_CPE_DOWNLOAD_FAIL_ACCESS_FILE] = { "9016", FAULT_9016, FAULT_CPE_TYPE_SERVER, "Download failure: unable to access file" },
	[FAULT_CPE_DOWNLOAD_FAIL_COMPLETE_DOWNLOAD] = { "9017", FAULT_9017, FAULT_CPE_TYPE_SERVER, "Download failure: unable to complete download" },
	[FAULT_CPE_DOWNLOAD_FAIL_FILE_CORRUPTED] = { "9018", FAULT_9018, FAULT_CPE_TYPE_SERVER, "Download failure: file corrupted" },
	[FAULT_CPE_DOWNLOAD_FAIL_FILE_AUTHENTICATION] = { "9019", FAULT_9019, FAULT_CPE_TYPE_SERVER, "Download failure: file authentication failure" },
	[FAULT_CPE_DOWNLOAD_FAIL_WITHIN_TIME_WINDOW] = { "9020", FAULT_9020, FAULT_CPE_TYPE_SERVER, "Download failure: unable to complete download" },
	[FAULT_CPE_DUPLICATE_DEPLOYMENT_UNIT] = { "9026", FAULT_9026, FAULT_CPE_TYPE_SERVER, "Duplicate deployment unit" },
	[FAULT_CPE_SYSTEM_RESOURCES_EXCEEDED] = { "9027", FAULT_9027, FAULT_CPE_TYPE_SERVER, "System ressources exceeded" },
	[FAULT_CPE_UNKNOWN_DEPLOYMENT_UNIT] = { "9028", FAULT_9028, FAULT_CPE_TYPE_SERVER, "Unknown deployment unit" },
	[FAULT_CPE_INVALID_DEPLOYMENT_UNIT_STATE] = { "9029", FAULT_9029, FAULT_CPE_TYPE_SERVER, "Invalid deployment unit state" },
	[FAULT_CPE_INVALID_DOWNGRADE_REJECTED] = { "9030", FAULT_9030, FAULT_CPE_TYPE_SERVER, "Invalid deployment unit Update: Downgrade not permitted" },
	[FAULT_CPE_INVALID_UPDATE_VERSION_UNSPECIFIED] = { "9031", FAULT_9031, FAULT_CPE_TYPE_SERVER, "Invalid deployment unit Update: Version not specified" },
	[FAULT_CPE_INVALID_UPDATE_VERSION_EXIST] = { "9031", FAULT_9032, FAULT_CPE_TYPE_SERVER, "Invalid deployment unit Update: Version already exist" }
};

static void show_help(void)
{
	printf("Usage: icwmpd [OPTIONS]\n");
	printf(" -b, --boot-event                                    (CWMP daemon) Start CWMP with BOOT event\n");
	printf(" -g, --get-rpc-methods                               (CWMP daemon) Start CWMP with GetRPCMethods request to ACS\n");
	printf(" -c, --cli                              	     	 CWMP CLI\n");
	printf(" -h, --help                                          Display this help text\n");
}

int global_env_init(int argc, char **argv, struct env *env)
{
	int c, option_index = 0;

	/* This is to initialize the global context in mxml,
	 *  with out init mxml sometimes segfaults, when calling the destructor.
	 */
	mxml_error(NULL);

	while ((c = getopt_long(argc, argv, "bgchv", cwmp_long_options, &option_index)) != -1) {
		switch (c) {
		case 'b':
			env->boot = CWMP_START_BOOT;
			break;
		case 'g':
			env->periodic = CWMP_START_PERIODIC;
			break;
		case 'c':
			cwmp_main = (struct cwmp*)calloc(1, sizeof(struct cwmp));
			execute_cwmp_cli_command(argv[2], argv + 3);
			FREE(cwmp_main);
			exit(0);
		case 'h':
			show_help();
			exit(0);
		}
	}
	return CWMP_OK;
}

/*
 * List dm_paramter
 */
void add_dm_parameter_to_list(struct list_head *head, char *param_name, char *param_val, char *param_type,
			      int notification, bool writable)
{
	struct cwmp_dm_parameter *dm_parameter = NULL;

	if (!head || !param_name)
		return;

	list_for_each_entry(dm_parameter, head, list) {

		if (CWMP_STRCMP(param_name, dm_parameter->name) == 0) {
			if (param_val && CWMP_STRCMP(dm_parameter->value, param_val) != 0) {
				FREE(dm_parameter->value);
				dm_parameter->value = strdup(param_val);
			}
			dm_parameter->notification = notification;
			return;
		}
	}

	dm_parameter = calloc(1, sizeof(struct cwmp_dm_parameter));
	list_add_tail(&dm_parameter->list, head);

	dm_parameter->name = strdup(param_name);
	dm_parameter->value = param_val ? strdup(param_val) : NULL;
	dm_parameter->type = strdup(param_type ? param_type : "xsd:string");
	dm_parameter->access_list = NULL;
	dm_parameter->notification = notification;
	dm_parameter->writable = writable;
}

static void delete_dm_parameter_from_list(struct cwmp_dm_parameter *dm_parameter)
{
	list_del(&dm_parameter->list);
	FREE(dm_parameter->name);
	FREE(dm_parameter->value);
	FREE(dm_parameter->type);
	FREE(dm_parameter->access_list);
	FREE(dm_parameter);
}

void cwmp_free_all_dm_parameter_list(struct list_head *list)
{
	while (list->next != list) {
		struct cwmp_dm_parameter *dm_parameter;
		dm_parameter = list_entry(list->next, struct cwmp_dm_parameter, list);
		delete_dm_parameter_from_list(dm_parameter);
	}
}

/*
 * List Fault parameter
 */
void cwmp_add_list_fault_param(char *param_name, char *fault_msg, int fault_code, struct list_head *list_set_value_fault)
{
	struct cwmp_param_fault *param_fault = NULL;

	param_fault = calloc(1, sizeof(struct cwmp_param_fault));
	list_add_tail(&param_fault->list, list_set_value_fault);

	snprintf(param_fault->path_name, sizeof(param_fault->path_name), "%s", param_name ? param_name : "");
	snprintf(param_fault->fault_msg, sizeof(param_fault->fault_msg), "%s", fault_msg ? fault_msg : "");
	param_fault->fault_code = fault_code;
}

static void cwmp_del_list_fault_param(struct cwmp_param_fault *param_fault)
{
	list_del(&param_fault->list);
	free(param_fault);
}

void cwmp_free_all_list_param_fault(struct list_head *list_param_fault)
{
	while (list_param_fault->next != list_param_fault) {
		struct cwmp_param_fault *param_fault;
		param_fault = list_entry(list_param_fault->next, struct cwmp_param_fault, list);
		cwmp_del_list_fault_param(param_fault);
	}
}

int cwmp_asprintf(char **s, const char *format, ...)
{
	int size;
	char *str = NULL;
	va_list arg, argcopy;
	va_start(arg, format);
	va_copy(argcopy, arg);
	size = vsnprintf(NULL, 0, format, argcopy);
	if (size < 0) {
		va_end(argcopy);
		va_end(arg);
		return -1;
	}
	va_end(argcopy);
	str = (char *)calloc(sizeof(char), size + 1);
	vsnprintf(str, size + 1, format, arg);
	va_end(arg);
	*s = strdup(str);
	FREE(str);
	if (*s == NULL) {
		return -1;
	}
	return 0;
}

bool folder_exists(const char *path)
{
	struct stat folder_stat;

	return (stat(path, &folder_stat) == 0 && S_ISDIR(folder_stat.st_mode));
}

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}

// wait till firewall restart is not complete or 5 sec, whichever is less
void check_firewall_restart_state()
{
	int count = 0;
	bool init = false;

	do {
		char state[BUF_SIZE_32] = {0};

		get_uci_path_value(VARSTATE_CONFIG, "icwmp.cpe.firewall_restart", state, BUF_SIZE_32);
		if (CWMP_STRCMP(state, "init") == 0) {
			init = true;
			break;
		}

		sleep(1);
		count++;
	} while(count < 10);

	// mark the firewall restart as done
	g_firewall_restart = false;
	if (init == false) { // In case of timeout reset the firewall_restart flag
		CWMP_LOG(ERROR, "Firewall restart took longer than usual");
		set_uci_path_value(VARSTATE_CONFIG, "icwmp.cpe.firewall_restart", "init");
	}
}

void set_rpc_parameter_key(char *param_key)
{
	set_uci_path_value(NULL, "cwmp.cpe.ParameterKey", param_key ? param_key : "");
}

/*
 * Reboot
 */
void cwmp_reboot(char *command_key)
{
	set_rpc_parameter_key(command_key);

	struct blob_buf b = { 0 };
	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	icwmp_ubus_invoke("rpc-sys", "reboot", b.head, NULL, NULL);

	blob_buf_free(&b);

	// Wait before exit to avoid getting restarted by procd
	sleep(300);
	CWMP_LOG(ERROR, "# Problem in system restart #");
}

/*
 * FactoryReset
 */
void cwmp_factory_reset() //use the ubus rpc-sys factory
{
	struct blob_buf b = { 0 };
	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	icwmp_ubus_invoke("rpc-sys", "factory", b.head, NULL, NULL);

	blob_buf_free(&b);

	// Wait before exit to avoid getting restarted by procd
	sleep(300);
	CWMP_LOG(ERROR, "# Problem in system factory reset #");
}

unsigned int get_file_size(char *file_name)
{
	FILE *fp = fopen(file_name, "r");

	if (fp == NULL) {
		CWMP_LOG(INFO, "File Not Found!");
		return -1;
	}

	fseek(fp, 0L, SEEK_END);
	unsigned int res = ftell(fp);

	fclose(fp);

	return res;
}

int opkg_install_package(char *package_path)
{
	FILE *fp;
	char path[1035];
	char cmd[512];

	CWMP_LOG(INFO, "Apply downloaded config ...");

	int ret = snprintf(cmd, sizeof(cmd), "opkg --force-depends --force-maintainer install %s", package_path);
	if (ret < 0 || ret > 512)
		return -1;
	fp = popen(cmd, "r");
	if (fp == NULL) {
		CWMP_LOG(INFO, "Failed to run command");
		return -1;
	}

	/* Read the output a line at a time - output it. */
	while (fgets(path, sizeof(path), fp) != NULL) {
		if (strstr(path, "Installing") != NULL)
			return 0;
	}

	/* close */
	pclose(fp);
	return -1;
}

int copy(const char *from, const char *to)
{
	int fd_to, fd_from;
	char buf[4096];
	ssize_t nread;
	int saved_errno;

	fd_from = open(from, O_RDONLY);
	if (fd_from < 0)
		return -1;

	fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd_to < 0)
		goto out_error;

	while ((nread = read(fd_from, buf, sizeof buf)) > 0) {
		char *out_ptr = buf;
		ssize_t nwritten;

		do {
			nwritten = write(fd_to, out_ptr, nread);

			if (nwritten >= 0) {
				nread -= nwritten;
				out_ptr += nwritten;
			} else if (errno != EINTR) {
				goto out_error;
			}
		} while (nread > 0);
	}

	if (nread == 0) {
		if (close(fd_to) < 0) {
			fd_to = -1;
			goto out_error;
		}
		close(fd_from);

		/* Success! */
		return 0;
	}

out_error:
	saved_errno = errno;

	close(fd_from);
	if (fd_to >= 0)
		close(fd_to);

	errno = saved_errno;
	return -1;
}

bool file_exists(const char *path)
{
	struct stat buffer;

	return stat(path, &buffer) == 0;
}

int cwmp_get_fault_code(int fault_code)
{
	int i;

	for (i = 1; i < __FAULT_CPE_MAX; i++) {
		if (FAULT_CPE_ARRAY[i].ICODE == fault_code)
			break;
	}

	if (i == __FAULT_CPE_MAX)
		i = FAULT_CPE_INTERNAL_ERROR;

	return i;
}

int cwmp_get_fault_code_by_string(char *fault_code)
{
	int i;

	if (fault_code == NULL)
		return FAULT_CPE_NO_FAULT;

	for (i = 1; i < __FAULT_CPE_MAX; i++) {
		if (CWMP_STRCMP(FAULT_CPE_ARRAY[i].CODE, fault_code) == 0)
			break;
	}

	if (i == __FAULT_CPE_MAX)
		i = FAULT_CPE_INTERNAL_ERROR;

	return i;
}

/*
 * Memory mgmt
 */

void *icwmp_malloc(size_t size)
{
	struct cwmp_mem *m = malloc(sizeof(struct cwmp_mem) + size);
	if (m == NULL)
		return NULL;
	list_add(&m->list, &cwmp_memory_list);
	return (void *)m->mem;
}

void *icwmp_calloc(int n, size_t size)
{
	struct cwmp_mem *m = calloc(n, sizeof(struct cwmp_mem) + size);
	if (m == NULL)
		return NULL;
	list_add(&m->list, &cwmp_memory_list);
	return (void *)m->mem;
}

void *icwmp_realloc(void *n, size_t size)
{
	struct cwmp_mem *m = NULL;
	if (n != NULL) {
		m = container_of(n, struct cwmp_mem, mem);
		list_del(&m->list);
	}
	struct cwmp_mem *new_m = realloc(m, sizeof(struct cwmp_mem) + size);
	if (new_m == NULL) {
		icwmp_free(m);
		return NULL;
	} else
		m = new_m;
	list_add(&m->list, &cwmp_memory_list);
	return (void *)m->mem;
}

char *icwmp_strdup(const char *s)
{
	if (s == NULL)
		return NULL;
	size_t len = strlen(s) + 1;
	void *new = icwmp_malloc(len);
	if (new == NULL)
		return NULL;
	return (char *)CWMP_MEMCPY(new, s, len);
}

int icwmp_asprintf(char **s, const char *format, ...)
{
	int size;
	char *str = NULL;
	va_list arg, argcopy;

	va_start(arg, format);
	va_copy(argcopy, arg);
	size = vsnprintf(NULL, 0, format, argcopy);
	va_end(argcopy);

	if (size < 0) {
		va_end(arg);
		return -1;
	}
	str = (char *)calloc(sizeof(char), size + 1);
	vsnprintf(str, size + 1, format, arg);
	va_end(arg);

	*s = icwmp_strdup(str);
	free(str);
	if (*s == NULL)
		return -1;
	return 0;
}

void icwmp_free(void *m)
{
	if (m == NULL)
		return;
	struct cwmp_mem *rm;
	rm = container_of(m, struct cwmp_mem, mem);
	if (rm != NULL) {
		list_del(&rm->list);
		free(rm);
	}
}

void icwmp_cleanmem()
{
	struct cwmp_mem *mem;
	while (cwmp_memory_list.next != &cwmp_memory_list) {
		mem = list_entry(cwmp_memory_list.next, struct cwmp_mem, list);
		if (mem != NULL) {
			list_del(&mem->list);
			free(mem);
		}
	}
}

/*
 * Services Management
 */
void icwmp_init_list_services()
{
	int i;

	nbre_services = 0;
	for (i = 0; i < MAX_NBRE_SERVICES; i++)
		list_services[i] = NULL;
}

int icwmp_add_service(char *service)
{
	if (nbre_services >= MAX_NBRE_SERVICES)
		return -1;
	list_services[nbre_services++] = strdup(service);
	return 0;
}

void icwmp_free_list_services()
{
	int i = 0;
	for (i = 0; i < nbre_services; i++) {
		FREE(list_services[i]);
	}
	nbre_services = 0;
}

void icwmp_restart_services()
{
	int i;

	for (i = 0; i < nbre_services; i++) {
		if (list_services[i] == NULL)
			continue;

		struct blob_buf b = { 0 };
		CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
		blob_buf_init(&b, 0);
		bb_add_string(&b, "config", list_services[i]);

		if (CWMP_STRCMP(list_services[i], "cwmp") == 0) {
			commit_uci_package("cwmp");
		} else {
			icwmp_ubus_invoke("uci", "commit", b.head, NULL, NULL);
		}

		blob_buf_free(&b);

		if (CWMP_STRCMP(list_services[i], "firewall") == 0) {
			g_firewall_restart = true;
		}
	}
	if (g_firewall_restart) {
			CWMP_LOG(INFO, "Initiating Firewall restart");
			set_uci_path_value(VARSTATE_CONFIG, "icwmp.cpe.firewall_restart", "in_progress");
	}
	icwmp_free_list_services();
}

/*
 * Arguments validation
 */
bool icwmp_validate_string_length(char *arg, int max_length)
{
	if (arg != NULL && strlen(arg) > (size_t)max_length)
		return false;
	return true;
}

bool icwmp_validate_boolean_value(char *arg)
{
	if (!arg ||( CWMP_STRCMP(arg, "1") != 0 && CWMP_STRCMP(arg, "0") != 0 && CWMP_STRCMP(arg, "true") != 0 && CWMP_STRCMP(arg, "false") != 0))
		return false;
	return true;
}

bool icwmp_validate_unsignedint(char *arg)
{
	int arg_int;

	if(arg == NULL)
		return false;

	if (strcmp(arg, "0") == 0)
		arg_int = 0;
	else {
		arg_int = atoi(arg);
		if (arg_int == 0)
			return false;
	}
	return arg_int >= 0;
}

bool icwmp_validate_int_in_range(char *arg, int min, int max)
{
	int arg_int;

	if(arg == NULL)
		return false;

	if (strcmp(arg, "0") == 0)
		arg_int = 0;
	else {
		arg_int = atoi(arg);
		if (arg_int == 0)
			return false;
	}
	return arg_int >= min && arg_int <= max;
}

char *string_to_hex(const unsigned char *str, size_t size)
{
	size_t i;

	char *hex = (char*) calloc(size * 2 + 1, sizeof(char));

	if (!hex) {
		CWMP_LOG(ERROR, "Unable to allocate memory for hex string\n");
		return NULL;
	}

	if (size == 0)
		return hex;

	for (i = 0; i < size; i++)
		snprintf(hex + (i * 2), 3, "%02X", str[i]);

	return hex;
}

int copy_file(char *source_file, char *target_file)
{
	char ch;
	FILE *source, *target;
	source = fopen(source_file, "r");
	if (source == NULL) {
		CWMP_LOG(ERROR, "Not able to open the source file: %s\n", source_file);
		return -1;
	}
	target = fopen(target_file, "w");
	if (target == NULL) {
		fclose(source);
		CWMP_LOG(ERROR, "Not able to open the target file: %s\n", target_file);
		return -1;
	}

	ch = fgetc(source);
	while( feof(source) != EOF) {
		fputc(ch, target);
		ch = fgetc(source);
	}

	CWMP_LOG(ERROR, "File copied successfully.\n");
	fclose(source);
	fclose(target);
	return 0;
}

static void ubus_network_interface_callback(struct ubus_request *req __attribute__((unused)), int type __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *tb[1] = {0};
	struct blobmsg_policy p[1] = {
			{ "l3_device", BLOBMSG_TYPE_STRING }
	};

	if (msg == NULL)
		return;

	blobmsg_parse(p, 1, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[0])
		return;

	char *l3_device = blobmsg_get_string(tb[0]);
	if (!CWMP_STRLEN(l3_device))
		return;

	snprintf(cwmp_main->net.interface, sizeof(cwmp_main->net.interface), "%s", l3_device);

	CWMP_LOG(DEBUG, "CWMP IFACE - interface: %s && device: %s", cwmp_main->conf.default_wan_iface, cwmp_main->net.interface);
}

static bool is_ipv6_addr_available(const char *device)
{
	struct ifaddrs *ifaddr = NULL,*ifa = NULL;
	void *in_addr = NULL;
	bool ipv6_addr_available = false;
	int family, err = 0;

	if (CWMP_STRLEN(device) == 0)
		return false;

	err = getifaddrs(&ifaddr);
	if (err != 0)
		return false;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

		if (ifa->ifa_addr == NULL || CWMP_STRCMP(ifa->ifa_name, device) != 0)
			continue;

		family = ifa->ifa_addr->sa_family;

		// Skip this result, if it is not an IPv6 node
		if (family != AF_INET6)
		    continue;

		#define NOT_GLOBAL_UNICAST(addr) \
            		( (IN6_IS_ADDR_UNSPECIFIED(addr)) || (IN6_IS_ADDR_LOOPBACK(addr))  ||   \
              		(IN6_IS_ADDR_MULTICAST(addr))   || (IN6_IS_ADDR_LINKLOCAL(addr)) ||   \
              		(IN6_IS_ADDR_SITELOCAL(addr)) )

		if (family == AF_INET6) {

			in_addr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;

			// Skip this result, if it is an IPv6 address, but not globally routable
			if (NOT_GLOBAL_UNICAST((struct in6_addr *)in_addr))
				continue;

			ipv6_addr_available = true;
			break;
		}
	}

	freeifaddrs(ifaddr);

	return ipv6_addr_available;
}

bool is_ipv6_enabled(void)
{
	if (cwmp_main->conf.force_ipv4 == true)
		return false;

	if (CWMP_STRLEN(cwmp_main->net.interface) == 0) {
		struct blob_buf b = {0};
		char network_interface[64];

		CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
		blob_buf_init(&b, 0);

		snprintf(network_interface, sizeof(network_interface), "network.interface.%s", cwmp_main->conf.default_wan_iface);

		int e = icwmp_ubus_invoke(network_interface, "status", b.head, ubus_network_interface_callback, NULL);

		blob_buf_free(&b);

		if (e != 0 || CWMP_STRLEN(cwmp_main->net.interface) == 0)
			return false;
	}

	if (!is_ipv6_addr_available(cwmp_main->net.interface))
		return false;

	return true;
}

bool is_ipv6_status_changed(void)
{
	bool curr_ipv6_status = is_ipv6_enabled();
	bool ipv6_status_changed = (curr_ipv6_status != cwmp_main->net.ipv6_status);
	cwmp_main->net.ipv6_status = curr_ipv6_status;

	return ipv6_status_changed;
}

char *get_time(time_t t_time)
{
	static char local_time[32] = {0};
	struct tm *t_tm;

	t_tm = localtime(&t_time);
	if (t_tm == NULL)
		return NULL;

	if (strftime(local_time, sizeof(local_time), "%FT%T%z", t_tm) == 0)
		return NULL;

	local_time[25] = local_time[24];
	local_time[24] = local_time[23];
	local_time[22] = ':';
	local_time[26] = '\0';

	return local_time;
}

time_t convert_datetime_to_timestamp(char *value)
{
	struct tm tm = { 0 };
	int year = 0, month = 0, day = 0, hour = 0, min = 0, sec = 0;

	sscanf(value, "%4d-%2d-%2dT%2d:%2d:%2d", &year, &month, &day, &hour, &min, &sec);
	tm.tm_year = year - 1900; /* years since 1900 */
	tm.tm_mon = month - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = min;
	tm.tm_sec = sec;

	return mktime(&tm);
}

bool str_to_bool(char *value)
{
	if (!value)
		return false;

	if (strncasecmp(value, "true", 4) == 0 ||
	    value[0] == '1' ||
	    strncasecmp(value, "on", 2) == 0 ||
	    strncasecmp(value, "yes", 3) == 0 ||
	    strncasecmp(value, "enable", 6) == 0)
		return true;

	return false;
}

bool match_reg_exp(char *reg_exp, char *param_name)
{
	if (reg_exp == NULL || param_name == NULL)
		return false;

	regex_t reegex;
	int ret = regcomp(&reegex, reg_exp, REG_EXTENDED);
	if (ret != 0)
		return false;

	ret = regexec(&reegex, param_name, 0, NULL, 0);
	regfree(&reegex);
	if (ret != 0)
		return false;

	return true;
}

void cwmp_invoke_intf_reset(char *path)
{
	struct blob_buf b = {0};
	char command[256] = {0};

	if (CWMP_STRLEN(path) == 0)
		return;

	snprintf(command, sizeof(command), "%sReset()", path);

	CWMP_LOG(DEBUG, "Reset interface: %s", path);

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));

	blob_buf_init(&b, 0);
	bb_add_string(&b, "command", command);
	bb_add_string(&b, "command_key", "cwmp_reset_intf");

	icwmp_ubus_invoke(BBFDM_OBJECT_NAME, "operate", b.head, NULL, NULL);
	blob_buf_free(&b);
}

int get_month_days(struct tm time)
{
	if (time.tm_mon == 2)
		return (time.tm_year % 4 == 0 ) ? 29 : 28;
	if (((time.tm_mon % 2 == 0) && (time.tm_mon <= 7)) ||  ((time.tm_mon % 2 == 1) && (time.tm_mon > 7)))
		return 30;
	if (((time.tm_mon % 2 == 1) && (time.tm_mon <= 7)) ||  ((time.tm_mon % 2 == 0) && (time.tm_mon > 7)))
		return 31;
	return 30;
}

void add_day_to_time(struct tm *time)
{
	int month_days = get_month_days(*time);
	if (time->tm_mon == month_days) {
		time->tm_mday = 1;
		if (time->tm_mon == 12) {
			time->tm_mon = 1;
			time->tm_year = time->tm_year + 1;
		} else
			time->tm_mon = time->tm_mon + 1;
	} else
		time->tm_mday = time->tm_mday + 1;
}

void add_bin_list(struct list_head *list, uint8_t *str, size_t len)
{
	bin_list_t *node;

	if (len >= 1024) {
		CWMP_LOG(ERROR, "Binary length out of index");
		return;
	}

	node = (bin_list_t *)calloc(1, sizeof(*node));
	if (!node) {
		CWMP_LOG(ERROR, "Out of memory!");
		return;
	}

	INIT_LIST_HEAD(&node->list);
	CWMP_MEMCPY(node->bin, str, len);
	node->len = len;

	list_add_tail(&node->list, list);
}

void add_str_binlist(struct list_head *list, char *str)
{
	if (str != NULL) {
		add_bin_list(list, (uint8_t *)str, strlen(str));
	}
}

void free_binlist(struct list_head *blist)
{
	bin_list_t *iter = NULL, *node;

	list_for_each_entry_safe(iter, node, blist, list) {
		list_del(&iter->list);
		FREE(iter);
	}
}

int cwmp_strcmp(const char *s1, const char *s2, const char *origin, int pos)
{
	if (s1 != NULL && s2 != NULL)
		return strcmp(s1, s2);
	else {
		CWMP_LOG(DEBUG, "%s:%d NULL argument found", origin, pos);
		return -1;
	}
}

int cwmp_strncmp(const char *s1, const char *s2, int len, const char *origin, int pos)
{
	if (s1 != NULL && s2 != NULL && len > 0)
		return strncmp(s1, s2, len);
	else {
		CWMP_LOG(DEBUG, "%s:%d NULL argument found", origin, pos);
		return -1;
	}
}

int cwmp_strlen(const char *s1, const char *origin, int pos)
{
	if (s1 != NULL)
		return strlen(s1);
	else {
		CWMP_LOG(DEBUG, "%s:%d NULL argument found", origin, pos);
		return 0;
	}
}

int cwmp_strcasecmp(const char *s1, const char *s2, const char *origin, int pos)
{
	if (s1 != NULL && s2 != NULL)
		return strcasecmp(s1, s2);
	else {
		CWMP_LOG(DEBUG, "%s:%d NULL argument found", origin, pos);
		return -1;
	}
}

char *cwmp_strstr(const char *s1, const char *s2, const char *origin, int pos)
{
	if (s1 != NULL && s2 != NULL)
		return strstr(s1, s2);
	else {
		CWMP_LOG(DEBUG, "%s:%d NULL argument found", origin, pos);
		return NULL;
	}
}

char *cwmp_strncpy(char *dst, const char *src, int size, const char *origin, int pos)
{
	if (size <= 0)
		return dst;

	if (dst != NULL && src != NULL) {
		strncpy(dst, src, size - 1);
		dst[size - 1] = '\0';
	} else {
		CWMP_LOG(DEBUG, "%s:%d NULL argument found", origin, pos);
	}

	return dst;
}

char *cwmp_strdup(const char *s1, const char *origin, int pos)
{
	if (s1)
		return strdup(s1);
	else {
		CWMP_LOG(DEBUG, "%s:%d NULL argument found", origin, pos);
		return NULL;
	}
}

void *cwmp_memset(void *src, int val, size_t size, const char *origin, int pos)
{
	if (src)
		return memset(src, val, size);
	else {
		CWMP_LOG(DEBUG, "%s:%d NULL argument found", origin, pos);
		return NULL;
	}
}

void *cwmp_memcpy(void *dst, const void *src, size_t size, const char *origin, int pos)
{
	if (dst != NULL && src != NULL)
		return memcpy(dst, src, size);
	else {
		CWMP_LOG(DEBUG, "%s:%d NULL argument found", origin, pos);
		return dst;
	}
}

void cwmp_restart_service(struct uloop_timeout *timeout  __attribute__((unused)))
{
	struct blob_buf b = { 0 };

	CWMP_MEMSET(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	bb_add_string(&b, "name", "icwmpd");
	bb_add_string(&b, "action", "restart");

	icwmp_ubus_invoke("rc", "init", b.head, NULL, NULL);

	blob_buf_free(&b);
	CWMP_LOG(DEBUG, "Scheduled icwmpd restart");
}
