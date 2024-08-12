#!/bin/sh

BBFDMD="/usr/sbin/bbfdmd"

bbfdm_add_service()
{
	local name path

	name="${1}"
	path="${2}"

	if [ -z "${name}" -o -z "$path" ]; then
		return 0;
	fi

	ubus call service add "{'name':'bbfdm.services','instances':{'$name':{'command':['$BBFDMD','-m','$path']}}}"
}

bbfdm_stop_service()
{
	local name

	name="${1}"
	if [ -z "${name}" ]; then
		return 0;
	fi

	if ubus call service list '{"name":"bbfdm.services"}' |grep -q "bbfdm.$name"; then
		ubus call service delete "{'name':'bbfdm.services','instance':'bbfdm.$name'}"
	fi
}

usages()
{
	echo "Usages $0: <OPTIONS>..."
	echo
	echo "    -h    show help"
	echo "    -k    micro-service name to stop"
	echo
}

while getopts "s:k:h" opts; do
	case "$opts" in
		h) usages; exit 0;;
		k) bbfdm_stop_service "${OPTARG}";;
	esac
done
