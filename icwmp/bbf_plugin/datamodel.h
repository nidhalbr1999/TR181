/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	Author: Feten Besbes <feten.besbes@pivasoftware.com>
 */

#ifndef __MANAGEMENT_SERVER_H
#define __MANAGEMENT_SERVER_H

#include <libbbfdm-api/dmcommon.h>

extern DMOBJ tCWMPObj[];
extern DMOBJ tManagementServerObj[];
extern DMLEAF tManagementServerParams[];
extern DMLEAF tHeartbeatPolicyParams[];
extern DMLEAF tInformParameterParams[];
extern DMLEAF tManageableDeviceParams[];
extern DMLEAF tTransferComplPolicyParams[];
extern DMLEAF tDUStateChangeComplPolicyParams[];

#endif
