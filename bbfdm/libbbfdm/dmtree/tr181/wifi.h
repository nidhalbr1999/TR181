/*
 * Copyright (C) 2023 IOPSYS Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __WIFI_H
#define __WIFI_H

#include "libbbfdm-api/dmcommon.h"

extern DMOBJ tWiFiObj[];
extern DMLEAF tWiFiParams[];
extern DMOBJ tWiFiRadioObj[];
extern DMOBJ tWiFiAccessPointObj[];
extern DMOBJ tWiFiSSIDObj[];
extern DMLEAF tWiFiAccessPointParams[];
extern DMLEAF tWiFiSSIDParams[];
extern DMLEAF tWiFiRadioParams[];
extern DMLEAF tWiFiAccessPointSecurityParams[];
extern DMLEAF tWiFiAccessPointAssociatedDeviceParams[];
extern DMOBJ tWiFiAccessPointAssociatedDeviceObj[];
extern DMLEAF tWiFiAccessPointAssociatedDeviceStatsParams[];
extern DMLEAF tWiFiRadioStatsParams[];
extern DMLEAF tWiFiSSIDStatsParams[];
extern DMOBJ tWiFiNeighboringWiFiDiagnosticObj[];
extern DMLEAF tWiFiNeighboringWiFiDiagnosticParams[];
extern DMLEAF tWiFiNeighboringWiFiDiagnosticResultParams[];
extern DMLEAF tWiFiAccessPointWPSParams[];
extern DMLEAF tWiFiAccessPointAccountingParams[];
extern DMOBJ tWiFiEndPointObj[];
extern DMLEAF tWiFiEndPointParams[];
extern DMLEAF tWiFiEndPointSecurityParams[];
extern DMLEAF tWiFiEndPointWPSParams[];
extern DMOBJ tWiFiEndPointProfileObj[];
extern DMLEAF tWiFiEndPointProfileParams[];
extern DMLEAF tWiFiEndPointProfileSecurityParams[];
extern DMLEAF tWiFiEndPointStatsParams[];

#endif
