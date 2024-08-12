/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: <Name> <Surname> <name.surname@iopsys.eu>
 */

#ifndef __ETHERNET_H
#define __ETHERNET_H

#include <libbbfdm-api/dmcommon.h>

extern DMOBJ tEthernetObj[];
extern DMLEAF tEthernetParams[];
extern DMOBJ tEthernetInterfaceObj[];
extern DMLEAF tEthernetInterfaceParams[];
extern DMLEAF tEthernetInterfaceStatsParams[];
extern DMOBJ tEthernetLinkObj[];
extern DMLEAF tEthernetLinkParams[];
extern DMLEAF tEthernetLinkStatsParams[];
extern DMOBJ tEthernetVLANTerminationObj[];
extern DMLEAF tEthernetVLANTerminationParams[];
extern DMLEAF tEthernetVLANTerminationStatsParams[];
extern DMLEAF tEthernetRMONStatsParams[];
extern DMLEAF tEthernetWoLParams[];
extern DMOBJ tEthernetLAGObj[];
extern DMLEAF tEthernetLAGParams[];
extern DMLEAF tEthernetLAGStatsParams[];


#endif //__ETHERNET_H

