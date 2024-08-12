/*
 * cwmp_zlib.h - ZLIB compresssion of CWMP messages
 *
 * Copyright (C) 2021-2022, IOPSYS Software Solutions AB.
 *
 *	  Author Mohamed Kallel <mohamed.kallel@pivasoftware.com>
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef __ZLIB_H
#define __ZLIB_H

int zlib_compress(char *message, unsigned char **zmsg, int *zlen, int type);

#endif
