/*
 * common.h
 * Misc functions used in idevicerestore
 *
 * Copyright (c) 2012-2019 Nikias Bassen. All Rights Reserved.
 * Copyright (c) 2012 Martin Szulecki. All Rights Reserved.
 * Copyright (c) 2010 Joshua Hill. All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __COMMON_H
#define __COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <unistd.h>

#include <plist/plist.h>


#define USER_AGENT_STRING "InetURL/1.0"

__attribute__((format(printf, 1, 2)))
void info(const char* format, ...);
__attribute__((format(printf, 1, 2)))
void error(const char* format, ...);
__attribute__((format(printf, 1, 2)))
void debug(const char* format, ...);

char *generate_guid(void);

uint8_t _plist_dict_get_bool(plist_t dict, const char *key);
uint64_t _plist_dict_get_uint(plist_t dict, const char *key);
int _plist_dict_copy_uint(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key);
int _plist_dict_copy_bool(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key);
int _plist_dict_copy_data(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key);
int _plist_dict_copy_string(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key);
int _plist_dict_copy_item(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key);

#ifdef __cplusplus
}
#endif

#endif
