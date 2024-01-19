// SPDX-License-Identifier: GPL-2.0-only

#ifndef SPEEDMGR__IP_MAP_H
#define SPEEDMGR__IP_MAP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *ip_map_t;

extern int ip_map_init(ip_map_t *map);
extern void ip_map_destroy(ip_map_t *map);
extern int ip_map_add(ip_map_t *map, const void *ip, char family, void *data);
extern int ip_map_del(ip_map_t *map, const void *ip, char family);
extern int ip_map_get(ip_map_t *map, const void *ip, char family, void **data);
extern uint32_t ip_map_count(ip_map_t *map, char family);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SPEEDMGR__IP_MAP_H */
