// SPDX-License-Identifier: GPL-2.0-only
#ifndef SPEEDMGR__HT_H
#define SPEEDMGR__HT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef void *ht_t;

struct ht_data {
	union {
		void *ptr;
		uint64_t u64;
		uint32_t u32;
		uint16_t u16;
		uint8_t u8;
	};
};

int ht_create(ht_t *ht);
void ht_destroy(ht_t *ht);
int ht_insert(ht_t *ht, const void *key, size_t key_len, const struct ht_data *data);
int ht_remove(ht_t *ht, const void *key, size_t key_len);
int ht_lookup(ht_t *ht, const void *key, size_t key_len, struct ht_data **data);
size_t ht_count(ht_t *ht);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef SPEEDMGR__HT_H */
