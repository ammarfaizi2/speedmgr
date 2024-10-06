// SPDX-License-Identifier: GPL-2.0-only

#include "ht.h"

#include <unordered_map>
#include <stdexcept>
#include <memory>
#include <string>

extern "C" {

static std::string hex_encode(const void *blob, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	std::string r(len * 2, '\0');
	size_t i;

	for (i = 0; i < len; i++) {
		r[2 * i] = hex[((const uint8_t *)blob)[i] >> 4];
		r[2 * i + 1] = hex[((const uint8_t *)blob)[i] & 0xf];
	}

	return r;
}

int ht_create(ht_t *ht)
{
	try {
		auto *p = new std::unordered_map<std::string, std::unique_ptr<struct ht_data>>;
		*ht = p;
		return 0;
	} catch (...) {
		return -ENOMEM;
	}
}

void ht_destroy(ht_t *ht)
{
	try {
		delete static_cast<std::unordered_map<std::string, std::unique_ptr<struct ht_data>> *>(*ht);
		*ht = nullptr;
	} catch (...) {
	}
}

int ht_insert(ht_t *ht, const void *key, size_t key_len, const struct ht_data *data)
{
	try {
		auto *p = static_cast<std::unordered_map<std::string, std::unique_ptr<struct ht_data>> *>(*ht);
		std::string k = hex_encode(key, key_len);

		auto it = p->find(k);
		if (it != p->end())
			return -EEXIST;

		p->emplace(k, std::make_unique<struct ht_data>(*data));
		return 0;
	} catch (...) {
		return -ENOMEM;
	}
}

int ht_remove(ht_t *ht, const void *key, size_t key_len)
{
	try {
		auto *p = static_cast<std::unordered_map<std::string, std::unique_ptr<struct ht_data>> *>(*ht);
		std::string k = hex_encode(key, key_len);

		auto it = p->find(k);
		if (it == p->end())
			return -ENOENT;

		p->erase(it);
		return 0;
	} catch (...) {
		return -ENOMEM;
	}
}

int ht_lookup(ht_t *ht, const void *key, size_t key_len, struct ht_data **data)
{
	try {
		auto *p = static_cast<std::unordered_map<std::string, std::unique_ptr<struct ht_data>> *>(*ht);
		std::string k = hex_encode(key, key_len);

		auto it = p->find(k);
		if (it == p->end())
			return -ENOENT;

		*data = it->second.get();
		return 0;
	} catch (...) {
		return -ENOMEM;
	}
}

size_t ht_count(ht_t *ht)
{
	try {
		auto *p = static_cast<std::unordered_map<std::string, std::unique_ptr<struct ht_data>> *>(*ht);
		return p->size();
	} catch (...) {
		return 0;
	}
}

} /* extern "C" */
