// SPDX-License-Identifier: GPL-2.0-only

#include <unordered_map>
#include <cstdint>
#include <cstring>
#include <cerrno>

#include "ip_map.h"

extern "C" {

struct ip_map {
	std::unordered_map<uint32_t, void *> ipv4;
};

int ip_map_init(ip_map_t *map)
{
	try {
		*map = new ip_map;
	} catch (std::bad_alloc &e) {
		return -ENOMEM;
	}

	return 0;
}

void ip_map_destroy(ip_map_t *map)
{
	struct ip_map *imap = (struct ip_map *)*map;

	delete imap;
	*map = nullptr;
}

int ip_map_add(ip_map_t *map, const void *ip, char family, void *data)
{
	struct ip_map *imap = (struct ip_map *)*map;

	try {
		if (family == 4) {
			uint32_t ipv4;

			memcpy(&ipv4, ip, sizeof(ipv4));
			imap->ipv4[ipv4] = data;
			return 0;
		}
	} catch (std::bad_alloc &e) {
		return -ENOMEM;
	}

	return -EINVAL;
}

int ip_map_del(ip_map_t *map, const void *ip, char family)
{
	struct ip_map *imap = (struct ip_map *)*map;

	try {
		if (family == 4) {
			uint32_t ipv4;

			memcpy(&ipv4, ip, sizeof(ipv4));
			if (imap->ipv4.find(ipv4) == imap->ipv4.end())
				return -ENOENT;

			imap->ipv4.erase(ipv4);
			return 0;
		}
	} catch (std::bad_alloc &e) {
		return -ENOMEM;
	}

	return -EINVAL;
}

int ip_map_get(ip_map_t *map, const void *ip, char family, void **data)
{
	struct ip_map *imap = (struct ip_map *)*map;

	try {
		if (family == 4) {
			uint32_t ipv4;

			memcpy(&ipv4, ip, sizeof(ipv4));
			if (imap->ipv4.find(ipv4) == imap->ipv4.end())
				return -ENOENT;

			*data = imap->ipv4[ipv4];
			return 0;
		}
	} catch (std::bad_alloc &e) {
		return -ENOMEM;
	}

	return -EINVAL;
}

uint32_t ip_map_count(ip_map_t *map, char family)
{
	struct ip_map *imap = (struct ip_map *)*map;

	try {
		if (family == 4)
			return imap->ipv4.size();
	} catch (std::bad_alloc &e) {
		return -ENOMEM;
	}

	return -EINVAL;
}

} /* extern "C" */
