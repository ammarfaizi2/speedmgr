// SPDX-License-Identifier: GPL-2.0-only

#include <unordered_map>
#include <functional>
#include <cstdint>
#include <cstring>
#include <cerrno>

#include "ip_map.h"

struct in_addr6 {
	char data[16];

	bool operator==(const in_addr6 &other) const
	{
		return memcmp(data, other.data, sizeof(data)) == 0;
	}
};

template <>
struct std::hash<in_addr6> {
	size_t operator()(const in_addr6 &ip) const
	{
		size_t i, ret = 0;

		for (i = 0; i < 16; i++)
			ret ^= ip.data[i] << (i % 8);

		return ret;
	}
};

struct ip_map {
	std::unordered_map<uint32_t, void *>	ipv4;
	std::unordered_map<in_addr6, void *>	ipv6;
};

extern "C" {

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

		if (family == 6) {
			in_addr6 ipv6;

			memcpy(ipv6.data, ip, sizeof(ipv6.data));
			imap->ipv6[ipv6] = data;
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

		if (family == 6) {
			in_addr6 ipv6;

			memcpy(ipv6.data, ip, sizeof(ipv6.data));
			if (imap->ipv6.find(ipv6) == imap->ipv6.end())
				return -ENOENT;

			imap->ipv6.erase(ipv6);
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

	if (family == 4) {
		uint32_t ipv4;

		memcpy(&ipv4, ip, sizeof(ipv4));
		if (imap->ipv4.find(ipv4) == imap->ipv4.end())
			return -ENOENT;

		*data = imap->ipv4[ipv4];
		return 0;
	}

	if (family == 6) {
		in_addr6 ipv6;

		memcpy(ipv6.data, ip, sizeof(ipv6.data));
		if (imap->ipv6.find(ipv6) == imap->ipv6.end())
			return -ENOENT;

		*data = imap->ipv6[ipv6];
		return 0;
	}

	return -EINVAL;
}

uint32_t ip_map_count(ip_map_t *map, char family)
{
	struct ip_map *imap = (struct ip_map *)*map;

	if (family == 4)
		return imap->ipv4.size();

	if (family == 6)
		return imap->ipv6.size();

	return -EINVAL;
}

} /* extern "C" */
