#!/bin/bash

set -x;

# If the first argument is "on", apply the iptables rules.
# If the first argument is "off", remove the iptables rules.

if [ "$1" == "on" ]; then
	iptables -t filter -I OUTPUT -p udp --dport 443 -j REJECT;
	iptables -t nat -I OUTPUT -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;

	ip6tables -t filter -I OUTPUT -p udp --dport 443 -j REJECT;
	ip6tables -t nat -I OUTPUT -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
elif [ "$1" == "off" ]; then
	iptables -t filter -D OUTPUT -p udp --dport 443 -j REJECT;
	iptables -t nat -D OUTPUT -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;

	ip6tables -t filter -D OUTPUT -p udp --dport 443 -j REJECT;
	ip6tables -t nat -D OUTPUT -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
else
    echo "Usage: $0 {on|off}"
    exit 1
fi
