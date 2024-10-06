#!/bin/bash

# If the first argument is "on", apply the iptables rules.
# If the first argument is "off", remove the iptables rules.

if [ "$1" == "on" ]; then
	set -x;
	sudo iptables -t nat -I OUTPUT -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
	sudo iptables -t nat -I PREROUTING -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
	sudo ip6tables -t nat -I OUTPUT -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
	sudo ip6tables -t nat -I PREROUTING -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
elif [ "$1" == "off" ]; then
	set -x;
	sudo iptables -t nat -D OUTPUT -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
	sudo iptables -t nat -D PREROUTING -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
	sudo ip6tables -t nat -D OUTPUT -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
	sudo ip6tables -t nat -D PREROUTING -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
else
	echo "Usage: $0 {on|off}";
	exit 1;
fi
