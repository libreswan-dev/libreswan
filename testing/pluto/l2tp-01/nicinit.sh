#!/bin/sh
iptables -t nat -F
iptables -F
echo done
