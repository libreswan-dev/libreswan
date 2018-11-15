/testing/guestbin/swan-prep --46
# confirm that the network is alive
ping6 -n -c 4 -I 2001:db8:0:1::254 2001:db8:0:2::254
# make sure that clear text does not get through
ip6tables -A INPUT -i eth1 -s 2001:db8:0:2::254 -p ipv6-icmp --icmpv6-type echo-reply  -j LOGDROP
# confirm with a ping
ping6 -n -c 4 -I 2001:db8:0:1::254 2001:db8:0:2::254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-6in6
ipsec auto --status
echo "initdone"
