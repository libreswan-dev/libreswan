ipsec auto --up  west-east-4in6
# FIXME: should work without -I option
ping -n -c 4 -I 192.0.1.254 192.0.2.254
../../pluto/bin/ipsec-look.sh
echo done
