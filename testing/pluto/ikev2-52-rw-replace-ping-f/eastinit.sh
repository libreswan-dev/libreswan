/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add rw-eastnet-x509-ipv4
echo "initdone"
