/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n west
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert
echo "initdone"
