/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n east
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/mainca/usage-both.p12
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
echo "initdone"
