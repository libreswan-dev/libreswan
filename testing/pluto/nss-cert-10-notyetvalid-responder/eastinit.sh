/testing/guestbin/swan-prep --x509 --x509name notyetvalid
certutil -d sql:/etc/ipsec.d -D -n west
ipsec _stackmanager start
mkdir -p /var/run/pluto
# set a time in the future so notyetvalid and west certs are valid
faketime -f +370d ipsec pluto  --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started
# if faketime works, adding conn should not give a warning about cert
ipsec auto --add nss-cert
echo "initdone"