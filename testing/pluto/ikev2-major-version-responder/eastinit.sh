/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-major-version-bump
ipsec auto --add westnet-eastnet-ikev2-major
echo "initdone"
