ipsec auto --up  westnet-eastnet
ipsec look
echo take-passthrough-unencrpted | nc -s 192.0.1.254 192.0.2.254 22
echo take-conn-encrypted | nc -s 192.0.1.254 192.0.2.254 222
echo done
