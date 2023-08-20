local 127.0.0.1
port 1194
proto tcp
dev tun
topology subnet
server 100.128.0.0 255.255.0.0
keepalive 10 120
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA512
user nobody
group nogroup
persist-key
persist-tun
verb 1
tls-server
tls-version-min 1.2
syslog
ca /opt/openvpn-${netns}/pki/ca.crt
cert /opt/openvpn-${netns}/pki/issued/server.crt
key /opt/openvpn-${netns}/pki/private/server.key
crl-verify /opt/openvpn-${netns}/crl.pem
dh /etc/openvpn/dh.pem
client-config-dir /opt/openvpn-${netns}/ccd
ccd-exclusive
script-security 2
up /etc/openvpn/openvpn-tc.sh
down /etc/openvpn/openvpn-tc.sh
client-connect /etc/openvpn/openvpn-tc.sh
client-disconnect /etc/openvpn/openvpn-tc.sh
status /opt/openvpn-${netns}/status.log
