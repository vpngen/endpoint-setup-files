[modules]
log_syslog
l2tp
auth_mschap_v2
chap-secrets
ippool
pppd_compat

[core]
thread-count=4

[common]
single-session=replace
max-sessions=256
max-starting=16

[ppp]
verbose=1
min-mtu=1280
mtu=1400
mru=1400
ipv4=require
ipv6=never
unit-cache=1

[l2tp]
bind=${ext_ip}
verbose=1
secret=
reorder-timeout=0
ifname=l2tp%d

[dns]
dns1=100.127.0.1

[client-ip-range]
0.0.0.0/0

[ip-pool]
gw-ip-address=100.127.0.1
100.127.0.1/17
100.127.255.2-254,name=ip_pool_adm

[log]
syslog=accel-pppd,daemon
copy=1
level=4

[pppd-compat]
verbose=1
ip-up=/etc/accel-ppp.ip-up
ip-down=/etc/accel-ppp.ip-down

[chap-secrets]
gw-ip-address=100.127.0.1
chap-secrets=/etc/accel-ppp.chap-secrets.${netns}

[cli]
verbose=1
tcp=127.0.0.1:2001
