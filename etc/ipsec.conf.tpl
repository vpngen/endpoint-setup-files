config setup
    plutodebug=none
    virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:25.0.0.0/8,%v4:100.64.0.0/10,%v6:fd00::/8,%v6:fe80::/10
    uniqueids=no
    listen=${ext_ip}

conn ikev1
    authby=secret
    pfs=no
    auto=add
    rekey=no
    left=${ext_ip}
    right=%any
    ikev2=never
    type=transport
    leftprotoport=17/1701
    rightprotoport=17/%any
    dpddelay=15
    dpdtimeout=30
    dpdaction=clear

conn ikev1-nat
    also=ikev1
    rightsubnet=vhost:%priv
