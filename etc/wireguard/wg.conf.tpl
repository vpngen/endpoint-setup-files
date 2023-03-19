[Interface]
ListenPort = 51820
SaveConfig = false
### Interface start and setup
PreUp = iptables -P INPUT DROP
PreUp = iptables -P FORWARD DROP
PreUp = ip6tables -P INPUT DROP
PreUp = ip6tables -P FORWARD DROP
PreUp = iptables -A INPUT -i %i -p icmp -m icmp --icmp-type 8 -j ACCEPT
PreUp = ip6tables -A INPUT -p ipv6-icmp -j ACCEPT -m comment --comment ${ext_if}
PreUp = iptables -A FORWARD -i %i -o ${ext_if} -j ACCEPT
PreUp = iptables -A FORWARD -o %i -i ${ext_if} -j ACCEPT
PreUp = ip6tables -A FORWARD -i %i -o ${ext_if} -j ACCEPT
PreUp = ip6tables -A FORWARD -o %i -i ${ext_if} -j ACCEPT
PreUp = iptables -t nat -A POSTROUTING -s ${int_ip_nm} -m hashlimit --hashlimit-name logv4 --hashlimit-mode srcip,dstip,dstport --hashlimit-upto 1/minute --hashlimit-burst 1 --hashlimit-htable-expire 60000 -j LOG --log-prefix "[LEA-DIR]: "
PreUp = iptables -t nat -A POSTROUTING -s ${int_ip_nm} -j SNAT --to ${ext_ip}
PreUp = ip6tables -t nat -A POSTROUTING -o ${ext_if} -m hashlimit --hashlimit-name logv6 --hashlimit-mode srcip,dstip,dstport --hashlimit-upto 1/minute --hashlimit-burst 1 --hashlimit-htable-expire 60000 -j LOG --log-prefix "[LEA-DIR]: "
PreUp = ip6tables -t nat -A POSTROUTING -o ${ext_if} -j MASQUERADE
PreUp = iptables -A INPUT -d ${ext_ip} -p udp -m udp --dport 51820 -j ACCEPT
PreUp = iptables -A INPUT -d ${ext_ip} -p udp -m udp --sport 53 -j ACCEPT
PreUp = iptables -A INPUT -i %i -p udp -m udp --dport 5353 -j ACCEPT
PreUp = ip6tables -A INPUT -i %i -p udp -m udp --dport 5353 -j ACCEPT
PreUp = iptables -t nat -A PREROUTING -i %i -p udp --dport 53 -j REDIRECT --to-ports 5353
PreUp = ip6tables -t nat -A PREROUTING -i %i -p udp --dport 53 -j REDIRECT --to-ports 5353
# Traffic control
PostUp = tc qdisc add dev %i root handle 1: htb
PostUp = tc qdisc add dev %i handle ffff: ingress
PostUp = tc filter add dev %i parent 1:0 prio 1 protocol ip u32
PostUp = tc filter add dev %i parent 1:0 prio 1 handle 2: protocol ip u32 divisor 256
PostUp = tc filter add dev %i parent 1:0 prio 1 protocol ip u32 ht 800:: match ip dst ${int_ip_nm} hashkey mask 0x000000ff at 16 link 2:
PostUp = tc filter add dev %i parent ffff:0 prio 1 protocol ip u32
PostUp = tc filter add dev %i parent ffff:0 prio 1 handle 3: protocol ip u32 divisor 256
PostUp = tc filter add dev %i parent ffff:0 prio 1 protocol ip u32 ht 800:: match ip src ${int_ip_nm} hashkey mask 0x000000ff at 12 link 3:
# Ban portscan
PreUp = ipset create PortScanners4 hash:ip family inet hashsize 32768 maxelem 65536 timeout 600
PreUp = ipset create ScannedPorts4 hash:ip,port,ip family inet hashsize 32768 maxelem 65536 timeout 60
PreUp = iptables -I FORWARD 1 -m state --state INVALID -j DROP
PreUp = iptables -I FORWARD 2 -p tcp -m state --state NEW -m set ! --match-set ScannedPorts4 src,dst,dst -m hashlimit --hashlimit-above 10/minute --hashlimit-burst 10 --hashlimit-mode srcip,dstip --hashlimit-name portscan --hashlimit-htable-expire 10000 -j SET --add-set PortScanners4 src --exist
PreUp = iptables -I FORWARD 3 -p tcp -m state --state NEW -j SET --add-set ScannedPorts4 src,dst,dst
PreUp = iptables -I FORWARD 4 -m state --state NEW -m set --match-set PortScanners4 src -j DROP
PreUp = ipset create PortScanners6 hash:ip family inet6 hashsize 32768 maxelem 65536 timeout 600
PreUp = ipset create ScannedPorts6 hash:ip,port,ip family inet6 hashsize 32768 maxelem 65536 timeout 60
PreUp = ip6tables -I FORWARD 1 -m state --state INVALID -j DROP
PreUp = ip6tables -I FORWARD 2 -p tcp -m state --state NEW -m set ! --match-set ScannedPorts6 src,dst,dst -m hashlimit --hashlimit-above 10/minute --hashlimit-burst 10 --hashlimit-mode srcip,dstip --hashlimit-name portscan --hashlimit-htable-expire 10000 -j SET --add-set PortScanners6 src --exist
PreUp = ip6tables -I FORWARD 3 -p tcp -m state --state NEW -j SET --add-set ScannedPorts6 src,dst,dst
PreUp = ip6tables -I FORWARD 4 -m state --state NEW -m set --match-set PortScanners6 src -j DROP
# Torrent connection blocking (forward rule should go before portscan rules)
PreUp = iptables -t mangle -A PREROUTING -j CONNMARK --restore-mark
PreUp = iptables -t mangle -A PREROUTING -m mark ! --mark 0 -j ACCEPT
PreUp = iptables -t mangle -A PREROUTING -m mark --mark 0 -m ipp2p --edk -j MARK --set-mark 1
PreUp = iptables -t mangle -A PREROUTING -m mark --mark 0 -m ipp2p --bit -j MARK --set-mark 1
PreUp = iptables -t mangle -A PREROUTING -j CONNMARK --save-mark
PreUp = iptables -I FORWARD 1 -m mark --mark 1 -j REJECT --reject-with icmp-admin-prohibited
PreUp = ip6tables -t mangle -A PREROUTING -j CONNMARK --restore-mark
PreUp = ip6tables -t mangle -A PREROUTING -m mark ! --mark 0 -j ACCEPT
PreUp = ip6tables -t mangle -A PREROUTING -m mark --mark 0 -m ipp2p --edk -j MARK --set-mark 1
PreUp = ip6tables -t mangle -A PREROUTING -m mark --mark 0 -m ipp2p --bit -j MARK --set-mark 1
PreUp = ip6tables -t mangle -A PREROUTING -j CONNMARK --save-mark
PreUp = ip6tables -I FORWARD 1 -m mark --mark 1 -j REJECT --reject-with icmp6-adm-prohibited
# Specific port ban
PreUp = iptables -I FORWARD 1 -p tcp -m multiport --dports 25,137,139 -j DROP
PreUp = iptables -I FORWARD 2 -p udp -m multiport --dports 137,138 -j DROP
PreUp = ip6tables -I FORWARD 1 -p tcp -m multiport --dports 25,137,139 -j DROP
PreUp = ip6tables -I FORWARD 2 -p udp -m multiport --dports 137,138 -j DROP
