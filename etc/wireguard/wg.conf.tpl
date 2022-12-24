[Interface]
ListenPort = 51820
SaveConfig = false
### Interface start and setup
PreUp = ip addr add ${ext_ip_nm} dev ${ext_if}
PreUp = ip link set dev ${ext_if} up
PreUp = ip route add default via ${ext_gw} dev ${ext_if}
PreUp = iptables -P INPUT DROP
PreUp = iptables -P FORWARD DROP
PreUp = ip6tables -P INPUT DROP
PreUp = ip6tables -P FORWARD DROP
PreUp = iptables -A INPUT -i %i -p icmp -m icmp --icmp-type 8 -j ACCEPT
PreUp = ip6tables -A INPUT -p ipv6-icmp -j ACCEPT -m comment --comment ${ext_if}
PreUp = iptables -A FORWARD -i %i -p tcp -m multiport --dports 25,137,139 -j DROP
PreUp = iptables -A FORWARD -i %i -p udp -m multiport --dports 137,138 -j DROP
PreUp = ip6tables -A FORWARD -i %i -p tcp -m multiport --dports 25,137,139 -j DROP
PreUp = ip6tables -A FORWARD -i %i -p udp -m multiport --dports 137,138 -j DROP
PreUp = iptables -A FORWARD -i %i -o ${ext_if} -j ACCEPT
PreUp = iptables -A FORWARD -o %i -i ${ext_if} -j ACCEPT
PreUp = ip6tables -A FORWARD -i %i -o ${ext_if} -j ACCEPT
PreUp = ip6tables -A FORWARD -o %i -i ${ext_if} -j ACCEPT
PreUp = iptables -t nat -A POSTROUTING -s ${int_ip_nm} -j SNAT --to ${ext_ip}
PreUp = ip6tables -t nat -A POSTROUTING -o ${ext_if} -j MASQUERADE
PreUp = iptables -A INPUT -d ${ext_ip} -p udp -m udp --dport 51820 -j ACCEPT
PreUp = iptables -t nat -A PREROUTING -i %i -p udp --dport 53 -j DNAT --to 1.1.1.1
PreUp = iptables -t nat -A PREROUTING -i %i -p tcp --dport 53 -j DNAT --to 1.1.1.1
PreUp = ip6tables -t nat -A PREROUTING -i %i -p udp --dport 53 -j DNAT --to 2606:4700:4700::1111
PreUp = ip6tables -t nat -A PREROUTING -i %i -p tcp --dport 53 -j DNAT --to 2606:4700:4700::1111
# Traffic control
PostUp = tc qdisc add dev %i root handle 1: htb
PostUp = tc qdisc add dev %i handle ffff: ingress
PostUp = tc filter add dev %i parent 1:0 prio 1 protocol ip u32
PostUp = tc filter add dev %i parent 1:0 prio 1 handle 2: protocol ip u32 divisor 256
PostUp = tc filter add dev %i parent 1:0 prio 1 protocol ip u32 ht 800:: match ip dst ${int_ip_nm} hashkey mask 0x000000ff at 16 link 2:
PostUp = tc filter add dev %i parent ffff:0 prio 1 protocol ip u32
PostUp = tc filter add dev %i parent ffff:0 prio 1 handle 3: protocol ip u32 divisor 256
PostUp = tc filter add dev %i parent ffff:0 prio 1 protocol ip u32 ht 800:: match ip src ${int_ip_nm} hashkey mask 0x000000ff at 12 link 3:
# Torrent blocking
PreUp = ipset create UserP2Pv4%i hash:ip family inet timeout 86400
PreUp = ipset create UserP2Pv6%i hash:ip family inet6 timeout 86400
PreUp = iptables -N FORWARD_P2P_TO_VETH_%i
PreUp = iptables -N FORWARD_P2P_TO_WG_%i
PreUp = iptables -N FORWARD_USER_P2P_TO_VETH_%i
PreUp = iptables -N FORWARD_USER_P2P_TO_WG_%i
PreUp = ip6tables -N FORWARD_P2P_TO_VETH_%i
PreUp = ip6tables -N FORWARD_P2P_TO_WG_%i
PreUp = ip6tables -N FORWARD_USER_P2P_TO_VETH_%i
PreUp = ip6tables -N FORWARD_USER_P2P_TO_WG_%i
PreUp = iptables -I FORWARD 1 -i %i -o ${ext_if} -m ipp2p --bit -g FORWARD_P2P_TO_VETH_%i
PreUp = iptables -I FORWARD 2 -i %i -o ${ext_if} -m set --match-set UserP2Pv4%i src -g FORWARD_USER_P2P_TO_VETH_%i
PreUp = iptables -I FORWARD 3 -o %i -i ${ext_if} -m ipp2p --bit -g FORWARD_P2P_TO_WG_%i
PreUp = iptables -I FORWARD 4 -o %i -i ${ext_if} -m set --match-set UserP2Pv4%i dst -g FORWARD_USER_P2P_TO_WG_%i
PreUp = ip6tables -I FORWARD 1 -i %i -o ${ext_if} -m ipp2p --bit -g FORWARD_P2P_TO_VETH_%i
PreUp = ip6tables -I FORWARD 2 -i %i -o ${ext_if} -m set --match-set UserP2Pv6%i src -g FORWARD_USER_P2P_TO_VETH_%i
PreUp = ip6tables -I FORWARD 3 -o %i -i ${ext_if} -m ipp2p --bit -g FORWARD_P2P_TO_WG_%i
PreUp = ip6tables -I FORWARD 4 -o %i -i ${ext_if} -m set --match-set UserP2Pv6%i dst -g FORWARD_USER_P2P_TO_WG_%i
PreUp = iptables -A FORWARD_P2P_TO_VETH_%i -j SET --add-set UserP2Pv4%i src --exist
PreUp = iptables -A FORWARD_P2P_TO_VETH_%i -j NFLOG --nflog-prefix FORWARD_P2P_TO_VETH_%i --nflog-group 2 --nflog-size 1500 --nflog-threshold 64
PreUp = iptables -A FORWARD_P2P_TO_VETH_%i -j REJECT --reject-with icmp-admin-prohibited
PreUp = iptables -A FORWARD_P2P_TO_WG_%i -j SET --add-set UserP2Pv4%i dst --exist
PreUp = iptables -A FORWARD_P2P_TO_WG_%i -j NFLOG --nflog-prefix FORWARD_P2P_TO_WG_%i --nflog-group 3 --nflog-size 1500 --nflog-threshold 64
PreUp = iptables -A FORWARD_P2P_TO_WG_%i -j DROP
PreUp = iptables -A FORWARD_USER_P2P_TO_VETH_%i -p tcp -m multiport --dports 53,80,443 -j ACCEPT
PreUp = iptables -A FORWARD_USER_P2P_TO_VETH_%i -p udp -m multiport --dports 53,443 -j ACCEPT
PreUp = iptables -A FORWARD_USER_P2P_TO_VETH_%i -j REJECT --reject-with icmp-admin-prohibited
PreUp = iptables -A FORWARD_USER_P2P_TO_WG_%i -p tcp -m multiport --sports 53,80,443 -j ACCEPT
PreUp = iptables -A FORWARD_USER_P2P_TO_WG_%i -p udp -m multiport --sports 53,443 -j ACCEPT
PreUp = iptables -A FORWARD_USER_P2P_TO_WG_%i -j DROP
PreUp = ip6tables -A FORWARD_P2P_TO_VETH_%i -j SET --add-set UserP2Pv6%i src --exist
PreUp = ip6tables -A FORWARD_P2P_TO_VETH_%i -j NFLOG --nflog-prefix FORWARD_P2P_TO_VETH_%i --nflog-group 2 --nflog-size 1500 --nflog-threshold 64
PreUp = ip6tables -A FORWARD_P2P_TO_VETH_%i -j REJECT --reject-with icmp6-adm-prohibited
PreUp = ip6tables -A FORWARD_P2P_TO_WG_%i -j SET --add-set UserP2Pv6%i dst --exist
PreUp = ip6tables -A FORWARD_P2P_TO_WG_%i -j NFLOG --nflog-prefix FORWARD_P2P_TO_WG_%i --nflog-group 3 --nflog-size 1500 --nflog-threshold 64
PreUp = ip6tables -A FORWARD_P2P_TO_WG_%i -j DROP
PreUp = ip6tables -A FORWARD_USER_P2P_TO_VETH_%i -p tcp -m multiport --dports 53,80,443 -j ACCEPT
PreUp = ip6tables -A FORWARD_USER_P2P_TO_VETH_%i -p udp -m multiport --dports 53,443 -j ACCEPT
PreUp = ip6tables -A FORWARD_USER_P2P_TO_VETH_%i -j REJECT --reject-with icmp6-adm-prohibited
PreUp = ip6tables -A FORWARD_USER_P2P_TO_WG_%i -p tcp -m multiport --sports 53,80,443 -j ACCEPT
PreUp = ip6tables -A FORWARD_USER_P2P_TO_WG_%i -p udp -m multiport --sports 53,443 -j ACCEPT
PreUp = ip6tables -A FORWARD_USER_P2P_TO_WG_%i -j DROP
# Ban portscan
PreUp = ipset create PortScanners%i hash:ip family inet hashsize 32768 maxelem 65536 timeout 600
PreUp = ipset create ScannedPorts%i hash:ip,port family inet hashsize 32768 maxelem 65536 timeout 60
PreUp = iptables -I FORWARD 1 -m state --state INVALID -j DROP
PreUp = iptables -I FORWARD 2 -p tcp -m state --state NEW -m set ! --match-set ScannedPorts%i src,dst -m hashlimit --hashlimit-above 10/minute --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name portscan --hashlimit-htable-expire 10000 -j SET --add-set PortScanners%i src --exist
PreUp = iptables -I FORWARD 3 -p tcp -m state --state NEW -j SET --add-set ScannedPorts%i src,dst
PreUp = iptables -I FORWARD 4 -m state --state NEW -m set --match-set PortScanners%i src -j DROP
### Interface release
PreDown = iptables -D FORWARD -i %i -o ${ext_if} -j ACCEPT
PreDown = iptables -D FORWARD -o %i -i ${ext_if} -j ACCEPT
PreDown = ip6tables -D FORWARD -i %i -o ${ext_if} -j ACCEPT
PreDown = ip6tables -D FORWARD -o %i -i ${ext_if} -j ACCEPT
PreDown = iptables -t nat -D POSTROUTING -s ${int_ip_nm} -j SNAT --to ${ext_ip}
PreDown = ip6tables -t nat -D POSTROUTING -o ${ext_if} -j MASQUERADE
PreDown = iptables -D FORWARD -i %i -p tcp -m multiport --dports 25,137,139 -j DROP
PreDown = iptables -D FORWARD -i %i -p udp -m multiport --dports 137,138 -j DROP
PreDown = ip6tables -D FORWARD -i %i -p tcp -m multiport --dports 25,137,139 -j DROP
PreDown = ip6tables -D FORWARD -i %i -p udp -m multiport --dports 137,138 -j DROP
PreDown = iptables -D INPUT -d ${ext_ip} -p udp -m udp --dport 51820 -j ACCEPT
PreDown = iptables -t nat -D PREROUTING -i %i -p udp --dport 53 -j DNAT --to 1.1.1.1
PreDown = iptables -t nat -D PREROUTING -i %i -p tcp --dport 53 -j DNAT --to 1.1.1.1
PreDown = ip6tables -t nat -D PREROUTING -i %i -p udp --dport 53 -j DNAT --to 2606:4700:4700::1111
PreDown = ip6tables -t nat -D PREROUTING -i %i -p tcp --dport 53 -j DNAT --to 2606:4700:4700::1111
PreDown = true && while [ $? -eq 0 ]; do iptables -D FORWARD -i %i -o ${ext_if} -j DROP 2>/dev/null; done || true
PreDown = true && while [ $? -eq 0 ]; do ip6tables -D FORWARD -i %i -o ${ext_if} -j DROP 2>/dev/null; done || true
# Torrent blocking
PreDown = iptables -D FORWARD -i %i -o ${ext_if} -m ipp2p --bit -g FORWARD_P2P_TO_VETH_%i
PreDown = iptables -D FORWARD -i %i -o ${ext_if} -m set --match-set UserP2Pv4%i src -g FORWARD_USER_P2P_TO_VETH_%i
PreDown = iptables -D FORWARD -o %i -i ${ext_if} -m ipp2p --bit -g FORWARD_P2P_TO_WG_%i
PreDown = iptables -D FORWARD -o %i -i ${ext_if} -m set --match-set UserP2Pv4%i dst -g FORWARD_USER_P2P_TO_WG_%i
PreDown = ip6tables -D FORWARD -i %i -o ${ext_if} -m ipp2p --bit -g FORWARD_P2P_TO_VETH_%i
PreDown = ip6tables -D FORWARD -i %i -o ${ext_if} -m set --match-set UserP2Pv6%i src -g FORWARD_USER_P2P_TO_VETH_%i
PreDown = ip6tables -D FORWARD -o %i -i ${ext_if} -m ipp2p --bit -g FORWARD_P2P_TO_WG_%i
PreDown = ip6tables -D FORWARD -o %i -i ${ext_if} -m set --match-set UserP2Pv6%i dst -g FORWARD_USER_P2P_TO_WG_%i
PreDown = iptables -F FORWARD_P2P_TO_VETH_%i
PreDown = iptables -F FORWARD_P2P_TO_WG_%i
PreDown = iptables -F FORWARD_USER_P2P_TO_VETH_%i
PreDown = iptables -F FORWARD_USER_P2P_TO_WG_%i
PreDown = ip6tables -F FORWARD_P2P_TO_VETH_%i
PreDown = ip6tables -F FORWARD_P2P_TO_WG_%i
PreDown = ip6tables -F FORWARD_USER_P2P_TO_VETH_%i
PreDown = ip6tables -F FORWARD_USER_P2P_TO_WG_%i
PreDown = iptables -X FORWARD_P2P_TO_VETH_%i
PreDown = iptables -X FORWARD_P2P_TO_WG_%i
PreDown = iptables -X FORWARD_USER_P2P_TO_VETH_%i
PreDown = iptables -X FORWARD_USER_P2P_TO_WG_%i
PreDown = ip6tables -X FORWARD_P2P_TO_VETH_%i
PreDown = ip6tables -X FORWARD_P2P_TO_WG_%i
PreDown = ip6tables -X FORWARD_USER_P2P_TO_VETH_%i
PreDown = ip6tables -X FORWARD_USER_P2P_TO_WG_%i
PreDown = ipset destroy UserP2Pv4%i
PreDown = ipset destroy UserP2Pv6%i
# Traffic control
PreDown = tc qdisc del dev %i root
PreDown = tc qdisc del dev %i handle ffff: ingress
# Ban portscan
PreDown = iptables -D FORWARD -m state --state INVALID -j DROP
PreDown = iptables -D FORWARD -p tcp -m state --state NEW -m set ! --match-set ScannedPorts%i src,dst -m hashlimit --hashlimit-above 10/minute --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name portscan --hashlimit-htable-expire 10000 -j SET --add-set PortScanners%i src --exist
PreDown = iptables -D FORWARD -p tcp -m state --state NEW -j SET --add-set ScannedPorts%i src,dst
PreDown = iptables -D FORWARD -m state --state NEW -m set --match-set PortScanners%i src -j DROP
PreDown = ipset destroy PortScanners%i
PreDown = ipset destroy ScannedPorts%i
