#!/bin/bash

# no need to decode "+" symbol, %XX only and filter to base64 plus additionals from second parameter
function ud_b64() { echo -e "${1//%/\\x}" | sed "s/[^[:alnum:]\+\/=$2]//g"; }

#set -x;
r=read;
e=echo;
$r a b c;
z=$r;
while [ ${#z} -gt 2 ]; do
        $r z;
done;
f=(`$e $b|sed 's/^[^=]*=//i'| sed 's/&/\n--/g'`);
t=(`$e $b|sed 's/=.*//'`);
h="HTTP/1.0";
o="$h 200 OK";
$e -e "$o\r\n\r\n";
case "${t}" in
        "/?peer_add" | "/?peer_del" | "/?stat" )
                if [ "${t}" == "/?peer_add" -o "${t}" == "/?peer_del" ]; then
                    if [ -z "${f[0]}" ]; then
                        echo "{\"code\": \"129\", \"error\": \"peer public key is not defined\"}"
                        exit 0
                    else
                        f[0]=`ud_b64 "${f[0]}"`
                    fi
                    for v in "${f[@]:1}"; do
                            case "${v}" in
                                    "--wg-public-key="* )
                                            v=`ud_b64 "${v}"`
                                            wpk="${v#*=}"
                                    ;;
                                    "--wg-psk-key="* )
                                            v=`ud_b64 "${v}"`
                                            wpsk="${v#*=}"
                                    ;;
                                    "--allowed-ips="* )
                                            v=`ud_b64 "${v}" ",\.:"`
                                            addrs="${v#*=}"
                                    ;;
                                    "--control-host="* )
                                            v=`ud_b64 "${v}" ":"`
                                            ctrl="${v#*=}"
                                    ;;
                            esac
                    done
                else
                    wpk="${f[0]}"
                fi
                if [ ! -z "${wpk}" ]; then
                    for ns in `ip netns list | cut -d \  -f 1`; do
                        wgi="`ip netns exec \"${ns}\" wg show all public-key | fgrep \"${wpk}\" | cut -d $'\t' -f 1`"
                        if [ ! -z "${wgi}" ]; then
                            break
                        fi
                    done
                fi
                if [ -z "${wgi}" ]; then
                    echo "{\"code\": \"128\", \"error\": \"no interface found for supplied public key\"}"
                    exit 0
                fi
                if [ "${t}" == "/?peer_add" -a -z "${addrs}" ]; then
                    echo "{\"code\": \"136\", \"error\": \"allowed ips pool can not be empty\"}"
                    exit 0
                fi
                if [ "${t}" == "/?peer_add" ]; then
                    if [ ! -z "${wpsk}" ]; then
                        ip netns exec "ns${wgi}" wg set "${wgi}" peer "${f[0]}" allowed-ips "${addrs}" preshared-key <(echo -n "${wpsk}")
                    else
                        ip netns exec "ns${wgi}" wg set "${wgi}" peer "${f[0]}" allowed-ips "${addrs}"
                    fi
                    ec=$?
                    if [ ${ec} -eq 0 -a ! -z "${ctrl}" ]; then
                        av6="`echo \"${addrs}\" | egrep -o \"[0-9a-f:]*:[0-9a-f:]*[0-9a-f:]\"`"
                        cv6="`echo \"${ctrl}\" | egrep -o \"[0-9a-f:]*:[0-9a-f:]*[0-9a-f:]\"`"
                        if [ ! -z "${av6}" -a ! -z "${cv6}" ]; then
                            clv4="`ip -n \"ns${wgi}\" -4 -o a | egrep -v ' wg[0-9]* ' | fgrep ' global ' | cut -d \  -f 7 | cut -d \/ -f 1`"
                            if [ -z "${clv4}" ]; then
                                echo "{\"code\": \"140\", \"warning\": \"control interface is not set due to incorrect ip address\"}"
                                exit 0
                            fi
                            chv6="`echo ${clv4} | sed 's/\./\n/g' | xargs printf 'fdcc:%02x%02x:%02x%02x::2' | sed 's/:0000/:/g' | sed 's/:00/:/g'`"
                            cv6ld=`expr $(printf "%d" "0x${cv6##*:}" 2>/dev/null) + 1`
                            if [ "$cv6ld" -le 1 -o "$cv6ld" -ge 65535 ] ; then
                                echo "{\"code\": \"141\", \"warning\": \"control interface is not set due the last number of control host ipv6 address should be from 0x1 to 0xfffd\"}"
                                exit 0
                            fi

                            ip link add "${wgi}veth0" type veth peer name "${wgi}veth1"
                            ip addr add "${cv6}/112" dev "${wgi}veth0"
                            ip link set "${wgi}veth0" up
                            ip link set "${wgi}veth1" netns "ns${wgi}"
                            ip -n "ns${wgi}" addr add "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`/112" dev "${wgi}veth1"
                            ip -n "ns${wgi}" link set "${wgi}veth1" up
                            ip route add "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`/112" dev "${wgi}veth0"
                            ip -n "ns${wgi}" route add "${cv6}/112" dev "${wgi}veth1"

                            ip netns exec "ns${wgi}" sysctl -q net.ipv6.conf.all.forwarding=1
                            ip netns exec "ns${wgi}" ip6tables -t nat -A POSTROUTING -s "${av6}" -d "${cv6}" -p tcp --dport 80 -j MASQUERADE
                            ip netns exec "ns${wgi}" ip6tables -A FORWARD -s "${av6}" -d "${cv6}" -p tcp -m tcp --dport 80 -j ACCEPT
                            ip netns exec "ns${wgi}" ip6tables -A FORWARD -d "${av6}" -s "${cv6}" -p tcp -j ACCEPT
                            ip6tables -t nat -A PREROUTING -s "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -p tcp -m tcp --dport 80 -j DNAT --to-destination [${chv6}]:80
                            ip6tables -t nat -A POSTROUTING -s "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -d ${chv6} -p tcp -m tcp -j MASQUERADE
                            ip6tables -A FORWARD -s "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -d ${chv6} -p tcp -m tcp --dport 80 -j ACCEPT
                            ip6tables -A FORWARD -d "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -s ${chv6} -p tcp -j ACCEPT
                        fi
                    fi
                    echo "{\"code\": \"${ec}\"}"
                elif [ "${t}" == "/?peer_del" ]; then
                    av6="`ip netns exec \"ns${wgi}\" wg show ${wgi} allowed-ips | fgrep \"${f[0]}\" | cut -d $'\t' -f 2 | egrep -o \"[0-9a-f:]*:[0-9a-f:]*[0-9a-f:]\"`"
                    if [ ! -z "${av6}" -a ! -z "`ip netns exec \"ns${wgi}\" ip6tables-save | fgrep \" ${av6}/\"`" ]; then
                        ip netns exec "ns${wgi}" ip6tables-save | fgrep " ${av6}/" | sed "s/^-A /-D /" | sed "s/-D POSTROUTING/-t nat -D POSTROUTING/" | xargs -I {} /bin/bash -c "ip netns exec \"ns${wgi}\" ip6tables {}"
                        c2v6="`ip netns exec \"ns${wgi}\" ip -6 -o a | egrep ' wg[0-9]*veth1 ' | fgrep ' global ' | cut -d \  -f 7 | cut -d \/ -f 1`"
                        if [ ! -z "${c2v6}" ]; then
                            ip6tables-save | fgrep " ${c2v6}/" | sed "s/^-A /-D /" | sed "s/-D PREROUTING/-t nat -D PREROUTING/" | sed "s/-D POSTROUTING/-t nat -D POSTROUTING/" | xargs -I {} /bin/bash -c "ip6tables {}"
                        fi
                        ip link del "${wgi}veth0"
                    fi
                    ip netns exec "ns${wgi}" wg set "${wgi}" peer "${f[0]}" remove
                    echo "{\"code\": \"$?\"}"
                else
                    st="$(ip netns exec \"ns${wgi}\" wg show \"${wgi}\" transfer 2>/dev/null | jq -R -s)"
                    echo "{\"code\": \"0\", \"result\": ${st}, \"timestamp\": \"$(date +%s)\"}"
                fi
        ;;
        "/?wg_add" )
                if [ -z "${f[0]}" ]; then
                    echo "{\"code\": \"131\", \"error\": \"Wireguard interface private key is not defined\"}"
                    exit 0
                else
                    f[0]=`ud_b64 "${f[0]}"`
                fi
                if [ ! -z "`fgrep -s \"${f[0]}\" /etc/wireguard/wg[0-9]*.conf`" ]; then
                    echo "{\"code\": \"135\", \"error\": \"Wireguard interface private key is duplicated\"}"
                    exit 0
                fi
                for i in {0..254}; do
                    if [ ! -f "/etc/wireguard/wg${i}.conf" ]; then
                        wgcnt="${i}"
                        wgi="wg${i}"
                        break
                    fi
                done
                if [ -z "${wgi}" ]; then
                    echo "{\"code\": \"132\", \"error\": \"there are no free Wireguard interfaces\"}"
                    exit 0
                fi
                for v in "${f[@]:1}"; do
                        case "${v}" in
                                "--internal-nets="* )
                                        v=`ud_b64 "${v}" ",\.:"`
                                        addrs="${v#*=}"
                                ;;
                                "--external-ip="* )
                                        v=`ud_b64 "${v}" "\."`
                                        ext_ip_nm="${v#*=}"
                                ;;
                                "--external-gateway="* )
                                        v=`ud_b64 "${v}" "\."`
                                        ext_gw="${v#*=}"
                                ;;
                        esac
                done
                if [ -z "${addrs}" ]; then
                    echo "{\"code\": \"133\", \"error\": \"mandatory parameter internal-nets is not set\"}"
                    exit 0
                fi
                if [ -z "${ext_ip_nm}" ]; then
                    echo "{\"code\": \"134\", \"error\": \"mandatory parameter external-ip is not set\"}"
                    exit 0
                fi
                if [ ! -z "${ext_ip_nm##*/[0-9]*}" ]; then
                    for wa in `cat /ip_wan.txt 2>/dev/null | sed 's/\s*,\s*/ /g'`; do
                        if [ "${wa##${ext_ip_nm}}" != "${wa}" ]; then
                            ext_ip_nm="`echo \"${wa}\" | cut -d \| -f 1`"
                            ext_gw="`echo \"${wa}\" | cut -d \| -f 2`"
                            ip_wan_found="found"
                            break
                        fi
                    done
                    if [ -z "${ip_wan_found}" ]; then
                        echo "{\"code\": \"139\", \"error\": \"mandatory parameter external-ip has no netmask\"}"
                        exit 0
                    fi
                fi
                if [ -z "${ext_gw}" ]; then
                    echo "{\"code\": \"137\", \"error\": \"mandatory parameter external-gateway is not set\"}"
                    exit 0
                fi
                ext_if="`ip -4 -o a | fgrep \"${ext_ip_nm}\" | cut -d \  -f 2`"
                if [ -z "${ext_if}" ]; then
                    echo "{\"code\": \"138\", \"error\": \"no interface found for external-ip\"}"
                    exit 0
                fi

                ip netns add "ns${wgi}"
                ip link set dev "${ext_if}" netns "ns${wgi}"
                ip -n "ns${wgi}" addr add "${ext_ip_nm}" dev "${ext_if}"
                ip -n "ns${wgi}" link set dev "${ext_if}" up
                ip -n "ns${wgi}" route add default via "${ext_gw}" dev "${ext_if}"
                ip netns exec "ns${wgi}" iptables -P INPUT DROP
                ip netns exec "ns${wgi}" iptables -P FORWARD DROP
                ip netns exec "ns${wgi}" ip6tables -P INPUT DROP
                ip netns exec "ns${wgi}" ip6tables -P FORWARD DROP
                ip netns exec "ns${wgi}" iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
                ip netns exec "ns${wgi}" ip6tables -A INPUT -p ipv6-icmp -j ACCEPT

                cp -f /etc/wireguard/wg.conf.tpl "/etc/wireguard/${wgi}.conf"
                chmod 600 "/etc/wireguard/${wgi}.conf"
                echo "Address = ${addrs}" | sed -e "s/,/\nAddress = /" >> "/etc/wireguard/${wgi}.conf"
                echo "PrivateKey = ${f[0]}" >> "/etc/wireguard/${wgi}.conf"
                sed -i "s/\${ext_if}/${ext_if}/g" "/etc/wireguard/${wgi}.conf"
                sed -i "s/\${ext_ip}/${ext_ip_nm%%/[0-9]*}/g" "/etc/wireguard/${wgi}.conf"

                ip netns exec "ns${wgi}" wg-quick up "${wgi}"

                ec=$?
                if [ $ec -ne 0 ]; then
                    rm -f /etc/wireguard/"${wgi}".conf
                else
                    systemctl enable wg-quick-ns@"${wgi}"
                fi
                echo "{\"code\": \"${ec}\"}"
        ;;
        "/?wg_del" )
                if [ -z "${f[0]}" ]; then
                    echo "{\"code\": \"130\", \"error\": \"Wireguard interface private key is not defined\"}"
                    exit 0
                else
                    f[0]=`ud_b64 "${f[0]}"`
                fi
                if [ ! -z "${f[0]}" ]; then
                    for ns in `ip netns list | cut -d \  -f 1`; do
                        wgi="`ip netns exec \"${ns}\" wg show all public-key | fgrep $(echo ${f[0]} | wg pubkey) | cut -d $'\t' -f 1`"
                        if [ ! -z "${wgi}" ]; then
                            break
                        fi
                    done
                fi
                if [ -z "${wgi}" ]; then
                    echo "{\"code\": \"128\", \"error\": \"no interface found for supplied private key\"}"
                    exit 0
                fi
                ccv6="`ip netns exec \"ns${wgi}\" ip -6 -o a | egrep ' wg[0-9]*veth1 ' | fgrep ' global ' | cut -d \  -f 7 | cut -d \/ -f 1`"
                if [ ! -z "${ccv6}" ]; then
                    ip6tables-save | fgrep " ${ccv6}/" | sed "s/^-A /-D /" | sed "s/-D PREROUTING/-t nat -D PREROUTING/" | sed "s/-D POSTROUTING/-t nat -D POSTROUTING/" | xargs -I {} /bin/bash -c "ip6tables {}"
                fi
                ip netns exec "ns${wgi}" wg-quick down "${wgi}"
                ec=$?
                ip netns del "ns${wgi}"
                if [ ${ec} -eq 0 ]; then
                    systemctl disable wg-quick-ns@"${wgi}"
                    rm -f /etc/wireguard/"${wgi}".conf
                fi
                echo "{\"code\": \"${ec}\"}"
        ;;
        "/?wg_block" | "/?wg_unblock" )
                if [ -z "${f[0]}" ]; then
                    echo "{\"code\": \"142\", \"error\": \"Wireguard interface public key is not defined\"}"
                    exit 0
                else
                    f[0]=`ud_b64 "${f[0]}"`
                fi
                if [ ! -z "${f[0]}" ]; then
                    for ns in `ip netns list | cut -d \  -f 1`; do
                        wgi="`ip netns exec \"${ns}\" wg show all public-key | fgrep "${f[0]}" | cut -d $'\t' -f 1`"
                        if [ ! -z "${wgi}" ]; then
                            break
                        fi
                    done
                fi
                if [ -z "${wgi}" ]; then
                    echo "{\"code\": \"143\", \"error\": \"no interface found for supplied public key\"}"
                    exit 0
                fi
                ext_if="`ip netns exec \"ns${wgi}\" ip -4 -o a | egrep -v ' wg[0-9]* ' | fgrep ' global ' | cut -d \  -f 2`"
                if [ ! -z "${ext_if}" ]; then
                    if [ "${t}" == "/?wg_block" ]; then
                        ip netns exec "ns${wgi}" iptables -I FORWARD 1 -i "${wgi}" -o "${ext_if}" -j DROP
                        ip netns exec "ns${wgi}" ip6tables -I FORWARD 1 -i "${wgi}" -o "${ext_if}" -j DROP
                    else
                        true; while [ $? -eq 0 ]; do
                            ip netns exec "ns${wgi}" iptables -D FORWARD -i "${wgi}" -o "${ext_if}" -j DROP 2>/dev/null
                        done
                        true; while [ $? -eq 0 ]; do
                            ip netns exec "ns${wgi}" ip6tables -D FORWARD -i "${wgi}" -o "${ext_if}" -j DROP 2>/dev/null
                        done
                    fi
                fi
                echo "{\"code\": \"0\"}"
        ;;
        * )
                echo "{\"code\": \"127\", \"error\": \"unimplemented\"}"
        ;;
esac
