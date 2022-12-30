#!/bin/bash

# no need to decode "+" symbol, %XX only and filter to base64 plus additionals from second parameter
function ud_b64() { echo -e "${1//%/\\x}" | sed "s/[^[:alnum:]\+\/=$2]//g"; }

spinlock="`[ ! -z \"${TMPDIR}\" ] && echo -n \"${TMPDIR}/\" || echo -n \"/tmp/\" ; basename \"${0}.spinlock\"`"
trap "rm -f \"${spinlock}\" 2>/dev/null" EXIT
while [ -f "${spinlock}" ] ; do
    sleep 0.1
done
touch "${spinlock}" 2>/dev/null

function set_unset_bandwidth_limit {
    ip="`ip netns exec \"ns$1\" wg show \"$1\" allowed-ips | fgrep \"$2\" | cut -d $'\t' -f 2 | sed 's/^[^0-9]*\([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\).*$/\1/'`"

    ip_byte3=`echo "$ip" | cut -d . -f 3`
    handle=`printf "%x\n" "$ip_byte3"`
    ip_byte4=`echo "$ip" | cut -d . -f 4`
    hash=`printf "%x\n" "$ip_byte4"`
    classid=`printf "%x\n" $(( 256 * ip_byte3 + ip_byte4 ))`

    ip netns exec "ns$1" tc filter del dev "$1" parent 1:0 protocol ip prio 1 handle 2:"${hash}":"${handle}" u32 ht 2:"${hash}": 2>/dev/null
    ip netns exec "ns$1" tc class del dev "$1" classid 1:"$classid" 2>/dev/null
    ip netns exec "ns$1" tc filter del dev "$1" parent ffff:0 protocol ip prio 1 handle 3:"${hash}":"${handle}" u32 ht 3:"${hash}": 2>/dev/null

    if [ ! -z "$3" -a ! -z "$4" ]; then
        ip netns exec "ns$1" tc class add dev "$1" parent 1: classid 1:"$classid" htb rate "$3"kbit \
        && ip netns exec "ns$1" tc filter add dev "$1" parent 1:0 protocol ip prio 1 handle 2:"${hash}":"${handle}" u32 \
            ht 2:"${hash}": match ip dst "$ip"/32 flowid 1:"$classid" \
        && ip netns exec "ns$1" tc filter add dev "$1" parent ffff:0 protocol ip prio 1 handle 3:"${hash}":"${handle}" u32 \
            ht 3:"${hash}": match ip src "$ip"/32 police rate "$4"kbit burst 80k drop flowid :"$classid"
    fi

    return $?
}

if [ "$1" == "replay" ]; then
    replay="true"
fi

function replay_log {
    [ ! -z "${replay}" ] && return 0
    case "$1" in
        "/?bw_set" | "/?peer_add" | "/?wg_block")
            echo "$4" >> "/etc/wireguard/${3}.replay"
        ;;
        "/?bw_unset" | "/?peer_del" | "/?wg_unblock")
            declare -A cm=( [bw_unset]=bw_set [peer_del]=peer_add [wg_unblock]=wg_block )
            ml="`fgrep \"/?${cm[${1##/\?}]}=$2\" \"/etc/wireguard/${3}.replay\"`" # third parameter is empty for wg_unblock
            fgrep -v "${ml}" "/etc/wireguard/${3}.replay" > "/etc/wireguard/${3}.replay.tmp"
            mv -f "/etc/wireguard/${3}.replay.tmp" "/etc/wireguard/${3}.replay"
        ;;
    esac
}

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
$e -e "$o\r\n\r";
case "${t}" in
        "/?bw_set" | "/?bw_unset")
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
                                "--up-kbit="* )
                                        v=`ud_b64 "${v}"`
                                        uprate="${v#*=}"
                                ;;
                                "--down-kbit="* )
                                        v=`ud_b64 "${v}"`
                                        downrate="${v#*=}"
                                ;;
                        esac
                done
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
                if [ "${t}" == "/?bw_set" ]; then
                    if [ -z "${uprate}" -o `expr ${uprate%[^0-9]*} + 0` -le 0 ]; then
                        echo "{\"code\": \"144\", \"error\": \"upload rate parameter up-kbit is not set, zero or not a number\"}"
                        exit 0
                    fi
                    if [ -z "${downrate}" -o `expr ${downrate%[^0-9]*} + 0` -le 0 ]; then
                        echo "{\"code\": \"145\", \"error\": \"download rate parameter down-kbit is not set, zero or not a number\"}"
                        exit 0
                    fi
                else
                    uprate="10240"
                    downrate="10240"
                fi
                set_unset_bandwidth_limit "${wgi}" "${f[0]}" "${downrate%[^0-9]*}" "${uprate%[^0-9]*}"
                [ $? -eq 0 ] && replay_log "${t}" "${f[0]}" "${wgi}" "${b}"
                echo "{\"code\": \"$?\"}"
        ;;
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
                            ip addr add "${cv6}/128" dev "${wgi}veth0"
                            ip link set "${wgi}veth0" up
                            ip link set "${wgi}veth1" netns "ns${wgi}"
                            ip -n "ns${wgi}" addr add "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`/128" dev "${wgi}veth1"
                            ip -n "ns${wgi}" link set "${wgi}veth1" up
                            ip route add "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`/128" dev "${wgi}veth0"
                            ip -n "ns${wgi}" route add "${cv6}/128" dev "${wgi}veth1"

                            ip netns exec "ns${wgi}" sysctl -q net.ipv6.conf.all.forwarding=1
                            ip netns exec "ns${wgi}" ip6tables -t nat -A POSTROUTING -s "${av6}" -d "${cv6}" -p tcp --dport 80 -j MASQUERADE
                            ip netns exec "ns${wgi}" ip6tables -A FORWARD -s "${av6}" -d "${cv6}" -p tcp -m tcp --dport 80 -j ACCEPT
                            ip netns exec "ns${wgi}" ip6tables -A FORWARD -d "${av6}" -s "${cv6}" -p tcp -j ACCEPT
                            ip6tables -t nat -A PREROUTING -s "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -p tcp -m tcp --dport 80 -j DNAT --to-destination [${chv6}]:80
                            ip6tables -t nat -A POSTROUTING -s "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -d ${chv6} -p tcp -m tcp -j MASQUERADE
                            ip6tables -A FORWARD -s "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -d ${chv6} -p tcp -m tcp --dport 80 -j ACCEPT
                            ip6tables -A FORWARD -d "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -s ${chv6} -p tcp -j ACCEPT

                            echo "${cv6} vpn.works vpn.my vpn.loc vpn.local vpn vpn.vpn vpn.gen" > /etc/dnsmasq.hosts."${wgi}"
                            /usr/bin/systemctl reload dnsmasq-ns@"${wgi}"
                        fi
                    fi
                    set_unset_bandwidth_limit "${wgi}" "${f[0]}" "10240" "10240"
                    [ ${ec} -eq 0 ] && replay_log "${t}" "${f[0]}" "${wgi}" "${b}"
                    echo "{\"code\": \"${ec}\"}"
                elif [ "${t}" == "/?peer_del" ]; then
                    av6="`ip netns exec \"ns${wgi}\" wg show ${wgi} allowed-ips | fgrep \"${f[0]}\" | cut -d $'\t' -f 2 | egrep -o \"[0-9a-f:]*:[0-9a-f:]*[0-9a-f:]\"`"
                    if [ ! -z "${av6}" -a ! -z "`ip netns exec \"ns${wgi}\" ip6tables-save | fgrep \" ${av6}/\"`" ]; then
                        echo > /etc/dnsmasq.hosts."${wgi}"
                        /usr/bin/systemctl reload dnsmasq-ns@"${wgi}"

                        ip netns exec "ns${wgi}" ip6tables-save | fgrep " ${av6}/" | sed "s/^-A /-D /" | sed "s/-D POSTROUTING/-t nat -D POSTROUTING/" | xargs -I {} /bin/bash -c "ip netns exec \"ns${wgi}\" ip6tables {}"
                        c2v6="`ip netns exec \"ns${wgi}\" ip -6 -o a | egrep ' wg[0-9]*veth1 ' | fgrep ' global ' | cut -d \  -f 7 | cut -d \/ -f 1`"
                        if [ ! -z "${c2v6}" ]; then
                            ip6tables-save | fgrep " ${c2v6}/" | sed "s/^-A /-D /" | sed "s/-D PREROUTING/-t nat -D PREROUTING/" | sed "s/-D POSTROUTING/-t nat -D POSTROUTING/" | xargs -I {} /bin/bash -c "ip6tables {}"
                        fi
                        ip link del "${wgi}veth0"
                    fi
                    set_unset_bandwidth_limit "${wgi}" "${f[0]}"
                    ip netns exec "ns${wgi}" wg set "${wgi}" peer "${f[0]}" remove
                    [ $? -eq 0 ] && replay_log "${t}" "${f[0]}" "${wgi}" "${b}"
                    echo "{\"code\": \"$?\"}"
                else
                    echo -n "{\"code\": \"0\", \"traffic\": "
                    ip netns exec "ns${wgi}" wg show "${wgi}" transfer 2>/dev/null | jq -R -s | tr -d '\n'
                    echo -n ", \"last-seen\": "
                    ip netns exec "ns${wgi}" wg show "${wgi}" latest-handshakes 2>/dev/null | jq -R -s | tr -d '\n'
                    echo -n ", \"endpoints\": "
                    ip netns exec "ns${wgi}" wg show "${wgi}" endpoints 2>/dev/null | sed 's#\(\t[0-9]*\.[0-9]*\.[0-9]*\).*$#\1.0/24#g' | jq -R -s | tr -d '\n'
                    echo ", \"timestamp\": \"$(date +%s)\"}"
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

                cp -f /etc/wireguard/wg.conf.tpl "/etc/wireguard/${wgi}.conf"
                chmod 600 "/etc/wireguard/${wgi}.conf"
                echo "Address = ${addrs}" | sed -e "s/,/\nAddress = /" >> "/etc/wireguard/${wgi}.conf"
                echo "PrivateKey = ${f[0]}" >> "/etc/wireguard/${wgi}.conf"
                sed -i "s/\${ext_if}/${ext_if}/g" "/etc/wireguard/${wgi}.conf"
                sed -i "s/\${ext_ip}/${ext_ip_nm%%/[0-9]*}/g" "/etc/wireguard/${wgi}.conf"
                sed -i "s#\${ext_ip_nm}#${ext_ip_nm}#g" "/etc/wireguard/${wgi}.conf" # we use hashmarks cause netmask is separated by slash
                sed -i "s/\${ext_gw}/${ext_gw}/g" "/etc/wireguard/${wgi}.conf"
                int_ip_nm="`echo ${addrs} | egrep -o '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/[0-9]*'`"
                sed -i "s#\${int_ip_nm}#${int_ip_nm}#g" "/etc/wireguard/${wgi}.conf" # we use hashmarks cause netmask is separated by slash

                echo > /etc/dnsmasq.hosts."${wgi}"

                systemctl start wg-quick-ns@"${ext_if}:${wgi}"

                ec=$?
                if [ $ec -eq 0 ]; then
                    systemctl enable wg-quick-ns@"${ext_if}:${wgi}"
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
                ext_if="`ip netns exec \"ns${wgi}\" ip -4 -o a | egrep -v ' wg[0-9]* ' | fgrep ' global ' | cut -d \  -f 2`"

                systemctl status wg-quick-ns@"${ext_if}:${wgi}" >/dev/null

                ec=$?
                if [ ${ec} -eq 0 ]; then
                    systemctl stop wg-quick-ns@"${ext_if}:${wgi}"
                    systemctl disable wg-quick-ns@"${ext_if}:${wgi}"
                    rm -f /etc/wireguard/"${wgi}".{conf,replay} 2>/dev/null
                    rm -f /etc/dnsmasq.hosts."${wgi}" 2>/dev/null

                    i=0
                    while [ -z "`ip -4 -o a | fgrep \" ${ext_if} \"`" ]; do
                        sleep 0.1
                        if [ $i -ge 100 ]; then
                            echo "{\"code\": \"146\", \"error\": \"interface did not come back to system namespace\"}"
                            exit 0
                        fi
                        i=$((i+1))
                    done
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
                replay_log "${t}" "${f[0]}" "${wgi}" "${b}"
                echo "{\"code\": \"0\"}"
        ;;
        * )
                echo "{\"code\": \"127\", \"error\": \"unimplemented\"}"
        ;;
esac
