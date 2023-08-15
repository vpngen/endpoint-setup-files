#!/bin/bash

# no need to decode "+" symbol, %XX only and filter to base64 plus additionals from second parameter
function ud_b64() { echo -e "${1//%/\\x}" | sed "s/[^[:alnum:]\+\/=$2]//g"; }

function nacl_d() {
    nacl_d_ret=$1
    nacl pubkey < /vg-endpoint.json >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "{\"code\": \"147\", \"error\": \"Nacl command not found or endpoint private key is invalid\"}"
        exit 0
    fi
    nacl_d_ret=`echo -n "${nacl_d_ret}" | nacl -b unseal /vg-endpoint.json`
    local nacl_d_ret_len=`echo -n "${nacl_d_ret}" | base64 -d | wc -c`
    if [ $? -ne 0 ]; then
        echo "{\"code\": \"148\", \"error\": \"$2 cannot be decrypted\"}"
        exit 0
    fi
    if [[ ! -z "$3" && $3 -ge 0 && ( ${nacl_d_ret_len} -lt $3 || ( ! -z "$4" && ${nacl_d_ret_len} -gt $4 ) ) ]]; then
        echo -n "{\"code\": \"149\", \"error\": \"$2 is less than $3"
        [ ! -z "$4" ] && echo -n " or greater than $4"
        echo " characters long\"}"
        exit 0
    fi
    return 0
}

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
            while read line; do
                ud_b64 "$line" "?_&" | fgrep -q "/?${cm[${1##/\?}]}=$2"
                [ $? -eq 1 ] &&
                    echo $line
            done < "/etc/wireguard/${3}.replay" > "/etc/wireguard/${3}.replay.tmp"
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
                if [ -z "${f[0]}" ]; then
                    echo "{\"code\": \"129\", \"error\": \"peer public key is not defined\"}"
                    exit 0
                else
                    f[0]=`ud_b64 "${f[0]}"`
                fi
                if [ "${t}" == "/?peer_add" -o "${t}" == "/?peer_del" ]; then
                    for v in "${f[@]:1}"; do
                            case "${v}" in
                                    "--wg-public-key="* )
                                            v=`ud_b64 "${v}"`
                                            wpk="${v#*=}"
                                    ;;
                                    "--wg-psk-key="* )
                                            v=`ud_b64 "${v}"`
                                            wpsk="${v#*=}"
                                            nacl_d "${wpsk}" "Wireguard preshared key" -1
                                            wpsk="${nacl_d_ret}"
                                    ;;
                                    "--allowed-ips="* )
                                            v=`ud_b64 "${v}" ",\.:"`
                                            addrs="${v#*=}"
                                    ;;
                                    "--control-host="* )
                                            v=`ud_b64 "${v}" ":"`
                                            ctrl="${v#*=}"
                                    ;;
                                    "--l2tp-username="* )
                                            v=`ud_b64 "${v}" "_"`
                                            l2tp_usr="${v#*=}"
                                            nacl_d "${l2tp_usr}" "L2TP username" 12 16
                                            l2tp_usr=`echo "${nacl_d_ret}" | base64 -d | sed "s/[^a-zA-Z0-9_]//g"`
                                    ;;
                                    "--l2tp-password="* )
                                            v=`ud_b64 "${v}"`
                                            l2tp_pwd="${v#*=}"
                                            nacl_d "${l2tp_pwd}" "L2TP user password" 16 64
                                            l2tp_pwd=`echo "${nacl_d_ret}" | base64 -d | tr -d "\042\047\140"`
                                    ;;
                                    "--openvpn-client-csr="* )
                                            v=`ud_b64 "${v}"`
                                            openvpn_csr="${v#*=}"
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
                            clv4="`ip -n \"ns${wgi}\" -4 r get 1.1.1.1 | head -1 | cut -d \  -f 7`"
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
                            ip netns exec "ns${wgi}" ip6tables -t nat -A POSTROUTING -s "${av6}" -d "${cv6}" -p tcp --dport 443 -j MASQUERADE
                            ip netns exec "ns${wgi}" ip6tables -A FORWARD -s "${av6}" -d "${cv6}" -p tcp -m tcp --dport 80 -j ACCEPT
                            ip netns exec "ns${wgi}" ip6tables -A FORWARD -s "${av6}" -d "${cv6}" -p tcp -m tcp --dport 443 -j ACCEPT
                            ip netns exec "ns${wgi}" ip6tables -A FORWARD -d "${av6}" -s "${cv6}" -p tcp -j ACCEPT
                            ip6tables -t nat -A PREROUTING -s "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -p tcp -m tcp --dport 80 -j DNAT --to-destination [${chv6}]:80
                            ip6tables -t nat -A PREROUTING -s "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -p tcp -m tcp --dport 443 -j DNAT --to-destination [${chv6}]:443
                            ip6tables -t nat -A POSTROUTING -s "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -d ${chv6} -p tcp -m tcp -j SNAT --to "${chv6%:[0-9a-f]*}:3"
                            ip6tables -A FORWARD -s "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -d ${chv6} -p tcp -m tcp --dport 80 -j ACCEPT
                            ip6tables -A FORWARD -s "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -d ${chv6} -p tcp -m tcp --dport 443 -j ACCEPT
                            ip6tables -A FORWARD -d "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -s ${chv6} -p tcp -j ACCEPT

                            echo "${cv6} vpn.works" > /etc/dnsmasq.hosts."${wgi}:5353"
                            echo "0.0.0.0 vpn.works" >> /etc/dnsmasq.hosts."${wgi}:5353"
                            /usr/bin/systemctl reload dnsmasq-ns@"${wgi}:5353"
                        fi
                    fi
                    cv6=
                    if [ ${ec} -eq 0 -a ! -z "${l2tp_usr}" -a ! -z "${l2tp_pwd}" ]; then
                        if [ ! -z "${ctrl}" ]; then
                            echo "\"${l2tp_usr}\" * \"${l2tp_pwd}\" ip_pool_adm 10240/10240 #${f[0]}" >> /etc/accel-ppp.chap-secrets."${wgi}"

                            echo "100.127.0.1 vpn.works" > /etc/dnsmasq.hosts."${wgi}:5354"
                            /usr/bin/systemctl reload dnsmasq-ns@"${wgi}:5354"

                            av6="`echo \"${addrs}\" | egrep -o \"[0-9a-f:]*:[0-9a-f:]*[0-9a-f:]\"`"
                            cv6="`echo \"${ctrl}\" | egrep -o \"[0-9a-f:]*:[0-9a-f:]*[0-9a-f:]\"`"
                            cv6ld=`expr $(printf "%d" "0x${cv6##*:}" 2>/dev/null) + 1`

                            ext_if="`ip -n \"ns${wgi}\" -4 r get 1.1.1.1 | head -1 | cut -d \  -f 5`"
                            ip netns exec "ns${wgi}" iptables -A INPUT -i "${ext_if}" -p udp --dport 500 -j ACCEPT
                            ip netns exec "ns${wgi}" iptables -A INPUT -i "${ext_if}" -p udp --dport 1701 -j ACCEPT
                            ip netns exec "ns${wgi}" iptables -A INPUT -i "${ext_if}" -p udp --dport 4500 -j ACCEPT

                            ip netns exec "ns${wgi}" ip6tables -A INPUT -s "${cv6}" -d "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -p tcp -m tcp -m multiport --sports 80,443 -m comment --comment " ${av6}/" -j ACCEPT
                            ip netns exec "ns${wgi}" iptables -t nat -A PREROUTING -i l2tp+ -d 100.127.0.1 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080
                            ip netns exec "ns${wgi}" iptables -t nat -A PREROUTING -i l2tp+ -d 100.127.0.1 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 8443
                        else
                            echo "\"${l2tp_usr}\" * \"${l2tp_pwd}\" * 10240/10240 #${f[0]}" >> /etc/accel-ppp.chap-secrets."${wgi}"
                        fi
                    fi
                    openvpn_cn=
                    while [ ${ec} -eq 0 -a ! -z "${openvpn_csr}" ]; do
                        echo -n "${openvpn_csr}" | base64 -d | gunzip > /opt/openvpn-"${wgi}"/pki/reqs/"${f[0]//\//_}".req
                        openvpn_cn="`cat /opt/openvpn-"${wgi}"/pki/reqs/"${f[0]//\//_}".req | openssl req -noout -subject -in - | fgrep subject=CN | cut -d ' ' -f 3`"
                        [ -z "$openvpn_cn" ] && break
                        cd /opt/openvpn-"${wgi}"
                        /usr/share/easy-rsa/easyrsa --batch --use-algo=ec --curve=secp521r1 --digest=sha512 --days=3650 sign-req client "${f[0]//\//_}" >/dev/null 2>&1

                        if [ ! -z "${ctrl}" ]; then
                            for i in {2..254}; do
                                fgrep -qr " 100.128.255.$i " /opt/openvpn-"${wgi}"/ccd/ \
                                    || echo -e "#${f[0]}\nifconfig-push 100.128.255.2 255.255.0.0" > /opt/openvpn-"${wgi}"/ccd/"${openvpn_cn}" \
                                    && break
                            done

                            echo "100.128.0.1 vpn.works" > /etc/dnsmasq.hosts."${wgi}:5355"
                            /usr/bin/systemctl reload dnsmasq-ns@"${wgi}:5355"

                            av6="`echo \"${addrs}\" | egrep -o \"[0-9a-f:]*:[0-9a-f:]*[0-9a-f:]\"`"
                            cv6="`echo \"${ctrl}\" | egrep -o \"[0-9a-f:]*:[0-9a-f:]*[0-9a-f:]\"`"
                            cv6ld=`expr $(printf "%d" "0x${cv6##*:}" 2>/dev/null) + 1`

                            ip netns exec "ns${wgi}" ip6tables -A INPUT -s "${cv6}" -d "${cv6%:[0-9a-f]*}:`printf \"%x\" \"$cv6ld\"`" -p tcp -m tcp -m multiport --sports 80,443 -m comment --comment " ${av6}/" -j ACCEPT
                            ip netns exec "ns${wgi}" iptables -t nat -A PREROUTING -i tun+ -d 100.128.0.1 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080
                            ip netns exec "ns${wgi}" iptables -t nat -A PREROUTING -i tun+ -d 100.128.0.1 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 8443
                            ip netns exec "ns${wgi}" iptables -A INPUT -i tun+ -d 100.128.0.1 -s 100.128.255.0/24 -p tcp -m multiport --dports 8080,8443 -j ACCEPT
                        else
                            touch /opt/openvpn-"${wgi}"/ccd/"${openvpn_cn}"
                        fi
                        break
                    done
                    if [ ! -z "${cv6}" ]; then
                        /usr/bin/systemctl start ipsec-keydesk-proxy-80@"${wgi}:${cv6}"
                        /usr/bin/systemctl start ipsec-keydesk-proxy-443@"${wgi}:${cv6}"
                    fi
                    set_unset_bandwidth_limit "${wgi}" "${f[0]}" "10240" "10240"
                    [ ${ec} -eq 0 ] && replay_log "${t}" "${f[0]}" "${wgi}" "${b}"
                    if [ ! -z "$openvpn_cn" ]; then
                        echo "{\"code\": \"${ec}\", \"openvpn-client-certificate\": \""`fgrep -A 1000 'BEGIN CERTIFICATE' /opt/openvpn-"${wgi}"/pki/issued/${f[0]//\//_}.crt | sed 's/\"/\\\\"/g;s/$/\\\\n/g' | tr -d '\n'`"\"}"
                    else
                        echo "{\"code\": \"${ec}\"}"
                    fi
                elif [ "${t}" == "/?peer_del" ]; then
                    av6="`ip netns exec \"ns${wgi}\" wg show ${wgi} allowed-ips | fgrep \"${f[0]}\" | cut -d $'\t' -f 2 | egrep -o \"[0-9a-f:]*:[0-9a-f:]*[0-9a-f:]\"`"
                    if [ ! -z "${av6}" -a ! -z "`ip netns exec \"ns${wgi}\" ip6tables-save | fgrep \" ${av6}/\"`" ]; then
                        /usr/bin/systemctl stop ipsec-keydesk-proxy-80@"${wgi}:*"
                        /usr/bin/systemctl stop ipsec-keydesk-proxy-443@"${wgi}:*"

                        ip netns exec "ns${wgi}" iptables -D INPUT -i tun+ -d 100.128.0.1 -s 100.128.255.0/24 -p tcp -m multiport --dports 8080,8443 -j ACCEPT
                        ip netns exec "ns${wgi}" iptables -t nat -D PREROUTING -i tun+ -d 100.128.0.1 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080
                        ip netns exec "ns${wgi}" iptables -t nat -D PREROUTING -i tun+ -d 100.128.0.1 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 8443

                        ip netns exec "ns${wgi}" iptables -t nat -D PREROUTING -i l2tp+ -d 100.127.0.1 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080
                        ip netns exec "ns${wgi}" iptables -t nat -D PREROUTING -i l2tp+ -d 100.127.0.1 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 8443

                        ext_if="`ip -n \"ns${wgi}\" -4 r get 1.1.1.1 | head -1 | cut -d \  -f 5`"
                        ip netns exec "ns${wgi}" iptables -D INPUT -i "${ext_if}" -p udp --dport 500 -j ACCEPT
                        ip netns exec "ns${wgi}" iptables -D INPUT -i "${ext_if}" -p udp --dport 1701 -j ACCEPT
                        ip netns exec "ns${wgi}" iptables -D INPUT -i "${ext_if}" -p udp --dport 4500 -j ACCEPT

                        echo > /etc/dnsmasq.hosts."${wgi}:5353"
                        echo > /etc/dnsmasq.hosts."${wgi}:5354"
                        echo > /etc/dnsmasq.hosts."${wgi}:5355"
                        /usr/bin/systemctl reload dnsmasq-ns@"${wgi}:5353"
                        /usr/bin/systemctl reload dnsmasq-ns@"${wgi}:5354"
                        /usr/bin/systemctl reload dnsmasq-ns@"${wgi}:5355"

                        ip netns exec "ns${wgi}" ip6tables-save | fgrep " ${av6}/" | sed "s/^-A /-D /" | sed "s/-D POSTROUTING/-t nat -D POSTROUTING/" | xargs -L 1 ip netns exec "ns${wgi}" ip6tables
                        c2v6="`ip netns exec \"ns${wgi}\" ip -6 -o a | egrep ' wg[0-9]*veth1 ' | fgrep ' global ' | cut -d \  -f 7 | cut -d \/ -f 1`"
                        if [ ! -z "${c2v6}" ]; then
                            ip6tables-save | fgrep " ${c2v6}/" | sed "s/^-A /-D /" | sed "s/-D PREROUTING/-t nat -D PREROUTING/" | sed "s/-D POSTROUTING/-t nat -D POSTROUTING/" | xargs -I {} /bin/bash -c "ip6tables {}"
                        fi
                        ip link del "${wgi}veth0"
                    fi
                    set_unset_bandwidth_limit "${wgi}" "${f[0]}"

                    fgrep -r "#${f[0]}" /opt/openvpn-"${wgi}"/ccd/ | cut -d \: -f 1 | xargs rm -f

                    # sed is not used due to complicated special symbol escaping
                    fgrep -v " #${f[0]}" /etc/accel-ppp.chap-secrets."${wgi}" > /etc/accel-ppp.chap-secrets."${wgi}".tmp
                    mv -f /etc/accel-ppp.chap-secrets."${wgi}"{.tmp,}

                    ip netns exec "ns${wgi}" wg set "${wgi}" peer "${f[0]}" remove
                    [ $? -eq 0 ] && replay_log "${t}" "${f[0]}" "${wgi}" "${b}"
                    echo "{\"code\": \"$?\"}"
                else
                    echo -n "{\"code\": \"0\", \"traffic\": "
                    join -j 1 -a 1 -a 2 -e 0 -o 0,1.2,1.3,2.2,2.3 \
                        <(ip netns exec "ns${wgi}" wg show "${wgi}" transfer 2>/dev/null | tr "\t" " ") \
                        <(join -j 1 -a 1 -e 0 -o 1.6,2.2,2.3 \
                            <(cat /etc/accel-ppp.chap-secrets."${wgi}" | tr -d \" | sort -k1,1) \
                            <(ip netns exec "ns${wgi}" accel-cmd -4 -t 3 show sessions username,rx-bytes-raw,tx-bytes-raw | tail -n +3 | tr -d " \r" | tr "|" " " | sort -k 1,1 -u) \
                            | sed "s/^#//") \
                        | tr " " "\t" | jq -R -s | tr -d '\n'
                    echo -n ", \"last-seen\": "
                    join -j 1 -a 1 -a 2 -e 0 -o 0,1.2,2.2 \
                        <(ip netns exec "ns${wgi}" wg show "${wgi}" latest-handshakes 2>/dev/null | tr "\t" " ") \
                        <(join -j 1 -a 1 -e 0 -o 1.6,2.2 \
                            <(cat /etc/accel-ppp.chap-secrets."${wgi}" | tr -d \" | sort -k1,1) \
                            <(ip netns exec "ns${wgi}" accel-cmd -4 -t 3 show sessions username | tail -n +3 | tr -d " \r" | tr "|" " " | sed 's/$/ '`date +%s`'/'| sort -k 1,1 -u) \
                            | sed "s/^#//") \
                        | tr " " "\t" | jq -R -s | tr -d '\n'
                    echo -n ", \"endpoints\": "
                    join -j 1 -a 1 -a 2 -e "(none)" -o 0,1.2,2.2 \
                        <(ip netns exec "ns${wgi}" wg show "${wgi}" endpoints 2>/dev/null | tr "\t" " ") \
                        <(join -j 1 -a 1 -e "(none)" -o 1.6,2.2 \
                            <(cat /etc/accel-ppp.chap-secrets."${wgi}" | tr -d \" | sort -k1,1) \
                            <(ip netns exec "ns${wgi}" accel-cmd -4 -t 3 show sessions username,calling-sid | tail -n +3 | tr -d " \r" | tr "|" " " | sort -k 1,1 -u) \
                            | sed "s/^#//") \
                        | tr " " "\t" | sed 's#\.[0-9]*:[0-9]*\t#.0/24\t#g' | sed 's#\.[0-9]*$#.0/24#g' | jq -R -s | tr -d '\n'
                    echo ", \"timestamp\": \"$(date +%s)\"}"
                fi
        ;;
        "/?wg_add" )
                if [ -z "${f[0]}" ]; then
                    echo "{\"code\": \"131\", \"error\": \"Wireguard interface private key is not defined\"}"
                    exit 0
                else
                    f[0]=`ud_b64 "${f[0]}"`
                    nacl_d "${f[0]}" "Wireguard interface private key" 32 32
                    f[0]="${nacl_d_ret}"
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
                wg_port="51820"
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
                                "--l2tp-preshared-key="* )
                                        v=`ud_b64 "${v}"`
                                        l2tp_psk="${v#*=}"
                                        nacl_d "${l2tp_psk}" "L2TP server preshared key" 16 64
                                        l2tp_psk=`echo "${nacl_d_ret}" | base64 -d | tr -d "\042\047\140"`
                                ;;
                                "--wireguard-port="* )
                                        wg_port="${v#*=}"
                                        wg_port="${wg_port%%[^0-9]*}"
                                ;;
                                "--cloak-bypass-uid="* )
                                        v=`ud_b64 "${v}"`
                                        cloak_b_uid=`echo "${v#*=}" | tr -d "\042\047\140" | head -c 32`
                                ;;
                                "--cloak-domain="* )
                                        v=`ud_b64 "${v}" "\."`
                                        cloak_domain=`echo "${v#*=}" | grep -E "^[a-zA-Z0-9]+([-.]?[a-zA-Z0-9]+)*\.[a-zA-Z]+$"`
                                ;;
                                "--openvpn-ca-crt="* )
                                        v=`ud_b64 "${v}"`
                                        openvpn_ca_crt="${v#*=}"
                                ;;
                                "--openvpn-ca-key="* )
                                        v=`ud_b64 "${v}"`
                                        openvpn_ca_key="${v#*=}"
                                        nacl_d "${openvpn_ca_key}" "OpenVPN CA key"
                                        openvpn_ca_key="${nacl_d_ret}"
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
                if [ -z "${wg_port}" -o "${wg_port}" -le 1024 -o "${wg_port}" -ge 65535 ]; then
                    echo "{\"code\": \"150\", \"error\": \"Wireguard port is not in range 1025-65534\"}"
                fi
                if [ -z "${cloak_b_uid}" ]; then
                    echo "{\"code\": \"151\", \"error\": \"mandatory parameter cloak-bypass-uid is not set\"}"
                    exit 0
                fi
                if [ -z "${openvpn_ca_key}" ]; then
                    echo "{\"code\": \"152\", \"error\": \"mandatory parameter openvpn-ca-key is not set\"}"
                    exit 0
                fi
                if [ -z "${openvpn_ca_crt}" ]; then
                    echo "{\"code\": \"153\", \"error\": \"mandatory parameter openvpn-ca-key is not set\"}"
                    exit 0
                fi

                echo "EXT_DEV=${ext_if}" > "/etc/wg-quick-ns.env.${wgi}"
                echo "EXT_IP=${ext_ip_nm%%/[0-9]*}" >> "/etc/wg-quick-ns.env.${wgi}"
                echo "EXT_CIDR=${ext_ip_nm##*/}" >> "/etc/wg-quick-ns.env.${wgi}"
                echo "EXT_GW=${ext_gw}" >> "/etc/wg-quick-ns.env.${wgi}"

                cp -f /etc/wireguard/wg.conf.tpl "/etc/wireguard/${wgi}.conf"
                chmod 600 "/etc/wireguard/${wgi}.conf"
                echo "Address = ${addrs}" | sed -e "s/,/\nAddress = /" >> "/etc/wireguard/${wgi}.conf"
                echo "PrivateKey = ${f[0]}" >> "/etc/wireguard/${wgi}.conf"
                sed -i "s/\${wg_port}/${wg_port}/g" "/etc/wireguard/${wgi}.conf"
                sed -i "s/\${ext_if}/${ext_if}/g" "/etc/wireguard/${wgi}.conf"
                sed -i "s/\${ext_ip}/${ext_ip_nm%%/[0-9]*}/g" "/etc/wireguard/${wgi}.conf"
                int_ip_nm="`echo ${addrs} | egrep -o '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/[0-9]*'`"
                sed -i "s#\${int_ip_nm}#${int_ip_nm}#g" "/etc/wireguard/${wgi}.conf" # we use hashmarks cause netmask is separated by slash

                ( [ -z "${l2tp_psk}" ] && echo -n || echo ": PSK \"${l2tp_psk}\"" ) > /etc/ipsec.secrets."${wgi}"
                chmod 600 /etc/ipsec.secrets."${wgi}"
                cat /etc/ipsec.conf.tpl \
                    | sed "s/\${ext_ip}/${ext_ip_nm%%/[0-9]*}/g" \
                    > /etc/ipsec.conf."${wgi}"

                echo -n > /etc/accel-ppp.chap-secrets."${wgi}"
                chmod 600 /etc/accel-ppp.chap-secrets."${wgi}"
                cat /etc/accel-ppp.conf.tpl \
                    | sed "s/\${ext_ip}/${ext_ip_nm%%/[0-9]*}/g" \
                    | sed "s/\${netns}/${wgi}/g" \
                    > /etc/accel-ppp.conf."${wgi}"

                echo > /etc/dnsmasq.hosts."${wgi}:5353"
                echo > /etc/dnsmasq.hosts."${wgi}:5354"
                echo > /etc/dnsmasq.hosts."${wgi}:5355"

                mkdir -p /opt/openvpn-"${wgi}"/ccd
                cp -f /etc/openvpn/server.conf.tpl /opt/openvpn-"${wgi}"/server.conf
                sed -i "s/\${wgi}/${wgi}/g" /opt/openvpn-"${wgi}"/server.conf

                cd /opt/openvpn-"${wgi}"
                /usr/share/easy-rsa/easyrsa --batch --use-algo=ec --curve=secp521r1 --digest=sha512 init-pki >/dev/null
                /usr/share/easy-rsa/easyrsa --batch --use-algo=ec --curve=secp521r1 --digest=sha512 --days=3650 build-ca nopass >/dev/null 2>&1
                echo -n "${openvpn_ca_key}" | base64 -d | gunzip > /opt/openvpn-"${wgi}"/pki/private/ca.key
                chmod 600 /opt/openvpn-"${wgi}"/pki/private/ca.key
                echo -n "${openvpn_ca_crt}" | base64 -d | gunzip > /opt/openvpn-"${wgi}"/pki/ca.crt
                EASYRSA_REQ_CN=server /usr/share/easy-rsa/easyrsa --batch --use-algo=ec --curve=secp521r1 --digest=sha512 gen-req server nopass >/dev/null 2>&1
                /usr/share/easy-rsa/easyrsa --batch --use-algo=ec --curve=secp521r1 --digest=sha512 --days=3650 sign-req server server >/dev/null 2>&1
                touch /opt/openvpn-"${wgi}"/pki/index.txt
                /usr/share/easy-rsa/easyrsa --batch --days=3650 gen-crl >/dev/null
                cp -f /opt/openvpn-"${wgi}"/pki/crl.pem /opt/openvpn-"${wgi}"/crl.pem
                chmod 644 /opt/openvpn-"${wgi}"/crl.pem

                mkdir -p /opt/cloak-"${wgi}"
                cp -f /etc/cloak/ck-server.json.tpl /opt/cloak-"${wgi}"/ck-server.json
                sed -i "s#\${cloak_bypass_uid}#${cloak_b_uid}#g" /opt/cloak-"${wgi}"/ck-server.json
                sed -i "s#\${cloak_domain}#${cloak_domain:-yandex.com}#g" /opt/cloak-"${wgi}"/ck-server.json
                sed -i "s#\${cloak_private_key}#${f[0]}#g" /opt/cloak-"${wgi}"/ck-server.json
                sed -i "s/\${ext_ip}/${ext_ip_nm%%/[0-9]*}/g" /opt/cloak-"${wgi}"/ck-server.json

                systemctl start wg-quick-ns@"${wgi}"

                ec=$?
                if [ $ec -eq 0 ]; then
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
                    nacl_d "${f[0]}" "Wireguard interface private key" 32 32
                    f[0]="${nacl_d_ret}"
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
                ext_if="`ip -n \"ns${wgi}\" -4 r get 1.1.1.1 | head -1 | cut -d \  -f 5`"

                systemctl status wg-quick-ns@"${wgi}" >/dev/null

                ec=$?
                if [ ${ec} -eq 0 ]; then
                    systemctl stop wg-quick-ns@"${wgi}"
                    systemctl disable wg-quick-ns@"${wgi}"
                    rm -f /etc/wireguard/"${wgi}".{conf,replay} 2>/dev/null
                    rm -f /etc/dnsmasq.hosts."${wgi}:5353" 2>/dev/null
                    rm -f /etc/dnsmasq.hosts."${wgi}:5354" 2>/dev/null
                    rm -f /etc/dnsmasq.hosts."${wgi}:5355" 2>/dev/null

                    rm -f /etc/ipsec.secrets."${wgi}" /etc/ipsec.conf."${wgi}" /etc/accel-ppp.chap-secrets."${wgi}" /etc/accel-ppp.conf."${wgi}" 2>/dev/null
                    rm -f "/etc/wg-quick-ns.env.${wgi}" 2>/dev/null

                    rm -rf /opt/openvpn-"${wgi}" /opt/cloak-"${wgi}"

                    i=0
                    while [ -z "`ip -4 -o a | fgrep \" ${ext_if} \"`" ]; do
                        sleep 0.1
                        if [ $i -ge 300 ]; then
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
                ext_if="`ip -n \"ns${wgi}\" -4 r get 1.1.1.1 | head -1 | cut -d \  -f 5`"
                if [ ! -z "${ext_if}" ]; then
                    if [ "${t}" == "/?wg_block" ]; then
                        ip netns exec "ns${wgi}" iptables -I FORWARD 1 -o "${ext_if}" -j DROP
                        ip netns exec "ns${wgi}" ip6tables -I FORWARD 1 -o "${ext_if}" -j DROP
                    else
                        true; while [ $? -eq 0 ]; do
                            ip netns exec "ns${wgi}" iptables -D FORWARD -o "${ext_if}" -j DROP 2>/dev/null
                        done
                        true; while [ $? -eq 0 ]; do
                            ip netns exec "ns${wgi}" ip6tables -D FORWARD -o "${ext_if}" -j DROP 2>/dev/null
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
