#!/bin/bash

tc="/usr/bin/sudo /usr/sbin/tc"

function openvpn_set_unset_bandwidth_limit {
    ip="`cat /opt/openvpn-\"$1\"/tc/\"$2\".active_ip 2>/dev/null | sed 's/^[^0-9]*\([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\).*$/\1/'`"
    [ -z "$ip" ] && return 0

    tc_limits="`grep -o \"[0-9][0-9]*/[0-9][0-9]*\" /opt/openvpn-\"$1\"/tc/\"$2\" 2>/dev/null`"
    tc_down=${tc_limits%\/*}
    tc_up=${tc_limits#*\/}

    ip_byte3=`echo "$ip" | cut -d . -f 3`
    handle=`printf "%x\n" "$ip_byte3"`
    ip_byte4=`echo "$ip" | cut -d . -f 4`
    hash=`printf "%x\n" "$ip_byte4"`
    classid=`printf "%x\n" $(( 256 * ip_byte3 + ip_byte4 ))`

    $tc filter del dev "$dev" parent 2:0 protocol ip prio 1 handle 2:"${hash}":"${handle}" u32 ht 2:"${hash}":
    $tc class del dev "$dev" classid 2:"$classid"
    $tc filter del dev "$dev" parent ffff:0 protocol ip prio 1 handle 3:"${hash}":"${handle}" u32 ht 3:"${hash}":

    if [ "$3" == "set" -a ! -z "$tc_down" -a ! -z "$tc_up" ]; then
        $tc class add dev "$dev" parent 2: classid 2:"$classid" htb rate "$tc_down"kbit
        $tc filter add dev "$dev" parent 2:0 protocol ip prio 1 handle 2:"${hash}":"${handle}" u32 \
            ht 2:"${hash}": match ip dst "$ip"/32 flowid 2:"$classid"
        $tc filter add dev "$dev" parent ffff:0 protocol ip prio 1 handle 3:"${hash}":"${handle}" u32 \
            ht 3:"${hash}": match ip src "$ip"/32 police rate "$tc_up"kbit burst 80k drop flowid :"$classid"
    fi

    return $?
}

case "$script_type" in
    up)
        $tc qdisc add dev "$dev" root handle 2: htb
        $tc qdisc add dev "$dev" handle ffff: ingress
        $tc filter add dev "$dev" parent 2:0 prio 1 protocol ip u32
        $tc filter add dev "$dev" parent 2:0 prio 1 handle 2: protocol ip u32 divisor 256
        $tc filter add dev "$dev" parent 2:0 prio 1 protocol ip u32 ht 800:: match ip dst "$ifconfig_local"/"$ifconfig_netmask" hashkey mask 0x000000ff at 16 link 2:
        $tc filter add dev "$dev" parent ffff:0 prio 1 protocol ip u32
        $tc filter add dev "$dev" parent ffff:0 prio 1 handle 3: protocol ip u32 divisor 256
        $tc filter add dev "$dev" parent ffff:0 prio 1 protocol ip u32 ht 800:: match ip src "$ifconfig_local"/"$ifconfig_netmask" hashkey mask 0x000000ff at 12 link 3:
    ;;
    down)
        $tc qdisc del dev "$dev" root handle 2: htb
        $tc qdisc del dev "$dev" handle ffff: ingress
    ;;
    client-connect)
        ns="`dirname \"$config\" | awk -F \- '{print $NF}'`"
        echo "$ifconfig_pool_remote_ip" > /opt/openvpn-"$ns"/tc/"$common_name".active_ip
        echo "$dev" > /opt/openvpn-"$ns"/tc/"$common_name".active_tun
        openvpn_set_unset_bandwidth_limit "$ns" "$common_name" "set"
    ;;
    client-disconnect)
        ns="`dirname \"$config\" | awk -F \- '{print $NF}'`"
        openvpn_set_unset_bandwidth_limit "$ns" "$common_name" "unset"
        rm -f /opt/openvpn-"$ns"/tc/"$common_name".active_ip /opt/openvpn-"$ns"/tc/"$common_name".active_tun 2>/dev/null
    ;;
    *)
        case "$1" in
            update)
                [ -z "$2" ] && echo "$0 $1: missing argument: namespace id" >&2 && exit 1
                [ -z "$3" ] && echo "$0 $1 $2: missing argument: client id" >&2 && exit 1
                cn="`fgrep -rH \"#$3\" /opt/openvpn-\"$2\"/ccd/ | cut -d \: -f 1 | awk -F \/ '{print $NF}'`"
                [ ! -z "$4" -a ! -z "$5" ] && echo "$4/$5" > /opt/openvpn-"$2"/tc/"$cn" || rm -f /opt/openvpn-"$2"/tc/"$cn" 2>/dev/null
                [ -f /opt/openvpn-"$2"/tc/"$cn".active_tun ] && dev=`cat /opt/openvpn-"$2"/tc/"$cn".active_tun` openvpn_set_unset_bandwidth_limit "$2" "$cn" "set"
            ;;
            *)
                echo "$0: unknown operation: $1" >&2
                exit 1
            ;;
    esac
    ;;
esac

exit 0
