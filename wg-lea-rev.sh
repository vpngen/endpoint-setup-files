#!/bin/bash

for i in `ip netns list | cut -d \  -f 1`; do
    (
        (
        ip netns exec "$i" wg show all dump | egrep "\.[0-9][0-9]?[0-9]?:[0-9]" | sed -E "s#(\.[0-9][0-9]?[0-9]?)\/[0-9].*#\1#g" ;
#        ip netns exec "$i" accel-cmd -4 -t 3 show sessions ifname,username,state,calling-sid,ip | tail -n +3 | tr -d '\|\r' ;
        join -1 3 -2 2 -o 1.1,1.2,1.3,1.4,2.1 \
            <( join -1 5 -2 1 -o 1.1,1.2,1.3,2.2 \
                <(grep -rH '^#' /opt/openvpn-${i:2}/ccd/ 2>/dev/null | sed 's#^.*/\([^/]*\):\##tun0 dummy \1 #' | sort -k5,5) \
                <(cat /opt/cloak-${i:2}/userinfo/userauthdb.log 2>/dev/null | sort -k1,1) \
                | sort -k 3,3) \
            <(cat /opt/openvpn-${i:2}/status.log 2>/dev/null | tr ',' ' ' | sort -k2,2)
        ) | xargs -I {} /bin/bash -c "echo -n \"{}\"\  ; ip netns exec "$i" ip r get 1.1.1.1 | head -1 | cut -d \  -f 7"
    ) | awk 'BEGIN {OFS=""} {split($4,a,":"); print "[LEA","-REV]: IN= OUT=",$1," SRC=",a[1]," DST=",$5," EXT=",$6}'
done

exit 0
