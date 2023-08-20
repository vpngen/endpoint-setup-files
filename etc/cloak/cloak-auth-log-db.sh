#!/bin/bash

spinlock="`[ ! -z \"${TMPDIR}\" ] && echo -n \"${TMPDIR}/\" || echo -n \"/tmp/\" ; basename \"${0}.spinlock\"`"
trap "rm -f \"${spinlock}\" 2>/dev/null" EXIT
while [ -f "${spinlock}" ] ; do
    sleep 0.01
done
touch "${spinlock}" 2>/dev/null

case "$1" in
    *' msg="New session" '*)
        ns="`egrep -o \" cloak-ns-[^\[]*\" <<< \"$1\" | cut -d \- -f 3`"
        uid="`egrep -o \" UID=[^ ]*\" <<< \"$1\" | cut -d \\\" -f 2`"
        addr="`egrep -o \" remoteAddr=[^:]*\" <<< \"$1\" | cut -d \\\" -f 2`"
    ;;
    *' msg="Session closed" '* | *' msg="Terminating active user" '*)
        ns="`egrep -o \" cloak-ns-[^\[]*\" <<< \"$1\" | cut -d \- -f 3`"
        uid="`egrep -o \" UID=[^ ]*\" <<< \"$1\" | cut -d \\\" -f 2`"
    ;;
esac

if [ ! -z "$ns" ]; then
    sed -ni "s#^${uid} .*##" /opt/cloak-"$ns"/userinfo/userauthdb.log 2>/dev/null
    [ ! -z "$addr" ] && echo "${uid} ${addr}" >> /opt/cloak-"$ns"/userinfo/userauthdb.log 2>/dev/null
fi

exit 0
