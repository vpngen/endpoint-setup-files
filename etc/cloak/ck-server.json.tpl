{
  "ProxyBook": { "openvpn": [ "tcp", "localhost:1194" ] },
  "BypassUID": [],
  "BindAddr": [ "${ext_ip}:443" ],
  "RedirAddr": "${cloak_domain}",
  "PrivateKey": "${cloak_private_key}",
  "AdminUID": "${cloak_admin_uid}",
  "DatabasePath": "/opt/cloak-${netns}/userinfo/userinfo.db",
  "StreamTimeout": 300
}
