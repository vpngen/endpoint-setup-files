{
  "ProxyBook": { "openvpn": [ "tcp", "localhost:1194" ] },
  "BypassUID": [ "${cloak_bypass_uid}" ],
  "BindAddr": [ "${ext_ip}:443" ],
  "RedirAddr": "${cloak_domain}",
  "PrivateKey": "${cloak_private_key}",
  "AdminUID": "",
  "DatabasePath": "",
  "StreamTimeout": 300
}
