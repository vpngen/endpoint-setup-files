{
  "Transport": "direct",
  "ProxyMethod": "openvpn",
  "EncryptionMethod": "plain",
  "UID": "${cloak_admin_uid}",
  "PublicKey": "${cloak_public_key}",
  "ServerName": "www.bing.com",
  "NumConn": 1,
  "BrowserSig": "chrome",
  "StreamTimeout": 300,
  "RemoteHost": "${ext_ip}",
  "LocalPort": "${local_admin_port}"
}
