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
  "LocalHost": "127.0.0.1",
  "LocalPort": "1984"
}
