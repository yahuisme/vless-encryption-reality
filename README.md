# vless-encryption-reality
基于最新 Xray 的 VLESS Encryption + REALITY + Vision 一键安装和管理脚本

## 一键安装
```
bash <(curl -L https://raw.githubusercontent.com/yahuisme/vless-encryption-reality/main/install.sh)
```

## 无交互安装
```
bash <(curl -L https://raw.githubusercontent.com/yahuisme/vless-encryption-reality/main/install.sh) install --port 12345 --uuid 'd0f6a483-51b3-44eb-94b6-1f5fc9272c81' --sni 'www.sega.com'
```
自行修改端口、uuid 和 sni 参数。

## 提示
此协议基于 Xray 最新支持的 VLESS 量子加密，目前支持的客户端极少，截至目前（2025-09-15），使用最新版的 V2rayN 可以直接导入订阅链接使用。
