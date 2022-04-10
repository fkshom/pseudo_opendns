# pseudo_opendns

- DNSフォワーダーとして動作します
- `myip.opendns.com`（複数定義可能）へのAレコードリクエストの場合は、送信元IPアドレスをAレコードとして返します
- それ以外のリクエストの場合は、上流のDNSサーバへ問い合わせます

[Get public IP using DNS | Code](https://code.blogs.iiidefix.net/posts/get-public-ip-using-dns/)

```sh
dig @localhost -p 5353 myip.opendns.com A
dig @localhost -p 5353 o-o.myaddr.l.google.com TXT
dig @localhost -p 5353 whoami.akamai.net A
```


```
# .env

BIND_ADDR=0.0.0.0
PORT=5353
UPSTREAM=8.8.8.8
MYIP_QUERY="
myip.opendns.com A
o-o.myaddr.l.google.com TXT
whoami.akamai.net A
"
```