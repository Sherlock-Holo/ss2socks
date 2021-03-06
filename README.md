# ss2socks
## convert shadowsocks back to socks

### Why write this program
My Phone just installed shadwosocks-android and I don't want to install something else.

But I want to use other proxy tools like v2ray, goproxy etc.

So, this program will help me convert shadowsocks protocol back to socks5 and then connect to other proxy tools.

### Working principle
|program|communicate protocol|program|communicate protocol|program|
|:-:|:-:|:-:|:-:|:-:|
|`shadowsocks-android`|shadowsocks protocol|`ss2socks`|socks protocol|`back end`|

### Usage
`kotlin ss2socks.jar -c config.toml`

or

(recommend because I found some problems on Arch with `kotlin`)

`java -jar ss2socks.jar -c config.toml`

### Feature
- Coroutine support

- Direct ByteBuffer for better IO performance, and use buffer pool to reuse DirectByteBuffer

- Security channel: keep your data safety when you are in strange WiFi

- Google DNS redirect to local DNS(127.0.0.1:53): avoid DNS pollution so you need a local DNS resolver a.g `dnsmasq`

### Notice
shadowsocks encrypt mode only support `aes-256-ctr` for now.

### Config file example
```
[server]
ssAddr = "127.0.0.2"
ssPort = 1088
backEndAddr = "127.0.0.2"
backEndPort = 1888

[security]
cipherMode = "aes-256-ctr"
password = "holo"

[securityChannel]
# Make GeoIP true to use security channel mode,
# and then set the GeoIPDatabaseFilePath.
GeoIP = true
GeoIPDatabaseFilePath = "/home/sherlock/Downloads/GeoLite2-City.mmdb"
```
