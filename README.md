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
`kotlin ss2socks.jar -c config.yaml`

or

`java -jar ss2socks.jar -c config.yaml`

### Feature
- Coroutine support

- Auto expand Buffer

### Notice
shadowsocks libs.encrypt mode is `aes-256-ctr`.

### Config file example
```
ssAddr: 127.0.0.2
ssPort: 1088
backEndAddr: 127.0.0.2
backEndPort: 1888
password: holo
```
