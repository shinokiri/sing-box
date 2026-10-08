---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

### 结构

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 4,
  "psk": "password",
  "userkey": "",
  "reuse": false,
  "udp_flow": false,
  "network": "tcp",
  "obfs_mode": "",
  "obfs_host": "",

  ... // 拨号字段
}
```

### 版本 6 结构

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 6,
  "psk": "password",
  "userkey": "",
  "reuse": false,
  "udp_flow": false,
  "network": "tcp",
  "mode": "",
  "http_framing": false,

  ... // 拨号字段
}
```

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### version

==必填==

Snell 协议版本，`4` `6` 之一。

版本 `4` 支持 HTTP 混淆（`obfs_mode` / `obfs_host`）；版本 `6` 以流量整形（`mode`）
取而代之，并要求 `psk` 长度为 12 到 255 字节。

!!! note

    由于我们有意不支持 Snell v5 的 QUIC 代理模式，v5 的线路协议实际上与 v4 没有区别，
    因此不提供独立的 v4 服务器和 v5 客户端。

#### psk

==必填==

预共享密钥。

#### userkey

用户密钥，用于向多用户服务器进行认证。

#### reuse

启用连接复用（Snell v2 `CONNECT` 命令）。

#### udp_flow

启用实验性的 sing-tun UDP Flow 适配器。它会让每个 UDP 五元组分别解析并执行 DNAT，并在条件允许时让同一 selector 复用一条 Snell UDP packet connection。Fake-IP UDP 流量在路由到该出站前必须先经过 `resolve` 路由动作。

#### network

启用的网络协议。

`tcp` 或 `udp`。

默认所有。

#### obfs_mode

==仅版本 4==

HTTP 混淆模式，`none` `http` 之一。

默认为 `none`。

#### obfs_host

==仅版本 4==

`obfs_mode` 为 `http` 时发送的 HTTP `Host` 头。

默认为 `bing.com`。

#### mode

==仅版本 6==

流量整形模式，`default` `unshaped` `unsafe-raw` 之一。

默认为 `default`。

#### http_framing

==仅版本 6 的 default 模式；此分支扩展==

启用首条客户端写入的配套 HTTP 封装，用于绕过已复现的 TCP Fast Open 持续低速问题，默认关闭。两端必须配套支持：出站连接到同样启用该选项的入站，或连接到向现有 Snell 服务转发的 `snell-http-relay`。启用后不能直接连接未经修改的 Snell 监听端口。

接收端重建流量整形中可确定的填充字节，保留原来的 Snell 盐值、密文及认证。这些重建字节抵消封装头的长度；可重建填充不足的配置会在初始化时被拒绝。TCP 分段由内核照常决定，不需要 MSS 缓存或额外的预热连接。收到封装头和盐位置字节即可开始解码，不等待完整正文。后续写入与服务器回复仍使用原有 Snell 格式。此选项本身不启用 TCP Fast Open，仍需使用相应的拨号或监听设置。

固定的 `.invalid` Host 值只是封装字面量，不会解析该域名，也不需要 HTTP 服务或 TLS 握手。此机制已针对特定路径上的复现故障测试；原有 Snell 加密继续生效。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
