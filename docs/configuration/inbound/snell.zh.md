---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

### 结构

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // 监听字段

  "version": 5,
  "psk": "password",
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "obfs_mode": ""
}
```

### 版本 6 结构

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // 监听字段

  "version": 6,
  "psk": "password",
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "mode": "",
  "http_framing": false
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### version

==必填==

Snell 协议版本，`5` `6` 之一。

版本 `5` 支持 HTTP 混淆（`obfs_mode`）；版本 `6` 以流量整形（`mode`）取而代之，并要求
`psk` 长度为 12 到 255 字节。

!!! note

    由于我们有意不支持 Snell v5 的 QUIC 代理模式，v5 的线路协议实际上与 v4 没有区别，
    因此不提供独立的 v4 服务器和 v5 客户端。

#### psk

==必填==

预共享密钥。

#### users

Snell 用户。

设置后，服务器运行于多用户模式：每一项包含 `name`（可选，用于日志）和 `userkey`
（用户密钥）。

#### obfs_mode

==仅版本 5==

HTTP 混淆模式，`none` `http` 之一。

默认为 `none`。

#### mode

==仅版本 6==

流量整形模式，`default` `unshaped` `unsafe-raw` 之一。

默认为 `default`。

#### http_framing

==仅版本 6 的 default 模式；此分支扩展==

启用首条客户端写入的配套 HTTP 封装，用于绕过已复现的 TCP Fast Open 持续低速问题，默认关闭。两端必须配套支持：出站连接到同样启用该选项的入站，或连接到向现有 Snell 服务转发的 `snell-http-relay`。启用后不能直接连接未经修改的 Snell 监听端口。

接收端重建流量整形中可确定的填充字节，保留原来的 Snell 盐值、密文及认证。这些重建字节抵消封装头的长度；可重建填充不足的配置会在初始化时被拒绝。TCP 分段由内核照常决定，不需要 MSS 缓存或额外的预热连接。收到封装头和盐位置字节即可开始解码，不等待完整正文。后续写入与服务器回复仍使用原有 Snell 格式。此选项本身不启用 TCP Fast Open，仍需使用相应的拨号或监听设置。

固定的 `.invalid` Host 值只是封装字面量，不会解析该域名，也不需要 HTTP 服务或 TLS 握手。此机制已针对特定路径上的复现故障测试；原有 Snell 加密继续生效。
