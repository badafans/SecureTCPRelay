# SecureTCPRelay

**SecureTCPRelay** 是一个灵活且安全的 TCP 转发代理，支持动态选择转发目标和基于域名的访问控制。该程序能够处理 非TLS（HTTP & WS）和TLS（HTTPS & WSS），并根据配置自动选择目标地址进行转发。

## 特性

- **动态转发**：根据配置，程序可以将流量转发到不同的目标地址。
- **基于 IP 和域名的访问控制**：允许配置白名单 IP 范围和域名模式。
- **活跃连接跟踪**：实时跟踪并记录当前活跃连接数量。
- **支持多个目标地址**：根据需要转发TCP到不同的目标地址。
- **Host 与 SNI 支持**：基于域名过滤，能够拦截非白名单域名请求。
- **TLS 与 非TLS 端口共用**：能够识别并处理 TLS 和 非TLS 请求，只需暴露一个端口即可。

## 安装

将项目克隆到本地并编译：

```bash
git clone https://github.com/badafans/SecureTCPRelay.git
cd SecureTCPRelay
go build
```

## 使用

启动代理服务器并配置监听地址、转发目标地址、允许的 IP 范围和域名列表：

```bash
./SecureTCPRelay -src=<local-address> -dst=<forward-addresses> -cidr=<allowed-cidrs> -domain=<allowed-domains>
```

- `-src`: 本地监听的 IP 和端口（默认 `0.0.0.0:1234`）
- `-dst`: 转发的目标 IP 和端口,多目标模式用逗号分隔(第一个是非TLS地址,第二个是TLS地址,多出部分地址无效)
- `-cidr`: 允许的来源 IP 范围 (CIDR)，多个范围用逗号分隔（默认 `0.0.0.0/0,::/0`）
- `-domain`: 允许的域名列表,用逗号分隔,支持通配符*,默认转发所有域名

### 示例

要在 `0.0.0.0:8080` 上监听并将流量转发到 `192.168.1.100:80` 和 `192.168.1.100:443`，同时允许来自 `192.168.1.0/24` 的 IP 并允许访问 `abc.com` 和 `*.example.org` 的域名，你可以使用以下命令：

```bash
./SecureTCPRelay -src=0.0.0.0:8080 -dst=192.168.1.100:80,192.168.1.100:443 -cidr=192.168.1.0/24 -domain=abc.com,*.example.org
```
非TLS（HTTP & WS）的请求将被转发到 `192.168.1.100:80` ，TLS（HTTPS & WSS）的请求将被转发到 `192.168.1.100:443` 

## 配置说明

### CIDR 配置

CIDR 配置用于限制允许的客户端 IP 地址范围。例如，`192.168.1.0/24` 允许来自 `192.168.1.0` 到 `192.168.1.255` 的所有 IP 地址。

### 域名列表

域名列表用于控制允许的目标域名。支持通配符 `*`。例如，`*.example.com` 将匹配 `sub.example.com` 和 `www.example.com` 等域名。

## 贡献

欢迎对 `SecureTCPRelay` 进行贡献。如果你有建议或发现了问题，请提交问题报告或拉取请求。

## 许可证

`SecureTCPRelay` 采用 MIT 许可证。