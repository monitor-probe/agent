# monitor-agent

[monitor](https://github.com/monitor-probe/monitor) 的 Linux agent。采集本机指标，经 WebSocket 上报 hub。

静态链接单文件，无运行时依赖，常驻内存数 MB。

## 特性

- 直接读 `/proc` 与 `statvfs`，不依赖 sysinfo
- 内存对齐 `free(1)` 的 used 列，磁盘对齐 `df(1)` 的 Used 列
- 无状态：不写文件，不保存跨重启的数据，流量累加由 hub 负责
- token 走 `Authorization` 头，不进反向代理的 access log
- 非回环地址拒绝明文 `ws://`

## 安装

在 hub 的面板添加节点，复制生成的命令在目标主机执行：

```bash
curl -fsSL https://your-hub/install.sh | sh -s -- --server https://your-hub --token <token>
```

安装脚本识别 systemd 与 OpenRC，二进制装到 `/opt/monitor/monitor-agent`，token 写入
`/opt/monitor/agent.env`（0600）——和 hub 同一个目录，那台机器上只有这一处要看。

## 运行

```bash
monitor-agent --server https://your-hub --token <token>
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--server` | 必填 | hub 地址，也可用 `MONITOR_SERVER` |
| `--token` | 必填 | 节点 token，也可用 `MONITOR_TOKEN` |
| `--interval` | 1 | 上报间隔（秒），1–3600 |
| `--iface` | 空 | 流量统计的网卡，逗号分隔，也可用 `MONITOR_IFACE`；见下 |

### 统计哪些网卡的流量

默认规则是同一份线上的字节只数一次：lo、容器与虚拟机网卡、隧道不计；bond、网桥、VLAN、PPPoE
这类叠在别的网卡上的设备也不计，只计它们底下的那块。除了按名字，还按内核给出的链路类型、`DEVTYPE`
和 `lower_*` 链接判断，改过名的隧道和网桥同样认得出。

转发流量的机器（软路由、桥接了软路由的宿主机）上，同一个包会经过两块真网卡，哪块面向运营商只有
使用者知道，这时用 `--iface`：

- `--iface eth1` 或 `--iface pppoe-wan`：只统计列出的网卡，内置规则不再生效
- `--iface -vxlan100`：从默认结果里去掉一块，`-` 开头的都是排除，排除优先于列出
- 末尾的 `*` 匹配前缀，如 `--iface 'enp*'`

启动时打印一行 `counting traffic on: ...`，列出此刻计入的网卡。设了 `--iface` 时它会拼进上报的
`boot_id`，改设置后 hub 重新对基线，不会把新旧两组网卡读数之差记成流量。

## 上报字段

`src/collect.rs` 中的 `Facts` 与 `Metrics` 两个 struct 直接序列化为线上 JSON，是字段的权威定义。

- **`Facts`** 连接时上报一次：主机名、系统、内核、架构、虚拟化类型、CPU 型号与核数、内存与磁盘总量、本机 IPv4 / IPv6（每族一个，公网地址优先；IPv6 不取临时地址和已废弃地址）
- **`Metrics`** 每 `--interval` 秒上报：CPU、负载、内存、swap、磁盘、网卡收发速率与内核累计计数器、TCP / UDP 连接数、进程数、运行时间

`net_rx_total` / `net_tx_total` 为所计网卡的内核 lifetime 计数器之和，原样上报；`boot_id` 取自
`/proc/sys/kernel/random/boot_id`（设了 `--iface` 时后接 `/` 与网卡列表），标明这两个读数在哪段区间内
可以相减，是 hub 判定计数器重新开始的唯一依据，**不要删**。

连接 hub 时逐个尝试解析出的地址，除最后一个外每个限 5 秒。网卡上只有内网 IPv4（NAT）时先连 hub 的
IPv4：NAT 的公网地址不在网卡上，hub 只有看到一条 IPv4 连接才知道它。

协议说明见 [hub 仓库](https://github.com/monitor-probe/monitor)。

## 构建

需要 Rust stable。

```bash
cargo build --release
cargo test
cargo clippy --all-targets
```

发布产物为 musl 静态链接二进制，推送 `v*` tag 由 `.github/workflows/release.yml` 构建。

## 许可

MIT
