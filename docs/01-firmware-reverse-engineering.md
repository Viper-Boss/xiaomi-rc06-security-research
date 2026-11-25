# 01 — 固件逆向分析（RC06 / 1.1.38）

对象：从官方 CDN 下载的 RC06 1.1.38 完整固件包。全程静态分析，未在设备上执行任何代码。

## 1. 样本信息

| 项目 | 值 |
|---|---|
| 大小 | 39,060,492 字节 |
| SHA256 | `77d8bd587418310c12c32922f8af63994079baa12c3a4772891494631bd84d8e` |
| 版本 | ROM 1.1.38，CHANNEL=release，硬件 RC06 |
| 内核 | Linux 5.4.164（ARM64，FIT），设备树 `ipq9574-alxx`（高通 IPQ9574） |
| 构建时间 | 2026-01-27 04:23 UTC（固件），04:50 UTC（根文件系统） |

## 2. 封装结构（已完全解开）

```
miwifi_rc06_..._1.1.38.bin
├─ HDR1 头 (0x00..0x90)
├─ 0xBEBE 记录: xiaoqiang_version（ROM/CHANNEL/HARDWARE/内核版本/构建时间）
├─ 0xBEBE 记录: root.ubi (39,059,456 B = 298 × 128KiB)
│  ├─ vol_hdr   : 块 0-1    分区描述表（kernel / ubi_rootfs）
│  ├─ kernel_fit: 块 2-32   ARM64 OpenWrt FIT: Linux-5.4.164 + ipq9574 dtb
│  └─ rootfs    : 块 33-297 squashfs v4.0, xz, 256KiB 块, 33,449,900 B
└─ 尾部 272 字节（签名/校验）
```

UBI 的 EC/VID 头是小米/高通方案的变体（偏移大端、块序号 64 位大端），常规 `ubireader` / `PySquashfsImage` 直接读会失败，需要先按上述布局重组。

根文件系统共 **5579 个条目**：4698 个普通文件、565 个符号链接、315 个目录、1 个字符设备，展开约 133 MB。

## 3. 开机自启与网络服务（/etc/rc.d 的 S* 链接，约 70 项）

- 基础：`network`, `dnsmasq`, `firewall`, `odhcpd`, `miniupnpd`, `samba`, `afpd`, `avahi-daemon`
- Web：`nginx`（80 / 443 / 8080 / 8099 / 8900，8099/8900 为 TLS）、`rpcd`、`uhttpd`
- 小米/高通自有：`datacenter`, `datacenterClient`, `netapi`, `mipctld`, `miot`, `meshd`, `topomon`, `trafficd`, `xiaoqiang_sync`, `xq_info_sync_mqtt`, `port_service`, `pluginmanager`, `smartcontroller`, `mobile_accel`, `miqos`, `wan_check`, `miwifi-discovery`
- 安全/云：`anti_attack`, `antiy_dpi`, `antiy-url-fw`, `haohan_dpi`, `local_gw_security`, `milog`, `miwifi-logd`, `filetunnel`, `stunserver`, `autovpn`, `smartvpn`

**SSH / Telnet 出厂不可用的原因**（固件代码）：

```sh
# /etc/init.d/dropbear
# 稳定版不能打开ssh服务
flg_ssh=`nvram get ssh_en`
channel=`uci get .../version.CHANNEL`
if [ "$flg_ssh" != "1" -o "$channel" = "release" ]; then return 0; fi
```

稳定版（release）即使 `ssh_en=1` 也直接 return。这是后续 connect8 补丁必须同时改 nvram 和脚本版本检查的原因。`telnet` 脚本无条件启动 telnetd，但镜像里**没有 `/usr/sbin/telnetd`**，所以 23 端口不开——与初始扫描（22/23 关闭）一致。

## 4. 与“监控/上报”相关的发现

固件**内置**下列云连接与数据采集能力，这是原厂设计：

1. **小米云端点**（`/etc/config/miwifi`）：`api.miwifi.com`、`log.miwifi.com`、`s.miwifi.com`、`app.miwifi.com`、`stun.miwifi.com`、`broker.miwifi.com`（MQTT broker）。
2. **MQTT / 日志上报**：`xq_info_sync_mqtt` 含订阅 topic、上传密钥、设备列表同步、`syslog_upload.lua`；`/etc/config/milog` 定义大量 `sec_*` 事件标签（网关风险、Web 风险、端口扫描、WLAN 密码修改等）。**出厂 `milog.global.enable = 0`（关闭）**。
3. **统计点系统**：`/etc/periodic/01_st_coll`、`99_st_conv`、`doStatPoints`、`/tmp/stat_points/*.log`。
4. **远程文件通道**：`/opt/filetunnel/tunnelserver` 开机启动，二进制含 `miwifi::tunnel::pb::ChunkUploadRequest`、`relay`、`MITPSession`、`xiaomi::mqtt`，上传目录 `/userdisk/data/.tunneluploads/`——具备“云端发起的分块文件上传/中继”能力。
5. **DPI/URL 过滤**：`libdpi_antiy.so`、`libdpi_haohan.so`，经 iptables 标记流量做检查。但 `/etc/config/security` 中 `malicious_url_firewall=0`、`virus_file_firewall=0`、`privacy_protection=0`，`/etc/config/antiy_url_policy` 中 `enable=0`——**出厂配置关闭**。

`libpcap`、`tcpdump`、`trace-cmd` 等属于 OpenWrt 常规诊断组件，不能据此判断有人在监控。

## 5. 可疑端口 25 / 110 / 143 的解释

- 镜像里**没有 SMTP/POP3/IMAP 服务程序**，三个端口连上后都没有 banner。
- 它们出现在 `/etc/config/miqos` 的 QoS 分类列表：`config class p3 → tcp_ports '25,110,139,143,220,585,993,995'`。这类匹配配合 `nfnlq_userland` 会把新连接标记/送入用户态，扫描时 SYN 被接受但没有应用层服务回应，形成“假开放”。
- 结论（推断）：QoS/防火墙标记所致，而非架了邮件服务。root 后用 `netstat -tlnp | grep -E ':(25|110|143)\b'` 可一秒定论——后续实测证实这三个端口确实无进程监听。

## 6. 结论与边界

- 公开固件里没有发现“额外的、隐蔽的监控程序”；但原厂固件**本身**带云端管理、日志/统计上报、远程文件隧道、DPI URL 检查能力，其中 DPI/恶意网址/隐私防护与 milog 日志上传的出厂配置是关闭的。
- 本分析针对**公开固件镜像**。设备实际运行时的 overlay 配置、已安装插件、运行中进程，无 root 看不到；二者可能不同。

## 7. root 后的审计命令（拿到 SSH 后可直接用）

```sh
ps w
netstat -tlnpu                         # 重点看 25/110/143、8883、19553、784 的 PID
cat /etc/crontabs/root
for f in /etc/rc.d/S*; do readlink "$f"; done
iptables -t nat -L -n -v
iptables -t filter -L -n -v
lsmod
ls -la /data/etc/ /etc/dropbear/ /userdisk/
find / -type f -newermt '2026-01-27' -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null
cat /etc/config/miwifi /etc/config/milog /etc/config/security
tcpdump -i any -nn -c 200 'not port 22'   # 看实际外联
```
