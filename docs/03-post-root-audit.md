# 03 — 取得 root 后的进程审计

方式：connect8 独立精简脚本（SimpleDocker 容器逃逸 → cgroup release_agent → 宿主机 root 执行 payload）。结果：SSH 在 22 端口开启，`root` 账号可用。

> 本文记录一次真实设备上的审计结果，隐去了所有设备标识与凭据。结论只代表该样本设备当时的状态。

## 1. 取得 root 的过程（通用化）

1. 登录路由器 Web 后台（`http://<路由器IP>`）。
2. 确认外接存储已识别（ext4 U 盘）。
3. `get_docker_info` 显示 Docker 与第三方管理（端口 9001）均已安装但服务未启动；调用 `api/xqnetwork/set_mi_docker mode=1` 启动，数秒后 9001 开放。
4. 运行 `connect8_standalone.py`，SimpleDocker 用默认账号登录成功，逃逸链完整跑通。
5. payload 以 uid=0 执行，修改 root 密码并启动 dropbear；`netstat` 确认 22 端口 LISTEN，SSH 实际登录验证 `id` 返回 `uid=0(root)`。

注：payload 日志里出现一行 `Failed moving key file to /etc/dropbear/dropbear_rsa_host_key: File exists`，是已有 host key 导致的新 key 写入失败，不影响 dropbear 启动与登录。

## 2. 进程审计结论

### 是否有“监控”

- **没有抓包/中间人类进程**：`ps` 中未见 tcpdump、libpcap 抓包、mitmproxy 一类程序；唯一带 `proxy` 字样的是 Docker 的 `docker-proxy`（端口映射用）。
- **没有额外植入的未知进程**：进程列表与固件内自带的 OpenWrt/小米组件一致。
- **syslog-ng 没有远程日志目标**：所有 destination 都是本地文件（`/tmp/messages`、`/tmp/stat_points/*`、`/tmp/meminfo.log`、`/tmp/wifi_analysis.log`），未见向外部主机发送 syslog。

### 原厂固件确有“数据上报”能力，且在运行

| 进程 | 作用 | 状态 |
|---|---|---|
| `/usr/bin/messagingagent --mqtts_enable 1` | 小米云消息通道 | 运行中，已建立到某云服务商 IP:8887 的外联（推断为小米云端服务） |
| `/usr/sbin/xq_info_sync_mqtt` | 设备信息 MQTT 同步 | 运行中，连本机 `mosquitto:8883` |
| `/opt/filetunnel/tunnelserver` + `stunserver` | 云端隧道 / NAT 打洞 | 运行中，审计时无活跃隧道外联 |
| `/usr/sbin/datacenter` | 数据中心 | 运行中 |
| `/usr/sbin/netapi` | 本地网络 API | 运行中 |
| `sp_check.sh`（cron 每 5 分钟） | 统计点检查与上传 | 启用，读取 `/tmp/stat_points/*.log` 打包上传 |
| DPI 类（antiy / haohan） | URL 安全检查 | 固件里有库，**进程未运行**，配置开关默认关闭 |

判断：这些是小米原厂固件的标准组件，行为与固件分析一致；没有发现第三方或隐蔽的监控程序。但“路由器会向小米云上报设备/使用统计”这件事本身是确实存在的，出厂配置如此。

### 定时任务

`/etc/crontabs/root` 中除常规 logrotate、ntp、OTA 预下载外，值得注意的：

- `*/5 * * * * sp_check.sh` — 统计点上传检查
- `0 */6 * * * sec_cfg_bak.sh` — 安全配置备份
- `* * * * * startscene_crontab.lua` — 场景联动（每分钟）
- `run-parts /etc/periodic` — 目录内只有 `01_st_coll`、`99_st_conv`（统计点收集/转换）

未发现反弹 shell、可疑下载执行类任务。

## 3. 端口真相（修正外部扫描的推断）

取得 root 后用 `netstat -tlnp` 实测：

- **25 / 110 / 143：确实没有进程监听**。外部 TCP 扫描显示“开放”是假象，由 QoS/防火墙层面的响应造成。
- **139 / 445：真的是 `smbd` 在监听**，绑定 LAN 地址及多个 IPv6 地址。之前“可能是假开放”的推断**是错的**。
- **9001**：Docker 的 `docker-proxy` 在监听。
- **22**：本次新开的 dropbear。
- **8883**：本机 `mosquitto`，与 `xq_info_sync_mqtt` 的内部连接。

## 4. SSH 持久化（实测有效方案）

最初尝试原版 connect8 的 `--persist`（写 `@reboot` cron）在这台机器上不生效。排查后确认两点关键约束，并给出可靠方案。

### 环境约束

- `/etc` 是 **ramfs**（重启丢失），但 `/etc/crontabs` 和 `/data` 是 **ubifs 真持久分区**。
- BusyBox 1.25.1 的 `crond` **不支持 `@reboot`**，改用**每分钟执行的幂等脚本**代替。
- 追加 crontab 条目后必须 `/etc/init.d/cron restart` 让 crond 重读，否则不生效。
- dropbear **不能用 `-F ... &` 启动**——后台作业会随 cron 会话收到 SIGHUP 被杀；应让 dropbear 自行 daemonize（不加 `-F`）。

### 方案

把恢复脚本放 `/data/xmir_ssh_restore.sh`，由持久 crontab 每分钟幂等执行，每次检查：

1. `nvram ssh_en=1`
2. 恢复 host key（持久副本存 `/data`）
3. 重新 patch `/etc/init.d/dropbear` 的 release 通道限制（ramfs 重启会还原）
4. 校验 root 密码 hash（shadow 软链到 `/data/etc/shadow`，持久）
5. 22 端口没监听就 daemonize 启动 dropbear

部署要点：

```sh
# 上传脚本到持久分区并赋权
cat > /data/xmir_ssh_restore.sh   # 内容见 tools/xmir_ssh_restore.sh
chmod +x /data/xmir_ssh_restore.sh
cp /etc/dropbear/dropbear_rsa_host_key /data/xmir_dropbear_rsa_host_key
chmod 600 /data/xmir_dropbear_rsa_host_key

# 加持久 cron（每分钟），并让 crond 重读
echo '* * * * * /data/xmir_ssh_restore.sh >/dev/null 2>&1' >> /etc/crontabs/root
/etc/init.d/cron restart
```

### 验证结果

- 模拟 `killall dropbear` 后，cron 在约 40 秒内自动把 dropbear 拉起，日志记录 `dropbear started (daemonized)`，新密码登录成功。
- **真实 `reboot` 验证通过**：重启后约 1 分钟开机，`uptime` 显示新启动时间，22 端口自动开放，SSH 密码登录成功，release 通道检查计数 = 0（补丁重启后仍生效），crond 在跑、crontab 条目都在。
- 一个细节：重启后恢复脚本日志没有新增记录，说明开机那刻 SSH 是靠 `nvram ssh_en=1` + 已持久化的 init 补丁由原厂开机流程直接拉起的；cron 脚本是每分钟巡检的兜底。两者叠加更稳。
- 判断设备状态别只看 ICMP：重启初期 ping 不通但 SSH 已能连。

## 5. 加固建议

1. **开启的 root SSH 是新的攻击面**，应设强密码，或用防火墙限制只有受信任 IP 能访问 22。
2. Samba 4.0.21（SambaCry 影响版本）确实在 445 监听，建议确认共享是否可写、是否仅限内网；可考虑直接关闭或设 `nt pipe support = no`。
3. 若要阻断小米云上报，可在 root 下停 `messagingagent`、`xq_info_sync_mqtt`、`sp_check.sh` 的 cron、`datacenter`，但要评估对 App 管理、OTA、Mesh 功能的影响。
