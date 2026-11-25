# Xiaomi BE7000 (RC06) 固件安全分析与 SSH 开启工具

对小米路由器 7000（BE7000，代号 RC06）官方固件的一次完整安全审计：从固件解包、组件漏洞清点，到在**自有设备**上通过 SimpleDocker 容器逃逸取得 root，并做进程/外联审计。

> 本仓库只面向**你自己拥有或已获明确书面授权**的设备。请遵守所在地法律（中国大陆参见《网络安全法》《刑法》第 285/286 条）。未经授权对他人设备使用属于违法行为，作者不承担任何责任。

---

## 1. 目标固件版本

| 项目 | 值 |
|---|---|
| 型号 | Xiaomi 路由器 7000（BE7000），代号 **RC06** |
| 固件版本 | **1.1.38**（`CHANNEL=release`，稳定版） |
| 内核 | Linux 5.4.164，ARM64，高通 IPQ9574 |
| 构建时间 | 2026-01-27 UTC |
| 官方包 SHA256 | `77d8bd587418310c12c32922f8af63994079baa12c3a4772891494631bd84d8e` |
| 官方下载 | `https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/rc06/miwifi_rc06_firmware_65d1d_1.1.38.bin` |

**版本很关键**：本利用依赖 SimpleDocker 容器逃逸，只在装得上 Docker/简单插件的固件上成立。升级固件后接口或配置路径可能变化，需重新验证。分析时（2026-11）1.1.38 是该机型最新稳定版。

---

## 2. 仓库内容

```
docs/
  01-firmware-reverse-engineering.md   固件封装结构、自启服务、上报组件分析
  02-vulnerability-analysis.md         组件版本清点、CVE 匹配、root 路径评估
  03-post-root-audit.md                取得 root 后的进程/外联/端口审计与加固建议
tools/
  connect8_standalone.py               SimpleDocker cgroup 逃逸开 SSH（独立精简版）
  xmir_ssh_restore.sh                  SSH 开机持久化脚本（幂等）
requirements.txt                      Python 依赖
```

三份文档是**分析记录**，两份脚本是**可运行的利用/持久化工具**。文档里的结论区分「已实测」与「推断」，请按标注理解。

---

## 3. 使用条件（必读）

利用脚本要成功，需同时满足：

1. **设备是你的**，且运行 RC06 / 固件 1.1.38（或行为一致的相近版本）。
2. **已插入 ext4 格式的 U 盘**（≥8G），并在路由器后台确认识别为外接存储。SimpleDocker 依赖外接存储。
3. **后台已安装 Docker / SimpleDocker**，浏览器能打开 `http://<路由器IP>:9001` 看到 SimpleDocker 登录页。
   - 若后台装了但 9001 没开：登录路由器后台，调用 `api/xqnetwork/set_mi_docker` 的 `mode=1` 启动（或后台页面里开关一次 Docker）。
   - SimpleDocker 默认账号 `admin` / `admin`（如已改过，用 `--docker-user` / `--docker-pass` 覆盖）。
4. **本机需装 Python 3 + `openssl`**：脚本用 `openssl passwd -1` 生成 hash。Windows 上的 Git Bash 一般自带；Linux/macOS 通常也有。
5. 知道**路由器 Web 后台管理员密码**（作为参数传入）。

预期结果：22 端口启动 dropbear，SSH 账号 `root`、密码为你用 `--password` 指定的值。**不刷固件、不改分区**，最坏情况是 SSH 没开起来，重跑即可。

---

## 4. 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 开 SSH（把三个占位符换成你自己的值）
# 第一个位置参数是 Web 后台密码（兼容原版 CLI；SimpleDocker 实际用 admin/admin 登录）
python tools/connect8_standalone.py '<你的路由器后台密码>' \
    --host 192.168.x.1 \
    --password '<你想设置的SSH密码>'

# 验证
ssh -o StrictHostKeyChecking=no \
    -o HostKeyAlgorithms=+ssh-rsa \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    root@192.168.x.1
```

`dropbear` 是老版本，只提供 `ssh-rsa` host key，新客户端需在 ssh 命令加上面两个 `-o` 参数。

> **安全提醒**：`--password` 请用一个强密码。若 LAN 中有其他设备，SSH 开着期间不要久置；用完可考虑关闭或限制来源 IP。

---

## 5. SSH 持久化（可选）

默认开出来的 SSH **重启后失效**。持久化脚本 `tools/xmir_ssh_restore.sh` 采用实测有效的方案：放在持久分区 `/data`，由持久 crontab 每分钟幂等执行，负责恢复 host key、补丁 dropbear 启动脚本、校验密码并拉起服务。

部署方式和坑点（ cron 不重载、`-F &` 被 SIGHUP 杀掉等）见 `docs/03-post-root-audit.md` 末尾。

---

## 6. 法律与伦理

- 仅用于**自有或明确授权**的设备；请勿用于未授权的第三方网络。
- 本工具不窃取数据、不植入后门，仅在目标设备上开启 SSH 供所有者运维；但**开启 root SSH 本身会扩大攻击面**，使用者需自行权衡并做好密码/访问控制。
- 固件与组件版权归小米及各上游项目所有；本仓库为安全研究用途，不含任何固件二进制。

## 7. 致谢

利用链基于 [h8suga/xmir-patcher](https://github.com/h8suga/xmir-patcher) 的 `feat/simpledocker-cgroup-escape` 分支（connect8），本仓库将其拆成独立、可审计的最小脚本。相关漏洞的历史讨论见恩山无线论坛。
