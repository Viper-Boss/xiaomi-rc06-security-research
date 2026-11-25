#!/bin/sh
# xmir SSH persistence —— 幂等，由持久 crontab 每分钟调用。
# 目标：Xiaomi RC06 / 固件 1.1.38（其他机型请自行核对路径）。
#
# 用法：
#   1) 把本脚本放到 /data/xmir_ssh_restore.sh 并 chmod +x
#   2) 传入 md5crypt hash 作为第一个参数（下方 HASH 默认从环境变量 SSH_ROOT_HASH 取）：
#        SSH_ROOT_HASH='<openssl passwd -1 的输出>' /data/xmir_ssh_restore.sh
#      或直接在部署时把 HASH 变量改成你的 hash（注意 hash 不是明文密码）。
#   3) 加持久 cron 并重启 crond：
#        echo '* * * * * /data/xmir_ssh_restore.sh >/dev/null 2>&1' >> /etc/crontabs/root
#        /etc/init.d/cron restart
#
# 关键约束（踩过的坑）：
#   - /etc 是 ramfs，重启丢失；/data 和 /etc/crontabs 是 ubifs 持久分区。
#   - BusyBox 1.25.1 crond 不支持 @reboot，用每分钟幂等脚本代替。
#   - 启动 dropbear 不要加 -F &：后台作业会随 cron 会话 SIGHUP 被杀；让其自行 daemonize。
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

LOG=/data/xmir_ssh_restore.log
# 支持三种来源：命令行参数 > 环境变量 > 下面留空自行填写
HASH="${1:-${SSH_ROOT_HASH:-}}"
KEY_DURABLE=/data/xmir_dropbear_rsa_host_key
KEY_LIVE=/etc/dropbear/dropbear_rsa_host_key

if [ -z "$HASH" ]; then
    echo "$(date '+%m-%d %H:%M:%S') ERROR: 未提供 root 密码 hash（参数或 SSH_ROOT_HASH）" >> "$LOG"
    exit 1
fi

log() { echo "$(date '+%m-%d %H:%M:%S') $*" >> "$LOG"; }

# 1) nvram 标记（跨重启持久）
if [ "$(nvram get ssh_en 2>/dev/null)" != "1" ]; then
    nvram set ssh_en=1 >/dev/null 2>&1 && nvram commit >/dev/null 2>&1
    log "nvram ssh_en=1 set"
fi

# 2) host key 在 /etc（ramfs，重启丢失）——在 /data 保留持久副本
mkdir -p /etc/dropbear
if [ ! -s "$KEY_LIVE" ]; then
    if [ -s "$KEY_DURABLE" ]; then
        cp "$KEY_DURABLE" "$KEY_LIVE" 2>/dev/null
    else
        /usr/bin/dropbearkey -t rsa -f "$KEY_LIVE" >/dev/null 2>&1
        [ -s "$KEY_LIVE" ] && cp "$KEY_LIVE" "$KEY_DURABLE" 2>/dev/null
    fi
    [ -s "$KEY_LIVE" ] && log "host key restored"
fi
chmod 600 "$KEY_LIVE" 2>/dev/null

# 3) /etc/init.d/dropbear 在 ramfs ——每次开机重新打 release 通道补丁
if grep -q '"release"' /etc/init.d/dropbear 2>/dev/null; then
    sed -i 's/ -o "$channel" = "release"//g' /etc/init.d/dropbear 2>/dev/null
    log "dropbear init release-gate patched"
fi

# 4) 校验 root 密码 hash（shadow 软链到 /data/etc/shadow，持久）
SHADOW=$(readlink -f /etc/shadow 2>/dev/null || echo /etc/shadow)
if ! grep -q "^root:$HASH:" "$SHADOW" 2>/dev/null; then
    { grep -v '^root:' "$SHADOW"; echo "root:$HASH:19000:0:99999:7:::"; } > /tmp/_xmir_sh && mv /tmp/_xmir_sh "$SHADOW"
    log "root password hash restored"
fi

# 5) 22 端口没监听就启动（daemonize，不用 -F &）
if ! netstat -tlnp 2>/dev/null | grep -q ':22 '; then
    /usr/sbin/dropbear -p 22 -K 300 -T 3 >/dev/null 2>&1
    sleep 1
    if netstat -tlnp 2>/dev/null | grep -q ':22 '; then
        log "dropbear started (daemonized)"
    else
        log "dropbear start FAILED"
    fi
fi
