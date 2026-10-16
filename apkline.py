#!/usr/bin/env python3
"""apkline.py —— App 分析流水线（抓包 / 静态 / 原生hook / 重打包 / 报告）

一条命令跑完 App 类项目的取证：
  python apkline.py static  --apk y.apk          # 静态分析（纯Python，无依赖）
  python apkline.py proxy   on|off               # 起/停抓包链路（Kali mitmproxy + 手机代理）
  python apkline.py capture --pkg <包名> --seconds 40
  python apkline.py repack  --apk y.apk          # 注入 frida-gadget + 重签名（Kali objection）
  python apkline.py hook    --seconds 45         # 原生层动态 hook（TLS/文件/连接/命令）
  python apkline.py report  --apk y.apk          # 汇总成 Markdown 报告
  python apkline.py all     --apk y.apk --pkg <包名>

设计约束（本项目实测得出）：
  · vivo ROM 拦截一切自动安装 → 装 APK 必须人工点"安装"（脚本只负责把文件推上去并发起）
  · frida Java 桥在 Android 6(API23) 不可用 → hook 只做原生层
  · 抓包日志含二进制 → 解析必须用 grep -a / 二进制安全读取
  · Kali 无 sudo → 工具走 ~/.local/bin 软链，不依赖 apt
  · 境外资源（apktool 等）必须开 WARP，用完关
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import time
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

CFG = {
    "adb": r"D:\dsh-vm\platform-tools\adb.exe",
    "vbox": r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    "kali_vm": "kali-linux-2026.2-virtualbox-amd64",
    "kali_user": "kali",
    "kali_pass": "kali",
    "phone": "192.168.31.66:5555",
    "proxy_host": "192.168.31.194",
    # 2026-10-12 21:52 改：宿主 8080 被 Steam(steamwebhelper) 占用，VBox 转发
    # mitm8080 原先 hostIP 为空（绑 0.0.0.0，对局域网敞开）。现改为 127.0.0.1:18080 -> guest:8080。
    # 注意：guest 内 mitmdump 仍监听 8080（不改 Kali 侧），只改宿主侧映射端口。
    "proxy_port": 18080,
    "host_only_ip": "192.168.56.1",
    "host_only_port": 27042,
    "kali_tools": "/home/kali/tools",
    "kali_buildtools": "/home/kali/tools/bt/android-14",
    "kali_mitm_log": "/tmp/mitm.log",
    "outdir": str(pathlib.Path(__file__).parent / "appline-out"),
    "frida": r"C:\Users\Administrator\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Scripts\frida.exe",
}
OUT = pathlib.Path(CFG["outdir"])


# ---------------- 基础执行 ----------------
def sh(cmd, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("encoding", "utf-8")
    kw.setdefault("errors", "replace")
    r = subprocess.run(cmd, **kw)
    return r.returncode, (r.stdout or ""), (r.stderr or "")


def log(*a):
    print(*a, flush=True)


def adb(*args):
    return sh([CFG["adb"], "-s", CFG["phone"]] + list(args))


def ga(script_text, name=None):
    """把脚本拷进 Kali 并以 kali 用户执行。"""
    name = name or f"_apkline_{int(time.time())}.sh"
    local = OUT / name
    OUT.mkdir(parents=True, exist_ok=True)
    local.write_text(script_text, encoding="utf-8", newline="\n")
    sh([CFG["vbox"], "guestcontrol", CFG["kali_vm"], "copyto", str(local), f"/home/kali/{name}",
        "--username", CFG["kali_user"], "--password", CFG["kali_pass"]])
    return sh([CFG["vbox"], "guestcontrol", CFG["kali_vm"], "run",
               "--username", CFG["kali_user"], "--password", CFG["kali_pass"],
               "--exe", "/bin/bash", "--", f"/home/kali/{name}"])


GA_ENV = f'export PATH=$PATH:~/.local/bin:{CFG["kali_buildtools"]}:{CFG["kali_tools"]}/platform-tools\n'


# ---------------- 1. 静态分析（纯 Python，无外部依赖）----------------
INTERESTING = [
    (r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,}", "URL"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b", "IP"),
    (r"android\.permission\.[A-Z_]+", "PERM"),
    (r"(?i)\b(api[_-]?key|secret|app[_-]?secret|access[_-]?key|token|password|passwd|signature|hmac|md5|sha1|sha256|aes|rsa)\b", "SECRET_KW"),
    (r"(?i)\b(imei|imsi|android_?id|oaid|idfa|mac_?address|device_?id|getDeviceId|getSubscriberId)\b", "DEVICE"),
    (r"[A-Za-z0-9+/]{32,}={0,2}", "B64_OR_HASH"),
    (r"[\u4e00-\u9fff]{2,}", "CN"),
]


def static_apk(apk: str) -> dict:
    p = pathlib.Path(apk)
    res = {"apk": str(p), "size": p.stat().st_size, "sha256": None, "dex": [], "hits": {}}
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    res["sha256"] = h.hexdigest()

    with zipfile.ZipFile(p) as z:
        names = z.namelist()
        res["entries"] = len(names)
        res["native_libs"] = sorted({n for n in names if n.startswith("lib/")})[:40]
        res["dex"] = [n for n in names if re.match(r"classes\d*\.dex$", n)]
        blob = b""
        for n in res["dex"]:
            blob += z.read(n)
        if "AndroidManifest.xml" in names:
            blob += z.read("AndroidManifest.xml")

    text = blob.decode("latin-1", "ignore")
    strings = set(re.findall(r"[ -~]{6,200}", text))
    strings |= set(re.findall(r"(?:[\u4e00-\u9fff]{2,})+", blob.decode("utf-8", "ignore")))
    for pat, tag in INTERESTING:
        found = set()
        for s in strings:
            for m in re.findall(pat, s):
                if isinstance(m, tuple):
                    m = m[0]
                found.add(m if len(m) < 200 else m[:200])
        if found:
            res["hits"][tag] = sorted(found)[:60]
    res["strings_total"] = len(strings)
    return res


# ---------------- 2. 抓包链路 ----------------
def proxy_on():
    log("[proxy] 启动 mitmproxy（Kali）")
    ga(GA_ENV + "pkill -f mitmdump; sleep 1; "
       "setsid nohup mitmdump -p 8080 --set confdir=/home/kali/.mitmproxy --set flow_detail=2 "
       "</dev/null > /tmp/mitm.log 2>&1 & disown; sleep 5; "
       "echo MITM_LISTEN=$(ss -tln | grep -c ':8080')", "_apkline_mitm.sh")
    log("[proxy] 主机 127.0.0.1:18080 → Kali 8080 端口转发")
    sh([CFG["vbox"], "controlvm", CFG["kali_vm"], "natpf1", "mitm18080,tcp,127.0.0.1,18080,,8080"])
    log("[proxy] 手机侧设置代理")
    adb("shell", f"settings put global http_proxy {CFG['proxy_host']}:{CFG['proxy_port']}")
    rc, o, _ = adb("shell", "settings get global http_proxy")
    log("  →", o.strip())
    log("[proxy] 提醒：需确保手机上已安装 mitmproxy CA（设置→安全→从存储安装）")


def proxy_off():
    log("[proxy] 关闭手机代理")
    adb("shell", "settings put global http_proxy :0")
    log("[proxy] 停 mitmproxy")
    ga(GA_ENV + "pkill -f mitmdump; echo stopped", "_apkline_mitm_stop.sh")


def capture(pkg: str, seconds: int = 40) -> dict:
    ga(GA_ENV + f": > {CFG['kali_mitm_log']}; echo cleared", "_apkline_clear.sh")
    log(f"[capture] 启动 App {pkg}")
    log("  ", adb("shell", f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1")[1].strip()[:120])
    time.sleep(seconds)
    log("[capture] 解析日志")
    script = GA_ENV + f'''
L={CFG['kali_mitm_log']}
echo "LINES=$(wc -l < $L)"
echo "==DOMAINS=="
grep -aoE 'https?://[a-zA-Z0-9._-]+' $L | sed 's|https\\?://||' | sort | uniq -c | sort -rn | head -30
echo "==REQS=="
grep -aE '^[0-9.]+:[0-9]+: (GET|POST|PUT|DELETE|CONNECT)' $L | awk '{{print $2, $3, $4}}' | sort -u | head -40
echo "==AUTH=="
grep -aiE '^ +(authorization|token|x-token|x-auth|cookie|sign|signature|x-sign)' $L | sed 's/^ *//' | sort -u | head -20
echo "==BODY_KEYS=="
grep -aoiE '"(password|passwd|pwd|token|imei|imsi|idcard|phone|mobile|bankcard|oaid|mac)"[: ]' $L | sort | uniq -c | sort -rn | head -15
echo "==PLAINTEXT_HTTP=="
grep -aoE 'GET http://[^ ]+' $L | sort -u | head -10
echo "CAPTURE-DONE"
'''
    rc, out, err = ga(script, "_apkline_cap.sh")
    data = {"pkg": pkg, "raw": out, "lines": 0, "domains": [], "requests": [], "auth": [], "body_keys": [], "plaintext_http": []}
    section = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("LINES="):
            data["lines"] = int(re.sub(r"\D", "", s) or 0)
        elif s.startswith("==") and s.endswith("=="):
            section = s.strip("=").lower()
        elif s == "CAPTURE-DONE":
            section = None
        elif section and s:
            data[{"domains": "domains", "reqs": "requests", "auth": "auth",
                  "body_keys": "body_keys", "plaintext_http": "plaintext_http"}.get(section, section)].append(s)
    return data


# ---------------- 3. 重打包注入 gadget ----------------
def repack(apk: str, arch: str = "armeabi-v7a") -> dict:
    local = OUT / pathlib.Path(apk).name
    OUT.mkdir(parents=True, exist_ok=True)
    if pathlib.Path(apk).resolve() != local.resolve():
        local.write_bytes(pathlib.Path(apk).read_bytes())
    sh([CFG["vbox"], "guestcontrol", CFG["kali_vm"], "copyto", str(local), "/home/kali/apks/_in.apk",
        "--username", CFG["kali_user"], "--password", CFG["kali_pass"]])
    script = GA_ENV + f'''
cd /home/kali/apks
rm -f /home/kali/apks/*.objection.apk
timeout 1500 objection patchapk -s _in.apk -a {arch} -D --ignore-nativelibs 2>&1 | tail -8
P=$(ls -1 /home/kali/apks/*.objection.apk 2>/dev/null | head -1)
echo "PRODUCT=$P"
[ -n "$P" ] && echo "SIZE=$(stat -c%s $P)" && unzip -l "$P" | grep -i frida | head -3
[ -n "$P" ] && apksigner verify --print-certs "$P" 2>/dev/null | grep -i 'Signer #1 certificate DN' | head -1
echo REPACK-DONE
'''
    rc, out, _ = ga(script, "_apkline_repack.sh")
    prod = None
    for line in out.splitlines():
        if line.startswith("PRODUCT=") and line.strip() != "PRODUCT=":
            prod = line.split("=", 1)[1].strip()
    res = {"output": out, "kali_path": prod, "local_path": None}
    if prod:
        dest = OUT / ("patched_" + pathlib.Path(apk).name)
        sh([CFG["vbox"], "guestcontrol", CFG["kali_vm"], "copyfrom", prod, str(dest),
            "--username", CFG["kali_user"], "--password", CFG["kali_pass"]])
        res["local_path"] = str(dest)
    return res


def install_patched(local_apk: str) -> str:
    """推到手机并发起安装（vivo 需人工点"安装"）。"""
    adb("push", local_apk, "/data/local/tmp/_patched.apk")
    log("[install] 请现在在手机上点【安装】…")
    rc, out, err = adb("shell", "pm install -r /data/local/tmp/_patched.apk")
    return out.strip()


# ---------------- 4. 原生层 hook ----------------
NATIVE_JS = r'''
function hx(p,n){ try{ var v=new Uint8Array(Memory.readByteArray(p,n)); var s=''; for(var i=0;i<v.length;i++){ var h=v[i].toString(16); s+=(h.length==1?'0':'')+h; } return s; }catch(e){ return 'ERR'; } }
function L(t,m){ console.log('['+t+'] '+m); }
function fx(n){ try{ if(Module.findGlobalExportByName) return Module.findGlobalExportByName(n); }catch(e){} try{ if(Module.getGlobalExportByName) return Module.getGlobalExportByName(n); }catch(e){} try{ return Module.findExportByName(null,n); }catch(e){} return null; }
['SSL_write','SSL_read'].forEach(function(fn){ var a=fx(fn); if(!a){L('TLS',fn+' missing');return;}
  Interceptor.attach(a,{onEnter:function(x){try{this.b=x[1];this.l=x[2].toInt32();}catch(e){}},
   onLeave:function(r){try{var n=r.toInt32(); if(n>0&&this.l>0) L('TLS',fn+' len='+n+' hex='+hx(this.b,Math.min(n,48)));}catch(e){}}});
  L('HOOK','TLS '+fn); });
var op=fx('open'); if(op){ Interceptor.attach(op,{onEnter:function(a){try{var s=a[0].readCString(); if(s&&!/^\/dev|^\/proc|^\/system|^\/apex|^\/vendor/.test(s)) L('OPEN',s);}catch(e){}}}); L('HOOK','open'); }
var cn=fx('connect'); if(cn){ Interceptor.attach(cn,{onEnter:function(a){try{var sa=a[1]; if(sa.readU16()===2){var port=(sa.add(2).readU8()<<8)|sa.add(3).readU8(); var ip=[0,1,2,3].map(function(i){return sa.add(4+i).readU8();}).join('.'); if(ip.indexOf('127.')!==0) L('CONNECT',ip+':'+port);}}catch(e){}}}); L('HOOK','connect'); }
['system','execve'].forEach(function(fn){ var a=fx(fn); if(a){ Interceptor.attach(a,{onEnter:function(x){try{L('EXEC',fn+': '+x[0].readCString());}catch(e){}}}); L('HOOK',fn); } });
L('INFO','modules='+Process.enumerateModules().length);
L('READY','native hooks installed');
'''


def hook(seconds: int = 45, app: str = "Gadget") -> dict:
    js = OUT / "_native.js"
    OUT.mkdir(parents=True, exist_ok=True)
    js.write_text(NATIVE_JS, encoding="utf-8")
    adb("forward", f"tcp:{CFG['host_only_port']}", f"tcp:{CFG['host_only_port']}")
    cmd = [CFG["frida"], "-H", f"127.0.0.1:{CFG['host_only_port']}", app, "-l", str(js),
           "--runtime=v8", "-q", "-t", str(seconds)]
    rc, out, err = sh(cmd, timeout=seconds + 60)
    events = [l for l in out.splitlines() if l.startswith("[")]
    return {"events": events, "raw": out, "ok": "READY" in out}


# ---------------- 5. 报告 ----------------
def report(apk: str = None, cap: dict = None, sta: dict = None, rep: dict = None) -> str:
    OUT.mkdir(parents=True, exist_ok=True)
    md = ["# App 分析报告（apkline 自动生成）", ""]
    if apk:
        md += [f"- **样本**：`{apk}`", ""]
    if sta:
        md += ["## 一、静态分析", "",
               f"- 大小：{sta['size']:,} 字节 ｜ sha256：`{sta['sha256']}`",
               f"- 条目：{sta['entries']} ｜ dex：{', '.join(sta['dex'])} ｜ 提取字符串：{sta['strings_total']}", ""]
        for tag, vals in sta.get("hits", {}).items():
            md += [f"### {tag}（{len(vals)}）", "```"] + vals[:25] + ["```", ""]
    if cap:
        md += ["## 二、抓包结果", "",
               f"- 日志行数：{cap['lines']}", "", "### 域名", "```"] + cap["domains"][:25] + ["```", ""]
        if cap["requests"]:
            md += ["### 请求（方法 主机 路径）", "```"] + cap["requests"][:30] + ["```", ""]
        if cap["auth"]:
            md += ["### 鉴权/标识头", "```"] + cap["auth"][:20] + ["```", ""]
        if cap["body_keys"]:
            md += ["### 请求体敏感字段", "```"] + cap["body_keys"][:20] + ["```", ""]
        if cap["plaintext_http"]:
            md += ["### ⚠️ 明文 HTTP 请求（中间人投毒面）", "```"] + cap["plaintext_http"][:15] + ["```", ""]
    if rep:
        md += ["## 三、重打包（frida-gadget）", "", "```", rep["output"][-1200:], "```", ""]
    md += ["## 四、待人工完成", "",
           "- [ ] 手机上点【安装】装重打包版（vivo ROM 拦截自动安装）",
           "- [ ] 操作 App 1 分钟以产生行为（hook 才能抓到事件）",
           "- [ ] Java 层分析需 Android 7+ 设备（frida 17 的 Java 桥不支持 API 23）", ""]
    p = OUT / "app-report.md"
    p.write_text("\n".join(md), encoding="utf-8")
    return str(p)


# ---------------- CLI ----------------
def main():
    ap = argparse.ArgumentParser(description="App 分析流水线")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("static"); p.add_argument("--apk", required=True)
    p = sub.add_parser("proxy"); p.add_argument("action", choices=["on", "off"])
    p = sub.add_parser("capture"); p.add_argument("--pkg", required=True); p.add_argument("--seconds", type=int, default=40)
    p = sub.add_parser("repack"); p.add_argument("--apk", required=True); p.add_argument("--arch", default="armeabi-v7a")
    p = sub.add_parser("install"); p.add_argument("--apk", required=True)
    p = sub.add_parser("hook"); p.add_argument("--seconds", type=int, default=45); p.add_argument("--app", default="Gadget")
    p = sub.add_parser("report"); p.add_argument("--apk"); p.add_argument("--cap", help="capture JSON"); p.add_argument("--sta", help="static JSON")
    p = sub.add_parser("all"); p.add_argument("--apk", required=True); p.add_argument("--pkg", required=True)
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    if a.cmd == "static":
        res = static_apk(a.apk)
        (OUT / "static.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
        log(f"[static] 条目={res['entries']} dex={res['dex']} 字符串={res['strings_total']}")
        for tag, vals in res["hits"].items():
            log(f"  {tag}: {len(vals)} 条，例：{vals[:3]}")
        log("  →", OUT / "static.json")
    elif a.cmd == "proxy":
        proxy_on() if a.action == "on" else proxy_off()
    elif a.cmd == "capture":
        res = capture(a.pkg, a.seconds)
        (OUT / "capture.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
        log(f"[capture] 行数={res['lines']} 域名={len(res['domains'])} 请求={len(res['requests'])}")
        for d in res["domains"][:10]:
            log("   ", d)
        if res["plaintext_http"]:
            log("  ⚠️ 明文 HTTP：")
            for x in res["plaintext_http"][:5]:
                log("   ", x)
        log("  →", OUT / "capture.json")
    elif a.cmd == "repack":
        res = repack(a.apk, a.arch)
        (OUT / "repack.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
        log(f"[repack] 产物: {res['local_path']}")
    elif a.cmd == "install":
        log(install_patched(a.apk))
    elif a.cmd == "hook":
        res = hook(a.seconds, a.app)
        log(f"[hook] ok={res['ok']} 事件={len(res['events'])}")
        for e in res["events"][:30]:
            log("   ", e)
    elif a.cmd == "report":
        def load(p):
            return json.loads(pathlib.Path(p).read_text(encoding="utf-8")) if p and pathlib.Path(p).exists() else None
        log("报告 →", report(a.apk, load(a.cap), load(a.sta), load(OUT / "repack.json")))
    elif a.cmd == "all":
        log("=== 1/4 静态分析 ===")
        sta = static_apk(a.apk)
        (OUT / "static.json").write_text(json.dumps(sta, ensure_ascii=False, indent=1), encoding="utf-8")
        log("=== 2/4 开抓包链路 ===")
        proxy_on()
        log("=== 3/4 抓包 ===")
        cap = capture(a.pkg, 40)
        (OUT / "capture.json").write_text(json.dumps(cap, ensure_ascii=False, indent=1), encoding="utf-8")
        log("=== 4/4 重打包 ===")
        rep = repack(a.apk)
        (OUT / "repack.json").write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding="utf-8")
        log("报告 →", report(a.apk, cap, sta, rep))
        proxy_off()


if __name__ == "__main__":
    main()
