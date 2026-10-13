#!/usr/bin/env python3
"""apkline.py 鈥斺€?App 鍒嗘瀽娴佹按绾匡紙鎶撳寘 / 闈欐€?/ 鍘熺敓hook / 閲嶆墦鍖?/ 鎶ュ憡锛?
涓€鏉″懡浠よ窇瀹?App 绫婚」鐩殑鍙栬瘉锛?  python apkline.py static  --apk y.apk          # 闈欐€佸垎鏋愶紙绾疨ython锛屾棤渚濊禆锛?  python apkline.py proxy   on|off               # 璧?鍋滄姄鍖呴摼璺紙Kali mitmproxy + 鎵嬫満浠ｇ悊锛?  python apkline.py capture --pkg <鍖呭悕> --seconds 40
  python apkline.py repack  --apk y.apk          # 娉ㄥ叆 frida-gadget + 閲嶇鍚嶏紙Kali objection锛?  python apkline.py hook    --seconds 45         # 鍘熺敓灞傚姩鎬?hook锛圱LS/鏂囦欢/杩炴帴/鍛戒护锛?  python apkline.py report  --apk y.apk          # 姹囨€绘垚 Markdown 鎶ュ憡
  python apkline.py all     --apk y.apk --pkg <鍖呭悕>

璁捐绾︽潫锛堟湰椤圭洰瀹炴祴寰楀嚭锛夛細
  路 vivo ROM 鎷︽埅涓€鍒囪嚜鍔ㄥ畨瑁?鈫?瑁?APK 蹇呴』浜哄伐鐐?瀹夎"锛堣剼鏈彧璐熻矗鎶婃枃浠舵帹涓婂幓骞跺彂璧凤級
  路 frida Java 妗ュ湪 Android 6(API23) 涓嶅彲鐢?鈫?hook 鍙仛鍘熺敓灞?  路 鎶撳寘鏃ュ織鍚簩杩涘埗 鈫?瑙ｆ瀽蹇呴』鐢?grep -a / 浜岃繘鍒跺畨鍏ㄨ鍙?  路 Kali 鏃?sudo 鈫?宸ュ叿璧?~/.local/bin 杞摼锛屼笉渚濊禆 apt
  路 澧冨璧勬簮锛坅pktool 绛夛級蹇呴』寮€ WARP锛岀敤瀹屽叧
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
    "phone": "192.168.x.x:5555",
    "proxy_host": "192.168.x.x",
    # 2026-10-12 21:52 鏀癸細瀹夸富 8080 琚?Steam(steamwebhelper) 鍗犵敤锛孷Box 杞彂
    # mitm8080 鍘熷厛 hostIP 涓虹┖锛堢粦 0.0.0.0锛屽灞€鍩熺綉鏁炲紑锛夈€傜幇鏀逛负 127.0.0.1:18080 -> guest:8080銆?    # 娉ㄦ剰锛歡uest 鍐?mitmdump 浠嶇洃鍚?8080锛堜笉鏀?Kali 渚э級锛屽彧鏀瑰涓讳晶鏄犲皠绔彛銆?    "proxy_port": 18080,
    "host_only_ip": "192.168.56.1",
    "host_only_port": 27042,
    "kali_tools": "/home/kali/tools",
    "kali_buildtools": "/home/kali/tools/bt/android-14",
    "kali_mitm_log": "/tmp/mitm.log",
    "outdir": str(pathlib.Path(__file__).parent / "appline-out"),
    "frida": r"frida",
}
OUT = pathlib.Path(CFG["outdir"])


# ---------------- 鍩虹鎵ц ----------------
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
    """鎶婅剼鏈嫹杩?Kali 骞朵互 kali 鐢ㄦ埛鎵ц銆?""
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


# ---------------- 1. 闈欐€佸垎鏋愶紙绾?Python锛屾棤澶栭儴渚濊禆锛?---------------
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


# ---------------- 2. 鎶撳寘閾捐矾 ----------------
def proxy_on():
    log("[proxy] 鍚姩 mitmproxy锛圞ali锛?)
    ga(GA_ENV + "pkill -f mitmdump; sleep 1; "
       "setsid nohup mitmdump -p 8080 --set confdir=/home/kali/.mitmproxy --set flow_detail=2 "
       "</dev/null > /tmp/mitm.log 2>&1 & disown; sleep 5; "
       "echo MITM_LISTEN=$(ss -tln | grep -c ':8080')", "_apkline_mitm.sh")
    log("[proxy] 涓绘満 127.0.0.1:18080 鈫?Kali 8080 绔彛杞彂")
    sh([CFG["vbox"], "controlvm", CFG["kali_vm"], "natpf1", "mitm18080,tcp,127.0.0.1,18080,,8080"])
    log("[proxy] 鎵嬫満渚ц缃唬鐞?)
    adb("shell", f"settings put global http_proxy {CFG['proxy_host']}:{CFG['proxy_port']}")
    rc, o, _ = adb("shell", "settings get global http_proxy")
    log("  鈫?, o.strip())
    log("[proxy] 鎻愰啋锛氶渶纭繚鎵嬫満涓婂凡瀹夎 mitmproxy CA锛堣缃啋瀹夊叏鈫掍粠瀛樺偍瀹夎锛?)


def proxy_off():
    log("[proxy] 鍏抽棴鎵嬫満浠ｇ悊")
    adb("shell", "settings put global http_proxy :0")
    log("[proxy] 鍋?mitmproxy")
    ga(GA_ENV + "pkill -f mitmdump; echo stopped", "_apkline_mitm_stop.sh")


def capture(pkg: str, seconds: int = 40) -> dict:
    ga(GA_ENV + f": > {CFG['kali_mitm_log']}; echo cleared", "_apkline_clear.sh")
    log(f"[capture] 鍚姩 App {pkg}")
    log("  ", adb("shell", f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1")[1].strip()[:120])
    time.sleep(seconds)
    log("[capture] 瑙ｆ瀽鏃ュ織")
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


# ---------------- 3. 閲嶆墦鍖呮敞鍏?gadget ----------------
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
    """鎺ㄥ埌鎵嬫満骞跺彂璧峰畨瑁咃紙vivo 闇€浜哄伐鐐?瀹夎"锛夈€?""
    adb("push", local_apk, "/data/local/tmp/_patched.apk")
    log("[install] 璇风幇鍦ㄥ湪鎵嬫満涓婄偣銆愬畨瑁呫€戔€?)
    rc, out, err = adb("shell", "pm install -r /data/local/tmp/_patched.apk")
    return out.strip()


# ---------------- 4. 鍘熺敓灞?hook ----------------
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


# ---------------- 5. 鎶ュ憡 ----------------
def report(apk: str = None, cap: dict = None, sta: dict = None, rep: dict = None) -> str:
    OUT.mkdir(parents=True, exist_ok=True)
    md = ["# App 鍒嗘瀽鎶ュ憡锛坅pkline 鑷姩鐢熸垚锛?, ""]
    if apk:
        md += [f"- **鏍锋湰**锛歚{apk}`", ""]
    if sta:
        md += ["## 涓€銆侀潤鎬佸垎鏋?, "",
               f"- 澶у皬锛歿sta['size']:,} 瀛楄妭 锝?sha256锛歚{sta['sha256']}`",
               f"- 鏉＄洰锛歿sta['entries']} 锝?dex锛歿', '.join(sta['dex'])} 锝?鎻愬彇瀛楃涓诧細{sta['strings_total']}", ""]
        for tag, vals in sta.get("hits", {}).items():
            md += [f"### {tag}锛坽len(vals)}锛?, "```"] + vals[:25] + ["```", ""]
    if cap:
        md += ["## 浜屻€佹姄鍖呯粨鏋?, "",
               f"- 鏃ュ織琛屾暟锛歿cap['lines']}", "", "### 鍩熷悕", "```"] + cap["domains"][:25] + ["```", ""]
        if cap["requests"]:
            md += ["### 璇锋眰锛堟柟娉?涓绘満 璺緞锛?, "```"] + cap["requests"][:30] + ["```", ""]
        if cap["auth"]:
            md += ["### 閴存潈/鏍囪瘑澶?, "```"] + cap["auth"][:20] + ["```", ""]
        if cap["body_keys"]:
            md += ["### 璇锋眰浣撴晱鎰熷瓧娈?, "```"] + cap["body_keys"][:20] + ["```", ""]
        if cap["plaintext_http"]:
            md += ["### 鈿狅笍 鏄庢枃 HTTP 璇锋眰锛堜腑闂翠汉鎶曟瘨闈級", "```"] + cap["plaintext_http"][:15] + ["```", ""]
    if rep:
        md += ["## 涓夈€侀噸鎵撳寘锛坒rida-gadget锛?, "", "```", rep["output"][-1200:], "```", ""]
    md += ["## 鍥涖€佸緟浜哄伐瀹屾垚", "",
           "- [ ] 鎵嬫満涓婄偣銆愬畨瑁呫€戣閲嶆墦鍖呯増锛坴ivo ROM 鎷︽埅鑷姩瀹夎锛?,
           "- [ ] 鎿嶄綔 App 1 鍒嗛挓浠ヤ骇鐢熻涓猴紙hook 鎵嶈兘鎶撳埌浜嬩欢锛?,
           "- [ ] Java 灞傚垎鏋愰渶 Android 7+ 璁惧锛坒rida 17 鐨?Java 妗ヤ笉鏀寔 API 23锛?, ""]
    p = OUT / "app-report.md"
    p.write_text("\n".join(md), encoding="utf-8")
    return str(p)


# ---------------- CLI ----------------
def main():
    ap = argparse.ArgumentParser(description="App 鍒嗘瀽娴佹按绾?)
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
        log(f"[static] 鏉＄洰={res['entries']} dex={res['dex']} 瀛楃涓?{res['strings_total']}")
        for tag, vals in res["hits"].items():
            log(f"  {tag}: {len(vals)} 鏉★紝渚嬶細{vals[:3]}")
        log("  鈫?, OUT / "static.json")
    elif a.cmd == "proxy":
        proxy_on() if a.action == "on" else proxy_off()
    elif a.cmd == "capture":
        res = capture(a.pkg, a.seconds)
        (OUT / "capture.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
        log(f"[capture] 琛屾暟={res['lines']} 鍩熷悕={len(res['domains'])} 璇锋眰={len(res['requests'])}")
        for d in res["domains"][:10]:
            log("   ", d)
        if res["plaintext_http"]:
            log("  鈿狅笍 鏄庢枃 HTTP锛?)
            for x in res["plaintext_http"][:5]:
                log("   ", x)
        log("  鈫?, OUT / "capture.json")
    elif a.cmd == "repack":
        res = repack(a.apk, a.arch)
        (OUT / "repack.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
        log(f"[repack] 浜х墿: {res['local_path']}")
    elif a.cmd == "install":
        log(install_patched(a.apk))
    elif a.cmd == "hook":
        res = hook(a.seconds, a.app)
        log(f"[hook] ok={res['ok']} 浜嬩欢={len(res['events'])}")
        for e in res["events"][:30]:
            log("   ", e)
    elif a.cmd == "report":
        def load(p):
            return json.loads(pathlib.Path(p).read_text(encoding="utf-8")) if p and pathlib.Path(p).exists() else None
        log("鎶ュ憡 鈫?, report(a.apk, load(a.cap), load(a.sta), load(OUT / "repack.json")))
    elif a.cmd == "all":
        log("=== 1/4 闈欐€佸垎鏋?===")
        sta = static_apk(a.apk)
        (OUT / "static.json").write_text(json.dumps(sta, ensure_ascii=False, indent=1), encoding="utf-8")
        log("=== 2/4 寮€鎶撳寘閾捐矾 ===")
        proxy_on()
        log("=== 3/4 鎶撳寘 ===")
        cap = capture(a.pkg, 40)
        (OUT / "capture.json").write_text(json.dumps(cap, ensure_ascii=False, indent=1), encoding="utf-8")
        log("=== 4/4 閲嶆墦鍖?===")
        rep = repack(a.apk)
        (OUT / "repack.json").write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding="utf-8")
        log("鎶ュ憡 鈫?, report(a.apk, cap, sta, rep))
        proxy_off()


if __name__ == "__main__":
    main()

