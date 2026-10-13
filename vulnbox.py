#!/usr/bin/env python3
"""vulnbox.py —— 漏洞盒子三件套本地化（ARL式资产测绘 / CVSS定级 / 查重）

背景：平台提供的三个工具（ARL资产工具、/cvss 评级计算、漏洞情报查重）都要登录才能用，
      我把它们的**核心能力**在本地实现，这样任何项目都能离线跑，且不必登录。

用法：
  python vulnbox.py scan  <域名或IP> [--ports 常见|全]        # ① ARL式资产测绘
  python vulnbox.py rate  AV:AC:PR:UI:S:C:I:A                 # ② CVSS 3.1 定级
    # 例：python vulnbox.py rate N:L:N:N:U:L:L:L   （一堆常见低危）
    # 例：python vulnbox.py rate N:L:N:N:U:H:H:H   （典型严重）
  python vulnbox.py rate --interactive                        # 交互式逐项选择
  python vulnbox.py dedup --target <host> --type <类型> --path <路径> [--param <参数>]
  python vulnbox.py seen                                      # 看本地查重库
"""
import argparse
import concurrent.futures as cf
import hashlib
import json
import pathlib
import re
import socket
import ssl
import sys
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

DIR = pathlib.Path(__file__).parent
SEEN = DIR / "dedup-seen.jsonl"

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5900,
                5985, 5986, 6379, 7001, 8000, 8080, 8081, 8443, 8888, 9000, 9090,
                9200, 11211, 27017]

# ---------------- ① ARL 式资产测绘 ----------------
def resolve(host: str):
    out = {"a": [], "aaaa": [], "cname": []}
    try:
        for fam, key in ((socket.AF_INET, "a"), (socket.AF_INET6, "aaaa")):
            try:
                for info in socket.getaddrinfo(host, None, fam):
                    ip = info[4][0]
                    if ip not in out[key]:
                        out[key].append(ip)
            except socket.gaierror:
                pass
    except Exception:  # noqa: BLE001
        pass
    return out


def crtsh_subdomains(domain: str, timeout=25):
    """用证书透明度日志(crt.sh)枚举子域——公开、免登录、无需 API key。"""
    subs = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
        for item in data:
            for name in str(item.get("name_value", "")).split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and re.match(r"^[a-z0-9._-]+$", name):
                    subs.add(name)
    except Exception as e:  # noqa: BLE001
        print(f"  [warn] crt.sh 查询失败：{e}")
    return sorted(subs)


def probe_port(host: str, port: int, timeout=1.5):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        banner = ""
        try:
            s.settimeout(1.2)
            banner = s.recv(128).decode("latin-1", "ignore").strip()
        except Exception:  # noqa: BLE001
            pass
        return port, True, banner
    except Exception:  # noqa: BLE001
        return port, False, ""
    finally:
        s.close()


def http_fingerprint(host: str, port: int, timeout=6):
    scheme = "https" if port in (443, 8443) else "http"
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(f"{scheme}://{host}:{port}/",
                                 headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(4096).decode("utf-8", "ignore")
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            return {"port": port, "status": r.status,
                    "server": r.headers.get("Server", ""),
                    "powered": r.headers.get("X-Powered-By", ""),
                    "title": title}
    except Exception as e:  # noqa: BLE001
        return {"port": port, "error": str(e)[:60]}


def cmd_scan(a):
    target = a.target.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    print(f"===== ARL式资产测绘：{target} =====")
    print("[1/4] DNS 解析")
    res = resolve(target)
    print(f"  A    : {', '.join(res['a']) or '-'}")
    print(f"  AAAA : {', '.join(res['aaaa']) or '-'}")
    ip = res["a"][0] if res["a"] else target

    domain = target
    subs = []
    if not re.match(r"^[\d.]+$", target) and "." in target:
        print("[2/4] 子域枚举（crt.sh 证书透明度）")
        subs = crtsh_subdomains(target)
        print(f"  发现 {len(subs)} 个子域：")
        for s in subs[:30]:
            print("   ", s)
    else:
        print("[2/4] 目标为 IP，跳过子域枚举")

    print(f"[3/4] 端口扫描（{len(COMMON_PORTS)} 个常见端口，目标 {ip}）")
    open_ports = []
    with cf.ThreadPoolExecutor(max_workers=50) as ex:
        for port, ok, banner in ex.map(lambda p: probe_port(ip, p), COMMON_PORTS):
            if ok:
                open_ports.append(port)
                print(f"   {port:>5} 开放  {banner[:60]}")
    print(f"  共 {len(open_ports)} 个开放端口")

    print("[4/4] Web 指纹")
    for p in [x for x in open_ports if x in (80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 3000, 5000, 8081)]:
        fp = http_fingerprint(ip if a.ip else target, p)
        print(f"   {p}: {fp}")

    out = {"target": target, "dns": res, "subdomains": subs,
           "open_ports": open_ports}
    p = DIR / "assetscan-last.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n→ 结果已存 {p}")
    print("→ 下一步：把开放端口/子域喂给漏洞验证（我们已有的 lab 与判据库）")


# ---------------- ② CVSS 3.1 定级 ----------------
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PRU = {"N": 0.85, "L": 0.62, "H": 0.27}     # Scope Unchanged
PRC = {"N": 0.85, "L": 0.68, "H": 0.50}     # Scope Changed
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def roundup(x):
    i = int(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (int(i / 10000) + 1) / 10.0


def cvss31(av, ac, pr, ui, s, c, i, aa):
    sc = s.upper() == "C"
    iss = 1 - ((1 - CIA[c.upper()]) * (1 - CIA[i.upper()]) * (1 - CIA[aa.upper()]))
    if sc:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    expl = 8.22 * AV[av.upper()] * AC[ac.upper()] * (PRC if sc else PRU)[pr.upper()] * UI[ui.upper()]
    if impact <= 0:
        return 0.0, impact, expl
    base = min((1.08 if sc else 1.0) * (impact + expl), 10.0)
    return roundup(base), impact, expl


# 平台等级区间（对齐 /cvss：严重/高危/中危/低危）
def grade(score):
    if score >= 9.0:
        return "严重", "¥350–1250（参考联想SRC）/ 平台上限更高"
    if score >= 7.0:
        return "高危", "¥200–950（参考联想SRC）"
    if score >= 4.0:
        return "中危", "¥100–400（参考联想SRC）"
    if score > 0:
        return "低危", "¥25–150（参考联想SRC），多数项目不收"
    return "无", "—"


def cmd_rate(a):
    if a.interactive or not a.vector:
        print("逐项选择（回车=用默认值）：")
        def ask(name, opts, default):
            print(f"  {name}: " + " / ".join(f"{k}={v}" for k, v in opts.items()))
            v = input(f"    选 [{default}]: ").strip().upper() or default
            return v
        av = ask("攻击向量AV", {"N": "网络", "A": "邻接", "L": "本地", "P": "物理"}, "N")
        ac = ask("攻击复杂度AC", {"L": "低", "H": "高"}, "L")
        pr = ask("权限要求PR", {"N": "无", "L": "低", "H": "高"}, "N")
        ui = ask("用户交互UI", {"N": "无", "R": "需要"}, "N")
        s = ask("影响范围S", {"U": "不变", "C": "改变"}, "U")
        c = ask("机密性C", {"H": "高", "L": "低", "N": "无"}, "L")
        i = ask("完整性I", {"H": "高", "L": "低", "N": "无"}, "L")
        aa = ask("可用性A", {"H": "高", "L": "低", "N": "无"}, "L")
    else:
        parts = re.split(r"[:/]", a.vector.upper())
        if len(parts) != 8:
            print("向量格式：AV:AC:PR:UI:S:C:I:A  例 N:L:N:N:U:H:H:H")
            return
        av, ac, pr, ui, s, c, i, aa = parts
    vec = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{aa}"
    try:
        score, impact, expl = cvss31(av, ac, pr, ui, s, c, i, aa)
    except KeyError as e:
        print(f"未知取值 {e}；AV/PR/UI 用 N/A/L/P 等，C/I/A 用 H/L/N")
        return
    g, money = grade(score)
    print(f"\n向量  : {vec}")
    print(f"基础分: {score}  （Impact={impact:.2f} Exploitability={expl:.2f}）")
    print(f"等级  : {g}")
    print(f"参考奖金: {money}")
    print("\n提交前自评清单：")
    print("  □ 是否满足该项目的收录范围（资产在 scope 内）")
    print("  □ 是否可复现（给出最小复现步骤与请求/响应）")
    print("  □ 是否已有同类报告（先跑 vulnbox.py dedup）")
    print('  □ 影响面证据是否充分（不是"理论上可"而是"实测拿到"）')
    print(f"  □ 报告里明确写出上面这个向量：{vec}")


# ---------------- ③ 查重 ----------------
def normalize(target, vtype, path, param):
    t = (target or "").lower().strip()
    t = re.sub(r"^https?://", "", t).rstrip("/")
    path = re.sub(r"/+", "/", (path or "").strip().lower())
    return "|".join([t, (vtype or "").lower().strip(), path, (param or "").lower().strip()])


def cmd_dedup(a):
    key = normalize(a.target, a.type, a.path, a.param)
    fp = hashlib.sha256(key.encode()).hexdigest()[:16]
    hits = []
    if SEEN.exists():
        for line in SEEN.read_text(encoding="utf-8").splitlines():
            try:
                o = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            if o.get("fp") == fp or o.get("key") == key:
                hits.append(o)
            elif o.get("target") == (a.target or "").lower().strip() \
                    and o.get("type") == (a.type or "").lower().strip() \
                    and o.get("path") == (a.path or "").strip().lower():
                hits.append(o)
    print(f"查重指纹 : {fp}")
    print(f"归一化键 : {key}")
    if hits:
        print(f"⚠️ 本地库命中 {len(hits)} 条 —— 可能是【重复提交】：")
        for h in hits[:5]:
            print("   ", json.dumps(h, ensure_ascii=False))
        print("→ 建议：换一个点、或确认是否与他人撞车（平台查重以对方库为准）")
    else:
        print("✅ 本地库无命中（注意：平台侧是否已有人报过仍需平台内查）")
        if a.record:
            with SEEN.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"fp": fp, "key": key, "target": a.target,
                                    "type": a.type, "path": a.path,
                                    "param": a.param}, ensure_ascii=False) + "\n")
            print(f"→ 已记入本地库 {SEEN.name}（下次同点会命中）")


def cmd_seen(_a):
    if not SEEN.exists():
        print("本地查重库为空")
        return
    lines = SEEN.read_text(encoding="utf-8").splitlines()
    print(f"本地查重库共 {len(lines)} 条：")
    for line in lines[-20:]:
        print("  ", line)


def main():
    ap = argparse.ArgumentParser(description="漏洞盒子三件套本地化")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="ARL式资产测绘")
    s.add_argument("target")
    s.add_argument("--ports", default="常见")
    s.add_argument("--ip", action="store_true", help="直接用目标当IP探测")

    r = sub.add_parser("rate", help="CVSS 3.1 定级")
    r.add_argument("vector", nargs="?", help="AV:AC:PR:UI:S:C:I:A")
    r.add_argument("-i", "--interactive", action="store_true")

    d = sub.add_parser("dedup", help="查重")
    d.add_argument("--target", required=True)
    d.add_argument("--type", required=True)
    d.add_argument("--path", default="")
    d.add_argument("--param", default="")
    d.add_argument("--record", action="store_true", help="无命中时记入本地库")

    sub.add_parser("seen", help="查看本地查重库")

    a = ap.parse_args()
    {"scan": cmd_scan, "rate": cmd_rate, "dedup": cmd_dedup, "seen": cmd_seen}[a.cmd](a)


if __name__ == "__main__":
    main()
