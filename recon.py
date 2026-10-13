"""资产测绘流水线：给一个域名 → 出资产清单（子域/存活/端口/指纹/接口）。

安全设计：每探测一个主机前都先过 armor 护栏（本地靶场 或 scope.json 白名单），
范围外一律不碰。

用法:
  python recon.py example.com                  # 全流程（需在 scope.json 内）
  python recon.py example.com --no-brute       # 不做子域爆破（只走 CT 日志）
  python recon.py 192.168.56.102               # 内网靶机（始终允许）
输出: assets.json + 控制台摘要
"""
import argparse
import concurrent.futures as cf
import json
import pathlib
import re
import socket
import ssl
import sys
import time
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import armor  # noqa: E402

# 常用子域字典（精简版，够跑中小项目）
WORDS = """www mail smtp pop imap webmail api app apps admin manage manager portal
test dev stage staging uat pre prod beta demo sandbox vpn oauth sso login auth
account accounts pay payment order shop store cdn static img image assets upload
files file download doc docs wiki git gitlab jenkins ci cd grafana kibana
monitor status health metrics db database mysql redis mongo es search log logs
proxy gw gateway router switch ns1 ns2 dns mail2 old new backup data intranet
oa crm erp hr finance report reports""".split()

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
             1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8009, 8080,
             8081, 8443, 8888, 9000, 9090, 9200, 27017]


def guard(target):
    """过护栏，返回 (ok, why)。"""
    try:
        why, _ = armor.assert_allowed(target)
        return True, why
    except armor.OutOfScope as e:
        return False, str(e)


def resolve(host):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:  # noqa: BLE001
        return []


def ct_subdomains(domain, timeout=25):
    """从证书透明日志（crt.sh）拉子域 —— 免费、无需 key。"""
    out = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "dsh-recon"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        for row in data:
            for n in str(row.get("name_value", "")).split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(domain):
                    out.add(n)
    except Exception as e:  # noqa: BLE001
        print(f"    (CT 日志查询失败: {e})")
    return out


def brute_subdomains(domain, words, timeout=0.6, workers=40):
    found = set()

    def probe(w):
        h = f"{w}.{domain}"
        try:
            socket.setdefaulttimeout(timeout)
            socket.getaddrinfo(h, None)
            return h
        except Exception:  # noqa: BLE001
            return None

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(probe, words):
            if r:
                found.add(r)
    return found


def scan_ports(host, ports, timeout=0.7, workers=60):
    openp = []

    def t(p):
        try:
            with socket.create_connection((host, p), timeout=timeout):
                return p
        except Exception:  # noqa: BLE001
            return None

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(t, ports):
            if r:
                openp.append(r)
    return sorted(openp)


def http_probe(host, timeout=8):
    """返回 (url, status, server, title, 长度)"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 dsh-recon"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(65536).decode("utf-8", "replace")
                title = (re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S) or [None, ""])[1].strip()[:60]
                return url, r.status, r.headers.get("Server", ""), title, len(body)
        except Exception:  # noqa: BLE001
            continue
    return None, None, None, None, 0


def extract_endpoints(host, timeout=8):
    """从首页与引用的 JS 里抽接口路径（项目规模的关键线索）。"""
    eps = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/", headers={"User-Agent": "dsh-recon"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                html = r.read(200000).decode("utf-8", "replace")
            break
        except Exception:  # noqa: BLE001
            html = ""
    if not html:
        return eps
    for m in re.finditer(r"""["'](/[a-zA-Z0-9_\-/.]{2,60})["']""", html):
        p = m.group(1)
        if any(p.lower().startswith(x) for x in ("/api", "/v1", "/v2", "/rest", "/graphql", "/admin", "/user")):
            eps.add(p)
    for m in re.finditer(r"""src=["']([^"']+\.js[^"']*)["']""", html, re.I):
        js = m.group(1)
        if js.startswith("//"):
            js = scheme + ":" + js
        elif js.startswith("/"):
            js = f"{scheme}://{host}{js}"
        if not js.startswith("http"):
            continue
        try:
            req = urllib.request.Request(js, headers={"User-Agent": "dsh-recon"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                code = r.read(400000).decode("utf-8", "replace")
            for mm in re.finditer(r"""["'](/[a-zA-Z0-9_\-/.]{3,60})["']""", code):
                p = mm.group(1)
                if any(p.lower().startswith(x) for x in ("/api", "/v1", "/v2", "/rest", "/graphql")):
                    eps.add(p)
        except Exception:  # noqa: BLE001
            continue
    return eps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--no-brute", action="store_true", help="跳过子域爆破")
    ap.add_argument("--ports", action="store_true", help="做端口扫描")
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    dom = a.domain.strip().lower()
    t0 = time.time()
    print(f"=== 资产测绘: {dom} ===")

    ok, why = guard(dom)
    print(f"[护栏] {'✅ 放行' if ok else '⛔ 拒绝'} — {why}")
    if not ok:
        print("范围外目标一律不探测。要测就先把授权范围写进 scope.json。")
        return 2

    result = {"domain": dom, "started": time.strftime("%Y-%m-%d %H:%M:%S"), "assets": []}

    print("[1] 根域解析")
    ips = resolve(dom)
    print(f"    {dom} -> {ips or '解析失败'}")
    if not ips:
        return 1

    hosts = {dom}
    if not a.no_brute:
        print("[2] 子域枚举")
        ct = ct_subdomains(dom)
        print(f"    CT 日志: {len(ct)} 个")
        hosts |= ct
        bf = brute_subdomains(dom, WORDS)
        print(f"    DNS 爆破: {len(bf)} 个（字典 {len(WORDS)} 词）")
        hosts |= bf
    else:
        print("[2] 子域枚举（已跳过）")

    alive = []
    print(f"[3] 存活探测（{len(hosts)} 个候选）")

    def worker(h):
        if not guard(h)[0]:
            return None
        url, status, server, title, ln = http_probe(h)
        if not url:
            return None
        return {"host": h, "url": url, "status": status, "server": server,
                "title": title, "size": ln, "ips": resolve(h)}

    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(worker, sorted(hosts)):
            if r:
                alive.append(r)
                print(f"    ✅ {r['url']:<45} {r['status']} {r['server'][:22]:<22} {r['title']}")

    print("[4] 端口扫描" + ("" if a.ports else "（未启用，加 --ports）"))
    if a.ports:
        for h in [dom] + [x["host"] for x in alive[:10]]:
            op = scan_ports(h, TOP_PORTS)
            print(f"    {h}: {op}")
            for x in alive:
                if x["host"] == h:
                    x["ports"] = op

    print("[5] 接口/JS 提取（项目规模关键）")
    all_eps = set()
    for x in alive[:15]:
        eps = extract_endpoints(x["host"])
        x["endpoints"] = sorted(eps)
        all_eps |= eps
        if eps:
            print(f"    {x['host']}: {len(eps)} 个接口")
    print(f"    合计去重接口 {len(all_eps)} 个")

    result["assets"] = alive
    result["endpoints"] = sorted(all_eps)
    result["elapsed_sec"] = round(time.time() - t0, 1)
    out = pathlib.Path(a.out) if a.out else HERE / "assets.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n=== 完成：{len(alive)} 个存活资产，{len(all_eps)} 个接口 → {out}（{result['elapsed_sec']}s）===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
