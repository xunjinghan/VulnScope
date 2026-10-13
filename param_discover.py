"""① 端点 / 参数发现器 —— 不再靠猜。

从站点自身提取攻击面：
  · 首页与一层同源链接里的 <a href>（端点 + query 参数）
  · 所有 <form> 的 action / method / 每个字段名
  · 内联与外链 JS 里的路径、fetch/XHR 目标
  · 常见动作型路由补全（change-password / transfer / withdraw / status 等）

产出 surface.json，供 logic_verify.py 等后续工具直接消费。

用法: python param_discover.py [base]
"""
import json
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from lxml import html as LH

from guard import assert_target_allowed

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8095").rstrip("/")
assert_target_allowed(BASE)
UA = "DSH-ParamDiscover/0.1 (read-only)"
HERE = pathlib.Path(__file__).resolve().parent

ACTION_HINTS = ["change-password", "changepassword", "password", "transfer", "withdraw",
                "deposit", "claim", "coupon", "order/create", "order/status", "status",
                "ship", "pay", "refund", "reset", "upload", "delete", "update", "edit", "admin"]


def fetch(path):
    url = BASE + path if path.startswith("/") else path
    assert_target_allowed(url)
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=12) as r:
            return r.status, r.read(300_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(100_000).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, str(e)


surface = {"base": BASE, "endpoints": {}, "forms": [], "notes": []}
s, home = fetch("/")
print(f"=== 端点/参数发现 {BASE} ===\n首页 HTTP {s}")

# --- 1. 链接（含 query 参数）---
try:
    doc = LH.fromstring(home)
except Exception:  # noqa: BLE001
    doc = None

links = set()
if doc is not None:
    for a in doc.xpath("//a[@href]"):
        links.add(urllib.parse.urljoin(BASE + "/", a.get("href")))

for l in list(links):
    p = urllib.parse.urlparse(l)
    if p.netloc and not l.startswith(BASE):
        continue
    path = p.path or "/"
    qs = urllib.parse.parse_qs(p.query)
    e = surface["endpoints"].setdefault(path, {"methods": set(), "params": set(), "sources": set()})
    e["methods"].add("GET")
    e["params"].update(qs.keys())
    e["sources"].add("首页链接")

# --- 2. 表单 ---
if doc is not None:
    for f in doc.xpath("//form"):
        action = urllib.parse.urljoin(BASE + "/", f.get("action") or "/")
        method = (f.get("method") or "get").upper()
        fields = [i.get("name") for i in f.xpath(".//input|.//select|.//textarea") if i.get("name")]
        surface["forms"].append({"action": action, "method": method, "fields": fields})
        p = urllib.parse.urlparse(action)
        e = surface["endpoints"].setdefault(p.path or "/", {"methods": set(), "params": set(), "sources": set()})
        e["methods"].add(method)
        e["params"].update(fields)
        e["sources"].add("表单")

# --- 3. JS 与内联脚本里的路径 ---
scripts = []
if doc is not None:
    scripts = [urllib.parse.urljoin(BASE + "/", x.get("src")) for x in doc.xpath("//script[@src]")]
inline = " ".join(doc.xpath("//script[not(@src)]/text()")) if doc is not None else ""
texts = [inline]
for js in scripts[:5]:
    st, body = fetch(js)
    if st == 200:
        texts.append(body)

js_paths = set()
for t in texts:
    js_paths.update(re.findall(r'["\'`](/(?:[A-Za-z0-9_\-./]+)?(?:\?[^"\'`]*)?)["\'`]', t or ""))
for p in js_paths:
    if len(p) < 2:
        continue
    q = urllib.parse.urlparse(p)
    e = surface["endpoints"].setdefault(q.path, {"methods": set(), "params": set(), "sources": set()})
    e["methods"].add("GET")
    e["params"].update(urllib.parse.parse_qs(q.query).keys())
    e["sources"].add("JS")

# --- 4. 动作型路由补全（只列出，不主动写）---
for h in ACTION_HINTS:
    surface["endpoints"].setdefault("/" + h, {"methods": set(), "params": set(), "sources": set()})
    surface["endpoints"]["/" + h]["sources"].add("动作型补全")
    surface["endpoints"]["/" + h]["methods"].add("POST")

# --- 输出 ---
print(f"\n发现端点 {len(surface['endpoints'])} 个：")
for path, meta in sorted(surface["endpoints"].items()):
    src = ",".join(sorted(meta["sources"]))
    print(f"  {path:34} {'/'.join(sorted(meta['methods'])):8} params={sorted(meta['params']) or '-'}  [{src}]")

print(f"\n表单 {len(surface['forms'])} 个：")
for f in surface["forms"]:
    print(f"  {f['method']:5} {f['action']:36} fields={f['fields']}")

out = HERE / "surface.json"
surface["endpoints"] = {k: {"methods": sorted(v["methods"]), "params": sorted(v["params"]),
                            "sources": sorted(v["sources"])} for k, v in surface["endpoints"].items()}
out.write_text(json.dumps(surface, ensure_ascii=False, indent=1), encoding="utf-8")
print(f"\n已存: {out}")
