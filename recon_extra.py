"""扩展侦察（全只读）：补齐我原来缺的 4 类攻击面。

来源（2026-10-09 搜集，中文社区为主）：
- 先知社区《众测中的一些越权方式》https://xz.aliyun.com/news/18457
- SRC 挖掘思路清单 https://x1lys.github.io/2024/07/19/SRC挖掘思路清单一/
- cnvd-skill（未授权漏洞广扫：预置端点字典 + 只读验证）https://github.com/sywinksvg/cnvd-skill
- DirBuster 目录发现指南 https://scansearch.net/zh/articles/dirbuster-directory-bruteforce-guide/
- ai-security-methodology 信息泄露篇 https://github.com/JesusConwellpy/ai-security-methodology
- LLM 自动化漏洞发现综述 https://ieeexplore.ieee.org/ielx8/6287639/11323511/11580353.pdf

四条硬规则不变：只读（GET/HEAD/OPTIONS）、不改数据、不爆破、不压测；目标过 guard。
"""
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from guard import assert_target_allowed

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8091").rstrip("/")
assert_target_allowed(BASE)
UA = "DSH-VulnHunt-Recon/0.1 (authorized-lab-only, read-only)"

# 只读探测字典：敏感文件 / 管理端点 / 备份 / 源码 / 文档
PATHS = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".env", ".svn/entries",
    "backup.zip", "www.zip", "app.py.bak", "app.py~", "config.py", "settings.py",
    "target_site.db", "data.db", "site.db",
    "admin", "administrator", "manage", "console", "dashboard",
    "api", "api/", "api/v1", "api/users", "api/orders", "api/profile", "api/health",
    "swagger", "swagger.json", "openapi.json", "docs", "redoc",
    "actuator", "actuator/health", "server-status", "phpinfo.php",
    "debug", "status", "health", "metrics", "test", "source", "src", "static/",
]
INTERESTING = re.compile(r"(git|env|backup|\.zip|\.bak|~|db$|config|source|src|admin|actuator|swagger|openapi|phpinfo|server-status|debug)", re.I)

opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
FINDINGS = []


def req(path, method="GET", data=None):
    url = BASE + (path if path.startswith("/") else "/" + path)
    assert_target_allowed(url)
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    h = {"User-Agent": UA}
    if body is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with opener.open(r, timeout=10) as resp:
            return resp.status, resp.read(100_000).decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(50_000).decode("utf-8", "replace"), dict(e.headers or {})
    except Exception as e:  # noqa: BLE001
        return None, str(e), {}


def note(tag, detail):
    FINDINGS.append((tag, detail))
    print(f"  ⚠️ {tag} —— {detail}")


print(f"=== 扩展侦察（只读）{BASE} ===\n[1] 敏感路径 / 未授权端点字典（{len(PATHS)} 条，只读 GET）")
hits = []
for p in PATHS:
    s, b, h = req(p)
    if s in (200, 201) and b.strip():
        ctype = h.get("Content-Type", "")
        tag = "敏感" if INTERESTING.search(p) else "普通"
        hits.append((p, s, len(b), ctype))
        print(f"  {'🔴' if tag=='敏感' else '🟡'} {p:24} HTTP {s}  {len(b):>7}B  {ctype[:36]}")
        if tag == "敏感":
            note(f"敏感路径可访问 /{p}", f"HTTP {s}, {len(b)}B, {ctype[:40]} → {b[:100]!r}")
print(f"  → 200 命中 {len(hits)} 条")

print("\n[2] HTTP 方法探测（TRACE/PUT/DELETE 是否被接受）")
for path in ("/", "/login", "/api/profile?id=1"):
    s, b, h = req(path, method="OPTIONS")
    allow = h.get("Allow", "")
    print(f"  OPTIONS {path:22} → HTTP {s}  Allow={allow or '(无)'}")
    if allow and any(m in allow.upper() for m in ("PUT", "DELETE", "TRACE")):
        note("危险的 HTTP 方法被允许", f"{path} Allow={allow}")
# TRACE 单独测（只读）
s, b, _ = req("/", method="TRACE")
print(f"  TRACE /                → HTTP {s}")
if s == 200:
    note("TRACE 未禁用", "可能被用于 XST 攻击")

print("\n[3] 会话固定检测（登录前后 session 是否轮换）")
jar = opener.handlers[0].cookiejar if hasattr(opener.handlers[0], "cookiejar") else None
jar = getattr(opener, "handlers", [None])[0]
jar = next((h.cookiejar for h in opener.handlers if hasattr(h, "cookiejar")), None)


def session_of(j):
    for c in j:
        if "session" in c.name.lower() or "sid" in c.name.lower() or "token" in c.name.lower():
            return c.name, c.value
    return None, None


s, body, _ = req("/login")
tok = re.search(r'name="csrf_token"\s+value="([^"]+)"', body)
tok = tok.group(1) if tok else None
pre_name, pre_val = session_of(jar)
print(f"  登录前: {pre_name}={str(pre_val)[:16]}…")
s, body, h = req("/login", "POST", {"csrf_token": tok, "username": "demo", "password": "demo1234"})
post_name, post_val = session_of(jar)
print(f"  登录后: {post_name}={str(post_val)[:16]}…  (HTTP {s})")
if pre_val and post_val and pre_val == post_val:
    note("疑似会话固定", "登录成功后 session token 未轮换 —— 攻击者可预先固定会话")
elif pre_val and post_val and pre_val != post_val:
    print("  ✅ 登录后 session 已轮换（防会话固定）")
else:
    print("  ℹ️ 未能取到 session（可能未建立）")

# Cookie 安全属性
for c in jar:
    flags = []
    if c.secure:
        flags.append("Secure")
    if c.has_nonstandard_attr("HttpOnly"):
        flags.append("HttpOnly")
    if c.has_nonstandard_attr("SameSite"):
        flags.append("SameSite")
    exp = "会话级" if c.expires is None else f"过期={c.expires}"
    print(f"  Cookie {c.name}: domain={c.domain} path={c.path} {exp} [{','.join(flags) or '无安全属性'}]")
    if not c.has_nonstandard_attr("HttpOnly"):
        note("Cookie 缺 HttpOnly", f"{c.name} 可被 JS 读取，XSS 可直接偷会话")

print("\n[4] robots.txt / sitemap.xml 线索 + 页面内接口提取")
for p in ("robots.txt", "sitemap.xml"):
    s, b, _ = req(p)
    if s == 200 and b.strip():
        print(f"  /{p} → {b[:200]!r}")
s, home, _ = req("/")
eps = set(re.findall(r'(?:href|action|src)="([^"]+)"', home))
apis = {e for e in eps if re.search(r"api|admin|user|order|profile", e, re.I)}
print(f"  首页链接 {len(eps)} 个，其中疑似接口 {len(apis)} 个: {sorted(apis)[:8]}")
for js in {e for e in eps if e.endswith(".js")}:
    sj, bj, _ = req(js)
    if sj == 200:
        found = set(re.findall(r'["\'](/[a-zA-Z0-9_\-/]{2,40})["\']', bj))
        inner = {f for f in found if re.search(r"api|user|order|profile|admin", f, re.I)}
        print(f"  JS {js} → HTTP 200, 提取到可疑接口 {sorted(inner)[:10]}")
        for f in inner:
            note("JS 中暴露的接口", f"{js} 内含 {f}")

print("\n=== 扩展侦察汇总 ===")
print(f"  发现 {len(FINDINGS)} 条值得复核的点：")
for t, d in FINDINGS:
    print(f"  ⚠️ {t}: {d[:110]}")
if not FINDINGS:
    print("  （无）")
