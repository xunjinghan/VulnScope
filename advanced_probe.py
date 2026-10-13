"""进阶探针（全只读）：补齐 9 类我原来没有的攻击面。

来源（2026-10-09 搜集）：
- HackTricks CORS bypass https://github.com/carbon-vault/hacktricks-archive/blob/master/pentesting-web/cors-bypass.md
- HackTricks JWT https://mintlify.wiki/HackTricks-wiki/hacktricks/pentesting-web/jwt-vulnerabilities
- OWASP WSTG Host Header Injection
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection.html
- DEF CON 31「Smashing the state machine」（web 竞态条件）
  https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/James%20'albinowax'%20Kettle%20-%20Smashing%20the%20state%20machine.pdf
- File upload checklist https://onsecurity.io/article/file-upload-checklist/
- 先知社区《众测中的一些越权方式》 https://xz.aliyun.com/news/18457

规则不变：只读（GET/HEAD/OPTIONS）、不改数据、不爆破、不压测；目标过 guard。
"""
import http.client
import ssl
import sys
import urllib.parse

from guard import assert_target_allowed

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8091").rstrip("/")
assert_target_allowed(BASE)
U = urllib.parse.urlparse(BASE)
HOST, PORT = U.hostname, (U.port or (443 if U.scheme == "https" else 80))
UA = "DSH-AdvProbe/0.1 (authorized-lab-only, read-only)"
FINDINGS = []


def raw(path, headers=None, method="GET"):
    """原生 http.client：可精确控制 Host / 任意头，且不自动跟随跳转。"""
    h = {"User-Agent": UA, "Accept": "*/*"}
    h.update(headers or {})
    if U.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(HOST, PORT, timeout=10, context=ctx)
    else:
        conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
    try:
        conn.request(method, path, headers=h)
        r = conn.getresponse()
        body = r.read(200_000).decode("utf-8", "replace")
        return r.status, r.getheaders(), body, None
    except Exception as e:  # noqa: BLE001
        return None, [], "", str(e)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def hget(hdrs, name):
    for k, v in hdrs:
        if k.lower() == name.lower():
            return v
    return None


def hit(tag, detail, sev="⚠️"):
    FINDINGS.append((sev, tag, detail))
    print(f"  {sev} {tag} —— {detail}")


print(f"=== 进阶探针（只读）{BASE} ===\n[1] 安全响应头完整性（OWASP 推荐集）")
s, hd, b, e = raw("/")
if e:
    print("  ❌ 连接失败:", e)
    sys.exit(1)
want = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy",
        "Referrer-Policy", "Permissions-Policy", "Strict-Transport-Security"]
present = [w for w in want if hget(hd, w)]
absent = [w for w in want if not hget(hd, w)]
print(f"  已设置: {present or '(无)'}")
print(f"  未设置: {absent or '(无)'}")
# 明文 HTTP 下 HSTS 无意义，不计入发现
really_absent = [w for w in absent if not (w == "Strict-Transport-Security" and U.scheme == "http")]
if really_absent:
    hit("安全响应头缺失", ", ".join(really_absent))

print("\n[2] CORS 配置（是否会反射任意 Origin）")
for origin in ("https://evil.example", "null", f"https://{HOST}.evil.example"):
    s, hd, b, e = raw("/", headers={"Origin": origin})
    acao = hget(hd, "Access-Control-Allow-Origin")
    acac = hget(hd, "Access-Control-Allow-Credentials")
    print(f"  Origin: {origin:34} → ACAO={acao!r} ACAC={acac!r}")
    if acao in (origin, "*") and acac and acac.lower() == "true" and acao != "*":
        hit("CORS 危险配置", f"反射 Origin={origin} 且允许携带凭据 → 可跨站读取用户数据", "🔴")
    elif acao == origin:
        hit("CORS 反射 Origin", f"ACAO 反射了 {origin}（若无凭据限制危害较低）")

print("\n[3] Host 头注入（密码重置投毒 / 缓存投毒前置）")
s, hd, b, e = raw("/", headers={"Host": "evil.example", "X-Forwarded-Host": "evil.example"})
reflected = "evil.example" in b
loc = hget(hd, "Location") or ""
print(f"  Host: evil.example → HTTP {s}，响应体含 evil.example={reflected}，Location={loc!r}")
if reflected or "evil.example" in loc:
    hit("Host 头注入", "恶意 Host/X-Forwarded-Host 被反射进响应或跳转里", "🔴")
else:
    print("  ✅ 未反射外来 Host")

print("\n[4] 参数污染（HTTP Parameter Pollution）")
for q in ("/api/profile?id=1&id=2", "/api/profile?id[]=1", "/api/profile?id=1%00&id=2"):
    s, hd, b, e = raw(q)
    print(f"  {q:32} → HTTP {s} {b[:70]!r}")

print("\n[5] CRLF 注入 / 响应头分裂")
for payload in ("/login?m=%0d%0aSet-Cookie:%20dsh=1", "/login?m=%0aX-Injected:%20dsh"):
    s, hd, b, e = raw(payload)
    inj = hget(hd, "Set-Cookie") or ""
    print(f"  {payload[:38]:40} → HTTP {s}，注入头出现={'dsh' in str(hd)}")
    if "dsh=1" in inj or hget(hd, "X-Injected"):
        hit("CRLF 注入", "参数进入了响应头，可被用于响应分裂", "🔴")
print("  参考: https://owasp.org/www-project-web-security-testing-guide/")

print("\n[6] 路径穿越（编码变体，只读）")
for p in ("/..%2f..%2fapp.py", "/%2e%2e/app.py", "/..%252fapp.py", "/static/../../app.py", "/%2e%2e%2f%2e%2e%2fetc%2fpasswd"):
    s, hd, b, e = raw(p)
    leak = ("import " in b and "def " in b) or "root:" in b
    print(f"  {p:38} → HTTP {s} {('⚠️ 疑似文件泄露' if leak else '')}")
    if leak:
        hit("路径穿越", f"{p} 返回了疑似源码/系统文件内容", "🔴")

print("\n[7] 缓存相关头（缓存欺骗检测基础）")
cc = hget(hd, "Cache-Control")
vary = hget(hd, "Vary")
print(f"  Cache-Control={cc!r}  Vary={vary!r}")
if cc is None:
    hit("未设置 Cache-Control", "动态页面若被中间缓存收录，可能被缓存欺骗利用")

print("\n[8] 方法覆盖头（只记信息，不判定为漏洞）")
s_plain, _, b_plain, _ = raw("/")
s, hd, b, e = raw("/", headers={"X-HTTP-Method-Override": "DELETE"}, method="GET")
# 注意：服务端【忽略】该头也会返回正常 200 —— 忽略=安全。
# 要确认是否真正生效需要一次写操作，按非破坏性原则不做，因此这里只作信息记录。
same = (s == s_plain and b == b_plain)
print(f"  GET 普通请求 → HTTP {s_plain}")
print(f"  GET + X-HTTP-Method-Override: DELETE → HTTP {s}，响应与普通请求相同={same}")
if same:
    print("  ✅ 该头被忽略（响应无差异）—— 未观察到方法覆盖生效；真正验证需写操作，按规则不做")
else:
    hit("方法覆盖头行为异常", f"带 override 头时响应发生变化（HTTP {s_plain}→{s}），建议人工确认是否真的执行了被覆盖的方法")

print("\n[9] 错误信息泄露（畸形请求）")
for p in ("/%", "/" + "a" * 300, "/api/profile?id=" + "9" * 60):
    s, hd, b, e = raw(p)
    leak = any(k in b for k in ("Traceback", "File \"", "sqlite3.", "line "))
    print(f"  {p[:34]:36} → HTTP {s} {('⚠️ 含实现细节' if leak else '')}")
    if leak:
        hit("错误页泄露实现细节", p, "🔴")

print("\n=== 进阶探针汇总 ===")
if FINDINGS:
    for sev, t, d in FINDINGS:
        print(f"  {sev} {t}: {d[:120]}")
else:
    print("  （无新发现）")
print(f"  共 {len(FINDINGS)} 条待复核")
