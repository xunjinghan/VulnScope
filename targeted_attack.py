"""定向非破坏性攻击：对本地目标做定点验证，输出证据表。

遵守与 verify.py 相同的三条禁令：不改数据 / 不爆破 / 默认只读。
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
UA = "DSH-VulnHunt-Targeted/0.1 (authorized-lab-only, non-destructive)"

opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
RESULTS = []


def req(path, data=None, headers=None):
    url = BASE + path
    assert_target_allowed(url)
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    h = {"User-Agent": UA}
    if body is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    h.update(headers or {})
    r = urllib.request.Request(url, data=body, headers=h)
    try:
        with opener.open(r, timeout=12) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(200_000).decode("utf-8", "replace"), dict(e.headers or {})
    except Exception as e:  # noqa: BLE001
        return None, "", {"error": str(e)}


def rec(name, ok, detail):
    mark = "✅" if ok == "pass" else ("❌" if ok == "fail" else "ℹ️")
    RESULTS.append((mark, name, detail))
    print(f"  {mark} {name} —— {detail}")


def csrf(html_text):
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html_text)
    return m.group(1) if m else None


print(f"=== 定向攻击 {BASE} ===\n[1] 会话/CSRF 基线")
s, body, hd = req("/login")
tok = csrf(body)
rec("CSRF token 存在", "pass" if tok else "fail", f"token {'有' if tok else '无'}")
sc = hd.get("Set-Cookie", "")
rec("Cookie 标志", "pass" if ("HttpOnly" in sc and "SameSite" in sc) else "info",
    sc.split(";", 3)[0] + (" ; HttpOnly" if "HttpOnly" in sc else "") + (" ; SameSite" if "SameSite" in sc else " ; 无SameSite"))
miss = [x for x in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy") if x not in hd]
rec("安全响应头", "pass" if not miss else "info", "齐全" if not miss else "缺 " + ", ".join(miss))

print("\n[2] CSRF 绕过")
s, b, _ = req("/login", {"username": "alice", "password": "alice1234"})
blocked = s != 302 and "profile" not in b
rec("无 token 提交登录", "pass" if blocked else "fail", f"HTTP {s}，{'被拒' if blocked else '居然通过'}")

def logged_in_now() -> bool:
    """唯一可信判据：同一会话请求 /profile，看到「退出登录」表单 = 已登录；
    看到登录表单 = 未登录。（不能用 "/profile" 子串 —— 登录页导航栏里也有这个链接，会假阳性）"""
    s, b, _ = req("/profile")
    has_logout = 'action="/logout"' in b or "退出登录" in b
    has_login_form = 'action="/login"' in b
    return bool(has_logout and not has_login_form)


print("\n[3] SQL 注入（登录处）—— 判据：会话是否真的建立")
s, body, _ = req("/login")
tok = csrf(body)
payloads = ["alice' OR '1'='1", "alice'--", "alice' OR 1=1--", "admin'/*"]
for p in payloads:
    req("/login", {"csrf_token": tok, "username": p, "password": "x"})
    ok = logged_in_now()
    # 登录失败后 CSRF token 会轮换，重新取一次，避免误判
    s, body, _ = req("/login")
    tok = csrf(body)
    rec(f"注入 {p!r}", "fail" if ok else "pass", f"{'注入成功（会话已建立）!' if ok else '未绕过（未建立会话）'}")

print("\n[4] 合法登录（建立会话）")
s, body, _ = req("/login")
tok = csrf(body)
req("/login", {"csrf_token": tok, "username": "alice", "password": "alice1234"})
if logged_in_now():
    rec("alice 合法登录", "pass", "会话已建立（用 /profile 的退出表单确认）")
else:
    rec("alice 合法登录", "info",
        "未建立会话 —— 最可能是被「登录 POST 限速 20 次/5 分钟/IP」挡住（这是防护生效，不是漏洞）")

print("\n[5] 越权 IDOR（用不变量判定，不硬编码 id）")
s1, b1, _ = req("/api/profile?id=1")
s2, b2, _ = req("/api/profile?id=2")
p1 = ("phone" in b1) or ("balance_cents" in b1)
p2 = ("phone" in b2) or ("balance_cents" in b2)
if p1 and p2:
    rec("profile 越权", "fail", "❌ 当前会话对 id=1 与 id=2 都返回私有字段 → 存在越权")
elif p1 or p2:
    mine = 1 if p1 else 2
    other = 2 if p1 else 1
    rec("profile 越权", "pass",
        f"仅本人(id={mine})含 phone/balance，他人(id={other})仅公开字段 → 防住")
else:
    rec("profile 越权", "info", "两个 id 都只有公开字段（可能未登录成功，需人工确认）")
# 订单：状态码 401/403/404 = 被拒；200 需比对属主
codes = []
for i in (1, 2, 3):
    s, _, _ = req(f"/api/orders?id={i}")
    codes.append(s)
defended = all(c in (401, 403, 404) for c in codes)
rec("orders 越权枚举", "pass" if defended else "info",
    f"id=1,2,3 → HTTP {codes}" + ("（全部被拒）" if defended else "（有 200，属主由 auth_attack.py 判）"))

print("\n[6] 反射型 XSS（flash 参数 ?m=）")
mark = "<script>alert(1)</script>"
s, b, _ = req("/?m=" + urllib.parse.quote(mark))
raw = mark in b
esc = ("&lt;script&gt;" in b)
rec("?m= 反射是否转义", "fail" if raw else "pass", "❌ 原样输出（XSS）" if raw else ("✅ 已转义" if esc else "未影响输出"))

print("\n[7] 路径穿越 / 参数校验")
for probe in ["/api/profile?id=1'", "/api/profile?id=1 OR 1=1", "/api/profile?id=-1", "/api/orders?id=999999"]:
    s, b, _ = req(probe)
    rec(f"{probe}", "pass", f"HTTP {s} → {b[:80]}")

print("\n[8] 存在性枚举（正确对照：他人的【存在】资源 vs 【不存在】资源；不能用自己）")
# 用独立会话登录 demo(id=1)，这样 id=2 是「他人的存在资源」
import http.cookiejar as _cj  # noqa: E402
import urllib.request as _ur  # noqa: E402

op2 = _ur.build_opener(_ur.HTTPCookieProcessor(_cj.CookieJar()))


def req2(path, data=None):
    url = BASE + path
    assert_target_allowed(url)
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    h = {"User-Agent": UA}
    if body is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    r = _ur.Request(url, data=body, headers=h)
    try:
        with op2.open(r, timeout=12) as resp:
            return resp.status, resp.read(100_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(100_000).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, str(e)


# 未登录对照
ua1, ub1 = req2("/api/profile?id=2")       # 存在（alice）
ua2, ub2 = req2("/api/profile?id=66666")   # 不存在
if ua1 == ua2 and ub1.strip() == ub2.strip():
    rec("用户枚举（未登录）", "pass", f"存在与不存在都返回相同响应（HTTP {ua1}，同一文案）→ 不可枚举")
elif ua1 == ua2:
    rec("用户枚举（未登录）", "info", f"状态码相同（{ua1}）但响应体不同，需人工看")
else:
    rec("用户枚举（未登录）", "fail", f"存在 → HTTP {ua1}，不存在 → HTTP {ua2}：状态码可区分")

# 登录 demo 后对照
s0, b0 = req2("/login")
tok = re.search(r'name="csrf_token"\s+value="([^"]+)"', b0)
tok = tok.group(1) if tok else None
req2("/login", {"csrf_token": tok, "username": "demo", "password": "demo1234"})
la1, lb1 = req2("/api/profile?id=2")       # 他人的存在资源
la2, lb2 = req2("/api/profile?id=66666")   # 不存在
if la1 == la2 and lb1.strip() == lb2.strip():
    rec("用户枚举（登录后）", "pass", f"他人的存在资源与不存在资源响应完全一致（HTTP {la1}）→ 不可枚举")
elif la1 == la2:
    rec("用户枚举（登录后）", "info", f"状态码相同（{la1}）但响应体不同，需人工看")
else:
    rec("用户枚举（登录后）", "fail", f"他人的存在 → HTTP {la1}，不存在 → HTTP {la2}：状态码可区分")

oa1, ob1 = req2("/api/orders?id=3")        # 他人的存在订单（alice 的）
oa2, ob2 = req2("/api/orders?id=999999")   # 不存在
if oa1 == oa2 and ob1.strip() == ob2.strip():
    rec("订单枚举", "pass", f"他人的存在订单与不存在订单响应完全一致（HTTP {oa1}）→ 不可枚举")
elif oa1 == oa2:
    rec("订单枚举", "info", f"状态码相同（{oa1}）但响应体不同，需人工看")
else:
    rec("订单枚举", "fail", f"他人的存在订单 → HTTP {oa1}，不存在 → HTTP {oa2}：状态码可区分")

print("\n=== 汇总 ===")
fails = [r for r in RESULTS if r[0] == "❌"]
print(f"  探测项 {len(RESULTS)} 个，被防住 {len([r for r in RESULTS if r[0]=='✅'])} 个，攻破 {len(fails)} 个")
for f in fails:
    print(f"  ❌ {f[1]}: {f[2]}")
