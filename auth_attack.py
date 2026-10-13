"""带会话的越权攻击（修正判定逻辑）：401/403 = 被防住，不是攻破。

用法: python auth_attack.py [base] [username] [password]
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
USER = sys.argv[2] if len(sys.argv) > 2 else "demo"
PWD = sys.argv[3] if len(sys.argv) > 3 else "demo1234"
assert_target_allowed(BASE)
UA = "DSH-VulnHunt-Auth/0.1 (authorized-lab-only)"

opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
R = []


def req(path, data=None, follow=True):
    url = BASE + path
    assert_target_allowed(url)
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    h = {"User-Agent": UA}
    if body is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(url, data=body, headers=h)
    try:
        with opener.open(r, timeout=12) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(200_000).decode("utf-8", "replace"), dict(e.headers or {})
    except Exception as e:  # noqa: BLE001
        return None, str(e), {}


def rec(name, ok, detail):
    mark = {"pass": "✅", "fail": "❌", "info": "ℹ️"}[ok]
    R.append((mark, name, detail))
    print(f"  {mark} {name} —— {detail}")


print(f"=== 带会话越权攻击 {BASE}  账号={USER} ===")
s, body, _ = req("/login")
tok = re.search(r'name="csrf_token"\s+value="([^"]+)"', body)
tok = tok.group(1) if tok else None
s, body, hd = req("/login", {"csrf_token": tok, "username": USER, "password": PWD})

# 判定登录是否成功：看是否建立了有效会话（用一个只有本人能看的接口验证）
s_p, b_p, _ = req("/profile")
logged_in = (s_p == 200 and USER in b_p and "登录" not in b_p[:200])
rec(f"{USER} 登录并建立会话", "pass" if logged_in else "fail",
    f"login HTTP {s}；/profile HTTP {s_p}；{'会话有效' if logged_in else '会话无效（可能被防爆破锁定 / 凭据不符）'}")

if not logged_in:
    s, b, _ = req("/login")
    hint = re.search(r'class="flash"[^>]*>(.*?)</div>', b, re.S)
    if hint:
        print("     登录页提示：" + re.sub(r"\s+", " ", hint.group(1))[:160])
    s_o, b_o, _ = req(f"/api/orders?id=1")
    print(f"     顺带确认防爆破是否在生效：/api/orders?id=1 → HTTP {s_o} {b_o[:80]}")
    print("\n>>> 结论：合法登录被拒。若因防爆破锁定，说明该防护真实有效（这本身是防住，不是被攻破）。")
    sys.exit(0)

print("\n[越权 IDOR · 已登录为 " + USER + "]")
# 自己的资料（应含私有字段）
s_me, b_me, _ = req("/api/profile?id=1" if USER == "demo" else "/api/profile?id=2")
s_other, b_other, _ = req("/api/profile?id=2" if USER == "demo" else "/api/profile?id=1")
me_priv = ("balance_cents" in b_me) or ("phone" in b_me)
other_priv = ("balance_cents" in b_other) or ("phone" in b_other)
rec("本人资料含私有字段", "pass" if me_priv else "info", b_me[:100])
rec("他人资料是否越权拿到私有字段", "fail" if other_priv else "pass",
    "❌ 越权成功" if other_priv else f"仅公开字段 → {b_other[:100]}")

# 订单越权：不能硬编码 id —— 要看响应里的属主 user_id 是否等于自己
me = 1 if USER == "demo" else 2
s_own, b_own, _ = req("/api/orders?id=1")
rec("本人订单可读", "pass" if s_own == 200 else "info", f"HTTP {s_own} → {b_own[:90]}")
for probe in ("id=1", "id=2", "id=3", "id=999"):
    s, b, _ = req(f"/api/orders?{probe}")
    if s in (401, 403, 404):
        rec(f"订单 {probe}", "pass", f"HTTP {s} 被拒 → {b[:70]}")
        continue
    if s == 200:
        import json as _json
        try:
            owner = _json.loads(b).get("user_id")
        except Exception:  # noqa: BLE001
            owner = None
        if owner == me:
            rec(f"订单 {probe}", "pass", f"HTTP 200 且 user_id={owner} = 本人，合法")
        elif owner is None:
            rec(f"订单 {probe}", "info", f"HTTP 200 但读不出属主 → {b[:70]}")
        else:
            rec(f"订单 {probe}", "fail", f"❌ 越权：读到他人的单（user_id={owner}）→ {b[:90]}")
    else:
        rec(f"订单 {probe}", "info", f"HTTP {s} → {b[:70]}")

print("\n=== 汇总 ===")
fails = [r for r in R if r[0] == "❌"]
print(f"  探测 {len(R)} 项：防住 {len([r for r in R if r[0]=='✅'])}，攻破 {len(fails)}")
for f in fails:
    print(f"  ❌ {f[1]}：{f[2]}")
