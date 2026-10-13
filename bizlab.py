"""业务逻辑靶场（自建，用于验证检测能力与报告产出）

故意植入 6 类业务逻辑缺陷，端口 8095（与既有工具链约定一致）：
  G1 金额篡改（服务端采信客户端 price）
  G2 负数数量（qty 为负时反向加钱）
  G3 优惠券可重复领取（无幂等）
  G4 提现并发竞态（先查后扣，TOCTOU）
  G5 订单状态可任意改写（无状态机）
  A2/A3 改密 / 转账 无 CSRF 校验

账号：demo/demo123  alice/alice123  bob/bob123  admin/admin123
仅监听 127.0.0.1，仅用于隔离环境自测。
"""
import http.server
import json
import sqlite3
import sys
import threading
import time
import urllib.parse
from http.cookies import SimpleCookie

PORT = 8095
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("""
CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, pass TEXT, balance INT, role TEXT);
CREATE TABLE sessions(token TEXT PRIMARY KEY, uid INT);
CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price INT);
CREATE TABLE orders(id INTEGER PRIMARY KEY, uid INT, pid INT, qty INT, price INT, status TEXT);
CREATE TABLE coupons(uid INT, code TEXT);
""")
for i, (n, p, b, r) in enumerate([("demo", "demo123", 50000, "user"), ("alice", "alice123", 88800, "user"),
                                  ("bob", "bob123", 100, "user"), ("admin", "admin123", 999999, "admin")], 1):
    DB.execute("INSERT INTO users VALUES(?,?,?,?,?)", (i, n, p, b, r))
DB.execute("INSERT INTO products VALUES(1,'手机',29900)")
DB.commit()
LOCK = threading.Lock()


def money(uid):
    return DB.execute("SELECT balance FROM users WHERE id=?", (uid,)).fetchone()[0]


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _uid(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        tok = c.get("session")
        if not tok:
            return None
        row = DB.execute("SELECT uid FROM sessions WHERE token=?", (tok.value,)).fetchone()
        return row[0] if row else None

    def _send(self, code, body, extra=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        uid = self._uid()
        if u.path == "/":
            self._send(200, f"<h1>业务逻辑靶场</h1><a href='/login'>登录</a> 余额 {money(uid) if uid else '-'}")
        elif u.path == "/login":
            self._send(200, "<form method=post action=/login><input name=username><input name=password type=password><button>登录</button></form>")
        elif u.path == "/home":
            if not uid:
                return self._send(302, "", {"Location": "/login"})
            self._send(200, f"<h2>{uid}</h2><p>余额 {money(uid)}</p>")
        elif u.path == "/coupon/claim":
            if not uid:
                return self._send(302, "", {"Location": "/login"})
            code = (q.get("code") or ["WELCOME10"])[0]
            # G3: 无幂等校验，可无限重复领取
            DB.execute("INSERT INTO coupons VALUES(?,?)", (uid, code))
            DB.execute("UPDATE users SET balance=balance+1000 WHERE id=?", (uid,))
            DB.commit()
            self._send(200, json.dumps({"ok": True, "balance": money(uid)}))
        elif u.path == "/order/status":
            if not uid:
                return self._send(302, "", {"Location": "/login"})
            oid = int((q.get("order_id") or ["1"])[0])
            st = (q.get("status") or ["shipped"])[0]
            # G5: 无状态机校验
            DB.execute("UPDATE orders SET status=? WHERE id=?", (st, oid))
            DB.commit()
            self._send(200, json.dumps({"ok": True, "order": oid, "status": st}))
        else:
            self._send(404, "not found")

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        uid = self._uid()
        if u.path == "/login":
            row = DB.execute("SELECT id FROM users WHERE name=? AND pass=?",
                             (form.get("username"), form.get("password"))).fetchone()
            if not row:
                return self._send(302, "", {"Location": "/?err=login"})
            tok = f"t{row[0]}{int(time.time())}"
            DB.execute("INSERT OR REPLACE INTO sessions VALUES(?,?)", (tok, row[0]))
            DB.commit()
            return self._send(302, "", {"Location": "/home", "Set-Cookie": f"session={tok}; Path=/"})
        if not uid:
            return self._send(302, "", {"Location": "/login"})
        if u.path == "/order/create":
            pid = int(form.get("product_id", 1))
            qty = int(form.get("qty", 1))
            # G1: 采信客户端 price；G2: 允许负数 qty
            price = int(form.get("price", 100))
            DB.execute("INSERT INTO orders(uid,pid,qty,price,status) VALUES(?,?,?,?, 'unpaid')", (uid, pid, qty, price))
            DB.execute("UPDATE users SET balance=balance-? WHERE id=?", (price * qty, uid))
            DB.commit()
            return self._send(200, json.dumps({"ok": True, "balance": money(uid)}))
        if u.path == "/wallet/withdraw":
            amt = int(form.get("amount", 1))
            # G4: 先查后扣（非原子）——并发可超额
            bal = money(uid)
            time.sleep(0.15)
            if bal >= amt:
                DB.execute("UPDATE users SET balance=balance-? WHERE id=?", (amt, uid))
                DB.commit()
                return self._send(200, json.dumps({"ok": True, "balance": money(uid)}))
            return self._send(200, json.dumps({"ok": False, "balance": bal}))
        if u.path == "/change-password":
            # A2: 无 CSRF 校验
            DB.execute("UPDATE users SET pass=? WHERE id=?", (form.get("new_password", "x"), uid))
            DB.commit()
            return self._send(200, json.dumps({"ok": True}))
        if u.path == "/wallet/transfer":
            # A3: 无 CSRF 校验
            to = int(form.get("to", 2))
            amt = int(form.get("amount", 0))
            DB.execute("UPDATE users SET balance=balance-? WHERE id=?", (amt, uid))
            DB.execute("UPDATE users SET balance=balance+? WHERE id=?", (amt, to))
            DB.commit()
            return self._send(200, json.dumps({"ok": True, "balance": money(uid)}))
        return self._send(404, "not found")


if __name__ == "__main__":
    print(f"业务逻辑靶场 listening on 127.0.0.1:{PORT}")
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
