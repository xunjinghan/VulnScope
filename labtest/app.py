"""本地烟测靶场：故意留洞的最小 Web 应用 —— 只监听 127.0.0.1。

用途：验证 vulnhunt 的「爬虫 → AI 判定 → 报告」链路能否跑通。
埋的洞（刻意的，用来当靶）：
  1. /search?q=        反射型 XSS + SQL 拼接痕迹
  2. /user?id=         越权(IDOR) —— 直接换 id 就能读别人资料，含 api_key
  3. /api/user?id=     同上，JSON 接口
  4. /login (POST)     SQL 拼接 + 无 CSRF token + 明文比较
  5. /static/app.js    JS 里硬编码 key
  6. 参数非法时回显异常细节（信息泄露）
"""
import json
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

USERS = {
    1: {"id": 1, "name": "alice", "email": "alice@lab.local", "role": "user", "api_key": "LAB-KEY-ALICE-0001"},
    2: {"id": 2, "name": "bob", "email": "bob@lab.local", "role": "admin", "api_key": "LAB-KEY-BOB-0002"},
}

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Lab Shop</title></head><body>
<h1>Lab Shop（故意有洞的靶场）</h1>
<ul>
  <li><a href="/search?q=shoes">搜索</a></li>
  <li><a href="/user?id=1">用户资料</a></li>
  <li><a href="/api/user?id=1">用户 API</a></li>
  <li><a href="/login">登录</a></li>
</ul>
<script src="/static/app.js"></script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "LabShop/0.1"

    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/":
            return self._send(PAGE)
        if u.path == "/search":
            term = q.get("q", [""])[0]
            html = (f"<h2>搜索：{term}</h2>"
                    f"<p>SQL: SELECT * FROM items WHERE name LIKE '%{term}%'</p>")
            return self._send(html)
        if u.path == "/user":
            uid = q.get("id", ["1"])[0]
            try:
                rec = USERS.get(int(uid))
            except ValueError:
                return self._send(f"<pre>Traceback (most recent call last):\n"
                                  f"ValueError: invalid literal for int() with base 10: '{uid}'</pre>", 500)
            return self._send(f"<h2>用户 {uid}</h2><pre>{json.dumps(rec, ensure_ascii=False, indent=1)}</pre>")
        if u.path == "/api/user":
            uid = q.get("id", ["1"])[0]
            try:
                rec = USERS.get(int(uid))
            except ValueError:
                return self._send(json.dumps({"error": f"invalid id: {uid}"}), 400, "application/json")
            return self._send(json.dumps(rec, ensure_ascii=False), 200, "application/json")
        if u.path == "/login":
            return self._send('<h2>登录</h2><form method="POST" action="/login">'
                              '<input name="username"><input name="password" type="password">'
                              '<input type="submit" value="登录"></form>')
        if u.path == "/static/app.js":
            return self._send("console.log('lab app loaded');\n"
                              "// TODO: move to config\nvar API_KEY = 'LAB-KEY-ALICE-0001';\n",
                              200, "application/javascript")
        return self._send("<h1>404</h1>", 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        fields = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        if self.path == "/login":
            user = fields.get("username", [""])[0]
            pw = fields.get("password", [""])[0]
            sql = f"SELECT * FROM users WHERE name='{user}' AND pass='{pw}'"
            ok = "成功" if user == "admin" else "失败"
            return self._send(f"<p>SQL: {sql}</p><p>登录{ok}</p>")
        return self._send("<h1>404</h1>", 404)

    def log_message(self, *a):  # 静音，别刷屏
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    print(f"[lab] 靶场已启动: http://127.0.0.1:{port}/  (Ctrl+C 停止)")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
