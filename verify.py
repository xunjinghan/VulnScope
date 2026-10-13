"""验证器：非破坏性地证明「漏洞到底能不能被利用」。

与 scan.py 的区别：
  scan.py  只做**判定**（AI 给线索），不发攻击请求
  verify.py 真的发请求验证，但**严格非破坏性**

三条硬禁令（写死在代码里，不是文档里的建议）：
  1. 载荷里禁止出现任何会修改数据的 SQL 关键字（DROP/DELETE/UPDATE/INSERT/ALTER/...）
  2. 默认只发 GET（幂等、只读）；只有「登录类」端点允许 POST，且用不存在的账号，不产生数据
  3. 不跑暴力破解、不压测、不高并发（每次请求间隔 sleep）

所有请求同样过 guard.py：目标必须是 localhost/内网。
"""
import argparse
import datetime
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from guard import assert_target_allowed

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

UA = "DSH-VulnHunt-Verify/0.1 (authorized-lab-only, non-destructive)"
DELAY = 0.35
TIMEOUT = 12
MARK = "dsh7f3a"

FORBIDDEN = re.compile(r"\b(drop|delete|update|insert|alter|truncate|attach|detach|pragma|grant|revoke|replace|merge|exec|execute|xp_|sp_|into\s+outfile|load_file)\b", re.I)
SQL_ERR = re.compile(r"(sql syntax|sqlite3\.operationalerror|sqlite3\.|unrecognized token|near \"|syntax error|mysql_|pg_query|odbc|jdbc|sqlstate)", re.I)
TRACE_ERR = re.compile(r"(traceback \(most recent call last\)|file \"[^\"]+\", line \d+|at [a-z0-9_.$]+\([a-z0-9_.$]+\.java:\d+\)|werkzeug\.debug)", re.I)
PII_HINT = re.compile(
    r"("
    r"[\w.+-]+@[\w-]+\.[\w.]{2,}"                      # 真实邮箱值
    r"|\b1[3-9]\d{9}\b"                                 # 真实手机号值
    r"|\b(api[_-]?key|access[_-]?token|secret)\b\s*[:=]\s*\S+"  # 键值对形态的凭据
    r"|余额\s*[:：]\s*\d"                                 # 余额带数字
    r")", re.I)


def check_payload(p: str):
    if FORBIDDEN.search(p):
        raise ValueError(f"载荷被禁令拦截（含改数据关键字）: {p}")


def request(url: str, method: str = "GET", data: dict | None = None, timeout: int = TIMEOUT):
    """发一个请求；返回 (status, headers, text, error)。全部经护栏校验。"""
    assert_target_allowed(url)
    body = None
    headers = {"User-Agent": UA, "Accept": "*/*"}
    if method == "POST":
        body = urllib.parse.urlencode(data or {}).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(200_000).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(200_000).decode("utf-8", "replace"), None
    except Exception as e:  # noqa: BLE001
        return None, {}, "", str(e)


def with_param(url: str, name: str, value: str) -> str:
    p = urllib.parse.urlparse(url)
    q = dict(urllib.parse.parse_qsl(p.query))
    q[name] = value
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(q)))


def snippet(t: str, n: int = 220) -> str:
    t = re.sub(r"\s+", " ", t).strip()
    return t[:n]


# ---------------- 各类探针 ----------------

def classify_reflection(body: str, label: str = "反射检查"):
    """判定反射形态（GET/POST 复用）。"""
    payload = f'{MARK}"><i>x</i>'
    if MARK not in body:
        return {"probe": label, "verdict": "未反射", "detail": "提交的值没有回显到响应里", "evidence": snippet(body)}
    if payload in body:
        return {"probe": label, "verdict": "❌ 已证实：反射未转义（XSS）",
                "detail": f"载荷 {payload!r} 原样出现在响应中，尖括号与引号都未被编码",
                "evidence": snippet(body)}
    if ("&lt;i&gt;" in body) or ("&#34;" in body) or ("&quot;" in body) or ("&lt;" in body):
        return {"probe": label, "verdict": "✅ 有输出编码", "detail": "反射存在，但尖括号/引号已被转义", "evidence": snippet(body)}
    return {"probe": label, "verdict": "⚠️ 疑似", "detail": "有反射但形态不明确，需人工看上下文", "evidence": snippet(body)}


def probe_reflection(url, name):
    """XSS：看参数值是否原样反射且未转义。"""
    payload = f'{MARK}"><i>x</i>'
    check_payload(payload)
    st, _, body, err = request(with_param(url, name, payload))
    time.sleep(DELAY)
    if err:
        return None
    return classify_reflection(body)


def probe_sql(url, name, baseline):
    """SQL 注入：只做【报错特征】与【布尔差异】两类只读探测。"""
    out = []
    p_err = f"{MARK}'"
    check_payload(p_err)
    st, _, body, err = request(with_param(url, name, p_err))
    time.sleep(DELAY)
    if not err and SQL_ERR.search(body):
        m = SQL_ERR.search(body)
        out.append({"probe": "SQL 报错特征", "verdict": "❌ 已证实：数据库报错回显",
                    "detail": f"载荷 {p_err!r} 触发了数据库错误特征 {m.group(0)!r}",
                    "evidence": snippet(body)})
    elif not err and TRACE_ERR.search(body):
        out.append({"probe": "异常堆栈回显", "verdict": "⚠️ 疑似：异常细节泄露",
                    "detail": "载荷触发了异常堆栈回显（不是数据库错误，但泄露实现细节，且常与注入点同源）",
                    "evidence": snippet(body)})
    # 布尔差异（仅当原始值是数字）
    if baseline and baseline.isdigit():
        a = with_param(url, name, f"{baseline} AND 1=1")
        b = with_param(url, name, f"{baseline} AND 1=2")
        for p in (f"{baseline} AND 1=1", f"{baseline} AND 1=2"):
            check_payload(p)
        sa, _, ba, ea = request(a)
        time.sleep(DELAY)
        sb, _, bb, eb = request(b)
        time.sleep(DELAY)
        if not ea and not eb and sa and sb and sa == sb:
            if len(ba) != len(bb) and abs(len(ba) - len(bb)) > 10:
                out.append({"probe": "SQL 布尔差异", "verdict": "❌ 已证实：布尔注入生效",
                            "detail": f"`{baseline} AND 1=1` 响应 {len(ba)} 字节，`{baseline} AND 1=2` 响应 {len(bb)} 字节，差异显著",
                            "evidence": f"1=1 → {snippet(ba, 120)} || 1=2 → {snippet(bb, 120)}"})
            elif ba == bb:
                out.append({"probe": "SQL 布尔差异", "verdict": "✅ 未见差异", "detail": "两种布尔条件的响应完全一致", "evidence": ""})
    return out


def probe_idor(url, name, baseline):
    """越权：对比不同对象 id 的返回，看是否能拿到非预期对象的数据。"""
    if not (baseline or "").isdigit():
        return None
    base = int(baseline)
    st1, _, b1, e1 = request(with_param(url, name, str(base)))
    time.sleep(DELAY)
    st2, _, b2, e2 = request(with_param(url, name, str(base + 1)))
    time.sleep(DELAY)
    st3, _, b3, e3 = request(with_param(url, name, str(base + 99999)))
    if e1 or e2:
        return None
    same_status_ok = st1 == 200 and st2 == 200
    diff_body = b1 != b2
    if same_status_ok and diff_body:
        return {"probe": "越权(IDOR) 对比", "verdict": "❌ 已证实：可直接枚举对象",
                "detail": f"未携带任何登录态，`{name}={base}` 与 `{name}={base+1}` 均返回 200 且内容不同"
                          f"（第 3 个不存在的 id 返回 {st3}）→ 能读到非预期对象的数据",
                "evidence": f"id={base}: {snippet(b1, 140)} || id={base+1}: {snippet(b2, 140)}"}
    if same_status_ok and not diff_body:
        return {"probe": "越权(IDOR) 对比", "verdict": "⚠️ 疑似", "detail": "不同 id 返回相同内容，可能是被统一重定向/占位页，需人工确认", "evidence": snippet(b1, 140)}
    return {"probe": "越权(IDOR) 对比", "verdict": "✅ 未见越权",
            "detail": f"id={base} → {st1}，id={base+1} → {st2}", "evidence": ""}


def probe_unauth(url):
    """未授权访问：敏感页面不带任何凭据是否可直读，且含 PII 特征。"""
    st, hdr, body, err = request(url)
    time.sleep(DELAY)
    if err or st != 200:
        return None
    if PII_HINT.search(body):
        return {"probe": "未授权访问", "verdict": "⚠️ 疑似：无凭据即可读到个人信息",
                "detail": "不带任何 Cookie/凭据请求，返回 200 且响应里出现个人信息特征",
                "evidence": snippet(body)}
    return None


def probe_headers(url):
    """安全响应头（信息类，不算漏洞）。"""
    st, hdr, _, err = request(url)
    time.sleep(DELAY)
    if err:
        return None
    low = {k.lower(): v for k, v in hdr.items()}
    missing = [h for h in ("x-content-type-options", "x-frame-options", "content-security-policy") if h not in low]
    if missing:
        return {"probe": "安全响应头", "verdict": "ℹ️ 信息", "detail": "缺少响应头: " + ", ".join(missing), "evidence": ""}
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data", help="scan.py 产出的 .json（含页面与候选点），或直接给 URL")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    if args.data.startswith("http"):
        print("⚠️ 需要先跑 scan.py 生成候选点 JSON；这里只做单页检查")
        pages, cands = [{"url": args.data}], []
    else:
        payload = json.loads(pathlib.Path(args.data).read_text(encoding="utf-8"))
        pages, cands = payload["pages"], payload["candidates"]

    out_path = pathlib.Path(args.out) if args.out else (
        pathlib.Path(__file__).resolve().parent / "reports" / f"verify-{datetime.datetime.now():%Y%m%d-%H%M%S}.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"=== 非破坏性验证 · {datetime.datetime.now():%Y-%m-%d %H:%M:%S} ===")
    print(f"候选点 {len(cands)} 个，页面 {len(pages)} 个")
    print("禁令：不改数据 / 不爆破 / 只 GET（登录端点除外）\n")

    findings, results = [], []
    for i, c in enumerate(cands, 1):
        url, name = c["url"], c["name"]
        baseline = c.get("sample", "")
        print(f"[{i}/{len(cands)}] {c['method']} {url}  参数={name}")
        group = []
        try:
            if c["method"] == "GET":
                r = probe_reflection(url, name)
                if r:
                    group.append(r)
                group += probe_sql(url, name, baseline)
                r = probe_idor(url, name, baseline)
                if r:
                    group.append(r)
            else:
                # POST：只对"登录类"端点做一次无害探测（用不存在的账号）
                path = urllib.parse.urlparse(url).path.lower()
                if any(k in path for k in ("login", "signin", "auth")):
                    data = {name: f"{MARK}'", "password": f"{MARK}'"} if name == "username" else {name: f"{MARK}'"}
                    for v in data.values():
                        check_payload(v)
                    st, _, body, err = request(url, "POST", data)
                    time.sleep(DELAY)
                    if not err and SQL_ERR.search(body):
                        group.append({"probe": "登录 SQL 报错特征", "verdict": "❌ 已证实：登录处数据库报错回显",
                                      "detail": "用不存在的账号 + 单引号提交，响应回显数据库错误",
                                      "evidence": snippet(body)})
                    elif not err and TRACE_ERR.search(body):
                        group.append({"probe": "登录 异常回显", "verdict": "⚠️ 疑似：登录处回显异常堆栈",
                                      "detail": "用不存在的账号 + 单引号提交，响应出现异常堆栈",
                                      "evidence": snippet(body)})
                    elif not err:
                        r = classify_reflection(body, "登录响应反射检查")
                        if r["verdict"] == "未反射":
                            r = {"probe": "登录 SQL 报错特征", "verdict": "✅ 未见报错回显",
                                 "detail": f"POST 返回 {st}，无数据库错误特征，也未回显提交值", "evidence": snippet(body, 120)}
                        group.append(r)
                else:
                    group.append({"probe": "（跳过）", "verdict": "ℹ️ 未自动探测",
                                  "detail": "非登录类 POST 端点：涉及写操作，按非破坏性原则不自动探测", "evidence": ""})
        except Exception as e:  # noqa: BLE001
            group.append({"probe": "异常", "verdict": "⚠️ 探测失败", "detail": str(e), "evidence": ""})

        for g in group:
            g["target"] = f"{c['method']} {url} ({name})"
            results.append(g)
            if g["verdict"].startswith("❌") or g["verdict"].startswith("⚠️"):
                findings.append(g)
                print(f"     {g['verdict']}")
        if not group:
            print("     （无发现）")

    # 页面级检查
    print(f"\n[页面级] 未授权访问 / 安全响应头 检查 {len(pages)} 个页面")
    for p in pages:
        for r in (probe_unauth(p["url"]), probe_headers(p["url"])):
            if r:
                r["target"] = f"GET {p['url']}"
                results.append(r)
                findings.append(r)
                print(f"     {r['verdict']}  ({p['url']})")

    proven = [f for f in findings if f["verdict"].startswith("❌")]
    suspected = [f for f in findings if f["verdict"].startswith("⚠️")]

    lines = [
        "# 非破坏性验证报告", "",
        f"- **时间**：{datetime.datetime.now():%Y-%m-%d %H:%M:%S}",
        f"- **候选点**：{len(cands)} 个 ｜ **页面**：{len(pages)} 个",
        f"- **已证实可利用**：**{len(proven)}** 个 ｜ **疑似**：{len(suspected)} 个",
        "", "> 三条禁令（代码级）：不改数据（无 DROP/DELETE/UPDATE/INSERT）、不爆破、不压测；",
        "> 默认只发 GET，仅登录类端点允许 POST 且用不存在账号。", "",
        "---", "", f"## 一、已证实（{len(proven)}）", "",
    ]
    if proven:
        for i, f in enumerate(proven, 1):
            lines += [f"### {i}. {f['probe']} — {f['target']}", "",
                      f"- **结论**：{f['verdict']}", f"- **依据**：{f['detail']}"]
            if f["evidence"]:
                lines += ["- **证据片段**：", "```", f["evidence"], "```"]
            lines.append("")
    else:
        lines += ["（无）", ""]
    lines += [f"## 二、疑似 / 信息（{len(suspected)}）", ""]
    for f in suspected:
        lines += [f"- **{f['probe']}** — {f['target']}：{f['detail']}"]
    lines += ["", "## 三、全部探测明细", "", "| 目标 | 探针 | 结论 |", "|---|---|---|"]
    for r in results:
        lines.append(f"| `{r['target']}` | {r['probe']} | {r['verdict']} |")
    lines += ["", "## 四、说明", "",
              "- 本工具只做**非破坏性验证**：证明有洞即停，不做利用链、不取数据、不落文件。",
              "- 「已证实」= 响应里有可复现的证据；「疑似」= 需要人工看上下文确认。", ""]

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n已证实 {len(proven)} 个，疑似 {len(suspected)} 个")
    print(f"报告：{out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
