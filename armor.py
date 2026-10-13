"""ARMOR —— 授权范围护栏 + 危害定级器（一个文件，两件事）

护栏（scope）：
  from armor import assert_allowed
  assert_allowed("https://app.example.com/x")   # 不在范围 → 抛异常，拒绝测试
  规则：① 永远允许回环/RFC1918（本地靶场）② scope.json 里且未过期 → 允许 ③ 其余一律拒绝

定级（severity）：
  from armor import classify
  classify({"name":"SQL注入(UNION)","category":"注入"})  ->  ("高", "可读取数据库内容")
  按"真实赏金视角"判级：可获数据/可进内网/可RCE = 高以上；只有展示无实害 = 低/信息

命令行:
  python armor.py check <url_or_host>
  python armor.py sev findings.json            # 给 findings 补 severity 字段
"""
import ipaddress
import json
import pathlib
import socket
import sys
import time
from urllib.parse import urlparse

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

HERE = pathlib.Path(__file__).resolve().parent
SCOPE_FILE = HERE / "scope.json"


class OutOfScope(Exception):
    """目标不在授权范围内 —— 必须停手。"""


# ---------------------------------------------------------------- 护栏
def _load_scope():
    if not SCOPE_FILE.exists():
        return {"projects": []}
    try:
        return json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        raise OutOfScope(f"scope.json 解析失败，为安全起见拒绝一切测试: {e}") from e


def _host_of(target):
    t = target.strip()
    if "://" not in t:
        t = "http://" + t
    h = urlparse(t).hostname or ""
    return h.lower().rstrip(".")


def _is_private_or_loopback(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        pass
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    # 域名形式也要解析一次
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_loopback or ip.is_private or ip.is_link_local:
                return True
    except Exception:  # noqa: BLE001
        pass
    return False


def _match(pattern, host):
    p = pattern.lower().strip()
    if p.startswith("*."):
        return host.endswith(p[1:]) and host != p[2:]
    if p.startswith("."):
        return host.endswith(p)
    return host == p


def check(target):
    """返回 (是否允许, 原因, 命中的项目名)。"""
    host = _host_of(target)
    if not host:
        return False, "无法解析目标主机名", None
    if _is_private_or_loopback(host):
        return True, "本地/内网靶场（始终允许）", "lab"
    scope = _load_scope()
    for proj in scope.get("projects", []):
        exp = proj.get("expires")
        if exp:
            try:
                if time.strptime(exp, "%Y-%m-%d") < time.localtime()[:3] + (0, 0, 0, 0, 0, 0):
                    continue
            except Exception:  # noqa: BLE001
                pass
        for pat in proj.get("out_of_scope", []):
            if _match(pat, host):
                return False, f"命中 out_of_scope（{pat}）", proj.get("name")
        for pat in proj.get("in_scope", []):
            if _match(pat, host):
                return True, f"命中 in_scope（{pat}）", proj.get("name")
    return False, "不在任何授权项目范围内 → 拒绝测试", None


def assert_allowed(target):
    ok, why, proj = check(target)
    if not ok:
        raise OutOfScope(f"[护栏拦截] {target} → {why}")
    return why, proj


# ---------------------------------------------------------------- 定级
# 规则: 关键字/类别 → (等级, 理由)。按"真实赏金视角"排序，先匹配先返回。
RULES = [
    (("rce", "命令注入", "反序列化", "任意文件写入", "远程代码"), "严重", "可获得服务器控制权"),
    (("sql注入", "sqli", "union"), "高", "可读取数据库内容（数据泄露）"),
    (("越权", "idor", "水平", "垂直"), "高", "可读取/操作他人数据"),
    (("ssrf",), "高", "可探测/访问内网，危害取决于内网可达面"),
    (("上传",), "高", "可能直接获得 webshell"),
    (("认证绕过", "登录绕过", "弱口令"), "高", "可未授权进入系统"),
    (("路径穿越", "目录穿越", "任意文件读取"), "中", "可读取服务器文件（非代码执行）"),
    (("ssti", "模板注入"), "高", "通常可升级为 RCE"),
    (("xxe",), "中", "可读文件或 SSRF"),
    (("存储型", "stored"), "中", "可影响其他用户/管理员"),
    (("csim", "csrf"), "中", "可诱导已登录用户执行敏感操作"),
    (("逻辑", "支付", "金额", "负数", "竞态", "状态机", "幂等", "优惠券"), "中", "可造成资金/业务损失"),
    (("cors",), "中", "配合凭据可跨域读取数据"),
    (("host头", "host注入"), "中", "可污染密码重置链接"),
    (("反射型", "reflected", "xss"), "低", "需诱导交互，实害有限"),
    (("信息泄露", "traceback", "debug", "备份"), "低", "泄露实现细节（无敏感数据时）"),
    (("响应头", "header", "版本"), "信息", "低价值，通常不收录"),
]


def classify(finding):
    # 中文/英文混排常带空格（"SQL 注入"），先去掉所有空格再匹配，否则关键字失配
    hay = " ".join(str(finding.get(k, "")) for k in ("name", "category", "desc", "evidence")).lower()
    hay = hay.replace(" ", "").replace("\u3000", "")
    for keys, sev, why in RULES:
        if any(k.lower() in hay for k in keys):
            return sev, why
    return "中", "未匹配到规则，需人工判定"


# ---------------------------------------------------------------- CLI
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "check":
        for t in sys.argv[2:]:
            ok, why, proj = check(t)
            print(f"  {'✅ 允许' if ok else '⛔ 拒绝'}  {t}  —  {why}" + (f"  [{proj}]" if proj else ""))
        return
    if cmd == "sev":
        p = pathlib.Path(sys.argv[2])
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data = data.get("findings", [])
        for f in data:
            if not f.get("severity"):
                s, why = classify(f)
                f["severity"], f["severity_reason"] = s, why
        out = p.with_name(p.stem + "-sev.json")
        out.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        from collections import Counter
        cnt = Counter(f["severity"] for f in data)
        print(f"已定级 → {out}")
        for s in ("严重", "高", "中", "低", "信息"):
            if cnt.get(s):
                print(f"    {s}: {cnt[s]} 条")
        print("\n  明细（前 15 条）:")
        for f in data[:15]:
            print(f"    [{f['severity']}] {f.get('id','')} {f.get('name','')[:40]}  — {f.get('severity_reason','')}")
        return
    print(__doc__)


if __name__ == "__main__":
    main()
