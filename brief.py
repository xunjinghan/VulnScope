"""开工简报：把「能力」从文件里灌进上下文。

用法:
  python brief.py            # 完整简报
  python brief.py -s         # 简短版（只看统计与最近教训）
"""
import json
import pathlib
import sqlite3
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

HERE = pathlib.Path(__file__).resolve().parent
DB = HERE / "knowledge.db"
SHORT = "-s" in sys.argv


def line(c="-"):
    print(c * 60)


line("=")
print("  DSH 漏洞挖掘 · 开工简报")
line("=")

# ---------- 1) 经验数据库 ----------
if DB.exists():
    c = sqlite3.connect(DB)
    print("\n[1] 经验数据库")
    for t, label in (("campaigns", "战役"), ("findings", "发现"), ("techniques", "技术"), ("lessons", "教训")):
        n = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"    {label}: {n} 条")
    print("\n    最近教训（必须记住的坑）:")
    for r in c.execute("SELECT lesson FROM lessons ORDER BY id DESC LIMIT 8"):
        print(f"      - {r[0][:110]}")
    if not SHORT:
        print("\n    技术库（按类别）:")
        for cat, n in c.execute("SELECT category, COUNT(*) FROM techniques GROUP BY category ORDER BY 2 DESC"):
            print(f"      [{cat}] {n}")
else:
    print("\n[1] 经验数据库不存在 → 先跑 kdb.py init && kdb.py seed")

# ---------- 2) 工具清单 ----------
print("\n[2] 我的脚本（存在的才能用）")
scripts = ["guard.py", "crawl.py", "param_discover.py", "lab_attack.py", "logic_verify.py",
           "session_strength.py", "auth_attack.py", "advanced_probe.py", "scan.py",
           "verify.py", "targeted_attack.py", "kdb.py", "report_gen.py", "brief.py"]
have, miss = [], []
for s in scripts:
    (have if (HERE / s).exists() else miss).append(s)
print("    ✅ " + " ".join(have))
print("    ❌ " + (" ".join(miss) if miss else "（无缺失）"))

# ---------- 3) 靶场 ----------
print("\n[3] 靶场")
for name, path, note in (
    ("自建靶场(8095)", HERE / "lab_findings.json", "26 项植入漏洞"),
    ("DVWA/bWAPP", HERE / "PLAYBOOK.md", "Kali 内 Apache"),
    ("Metasploitable2", HERE / "PLAYBOOK.md", "192.168.56.102"),
    ("小米R4A固件", pathlib.Path(r"D:\dsh-vm\firmware"), "已解包待挖洞"),
    ("vivo Y66", pathlib.Path(r"D:\dsh-vm\apks"), "已收样本"),
):
    mark = "✅" if path.exists() else "·"
    print(f"    {mark} {name:<18} {note}")

os_reports = HERE / "reports"
print(f"    已出报告: {len(list(os_reports.glob('*.md'))) if os_reports.exists() else 0} 份")

if SHORT:
    line("=")
    sys.exit(0)

# ---------- 4) 工作流 ----------
print("\n[4] 七步工作流（缺一不可）")
for i, s in enumerate(["确认授权(scope.json)", "资产测绘", "分类攻击", "逐条验证(可复现)",
                       "危害定级(低危丢弃)", "查重", "报告 + 入库"], 1):
    print(f"    {i}. {s}")

# ---------- 5) 漏洞矩阵优先级 ----------
print("\n[5] 打什么（按价值）")
print("    A 必打: 认证绕过/越权 · 注入到RCE · SSRF · 业务逻辑 · 凭据泄露")
print("    B 次打: 存储型XSS · CSRF(有后果) · 路径穿越 · XXE · CORS+凭据")
print("    C 不收: 缺响应头 · self-XSS · 版本号泄露 · 反射型XSS(需交互)")

# ---------- 6) PLAYBOOK ----------
pb = HERE / "PLAYBOOK.md"
print("\n[6] 总纲")
if pb.exists():
    for l in pb.read_text(encoding="utf-8").splitlines():
        if l.startswith("## "):
            print("    " + l[3:])
    print(f"\n    → 完整内容: {pb}")
else:
    print("    ⚠️ PLAYBOOK.md 不存在")

line("=")
print("  开工前自问：① 授权范围是什么？② 目标冻结了吗(md5+mtime)？③ 这轮验收标准是什么？")
line("=")
