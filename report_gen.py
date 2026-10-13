"""报告生成器：把发现转成【可提交级别】的漏洞报告（Markdown）。

用法:
  python report_gen.py --findings findings.json --project "项目名" [--target 目标]
                       [--author 提交人] [--out report.md]

findings.json 支持两种格式：
  A) [{"id":"B1","name":"水平越权","category":"越权","severity":"高","target":"https://x",
       "desc":"...","steps":["1 ...","2 ..."],"evidence":"请求/响应片段","impact":"...","fix":"..."}]
  B) 兼容 lab_attack 产出的 [{"id","name","hit","evidence",...}]（自动降级填充）
"""
import argparse
import json
import pathlib
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

SEV_ORDER = {"严重": 0, "高": 1, "中": 2, "低": 3, "信息": 4}
SEV_TAG = {"严重": "Critical", "高": "High", "中": "Medium", "低": "Low", "信息": "Info"}


def norm(f, idx):
    """把两种输入格式统一成报告用结构。"""
    return {
        "id": f.get("id") or f"VULN-{idx:02d}",
        "name": f.get("name") or f.get("title") or "未命名漏洞",
        "category": f.get("category") or f.get("cat") or "未分类",
        "severity": f.get("severity") or f.get("level") or "中",
        "target": f.get("target") or "",
        "desc": f.get("desc") or f.get("description") or "（待补充：漏洞原理与触发条件）",
        "steps": f.get("steps") or [f"（待补充：复现步骤）原始证据：{str(f.get('evidence',''))[:200]}"],
        "evidence": f.get("evidence") or "（待补充：请求包 / 响应片段）",
        "impact": f.get("impact") or "（待补充：攻击者可利用此漏洞做什么、影响范围）",
        "fix": f.get("fix") or "（待补充：修复建议，要具体到代码/配置层面）",
    }


def render(items, project, target, author):
    items.sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))
    now = time.strftime("%Y-%m-%d")
    out = []
    out.append(f"# {project} 漏洞测试报告\n")
    out.append(f"- **测试目标**：{target or '（待填写）'}")
    out.append(f"- **测试时间**：{now}")
    out.append(f"- **报告人**：{author}")
    out.append(f"- **漏洞总数**：{len(items)}（按危害降序）\n")
    out.append("## 漏洞汇总\n")
    out.append("| # | 漏洞名称 | 类别 | 危害等级 | 影响资产 |")
    out.append("|---|---|---|---|---|")
    for i, it in enumerate(items, 1):
        out.append(f"| {i} | {it['name']} | {it['category']} | **{it['severity']}** | {it['target'] or target} |")
    out.append("")
    for i, it in enumerate(items, 1):
        out.append(f"\n---\n\n## {i}. {it['name']}　[{it['severity']} / {SEV_TAG.get(it['severity'],'')}]\n")
        out.append(f"- **漏洞编号**：{it['id']}")
        out.append(f"- **漏洞类别**：{it['category']}")
        out.append(f"- **影响资产**：{it['target'] or target or '（待填写）'}")
        out.append(f"- **危害等级**：{it['severity']}\n")
        out.append("### 漏洞描述\n")
        out.append(it["desc"] + "\n")
        out.append("### 复现步骤\n")
        steps = it["steps"] if isinstance(it["steps"], list) else [str(it["steps"])]
        for n, s in enumerate(steps, 1):
            out.append(f"{n}. {s}")
        out.append("\n### 证据\n")
        out.append("```\n" + str(it["evidence"])[:2000] + "\n```\n")
        out.append("### 危害说明\n")
        out.append(it["impact"] + "\n")
        out.append("### 修复建议\n")
        out.append(it["fix"] + "\n")
    out.append("\n---\n\n## 说明\n")
    out.append("1. 本次测试在**授权范围内**进行，未做破坏性测试、未访问或下载任何个人数据。")
    out.append("2. 全部结论均**可复现**；如需配合验证，请按上述步骤在测试环境重放。")
    out.append("3. 建议按危害等级顺序修复；高危项建议 24 小时内处理。\n")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--project", default="漏洞测试")
    ap.add_argument("--target", default="")
    ap.add_argument("--author", default="（提交人）")
    ap.add_argument("--out", default="")
    ap.add_argument("--min-severity", default="低", help="低于此等级的不写入报告（低/中/高/严重）")
    a = ap.parse_args()

    raw = json.loads(pathlib.Path(a.findings).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("findings", [])
    # 兼容 lab_attack 格式：只有 hit=True 的算发现
    raw = [x for x in raw if x.get("hit", True)]
    items = [norm(x, i) for i, x in enumerate(raw, 1)]
    keep = [x for x in items if SEV_ORDER.get(x["severity"], 9) <= SEV_ORDER.get(a.min_severity, 3)]
    dropped = len(items) - len(keep)

    md = render(keep, a.project, a.target, a.author)
    out = pathlib.Path(a.out) if a.out else (pathlib.Path(__file__).resolve().parent / "reports" /
                                             f"报告-{a.project}-{time.strftime('%Y%m%d-%H%M')}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(f"报告已生成: {out}")
    print(f"  收录 {len(keep)} 条（丢弃低价值 {dropped} 条）")
    for it in keep:
        print(f"    [{it['severity']}] {it['id']} {it['name']}")
    print("\n提醒：必填项里有“（待补充）”，提交前必须补全，否则会被驳回。")


if __name__ == "__main__":
    main()
