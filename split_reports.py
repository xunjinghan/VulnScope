"""按类别拆分 findings 并生成「每类标准样例报告」，沉淀成模板库。

用法:
  python split_reports.py                 # 扫描本目录所有 *_findings*.json，按类别拆分生成样例报告
  python split_reports.py --list          # 只列分类统计

产出: reports/_样例报告/<类别>.md  （每类一份，作为今后写报告的对照模板）
"""
import json
import pathlib
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

HERE = pathlib.Path(__file__).parent
OUT = HERE / "reports" / "_样例报告"
SRC = ["bizlab_sev", "auth_findings-enriched", "inj_findings-enriched", "weblab2_findings-enriched",
       "logic_findings-sev-enriched"]


def load_all():
    """收集所有可用的 findings（优先取 -enriched 版本）。"""
    seen, allf = set(), []
    files = sorted(HERE.glob("*findings*.json"), key=lambda p: ("enriched" not in p.name, p.name))
    for p in files:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if isinstance(data, dict):
            data = data.get("findings", [])
        for f in data:
            key = (f.get("id"), f.get("name"))
            if key in seen:
                continue
            seen.add(key)
            f["_src"] = p.name
            allf.append(f)
    return allf


def main():
    allf = load_all()
    # 归类：按 id 前缀/类别映射到 8 大类
    def klass(f):
        i = str(f.get("id", ""))
        n = str(f.get("name", ""))
        c = str(f.get("category", ""))
        # 注意顺序：先判语义明确的类别，再按 id 前缀兜底（曾因 L 前缀先判导致"凭据泄露"被误分）
        if "泄露" in c or "泄露" in n or "敏感文件" in n or "AK/SK" in n:
            return "07-凭据泄露"
        if i.startswith("U"):
            return "05-文件上传RCE"
        if "SSRF" in n or "SSRF" in c:
            return "06-SSRF"
        if "XSS" in c or "XSS" in n:
            return "08-存储型XSS"
        if "命令注入" in c or "命令注入" in n:
            return "10-命令注入"
        if "穿越" in c or "穿越" in n:
            return "09-路径穿越"
        if "越权" in c or "越权" in n or "IDOR" in n:
            return "01-越权IDOR"
        if "SQL" in n or "注入" in n or "报错" in n:
            return "04-注入取数"
        if i.startswith("G") or "逻辑" in c or "逻辑" in n:
            return "02-业务逻辑"
        if i.startswith("A"):
            return "03-认证与会话"
        return "99-其他"

    groups = {}
    for f in allf:
        groups.setdefault(klass(f), []).append(f)

    if "--list" in sys.argv:
        for k in sorted(groups):
            print(f"  {k}: {len(groups[k])} 条")
        print(f"合计 {len(allf)} 条")
        return

    OUT.mkdir(parents=True, exist_ok=True)
    made = []
    for k in sorted(groups):
        items = groups[k]
        tmp = HERE / f"_tmp_{k.replace('/', '_')}.json"
        tmp.write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
        cmd = [sys.executable, str(HERE / "report_gen.py"), "--findings", str(tmp),
               "--project", f"样例报告·{k}", "--target", items[0].get("target", "-"),
               "--author", "DSH", "--min-severity", "低", "--out", str(OUT / f"{k}.md")]
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        ok = (OUT / f"{k}.md").exists()
        made.append((k, len(items), ok, (r.stdout or "").strip().splitlines()[-1] if r.stdout else ""))
        tmp.unlink(missing_ok=True)

    print("\n=== 样例报告生成结果 ===")
    for k, n, ok, msg in made:
        print(f"  {'✅' if ok else '❌'} {k:<18} {n} 条  {msg[:60]}")
    print(f"输出目录: {OUT}")


if __name__ == "__main__":
    main()
