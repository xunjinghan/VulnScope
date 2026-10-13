"""评分器：把我的靶场发现与豆包的 LAB-MANIFEST.md 对照，算命中率/漏报/误报。

用法: python lab_score.py <LAB-MANIFEST.md> [lab_findings.json]
"""
import json
import pathlib
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

HERE = pathlib.Path(__file__).resolve().parent
manifest_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None
findings_path = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "lab_findings.json"

if not manifest_path or not manifest_path.exists():
    print("用法: python lab_score.py <LAB-MANIFEST.md> [lab_findings.json]")
    sys.exit(1)

text = manifest_path.read_text(encoding="utf-8", errors="replace")

# 解析清单里的漏洞编号：兼容 "A1"、"A1."、"### A1"、"| A1 |" 等写法
ids = set(re.findall(r"\b([A-I][1-9])\b", text))
print(f"清单解析：识别到 {len(ids)} 个编号 -> {sorted(ids)}")
if not ids:
    print("⚠️ 没解析到编号；请检查清单格式（期望形如 A1 / B2 / C3 …）")
    sys.exit(2)

findings = json.loads(findings_path.read_text(encoding="utf-8"))
hit_ids = {f["id"] for f in findings if f.get("hit")}
checked_ids = {f["id"] for f in findings}

tp = sorted(ids & hit_ids)
fn = sorted(ids - hit_ids)                    # 清单里有、我没发现 = 漏报
fp = sorted(hit_ids - ids)                    # 我报了、清单里没有 = 误报
missed_checks = sorted(ids - checked_ids)     # 清单里有、我根本没测 = 未覆盖

total = len(ids)
print(f"\n=== 能力体检结果 ===")
print(f"  清单漏洞总数      : {total}")
print(f"  我命中(TP)        : {len(tp)}  {tp}")
print(f"  漏报(FN)          : {len(fn)}  {fn}")
print(f"  未覆盖(没测)      : {len(missed_checks)}  {missed_checks}")
print(f"  误报(FP)          : {len(fp)}  {fp}")
if total:
    print(f"\n  命中率 = {len(tp)}/{total} = {len(tp)/total*100:.1f}%")
    covered = total - len(missed_checks)
    if covered:
        print(f"  已测项命中率 = {len(tp)}/{covered} = {len(tp)/covered*100:.1f}%")

print("\n=== 逐条对照 ===")
for f in findings:
    mark = "🎯" if f["id"] in ids and f.get("hit") else ("❓" if f["id"] in ids else "·")
    flag = "命中" if (f["id"] in ids and f.get("hit")) else ("漏报(清单有我没发现)" if f["id"] in ids else "非清单项")
    print(f"  {mark} [{f['id']}] {f['name']} —— {flag}")

if fn:
    print("\n⚠️ 漏报明细（这些是我该发现却没发现的）：")
    for i in fn:
        line = next((l.strip() for l in text.splitlines() if re.search(rf"\b{i}\b", l)), "")
        print(f"  [{i}] {line[:140]}")
