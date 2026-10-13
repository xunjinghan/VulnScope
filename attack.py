"""一键攻击：对本地目标跑「AI 判定 → 非破坏性验证」，输出两份报告。

用法：
  python attack.py http://127.0.0.1:8080/ [--max-pages 25]
安全：所有请求都过 guard.py（只允许 localhost/内网）；验证阶段遵守 verify.py 的三条禁令。
"""
import argparse
import pathlib
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

HERE = pathlib.Path(__file__).resolve().parent
REPORTS = HERE / "reports"


def run(script: str, *args) -> int:
    cmd = [sys.executable, str(HERE / script), *args]
    print(f"\n$ python {script} {' '.join(args)}\n", flush=True)
    return subprocess.call(cmd, cwd=str(HERE))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--max-pages", type=int, default=25)
    ap.add_argument("--skip-ai", action="store_true")
    args = ap.parse_args()

    target = args.target if "://" in args.target else "http://" + args.target

    print("=" * 62)
    print(f"  AI 自动化漏洞渗透 · 目标 {target}")
    print("=" * 62)

    before = set(REPORTS.glob("report-*.json"))
    rc = run("scan.py", target, "--max-pages", str(args.max_pages))
    if rc != 0:
        print("❌ scan 阶段失败（多半是护栏拒绝了目标）")
        return rc

    new = sorted(set(REPORTS.glob("report-*.json")) - before, key=lambda p: p.stat().st_mtime)
    if not new:
        print("❌ 没找到新生成的扫描 JSON")
        return 1
    data = new[-1]
    print(f"\n>> 判定数据：{data.name}")

    rc2 = run("verify.py", str(data))
    print("\n" + "=" * 62)
    if rc2 == 0:
        print("✅ 完成：报告在 reports/ 目录")
        print("   - report-<时间戳>.md    AI 判定（线索）")
        print("   - verify-<时间戳>.md    非破坏性验证（结论+证据）")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
