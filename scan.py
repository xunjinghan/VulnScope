"""AI 自动化漏洞渗透 —— 主流程

  python scan.py <目标URL> [--max-pages 25] [--chunk 12] [--out report.md] [--no-ai]

流程：安全护栏 → 爬虫抽攻击面候选点 → 分批交给豆包判定 → 生成 Markdown 报告
硬约束：目标必须是 localhost/内网（guard.py），公网一律拒绝。
"""
import argparse
import datetime
import json
import pathlib
import sys

# Windows 控制台默认 GBK，无法输出 ✅/❌/⚠️ —— 统一改成 UTF-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

from crawl import crawl
from guard import assert_target_allowed
from llm import ask_doubao, available

PROMPT_TMPL = """你是 Web 安全测试助手。下面是从一个【授权靶场】抓到的攻击面候选点（JSON 数组）。
请逐个判断。要求严格按格式输出，不要输出其它内容，不要编造未给出的 URL。

候选点：
{payload}

输出格式（每个候选点一段，编号对应输入顺序）：
[1] URL=<url> 参数=<name>（<kind>/<method>）
漏洞类型：<(反射型XSS/SQL注入/越权IDOR/CSRF缺失/信息泄露/开放重定向/无明显问题) 之一>
可能性：<高|中|低>
理由：<一句话>
下一步：<一句话，具体验证动作>
"""


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--max-pages", type=int, default=25)
    ap.add_argument("--chunk", type=int, default=12, help="每次交给 AI 的候选点数量")
    ap.add_argument("--out", default="")
    ap.add_argument("--no-ai", action="store_true", help="只爬取，不做 AI 判定")
    args = ap.parse_args()

    target = args.target if "://" in args.target else "http://" + args.target
    out_path = pathlib.Path(args.out) if args.out else (
        pathlib.Path(__file__).resolve().parent / "reports" / f"report-{datetime.datetime.now():%Y%m%d-%H%M%S}.md"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"=== AI 自动化漏洞渗透 · {now()} ===")
    print(f"[1/4] 安全护栏校验: {target}")
    try:
        host = assert_target_allowed(target)
        print(f"      ✅ 允许（{host} 属于 localhost/内网）")
    except Exception as e:  # noqa: BLE001
        print(f"      ❌ 拒绝执行\n{e}")
        return 2

    print(f"[2/4] 爬取中（最多 {args.max_pages} 页）…")
    result = crawl(target, max_pages=args.max_pages)
    pages, cands = result["pages"], result["candidates"]
    print(f"      页面 {len(pages)} 个，攻击面候选点 {len(cands)} 个")

    ai_sections = []
    if args.no_ai or not cands:
        print("[3/4] 跳过 AI 判定")
    else:
        if not available():
            print("      ⚠️ 豆包通道不可用（node 或 doubao-cdp.mjs 缺失），跳过 AI 判定")
        else:
            print(f"[3/4] 交给豆包判定（每批 {args.chunk} 个，共 {(len(cands)+args.chunk-1)//args.chunk} 批）…")
            for i in range(0, len(cands), args.chunk):
                batch = cands[i:i + args.chunk]
                payload = json.dumps(batch, ensure_ascii=False, indent=1)
                print(f"      批 {i//args.chunk + 1}: {len(batch)} 个候选点 …", end="", flush=True)
                try:
                    ans = ask_doubao(PROMPT_TMPL.format(payload=payload))
                    ai_sections.append(ans)
                    print(" ok")
                except Exception as e:  # noqa: BLE001
                    ai_sections.append(f"（AI 判定失败：{e}）")
                    print(f" 失败: {e}")

    print("[4/4] 生成报告…")
    lines = [
        "# AI 自动化漏洞渗透报告",
        "",
        f"- **目标**：`{target}`",
        f"- **时间**：{now()}",
        f"- **爬取页面**：{len(pages)} 个",
        f"- **攻击面候选点**：{len(cands)} 个",
        f"- **AI 大脑**：本机豆包（CDP 通道）" if ai_sections else "- **AI 大脑**：（未使用）",
        "",
        "> ⚠️ 本工具**只能指向 localhost/内网**（guard.py 硬校验）。",
        "> AI 判定是**线索**不是结论，必须人工复核后再下结论。",
        "",
        "---",
        "",
        "## 一、AI 判定",
        "",
    ]
    if ai_sections:
        for s in ai_sections:
            lines += [s, ""]
    else:
        lines += ["（未启用或没有候选点）", ""]
    lines += ["---", "", "## 二、页面清单", "", "| 状态 | URL | 标题 | 字节 |", "|---|---|---|---|"]
    for p in pages:
        lines.append(f"| {p['status']} | `{p['url']}` | {p['title']} | {p['bytes']} |")
    lines += ["", "## 三、攻击面候选点原始清单", "", "| # | 类型 | 方法 | URL | 参数 | 来源 |", "|---|---|---|---|---|---|"]
    for i, c in enumerate(cands, 1):
        lines.append(f"| {i} | {c['kind']} | {c['method']} | `{c['url']}` | `{c['name']}` | {c['source']} |")
    lines += ["", "## 四、下一步（人工）", "",
              "1. 对「可能性=高」的候选点，用 Burp/ZAP 手工验证并留请求包证据",
              "2. 越权类：确认能否读到**他人**数据（不是接口存在就算）",
              "3. XSS 类：确认是否能执行（弹窗/PoC），注意反射点上下文",
              "4. 验证结果写回报告，标注「已确认 / 误报 / 待验证」", ""]

    out_path.write_text("\n".join(lines), encoding="utf-8")
    json_path = out_path.with_suffix(".json")
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"      ✅ 报告：{out_path}")
    print(f"      ✅ 原始数据：{json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
