"""shoucuo-vuln-bot 统一 CLI 入口。

用法:
  python main.py scan <URL> [--max-pages 25] [--out report.md]
  python main.py recon <URL>
  python main.py verify <URL> --vuln <type>
  python main.py evidence list [--status confirmed]
  python main.py evidence export <output.json>
  python main.py guard check <URL>
  python main.py intercept check "<command>"
  python main.py llm-pool status

设计原则:
- 所有子命令共享 guard.py 安全护栏
- 扫描结果自动存入 evidence.py 结构化证据库
- 危险操作经过 intercept.py 拦截审批
"""
import argparse
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def cmd_scan(args):
    from scan import main as scan_main
    sys.argv = ["scan.py", args.target, "--max-pages", str(args.max_pages)]
    if args.out:
        sys.argv += ["--out", args.out]
    if args.no_ai:
        sys.argv += ["--no-ai"]
    scan_main()


def cmd_recon(args):
    from guard import assert_target_allowed
    assert_target_allowed(args.target)
    from recon import run_recon
    run_recon(args.target)


def cmd_verify(args):
    from guard import assert_target_allowed
    assert_target_allowed(args.target)
    from verify import verify_vuln
    verify_vuln(args.target, args.vuln)


def cmd_evidence_list(args):
    from evidence import EvidenceStore
    store = EvidenceStore()
    # 修复：EvidenceStore 暴露的是 list_all() / list_by_status()，原实现调用了不存在的 list()
    evidences = store.list_by_status(args.status) if args.status else store.list_all()
    if not evidences:
        print("(无证据记录)")
        return
    for e in evidences:
        print(f"[{e.vuln_id}] {e.vuln_type} ({e.severity}) {e.endpoint} status={e.status} sha256={e.sha256[:12]}...")


def cmd_evidence_export(args):
    from evidence import EvidenceStore
    store = EvidenceStore()
    # 修复：export_report() 返回的是写入路径（字符串），不是带 total 的 dict
    path = store.export_report(args.output)
    print(f"已导出 {len(store.list_all())} 条证据到 {path}")


def cmd_guard_check(args):
    from guard import assert_target_allowed
    try:
        assert_target_allowed(args.target)
        print(f"[ALLOW] {args.target}")
    except Exception as e:
        print(f"[BLOCK] {e}")


def cmd_intercept_check(args):
    from intercept import Interceptor
    inter = Interceptor()
    decision = inter.check("shell", args.command)
    print(f"[{decision.action.upper()}] rule={decision.rule_id} reason={decision.reason}")


def cmd_llm_pool_status(args):
    from llm_pool import default_pool
    pool = default_pool()
    # 修复：LLMPool 的公开接口是 health_check()（返回 {name: {...}}），
    # 原实现访问了不存在的 pool.models / pool.get_circuit()
    health = pool.health_check()
    print("模型池状态:")
    for name, info in health.items():
        state = info.get("state") or {}
        print(f"  {info.get('provider')}/{name} priority={info.get('priority')} "
              f"available={info.get('available')} failures={state.get('failures', 0)}")


def main():
    parser = argparse.ArgumentParser(prog="vulnscope", description="shoucuo-vuln-bot AI 自动化漏洞挖掘工具集")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="AI 自动化漏洞扫描")
    p_scan.add_argument("target")
    p_scan.add_argument("--max-pages", type=int, default=25)
    p_scan.add_argument("--out", default="")
    p_scan.add_argument("--no-ai", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    # recon
    p_recon = sub.add_parser("recon", help="攻击面侦察")
    p_recon.add_argument("target")
    p_recon.set_defaults(func=cmd_recon)

    # verify
    p_verify = sub.add_parser("verify", help="漏洞验证")
    p_verify.add_argument("target")
    p_verify.add_argument("--vuln", required=True, help="漏洞类型，如 sqli/xss/ssrf")
    p_verify.set_defaults(func=cmd_verify)

    # evidence
    p_ev = sub.add_parser("evidence", help="结构化证据管理")
    ev_sub = p_ev.add_subparsers(dest="ev_cmd", required=True)
    p_ev_list = ev_sub.add_parser("list", help="列出证据")
    p_ev_list.add_argument("--status", default="", help="按状态筛选")
    p_ev_list.set_defaults(func=cmd_evidence_list)
    p_ev_exp = ev_sub.add_parser("export", help="导出证据报告")
    p_ev_exp.add_argument("output", help="输出 JSON 文件路径")
    p_ev_exp.set_defaults(func=cmd_evidence_export)

    # guard
    p_guard = sub.add_parser("guard", help="安全护栏检查")
    guard_sub = p_guard.add_subparsers(dest="guard_cmd", required=True)
    p_gc = guard_sub.add_parser("check", help="检查目标是否允许")
    p_gc.add_argument("target")
    p_gc.set_defaults(func=cmd_guard_check)

    # intercept
    p_int = sub.add_parser("intercept", help="操作拦截检查")
    int_sub = p_int.add_subparsers(dest="int_cmd", required=True)
    p_ic = int_sub.add_parser("check", help="检查命令是否危险")
    p_ic.add_argument("command")
    p_ic.set_defaults(func=cmd_intercept_check)

    # llm-pool
    p_pool = sub.add_parser("llm-pool", help="模型连接池状态")
    pool_sub = p_pool.add_subparsers(dest="pool_cmd", required=True)
    p_ps = pool_sub.add_parser("status", help="查看模型池状态")
    p_ps.set_defaults(func=cmd_llm_pool_status)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
