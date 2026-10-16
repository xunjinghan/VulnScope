"""安全护栏：只允许把扫描器指向 localhost / 内网地址。

这是硬性设计，不是建议：
- 任何公网目标一律拒绝（防误打到真实站点，也防手滑）
- 解析域名后逐个 IP 检查，防止 DNS 指向公网绕过

增强功能（参考 ARTEX guard 设计）：
- AuditLog: 每次目标校验记录 allow/block + 原因 + 时间戳
- FailureAttribution: 工具结果分类 blocked/error/ok，帮助调整策略
- PlatformGuardMessage: 拦截消息明确标注「平台管控·非目标防御」，避免扫描器尝试绕过
"""
import ipaddress
import json
import os
import re
import socket
import sys
import time
from collections import Counter
from urllib.parse import urlparse

# Windows 控制台默认 GBK，无法输出 ✅/❌ 这类符号 —— 统一改成 UTF-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

ALLOWED_SCHEMES = ("http", "https")

# 审计日志最大保留条数（环形缓冲）
_AUDIT_MAX = 2000
# 失败归因正则（参考 ARTEX reBlocked）
_RE_BLOCKED = re.compile(r"(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b")


# ============================================================
# 审计日志
# ============================================================
class AuditLog:
    """记录每次目标校验和工具调用的审计日志。

    参考 ARTEX guard.AuditEntry:
    - TS: 时间戳
    - Target/Action/Reason: 目标、动作(allow/block)、原因
    - 环形缓冲，最多保留 _AUDIT_MAX 条
    """

    def __init__(self, max_entries: int = _AUDIT_MAX):
        self._entries = []
        self._max = max_entries

    def record(self, target: str, action: str, reason: str = ""):
        entry = {
            "ts": int(time.time()),
            "target": target,
            "action": action,  # allow | block
            "reason": reason,
        }
        self._entries.append(entry)
        if len(self._entries) > self._max:
            self._entries = self._entries[-self._max:]

    def snapshot(self) -> list:
        """返回审计日志快照（最新的在最后）。"""
        return list(self._entries)

    def summary(self) -> dict:
        """返回 allow/block 统计。"""
        counts = Counter(e["action"] for e in self._entries)
        return {"allow": counts.get("allow", 0), "block": counts.get("block", 0)}

    def save(self, path: str):
        """保存审计日志到 JSON 文件。"""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"summary": self.summary(), "entries": self.snapshot()}, f, ensure_ascii=False, indent=2)


# 全局审计日志实例
_audit = AuditLog()


def get_audit() -> AuditLog:
    return _audit


# ============================================================
# 失败归因（参考 ARTEX Guard.postToolUse / Observer G5）
# ============================================================
class FailureAttribution:
    """分类工具执行结果，帮助调整策略而不是在 WAF 前放弃。

    分类：
    - blocked: 命中 403/WAF/rate-limit/captcha 等目标侧防御
    - error:   工具执行出错（网络错误、超时等）
    - ok:      正常返回
    """

    def __init__(self):
        self._counts = Counter()

    def classify(self, result_text: str, is_error: bool = False) -> str:
        if is_error:
            cls = "error"
        elif _RE_BLOCKED.search(result_text or ""):
            cls = "blocked"
        else:
            cls = "ok"
        self._counts[cls] += 1
        return cls

    def counts(self) -> dict:
        return dict(self._counts)

    def should_pivot(self) -> bool:
        """当 blocked 次数过多时，建议调整策略（换 payload/换端点）。"""
        b = self._counts.get("blocked", 0)
        total = sum(self._counts.values())
        return total >= 5 and b / total >= 0.6


# 全局失败归因实例
_attribution = FailureAttribution()


def get_attribution() -> FailureAttribution:
    return _attribution


# ============================================================
# 平台管控消息（参考 ARTEX systemBlockMessage）
# ============================================================
def platform_block_message(reason: str) -> str:
    """构造平台管控拦截消息。

    关键设计：明确告诉调用方「这是平台管控，不是目标防御」。
    如果只说「禁止执行」，扫描器会误以为是 WAF/403，本能地尝试绕过
    （换 payload、重编码、重试）——既无效又错误。
    """
    return (
        "【shoucuo-vuln-bot 平台管控·非目标防御】此调用被平台拦截。\n"
        f"原因：{reason}\n"
        "此操作被禁止，请换一个思路，不要尝试绕过平台管控。"
    )


# ============================================================
# 核心目标校验
# ============================================================
def _resolve_ips(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"域名解析失败: {host} ({e})")
    return sorted({i[4][0] for i in infos})


def _is_internal(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return a.is_loopback or a.is_private or a.is_link_local


def assert_target_allowed(url: str) -> str:
    """目标不合规就抛异常；合规返回归一化后的 host。

    判定顺序：
      ① 授权范围护栏 armor.check()（本地靶场 + scope.json 白名单）—— 若可用则以它为准
      ② armor 不可用时退回「只允许内网」的保守逻辑

    每次调用都会写入审计日志。
    """
    p = urlparse(url)
    if p.scheme not in ALLOWED_SCHEMES:
        reason = f"只支持 http/https，收到: {p.scheme}"
        _audit.record(url, "block", reason)
        raise ValueError(platform_block_message(reason))

    host = p.hostname
    if not host:
        reason = f"URL 缺少主机名: {url}"
        _audit.record(url, "block", reason)
        raise ValueError(platform_block_message(reason))

    # ---- ① 授权范围护栏 ----
    try:
        from armor import check as _scope_check
    except ImportError:
        _scope_check = None

    if _scope_check is not None:
        ok, why, proj = _scope_check(url)
        if ok:
            _audit.record(url, "allow", f"scope白名单: {proj}")
            return host
        reason = (
            f"{host} —— {why}\n"
            "   要把公网目标加入白名单，必须先在 scope.json 写入该项目授权范围（in_scope / out_of_scope / expires）。"
        )
        _audit.record(url, "block", why)
        raise PermissionError(platform_block_message(reason))

    # ---- ② 退回纯内网判定 ----
    if host.lower() in ("localhost",):
        _audit.record(url, "allow", "localhost")
        return host

    ips = _resolve_ips(host)
    public = [ip for ip in ips if not _is_internal(ip)]
    if public:
        reason = (
            f"{host} 解析到公网地址 {public}\n"
            "   本工具只允许 localhost / 内网网段（10.x, 172.16-31.x, 192.168.x, 127.x）。"
        )
        _audit.record(url, "block", f"公网地址: {public}")
        raise PermissionError(platform_block_message(reason))

    _audit.record(url, "allow", f"内网: {ips}")
    return host


# ============================================================
# 命令行工具
# ============================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="shoucuo-vuln-bot 安全护栏")
    parser.add_argument("urls", nargs="*", help="要校验的 URL 列表")
    parser.add_argument("--audit", action="store_true", help="显示审计日志统计")
    parser.add_argument("--save-audit", metavar="PATH", help="保存审计日志到文件")
    args = parser.parse_args()

    if args.audit:
        s = _audit.summary()
        print(f"审计统计: allow={s['allow']} block={s['block']}")
        a = get_attribution()
        print(f"失败归因: {a.counts()}")
        if a.should_pivot():
            print("⚠️  blocked 占比过高，建议调整策略")

    if args.save_audit:
        _audit.save(args.save_audit)
        print(f"审计日志已保存: {args.save_audit}")

    for u in args.urls:
        try:
            assert_target_allowed(u)
            print(f"✅ 允许: {u}")
        except Exception as e:  # noqa: BLE001
            print(f"❌ {u}\n   {e}")


# ============================================================
# 操作级安全拦截（集成 intercept.py）
# ============================================================
_interceptor = None

def _get_interceptor():
    """懒加载 Interceptor 单例。"""
    global _interceptor
    if _interceptor is None:
        try:
            from intercept import Interceptor
            _interceptor = Interceptor()
        except ImportError:
            _interceptor = False  # 标记为不可用，避免反复尝试
    return _interceptor if _interceptor is not False else None


def assert_operation_safe(tool: str, operation_input: str) -> bool:
    """操作级安全检查（集成 intercept.py）。

    在执行危险操作前调用，返回 True 表示允许，False 表示拒绝。
    与 assert_target_allowed 互补：
    - assert_target_allowed: 目标层面（只能扫内网）
    - assert_operation_safe: 操作层面（危险命令拦截）

    用法:
        if not assert_operation_safe("shell", "rm -rf /"):
            return  # 被拦截
    """
    inter = _get_interceptor()
    if inter is None:
        return True  # intercept 模块不可用时放行（不阻塞主流程）
    decision = inter.check(tool, operation_input)
    if decision.action == "deny":
        print(f"[INTERCEPT-DENY] {tool}: {decision.reason}")
        return False
    if decision.action == "ask":
        # 非交互环境下 ask 默认拒绝（安全优先）
        print(f"[INTERCEPT-ASK] {tool}: 需要人工审批，非交互模式默认拒绝")
        return False
    return True
