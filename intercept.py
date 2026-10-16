"""操作拦截器（参考 ARTEX intercept 设计）。

核心功能：
- 规则匹配：用户可配置的拦截规则（正则匹配命令/工具调用）
- 三级决策：deny（直接拒绝）、allow（允许）、ask（人工审批）
- LLM 兜底：没有规则匹配时，可配置让 LLM 判断是否危险
- 审批日志：每次拦截都记录，可审计

设计参考 ARTEX intercept/intercept.go:
- 规则存在 JSON 文件中，用户可增删改
- 内置规则标记为 [内置]，用户可禁用但不可删除
- 审批超时默认拒绝（安全优先）
"""
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class InterceptRule:
    """拦截规则。"""

    id: str                       # 规则 ID
    name: str                     # 规则名称
    pattern: str                  # 正则表达式（匹配命令/工具输入）
    action: str                   # deny / allow / ask
    description: str = ""         # 规则说明
    builtin: bool = False         # 是否内置规则
    enabled: bool = True          # 是否启用
    priority: int = 0             # 优先级，数字越小越先匹配


@dataclass
class InterceptDecision:
    """拦截决策。"""

    action: str                   # deny / allow / ask
    rule_id: str = ""             # 匹配的规则 ID
    reason: str = ""              # 决策原因
    matched: bool = False         # 是否有规则匹配


@dataclass
class ApprovalRecord:
    """审批记录。"""

    id: str                       # 记录 ID
    tool: str                     # 工具名
    input: str                    # 输入内容（截断）
    decision: str                 # 决策
    rule_id: str = ""             # 匹配的规则
    reason: str = ""              # 原因
    approver: str = ""            # 审批者（ask 时）
    timestamp: float = field(default_factory=time.time)


class Interceptor:
    """操作拦截器。"""

    def __init__(self, config_path: str = "intercept_rules.json"):
        self._rules: list[InterceptRule] = []
        self._approvals: list[ApprovalRecord] = []
        self._config_path = config_path
        self._llm_judge = None  # 可选的 LLM 兜底判断函数
        self._ask_timeout = 300  # 人工审批超时（秒），超时默认拒绝
        self._load()

    # ============================================================
    # 规则管理
    # ============================================================
    def _load(self):
        """从文件加载规则。"""
        if not os.path.exists(self._config_path):
            self._init_builtin_rules()
            self.save()
            return
        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._rules = [InterceptRule(**r) for r in data.get("rules", [])]
        except Exception:
            self._init_builtin_rules()

    def _init_builtin_rules(self):
        """初始化内置规则（参考 ARTEX 的 [内置] 规则）。"""
        self._rules = [
            InterceptRule(
                id="builtin-001",
                name="禁止删除文件",
                pattern=r"\b(rm|del|erase|unlink|Remove-Item)\b.*(-rf?|--force|/f|/s)",
                action="deny",
                description="禁止递归强制删除文件",
                builtin=True,
                priority=0,
            ),
            InterceptRule(
                id="builtin-002",
                name="禁止格式化磁盘",
                pattern=r"\b(format|mkfs|diskpart)\b",
                action="deny",
                description="禁止格式化磁盘或分区",
                builtin=True,
                priority=0,
            ),
            InterceptRule(
                id="builtin-003",
                name="禁止修改系统关键文件",
                pattern=r"(/etc/passwd|/etc/shadow|/etc/sudoers|C:\\Windows\\System32\\config\\)",
                action="deny",
                description="禁止修改系统关键配置文件",
                builtin=True,
                priority=0,
            ),
            InterceptRule(
                id="builtin-004",
                name="禁止公网扫描",
                pattern=r"\b(nmap|masscan|zmap)\b.*(?!127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))",
                action="deny",
                description="禁止扫描公网 IP（只允许内网）",
                builtin=True,
                priority=1,
            ),
            InterceptRule(
                id="builtin-005",
                name="写操作需审批",
                pattern=r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE)\b",
                action="ask",
                description="数据库写操作需要人工审批",
                builtin=True,
                priority=2,
            ),
            InterceptRule(
                id="builtin-006",
                name="文件上传需审批",
                pattern=r"\b(curl|wget|Invoke-WebRequest)\b.*(-F|--form|--upload-file)",
                action="ask",
                description="文件上传操作需要人工审批",
                builtin=True,
                priority=2,
            ),
        ]

    def save(self):
        """保存规则到文件。"""
        data = {"rules": [asdict(r) for r in self._rules]}
        os.makedirs(os.path.dirname(self._config_path) or ".", exist_ok=True)
        with open(self._config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def add_rule(self, rule: InterceptRule):
        """添加规则。"""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)
        self.save()

    def remove_rule(self, rule_id: str) -> bool:
        """删除规则（内置规则只能禁用，不能删除）。"""
        for i, r in enumerate(self._rules):
            if r.id == rule_id:
                if r.builtin:
                    return False  # 内置规则不可删除
                self._rules.pop(i)
                self.save()
                return True
        return False

    def enable_rule(self, rule_id: str, enabled: bool):
        """启用/禁用规则。"""
        for r in self._rules:
            if r.id == rule_id:
                r.enabled = enabled
                self.save()
                return True
        return False

    def list_rules(self) -> list:
        """列出所有规则。"""
        return list(self._rules)

    # ============================================================
    # 拦截判断
    # ============================================================
    def set_llm_judge(self, func):
        """设置 LLM 兜底判断函数。

        函数签名: func(tool: str, input_text: str) -> (action: str, reason: str)
        action: deny / allow / ask
        """
        self._llm_judge = func

    def match(self, tool: str, input_text: str) -> InterceptDecision:
        """匹配规则，返回决策。

        优先级：
        1. 按优先级遍历启用的规则
        2. 正则匹配成功 → 返回该规则的决策
        3. 无规则匹配 → 如果配置了 LLM 兜底，调用 LLM 判断
        4. 否则 allow（安全优先？不，无规则匹配时默认 allow，
           因为内置规则已经覆盖了最危险的操作）
        """
        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                if re.search(rule.pattern, input_text, re.IGNORECASE):
                    return InterceptDecision(
                        action=rule.action,
                        rule_id=rule.id,
                        reason=f"匹配规则: {rule.name} — {rule.description}",
                        matched=True,
                    )
            except re.error:
                continue

        # 无规则匹配，尝试 LLM 兜底
        if self._llm_judge is not None:
            try:
                action, reason = self._llm_judge(tool, input_text)
                return InterceptDecision(
                    action=action,
                    rule_id="llm-judge",
                    reason=reason,
                    matched=True,
                )
            except Exception:
                pass

        return InterceptDecision(action="allow", matched=False)

    def check(self, tool: str, input_text: str) -> InterceptDecision:
        """检查操作是否允许（带审批记录）。"""
        decision = self.match(tool, input_text)

        # 记录审批日志
        record = ApprovalRecord(
            id=f"appr-{int(time.time()*1000)}",
            tool=tool,
            input=input_text[:500],  # 截断，避免日志过大
            decision=decision.action,
            rule_id=decision.rule_id,
            reason=decision.reason,
        )
        self._approvals.append(record)
        if len(self._approvals) > 1000:
            self._approvals = self._approvals[-1000:]

        return decision

    def is_allowed(self, tool: str, input_text: str) -> tuple[bool, str]:
        """便捷方法：返回 (是否允许, 原因)。

        ask 状态默认拒绝（安全优先，需要显式审批）。
        """
        decision = self.check(tool, input_text)
        if decision.action == "allow":
            return True, decision.reason or "无规则匹配，默认允许"
        if decision.action == "deny":
            return False, f"被拦截: {decision.reason}"
        # ask → 默认拒绝，需要显式审批
        return False, f"需要审批: {decision.reason}（超时默认拒绝）"

    # ============================================================
    # 人工审批
    # ============================================================
    def approve(self, approval_id: str, approver: str, allowed: bool):
        """人工审批某个待审批操作。"""
        for r in self._approvals:
            if r.id == approval_id and r.decision == "ask":
                r.approver = approver
                r.decision = "allow" if allowed else "deny"
                return True
        return False

    def pending_approvals(self) -> list:
        """获取待审批列表。"""
        return [r for r in self._approvals if r.decision == "ask"]

    # ============================================================
    # 统计
    # ============================================================
    def stats(self) -> dict:
        """返回拦截统计。"""
        counts = {}
        for r in self._approvals:
            counts[r.decision] = counts.get(r.decision, 0) + 1
        return {
            "total": len(self._approvals),
            "by_decision": counts,
            "rules": len(self._rules),
            "enabled_rules": sum(1 for r in self._rules if r.enabled),
        }


# ============================================================
# 命令行工具
# ============================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="shoucuo-vuln-bot 操作拦截器")
    parser.add_argument("--config", default="intercept_rules.json", help="规则配置文件")
    parser.add_argument("--list", action="store_true", help="列出所有规则")
    parser.add_argument("--stats", action="store_true", help="显示统计")
    parser.add_argument("--check", nargs=2, metavar=("TOOL", "INPUT"), help="检查某操作")
    parser.add_argument("--enable", metavar="RULE_ID", help="启用规则")
    parser.add_argument("--disable", metavar="RULE_ID", help="禁用规则")
    args = parser.parse_args()

    interceptor = Interceptor(args.config)

    if args.list:
        print("=== 拦截规则 ===")
        for r in interceptor.list_rules():
            status = "✅" if r.enabled else "❌"
            builtin = "[内置]" if r.builtin else "[自定义]"
            print(f"  {status} {builtin} {r.id} {r.name}")
            print(f"       action={r.action} pattern={r.pattern[:60]}")

    if args.stats:
        s = interceptor.stats()
        print(f"=== 拦截统计 ===")
        print(f"  总检查: {s['total']}")
        print(f"  按决策: {s['by_decision']}")
        print(f"  规则数: {s['rules']}（启用 {s['enabled_rules']}）")

    if args.check:
        tool, inp = args.check
        allowed, reason = interceptor.is_allowed(tool, inp)
        status = "✅ 允许" if allowed else "❌ 拒绝"
        print(f"{status}: {tool} {inp[:50]}")
        print(f"  原因: {reason}")

    if args.enable:
        interceptor.enable_rule(args.enable, True)
        print(f"已启用规则: {args.enable}")

    if args.disable:
        interceptor.enable_rule(args.disable, False)
        print(f"已禁用规则: {args.disable}")
