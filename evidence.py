"""结构化证据存储（参考 ARTEX evidence/store.go 设计）。

每个漏洞发现都应该有完整的证据链：
- 漏洞基本信息（类型、严重度、端点、参数）
- 复现步骤（请求/响应原文）
- 危害证明（数据泄露/权限绕过/RCE 等）
- 验证状态（未验证/已复现/误报）
- sha256 哈希（防止证据被篡改）

设计原则：
- 证据不可变：一旦写入就不能修改，只能追加验证记录
- 每条证据带 sha256：引用时用哈希，防止「报告里的证据和实际文件不一致」
- 阳性阴性都留：阴性结果同样有价值（证明「这个端点测过了，没有洞」）
"""
import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class Evidence:
    """单条漏洞证据。"""

    # 基本信息
    vuln_id: str                    # 漏洞编号，如 VULN-001
    vuln_type: str                  # 漏洞类型，如 SQLi / XSS / CSRF
    severity: str                   # 严重度：critical/high/medium/low/info
    endpoint: str                   # 受影响端点
    parameter: str = ""             # 受影响参数
    description: str = ""           # 漏洞描述

    # 复现证据
    request_sample: str = ""        # 请求原文（脱敏后）
    response_sample: str = ""       # 响应原文（截断+脱敏）
    payload: str = ""               # 使用的 payload
    reproduction_steps: list = field(default_factory=list)  # 复现步骤

    # 危害证明
    impact: str = ""                # 危害说明
    impact_evidence: str = ""       # 危害证明（如泄露的数据、执行的命令输出）

    # 验证状态
    status: str = "unverified"      # unverified / confirmed / false_positive / mitigated
    verifier: str = ""              # 验证者
    verified_at: int = 0            # 验证时间戳
    verification_notes: str = ""    # 验证备注

    # 元数据
    created_at: int = field(default_factory=lambda: int(time.time()))
    created_by: str = ""            # 发现者
    tags: list = field(default_factory=list)
    sha256: str = ""                # 证据内容哈希（写入时计算）

    def compute_hash(self) -> str:
        """计算证据内容的 sha256（排除 sha256 字段本身）。"""
        d = asdict(self)
        d.pop("sha256", None)
        content = json.dumps(d, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def seal(self):
        """计算并写入哈希，之后证据不可变。"""
        self.sha256 = self.compute_hash()

    def verify(self, verifier: str, notes: str = "", status: str = "confirmed"):
        """标记验证结果。"""
        self.verifier = verifier
        self.verified_at = int(time.time())
        self.verification_notes = notes
        self.status = status
        self.seal()  # 重新计算哈希


class EvidenceStore:
    """证据存储（文件系统 + JSON）。"""

    def __init__(self, base_dir: str = "evidence"):
        self.base_dir = base_dir
        self._evidences: dict[str, Evidence] = {}
        self._load()

    def _path(self, vuln_id: str) -> str:
        return os.path.join(self.base_dir, f"{vuln_id}.json")

    def _load(self):
        """从磁盘加载已有证据。"""
        if not os.path.isdir(self.base_dir):
            return
        for fname in os.listdir(self.base_dir):
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.base_dir, fname), "r", encoding="utf-8") as f:
                    data = json.load(f)
                e = Evidence(**data)
                self._evidences[e.vuln_id] = e
            except Exception:
                continue

    def add(self, evidence: Evidence) -> Evidence:
        """添加一条证据（自动计算哈希并保存）。"""
        evidence.seal()
        self._evidences[evidence.vuln_id] = evidence
        self._save(evidence)
        return evidence

    def _save(self, evidence: Evidence):
        os.makedirs(self.base_dir, exist_ok=True)
        with open(self._path(evidence.vuln_id), "w", encoding="utf-8") as f:
            json.dump(asdict(evidence), f, ensure_ascii=False, indent=2)

    def get(self, vuln_id: str) -> Optional[Evidence]:
        return self._evidences.get(vuln_id)

    def list_all(self) -> list:
        return list(self._evidences.values())

    def list_by_status(self, status: str) -> list:
        return [e for e in self._evidences.values() if e.status == status]

    def list_by_severity(self, severity: str) -> list:
        return [e for e in self._evidences.values() if e.severity == severity]

    def summary(self) -> dict:
        """返回证据统计。"""
        by_status = {}
        by_severity = {}
        by_type = {}
        for e in self._evidences.values():
            by_status[e.status] = by_status.get(e.status, 0) + 1
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
            by_type[e.vuln_type] = by_type.get(e.vuln_type, 0) + 1
        return {
            "total": len(self._evidences),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_type": by_type,
        }

    def verify_hash(self, vuln_id: str) -> bool:
        """验证证据哈希是否匹配（防止篡改）。"""
        e = self._evidences.get(vuln_id)
        if not e:
            return False
        return e.sha256 == e.compute_hash()

    def export_report(self, path: str):
        """导出全部证据为汇总报告。"""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        report = {
            "generated_at": int(time.time()),
            "summary": self.summary(),
            "evidences": [asdict(e) for e in self._evidences.values()],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        return path


# ============================================================
# 便捷函数
# ============================================================
def quick_evidence(
    vuln_id: str,
    vuln_type: str,
    severity: str,
    endpoint: str,
    description: str = "",
    payload: str = "",
    impact: str = "",
) -> Evidence:
    """快速创建一条证据。"""
    return Evidence(
        vuln_id=vuln_id,
        vuln_type=vuln_type,
        severity=severity,
        endpoint=endpoint,
        description=description,
        payload=payload,
        impact=impact,
    )


# ============================================================
# 命令行工具
# ============================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="shoucuo-vuln-bot 证据存储")
    parser.add_argument("--dir", default="evidence", help="证据目录")
    parser.add_argument("--summary", action="store_true", help="显示统计")
    parser.add_argument("--list", action="store_true", help="列出所有证据")
    parser.add_argument("--verify", metavar="VULN_ID", help="验证某条证据的哈希")
    parser.add_argument("--export", metavar="PATH", help="导出汇总报告")
    args = parser.parse_args()

    store = EvidenceStore(args.dir)

    if args.summary:
        s = store.summary()
        print(f"证据总数: {s['total']}")
        print(f"按状态: {s['by_status']}")
        print(f"按严重度: {s['by_severity']}")
        print(f"按类型: {s['by_type']}")

    if args.list:
        for e in store.list_all():
            print(f"  [{e.severity:7s}] {e.vuln_id} {e.vuln_type:15s} {e.endpoint:40s} status={e.status}")

    if args.verify:
        ok = store.verify_hash(args.verify)
        print(f"  {args.verify}: {'✅ 哈希匹配' if ok else '❌ 哈希不匹配（证据可能被篡改）'}")

    if args.export:
        path = store.export_report(args.export)
        print(f"报告已导出: {path}")
