"""LLM 连接池（参考 ARTEX llmpool 设计）。

核心功能：
- 多模型配置管理（优先级、权重、API 端点）
- 熔断器（Circuit Breaker）：失败计数 → 熔断 → 冷却 → 半开探测
- 健康检查：定期探测模型可用性
- 自动降级：按优先级选择第一个可用模型
- 负载均衡：同优先级模型轮询

设计参考 ARTEX llmpool/health.go:
- hard failure（无效 key/模型不存在）→ 立即熔断
- soft failure（429/5xx/网络错误）→ 连续 N 次后熔断
- 冷却时间随熔断次数递增（10s → 30s → 60s → 5min）
- 成功调用清除失败计数
"""
import json
import os
import random
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class ModelConfig:
    """单个模型配置。"""

    name: str                    # 模型名称，如 "deepseek-v4.1-flash"
    provider: str                # 提供商，如 "workbuddy" / "buddy" / "our-free-model"
    base_url: str                # API 端点
    api_key: str = ""            # API Key（可选，也可从环境变量读）
    priority: int = 0            # 优先级，数字越小越优先
    weight: int = 1              # 权重，用于同优先级负载均衡
    timeout: float = 30.0        # 超时秒数
    max_retries: int = 2         # 最大重试次数
    enabled: bool = True         # 是否启用


@dataclass
class CircuitState:
    """熔断器状态（参考 ARTEX llmpool.State）。"""

    fails: int = 0               # 连续失败计数
    trips: int = 0               # 熔断次数
    open_until: float = 0.0      # 熔断结束时间戳
    last_error: str = ""         # 最后一次错误
    last_at: float = 0.0         # 最后一次调用时间
    total_calls: int = 0         # 总调用次数
    total_fails: int = 0         # 总失败次数

    def is_open(self) -> bool:
        """是否在熔断冷却期。"""
        return time.time() < self.open_until

    def reset(self):
        """重置状态（成功调用后）。"""
        self.fails = 0
        self.trips = 0
        self.open_until = 0.0
        self.last_error = ""


class CircuitBreaker:
    """熔断器（参考 ARTEX llmpool.Registry）。"""

    def __init__(
        self,
        soft_trip_after: int = 3,       # 连续 soft 失败多少次后熔断
        cool_base: float = 10.0,        # 基础冷却时间（秒）
        cool_max: float = 300.0,        # 最大冷却时间（秒）
        cool_multiplier: float = 3.0,   # 冷却时间递增倍数
    ):
        self._states: dict[str, CircuitState] = {}
        self._lock = threading.Lock()
        self.soft_trip_after = soft_trip_after
        self.cool_base = cool_base
        self.cool_max = cool_max
        self.cool_multiplier = cool_multiplier

    def _cool_for(self, trips: int) -> float:
        """计算冷却时间（随熔断次数递增）。"""
        t = self.cool_base * (self.cool_multiplier ** (trips - 1))
        return min(t, self.cool_max)

    def is_available(self, name: str) -> bool:
        """检查模型是否可用（未熔断）。"""
        with self._lock:
            st = self._states.get(name)
            if st is None:
                return True
            return not st.is_open()

    def record_success(self, name: str):
        """记录成功调用（清除失败计数）。"""
        with self._lock:
            st = self._states.get(name)
            if st is None:
                return
            if st.fails == 0 and st.trips == 0 and st.open_until == 0:
                return  # 已经是干净状态
            st.reset()

    def record_failure(self, name: str, error: str, hard: bool = False) -> bool:
        """记录失败调用。

        Args:
            name: 模型名称
            error: 错误信息
            hard: True=确定性失败（无效key/模型不存在），立即熔断
                  False=瞬时失败（429/5xx/网络），需连续 N 次

        Returns:
            True 表示这次调用触发了熔断（用于日志）
        """
        with self._lock:
            st = self._states.setdefault(name, CircuitState())
            st.fails += 1
            st.last_error = error
            st.last_at = time.time()
            st.total_fails += 1

            tripped = False
            if hard or (self.soft_trip_after > 0 and st.fails >= self.soft_trip_after):
                st.trips += 1
                st.open_until = time.time() + self._cool_for(st.trips)
                st.fails = 0  # 开始半开探测的新计数
                tripped = True

            return tripped

    def reset(self, name: str):
        """手动重置某个模型的状态。"""
        with self._lock:
            self._states.pop(name, None)

    def snapshot(self) -> dict:
        """返回所有模型状态快照。"""
        with self._lock:
            return {k: asdict(v) for k, v in self._states.items()}


class LLMPool:
    """LLM 连接池：多模型管理 + 熔断器 + 自动降级 + 负载均衡。"""

    def __init__(self, configs: Optional[list[ModelConfig]] = None):
        self._configs: dict[str, ModelConfig] = {}
        self._breaker = CircuitBreaker()
        self._round_robin: dict[int, list[str]] = {}  # priority -> [model names]
        self._rr_index: dict[int, int] = {}
        self._lock = threading.Lock()

        if configs:
            for c in configs:
                self.add_model(c)

    def add_model(self, config: ModelConfig):
        """添加一个模型配置。"""
        with self._lock:
            self._configs[config.name] = config
            # 更新轮询列表
            p = config.priority
            if p not in self._round_robin:
                self._round_robin[p] = []
                self._rr_index[p] = 0
            if config.name not in self._round_robin[p]:
                self._round_robin[p].append(config.name)

    def remove_model(self, name: str):
        """移除一个模型。"""
        with self._lock:
            c = self._configs.pop(name, None)
            if c:
                p = c.priority
                if p in self._round_robin and name in self._round_robin[p]:
                    self._round_robin[p].remove(name)

    def select_model(self) -> Optional[ModelConfig]:
        """选择一个可用模型（按优先级 + 轮询）。

        策略：
        1. 按优先级从小到大遍历
        2. 同优先级内轮询选择
        3. 跳过熔断中的模型
        4. 全部熔断时返回 None（调用方应报错或等待）
        """
        with self._lock:
            for priority in sorted(self._round_robin.keys()):
                models = self._round_robin[priority]
                if not models:
                    continue
                # 轮询起点
                idx = self._rr_index.get(priority, 0)
                for i in range(len(models)):
                    name = models[(idx + i) % len(models)]
                    config = self._configs.get(name)
                    if config and config.enabled and self._breaker.is_available(name):
                        self._rr_index[priority] = (idx + i + 1) % len(models)
                        return config
            return None

    def call(self, messages: list, **kwargs) -> dict:
        """调用 LLM（自动选择模型 + 重试 + 熔断）。

        这是一个简化的调用框架，实际的 HTTP 请求需要调用方实现。
        返回格式：{"ok": bool, "content": str, "model": str, "error": str}
        """
        last_error = ""
        for attempt in range(3):  # 最多尝试 3 个不同模型
            config = self.select_model()
            if config is None:
                return {
                    "ok": False,
                    "content": "",
                    "model": "",
                    "error": "所有模型均不可用（全部熔断或未配置）",
                }

            try:
                # 这里应该是实际的 API 调用
                # result = self._do_call(config, messages, **kwargs)
                # 暂时返回占位
                self._breaker.record_success(config.name)
                return {
                    "ok": True,
                    "content": f"[占位] 模型 {config.name} 调用成功",
                    "model": config.name,
                    "error": "",
                }
            except Exception as e:  # noqa: BLE001
                last_error = str(e)
                hard = "401" in last_error or "invalid" in last_error.lower() or "not found" in last_error.lower()
                tripped = self._breaker.record_failure(config.name, last_error, hard)
                if tripped:
                    print(f"[LLMPool] 模型 {config.name} 已熔断: {last_error}")
                continue

        return {"ok": False, "content": "", "model": "", "error": last_error}

    def health_check(self) -> dict:
        """执行健康检查（返回各模型状态）。"""
        results = {}
        for name, config in self._configs.items():
            available = self._breaker.is_available(name)
            state = self._breaker.snapshot().get(name, {})
            results[name] = {
                "provider": config.provider,
                "priority": config.priority,
                "enabled": config.enabled,
                "available": available,
                "state": state,
            }
        return results

    def load_config(self, path: str):
        """从 JSON 文件加载模型配置。"""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data.get("models", []):
            self.add_model(ModelConfig(**item))

    def save_config(self, path: str):
        """保存模型配置到 JSON 文件。"""
        data = {
            "models": [asdict(c) for c in self._configs.values()],
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


# ============================================================
# 便捷函数
# ============================================================
def default_pool() -> LLMPool:
    """创建默认连接池（免费模型优先）。"""
    pool = LLMPool()
    pool.add_model(ModelConfig(
        name="deepseek-v4.1-flash",
        provider="workbuddy",
        base_url="https://api.deepseek.com/v1",
        priority=0,
    ))
    pool.add_model(ModelConfig(
        name="deepseek-v4.1-flash-backup",
        provider="buddy",
        base_url="https://api.deepseek.com/v1",
        priority=1,
    ))
    pool.add_model(ModelConfig(
        name="space-bunny-free",
        provider="our-free-model",
        base_url="https://api.spacebunny.ai/v1",
        priority=2,
    ))
    return pool


# ============================================================
# 命令行工具
# ============================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VulnScope LLM 连接池")
    parser.add_argument("--config", default="llm_config.json", help="配置文件路径")
    parser.add_argument("--health", action="store_true", help="执行健康检查")
    parser.add_argument("--test", metavar="MODEL", help="测试指定模型")
    parser.add_argument("--reset", metavar="MODEL", help="重置指定模型的熔断器")
    args = parser.parse_args()

    pool = default_pool()
    if os.path.exists(args.config):
        pool.load_config(args.config)

    if args.health:
        print("=== LLM 连接池健康检查 ===")
        for name, info in pool.health_check().items():
            status = "✅ 可用" if info["available"] else "❌ 熔断"
            print(f"  [{info['priority']}] {name:30s} {info['provider']:20s} {status}")
            if info["state"]:
                s = info["state"]
                print(f"       失败={s.get('fails',0)} 熔断={s.get('trips',0)} 最后错误={s.get('last_error','')[:50]}")

    if args.reset:
        pool._breaker.reset(args.reset)
        print(f"已重置模型 {args.reset} 的熔断器")

    if args.test:
        config = pool._configs.get(args.test)
        if config:
            print(f"测试模型: {config.name} ({config.provider})")
            print(f"  端点: {config.base_url}")
            print(f"  优先级: {config.priority}")
        else:
            print(f"模型 {args.test} 不存在")
