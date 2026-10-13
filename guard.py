"""安全护栏：只允许把扫描器指向 localhost / 内网地址。

这是硬性设计，不是建议：
- 任何公网目标一律拒绝（防误打到真实站点，也防手滑）
- 解析域名后逐个 IP 检查，防止 DNS 指向公网绕过
"""
import ipaddress
import socket
import sys
from urllib.parse import urlparse

# Windows 控制台默认 GBK，无法输出 ✅/❌ 这类符号 —— 统一改成 UTF-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

ALLOWED_SCHEMES = ("http", "https")


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
    """
    p = urlparse(url)
    if p.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"只支持 http/https，收到: {p.scheme}")
    host = p.hostname
    if not host:
        raise ValueError(f"URL 缺少主机名: {url}")

    # ---- ① 授权范围护栏 ----
    try:
        from armor import check as _scope_check
    except ImportError:
        _scope_check = None
    if _scope_check is not None:
        ok, why, proj = _scope_check(url)
        if ok:
            return host
        raise PermissionError(
            f"⛔ 拒绝：{host} —— {why}\n"
            f"   要把公网目标加入白名单，必须先在 scope.json 写入该项目授权范围（in_scope / out_of_scope / expires）。"
        )

    # ---- ② 退回纯内网判定 ----
    if host.lower() in ("localhost",):
        return host

    ips = _resolve_ips(host)
    public = [ip for ip in ips if not _is_internal(ip)]
    if public:
        raise PermissionError(
            f"⛔ 拒绝：{host} 解析到公网地址 {public}\n"
            f"   本工具只允许 localhost / 内网网段（10.x, 172.16-31.x, 192.168.x, 127.x）。"
        )
    return host


if __name__ == "__main__":
    import sys

    for u in sys.argv[1:]:
        try:
            assert_target_allowed(u)
            print(f"✅ 允许: {u}")
        except Exception as e:  # noqa: BLE001
            print(f"❌ {u}\n   {e}")
