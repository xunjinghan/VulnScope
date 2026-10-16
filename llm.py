"""AI 大脑：把候选点交给豆包判定。

复用已经调通的「豆包 CDP 通道」（dsh-tools/doubao-cdp.mjs），
所以不额外花钱（走用户已付费的豆包额度），也不需要任何 API key。

前置：豆包需带调试端口运行
  powershell -File dsh-tools\\doubao-agent-start.ps1
"""
import os
import pathlib
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

NODE = os.environ.get("DSH_NODE") or (
    r"C:\Users\Administrator\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe"
)
DOUBAO = pathlib.Path(__file__).resolve().parents[1] / "doubao-cdp.mjs"


def available() -> bool:
    return pathlib.Path(NODE).exists() and DOUBAO.exists()


def ask_doubao(prompt: str, timeout: int = 300) -> str:
    """把 prompt 写文件后交给豆包（避免命令行编码问题），返回纯文本答案。"""
    tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8", newline="\n")
    try:
        tmp.write(prompt)
        tmp.close()
        proc = subprocess.run(
            [NODE, str(DOUBAO), "ask", tmp.name, "--file", "--new"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        # 把「Node 崩了 / 豆包没答上」当失败，绝不把报错文本混进报告
        err_markers = ("ReferenceError", "SyntaxError", "TypeError", "Node.js v", "FAILED", "Timeout", "timed out")
        if any(m in out for m in err_markers) and "===== ANSWER" not in out:
            raise RuntimeError("豆包通道执行失败：\n" + out.strip()[-800:])
        if "===== ANSWER" in out:
            tail = out.split("===== ANSWER", 1)[1]
            ans = tail.split("\n", 1)[1].strip() if "\n" in tail else tail.strip()
            if not ans:
                raise RuntimeError("豆包返回了空答案")
            return ans
        return out.strip()
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


if __name__ == "__main__":
    print("node:", NODE, os.path.exists(NODE))
    print("doubao script:", DOUBAO, DOUBAO.exists())
    print("\n--- 连通性测试 ---")
    print(ask_doubao("只回复四个字：通道正常"))
