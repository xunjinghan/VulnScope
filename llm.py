"""AI 澶ц剳锛氭妸鍊欓€夌偣浜ょ粰璞嗗寘鍒ゅ畾銆?
澶嶇敤宸茬粡璋冮€氱殑銆岃眴鍖?CDP 閫氶亾銆嶏紙dsh-tools/doubao-cdp.mjs锛夛紝
鎵€浠ヤ笉棰濆鑺遍挶锛堣蛋鐢ㄦ埛宸蹭粯璐圭殑璞嗗寘棰濆害锛夛紝涔熶笉闇€瑕佷换浣?API key銆?
鍓嶇疆锛氳眴鍖呴渶甯﹁皟璇曠鍙ｈ繍琛?  powershell -File dsh-tools\\doubao-agent-start.ps1
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
    r"node"
)
DOUBAO = pathlib.Path(__file__).resolve().parents[1] / "doubao-cdp.mjs"


def available() -> bool:
    return pathlib.Path(NODE).exists() and DOUBAO.exists()


def ask_doubao(prompt: str, timeout: int = 300) -> str:
    """鎶?prompt 鍐欐枃浠跺悗浜ょ粰璞嗗寘锛堥伩鍏嶅懡浠よ缂栫爜闂锛夛紝杩斿洖绾枃鏈瓟妗堛€?""
    tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8", newline="\n")
    try:
        tmp.write(prompt)
        tmp.close()
        proc = subprocess.run(
            [NODE, str(DOUBAO), "ask", tmp.name, "--file", "--new"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        # 鎶娿€孨ode 宕╀簡 / 璞嗗寘娌＄瓟涓娿€嶅綋澶辫触锛岀粷涓嶆妸鎶ラ敊鏂囨湰娣疯繘鎶ュ憡
        err_markers = ("ReferenceError", "SyntaxError", "TypeError", "Node.js v", "FAILED", "Timeout", "timed out")
        if any(m in out for m in err_markers) and "===== ANSWER" not in out:
            raise RuntimeError("璞嗗寘閫氶亾鎵ц澶辫触锛歕n" + out.strip()[-800:])
        if "===== ANSWER" in out:
            tail = out.split("===== ANSWER", 1)[1]
            ans = tail.split("\n", 1)[1].strip() if "\n" in tail else tail.strip()
            if not ans:
                raise RuntimeError("璞嗗寘杩斿洖浜嗙┖绛旀")
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
    print("\n--- 杩為€氭€ф祴璇?---")
    print(ask_doubao("鍙洖澶嶅洓涓瓧锛氶€氶亾姝ｅ父"))

