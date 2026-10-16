# 运行环境与网络要求（Environment & Network）

> **一句话结论**：Python 3.10+，`pip install -r requirements.txt` 装 4 个包即可；
> **中国大陆直连 PyPI 可用**（实测 345 ms），所以装依赖不需要代理。
> 唯一可能踩坑的是**可选的语音转写**（`faster-whisper` 要从 HuggingFace 拉模型，国内常不通，见第 4 节）。

实测时间：2026-10-16 15:02（UTC+8）
测试机：Windows 11 x64 · Python 3.12
网络：上海 · 中国移动 AS9808 家庭宽带 · **未开任何代理**（开代理后复测 25/25 端点全通）

---

## 1. 最低环境

| 组件 | 最低要求 | 我实测过的版本 | 说明 |
| --- | --- | --- | --- |
| 操作系统 | Windows 10 1809+ / Ubuntu 20.04+ / Debian 11+ / macOS 12+ | Windows 11 x64 | 流水线本身跨平台；AI 判定走 CDP 时才和桌面应用绑定 |
| Python | 3.8+（`requirements.txt` 标称），建议 **3.10+** | 3.12.7 | 3.9 及以下没实测过 |
| pip 依赖 | `lxml>=5.0`、`yt-dlp>=2024.1.0`、`imageio-ffmpeg>=0.4.9` | 同上 | 见 `requirements.txt` |
| 可选重依赖 | `faster-whisper>=1.0.0` | — | 只有 `videoread.py` 的语音转写用；**不装也能跑主流程** |
| AI 大脑（可选） | 豆包桌面版（开 CDP 调试端口）或任意 OpenAI 兼容 API | — | 不配也能跑：`--no-llm` 之类的纯规则模式 |
| 磁盘 | 约 500 MB（不含视频缓存与转写模型） | — | 语音模型另占 1 GB 量级 |
| 端口 | 8099（自带烟测靶场）、CDP 调试端口空闲 | — | 改端口见 `main.py --help` |

**安全边界（代码里写死的）**：只允许 `127.0.0.1` / 私网靶场目标，非回环/公网目标会被 `guard.py` 直接拒绝。

---

## 2. 装依赖（国内加速）

```bash
# 默认（国内直连 PyPI 实测可用，345 ms）
pip install -r requirements.txt

# 想更快就用镜像
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
# 或
pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/
```

`lxml` 在新版 Python 上有预编译 wheel，正常不需要本地编译；如果你在很旧的发行版上遇到编译报错，先升级 pip：`python -m pip install -U pip`。

---

## 3. 中国大陆网络实测（**未开代理**）

| 域名 | 国内直连结果 | 延迟 | 与本项目的关系 |
| --- | --- | --- | --- |
| `pypi.org` / `files.pythonhosted.org` | ✅ 可用 | 345 / 628 ms | `pip install` 直连可用 |
| `mirrors.aliyun.com` / `pypi.tuna.tsinghua.edu.cn` | ✅ 可用 | 476 / 670 ms | pip 国内镜像（可选加速） |
| `github.com`（网页 / HTTPS 克隆） | ⚠️ TLS 握手超时 | — | `git clone` 本仓库可能卡住 |
| `codeload.github.com`（Download ZIP） | ❌ 超时 | — | 「Download ZIP」会失败 |
| `raw.githubusercontent.com` | ❌ 连接被重置 | — | raw 直链不通 |
| `api.github.com` / `objects.githubusercontent.com` | ✅ 可用 | 331 / 389 ms | API、Release 附件可直连 |
| `registry-1.docker.io` 等 Docker Hub 域名 | ❌ 超时 | — | 本项目不需要 Docker，但你的靶场用 Docker 时要注意 |

> 结论：**跑本项目不需要代理**；只有"把代码 clone 到本地"这一步在国内可能卡住（用代理 / SSH / Release 附件均可）。

---

## 4. 官方安装链接 + 直连不通时用官方 WARP

| 工具 | 官方链接 | 国内直连（实测） |
| --- | --- | --- |
| Python 3.10+（建议） | <https://www.python.org/downloads/> | ✅ 669 ms |
| pip 国内镜像 | <https://pypi.tuna.tsinghua.edu.cn/simple> | ✅ 670 ms |
| Git | <https://git-scm.com/downloads> | 未实测（Windows 一般已自带） |
| HuggingFace 国内镜像（语音转写用） | <https://hf-mirror.com> | ✅ 439 ms（`huggingface.co` 直连 ❌ 超时） |

### 直连不通时：用**官方** WARP（别装第三方"加速器"）

| 官方入口 | 国内直连（实测） | 说明 |
| --- | --- | --- |
| `1.1.1.1`（WARP 官网） | ❌ **超时** | 官网在国内打不开，**这不是你的网络坏了** |
| `www.cloudflare.com` | ✅ 848 ms | 官网主页可开 |
| `developers.cloudflare.com` | ✅ 785 ms | 官方文档站，含各平台安装步骤 |
| `install.appcenter.ms` | ✅ 1583 ms | 官方安装包托管（Microsoft App Center） |

Windows 一条命令装（不需要翻墙）：

```powershell
winget install --id Cloudflare.Warp -e
```

> ⚠️ 别敲 `scoop install warp`：scoop 里那个 `warp` 是另一个不相干的工具（0.3.0）。

装完确认生效：

```powershell
& "C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe" status   # 期望 Connected
```

或打开 <https://www.cloudflare.com/cdn-cgi/trace> 看到 `warp=on`。

**注意**：① 本地靶场与回环目标不受影响（WARP 默认排除内网段）；② 卡在 `Connecting` 就 `warp-cli disconnect` 再 `connect`，约半分钟能上去；③ 免费档出口可能绕远，只在 clone / pip 卡住时开。

---

## 5. 常见报错 → 处理

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `faster-whisper` 首次运行卡在下载模型 | HuggingFace 在国内常不可达 | 设镜像后再跑：<br>`set HF_ENDPOINT=https://hf-mirror.com`（Windows CMD）<br>`$env:HF_ENDPOINT="https://hf-mirror.com"`（PowerShell）<br>`export HF_ENDPOINT=https://hf-mirror.com`（Linux/macOS）<br>不需要语音转写的话直接不装这个包 |
| `pip install lxml` 编译报错 | 过旧 Python / 无 wheel | 升级 pip，或换 3.10–3.12 |
| 连不上豆包 CDP / `Connection refused` | 桌面版没开调试端口，或端口不是默认值 | 先确认桌面版在跑、调试端口已开；也可改用 OpenAI 兼容 API |
| 目标被拒绝：`guard: 非回环目标` | 护栏生效（**预期行为**） | 用本地靶场（`127.0.0.1:8099`）或把授权目标加进白名单 |
| 浏览器打不开 `localhost:8099` | `localhost` 解析到 IPv6 | 用 `http://127.0.0.1:8099/` |
| `git clone` 卡住 | `github.com` 握手被干扰 | 开代理 / 用 SSH / 下 Release 附件 |

---

## 6. 这套东西是给谁跑的

护栏只允许回环与私网靶场：**它没法、也不会去打公网目标**。
想给别人用：让对方在自己的机器上装（依赖就 4 个包），不要把本地实例暴露出去。

---

## English summary

- Python 3.10+ (3.12 tested) + 4 pip packages; install with `pip install -r requirements.txt`.
- Mainland-China direct connection works for PyPI (345 ms) — **no proxy needed to run the pipeline**.
- Optional speech-to-text (`faster-whisper`) downloads models from HuggingFace, which is usually unreachable in mainland China; set `HF_ENDPOINT=https://hf-mirror.com` or skip that extra.
- Only *getting the code* is affected by the network: `codeload.github.com` (Download ZIP) and `raw.githubusercontent.com` are unreachable, `github.com` HTTPS clone is unstable; `api.github.com` and Release attachments work.
- The guard only permits loopback / private-lab targets by design.
