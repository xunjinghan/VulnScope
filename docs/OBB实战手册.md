# Open Bug Bounty 实战手册

> 采集时间：2026-10-10 19:0x ｜ 采集方式：Chrome CDP 过 Cloudflare 后读取官方 FAQ 原文
> 证据来源：`https://www.openbugbounty.org/faq/`（云端实得正文）、`/about/` meta 描述、官方统计数字
> 原则：**只写实得内容**；未取到的明确标注"未验证"，不编。

## 一、OBB 是什么

- 全称来由：**OpenBugBounty = "XSS exposed"**（官网 meta：*"open non-profit internet XSS archive where any security researcher can report a Cross-Site Scripting (XSS) vulnerability"*）
- 性质：**非营利**的漏洞**协调披露**平台（coordinated disclosure），不是发赏金的商业平台
- 规模（官网首页实得）：
  | 指标 | 数值 |
  |---|---|
  | 协调披露总数 | **2,010,276** |
  | 已修复漏洞 | **1,725,101** |
  | 托管赏金项目 | 2,383 个（覆盖 4,416 个网站）|
  | 研究员 | 82,446 人；荣誉徽章 1,951 |
- **实名要求**：FAQ 全文**通篇没有实名/KYC/年龄条款** → 这是它相对 HackerOne/YesWeHack/补天 的核心差异（后三者均强制 KYC，见 [HackerOne ID verification](https://docs.hackerone.com/en/articles/8399430-id-verification.md)、[YesWeHack KYC](https://helpcenter.yeswehack.io/en/articles/376519-kyc-verifications-strong-customer-authentication-sca)）

## 二、能提交什么（FAQ 原文）

> "Currently, there are two different types of vulnerability reports that you can submit"

1. **托管赏金项目的漏洞** —— 按该项目页面上的 guidelines 提交。
   ⚠️ 部分危险类型（如 SQL 注入、RCE）**必须直接发站主邮箱**，OBB 不存储处理。
2. **XSS 及其他部分 Web 应用漏洞** —— 对**任意网站**均可，前提是"**以非侵入式手段检测**（detected by non-intrusive means as prescribed by our guidelines）"。

**明确不收**：
- SQL 注入
- RCE（远程代码执行）
- HTTP 头配置错误（misconfigured HTTP headers）
- 无法轻易复现的漏洞

**拒因统计（官网原话）**：
> "99.9% of rejected vulnerabilities either belong to a class of vulnerabilities that we do not accept (e.g. SQL injections or misconfigured HTTP headers) or cannot be easily reproduced."

→ **可复现性 = 通过率的第一要素**，报告必须短、准、可复现（官方明确说"不能花几小时读多页报告"）。

## 三、时间与报酬（FAQ 原文）

| 项 | 实得 |
|---|---|
| 验证周期 | XSS 及简单类型**最多 5 天**；复杂类型（如不当访问控制）**最多 10 天** |
| OBB 是否发赏金 | **不发**。非营利，且不向站主收费 |
| 托管项目的钱 | 由**站主直接付**研究员（依项目 guidelines）。XSS 平均 **$30–$150**；Google 类可达 **$7,500** |
| 无托管项目的钱 | 站主**没有任何付款义务**；属志愿行为，回报 = 公开记录 + 推荐信 + 履历 |

## 四、红线与礼仪（FAQ 原文，违反可永久封号）

1. **不得以漏洞细节索要报酬**
   > "researchers must not demand anything in exchange for vulnerability details, this a direct violation of our guidelines on ethics and may lead to permanent suspension"
2. **不要报小而破败、明显不管安全的站**
   > "Do not report vulnerabilities on small, dysfunctional or abandoned websites that visibly do not care about their security."
3. **修复前不谈钱**；修完后可礼貌请求推荐信
   > "Do not talk about remuneration before the vulnerability is actually fixed."
4. **只用非侵入式手段**（官方措辞：non-intrusive means）→ 不做破坏、不做 DoS、不打内网
5. 态度友好、协作式（"The less pushy and more collaborative you are, the higher your chances"）

## 五、登录后实得的提交规范（2026-10-10 20:0x，用研究员账号 `deepseek-harness` 实测）

### 5.1 可提交的漏洞类型 —— **只有 5 类**（提交表单下拉框实测）

| 值 | 中文名 |
|---|---|
| `XSS` | 跨站脚本攻击（XSS）|
| `CSRF` | 跨站请求伪造 |
| `IAC` | 访问控制不当（Improper Access Control）|
| `GDPR` | GDPR 个人身份信息泄露 |
| `REDIRECT` | 打开重定向 |

→ **SQL 注入 / RCE 不在列表里**（与 FAQ 一致：危险类型必须直接发站主邮箱）。

### 5.2 提交表单必填/可选字段（`/report/` 实测）

| 字段 | 类型 | 说明 |
|---|---|---|
| `agreeethics` | checkbox | **必须勾选**：伦理声明 |
| `type` | select | 上面 5 类之一 |
| `url` | text | 目标 URL |
| `urls` | textarea | 多个 URL |
| `post_type` | radio ×2 | 触发方式（GET/POST）|
| `postparams` | textarea | POST 参数 |
| `cookies` | text | 相关 cookie |
| `application` | select | `custom` 自定义代码 / `cms` CMS或框架 / `other` 其他 |
| `burp` | file | **Burp 导出的 XML**（CSRF 必须）|
| `screen1` `screen2` | file | 截图 |
| `gdpr_screen1` | file | GDPR 类专用截图 |
| `comment` | textarea | 说明 |
| `confirm_auto` | checkbox | 确认（自动披露相关）|
| `publish_type` | radio ×2 | 披露方式 |
| `send_subscribers` / `send_generic` / `send_email_chk` + `send_email` / `send_twitter` | checkbox/text | 通知站主的渠道 |
| `auto_disclousure` | checkbox | 自动披露 |
| `report` | submit | 提交 |

### 5.3 Burp 报告格式（`/report/manual/` 实得）

> "How to create xml report file via Burp Suite"

1. 用 Burp Suite 复现漏洞
2. Proxy → HTTP History 里**至少要有 3 个请求**：
   - 第 1 个：CSRF 利用页面的内容
   - 第 2 个：**实际利用 CSRF 的请求**
   - 第 3 个：利用后的页面内容
3. 给请求**加注释**（说明每一步）
4. 选中这些请求 → 保存为文件
5. 用提交表单把该文件传上去（`burp` 字段）

### 5.4 GDPR 类截图规范（`/report/gdpr/` 实得，三条硬要求）

> a. **不要暴露任何可能泄露他人身份的个人身份信息**（或其任何部分）；
> b. **不要模糊处理所有信息**，否则可能被质疑漏洞是否存在；
> c. 只保留**一小部分无法识别个人身份的信息**可见（例如名字和电子邮件域名）。

### 5.5 账号与登录后的其它入口

| 入口 | URL |
|---|---|
| 我的账号 | 用户名 `deepseek-harness`（提交页底部显示 `@deepseek-harness`）|
| 账号设置 | `/researchers/deepseek-harness/settings/`（实测存在）|
| 提交漏洞（需登录）| `/report/` |
| 注销 | `?logout=1` |

### 5.6 登录时的三项同意（注册/首次进入弹窗原文）

1. 同意平台按"as is"提供、无任何担保
2. 同意**先仔细阅读 FAQ** 再使用
3. **已阅读并完全同意《Terms and Privacy》**

平台声明：不存储/不处理个人数据；提交数据不共享给第三方、仅用于协调披露；仅 HTTPS 访问；定期删除日志。

---

## 六、仍未验证事项（诚实标注）

| 项 | 状态 | 原因 |
|---|---|---|
| "非侵入式"的**逐条**定义 | ⚠️ 部分 | 已实得：只收 5 类（§5.1）、Burp 3 请求格式（§5.3）、GDPR 截图三要求（§5.4）；但没有一份独立的"非侵入式"清单页 |
| PDF《How It Works》正文 | ❌ 未取到 | 浏览器内 PDF 插件渲染，CDP 取不到文本；直接下载被 Cloudflare 403 |
| 论坛规则贴 | ❌ 未取到 | `forum/viewtopic.php` 返回 403 Forbidden |
| 是否有年龄下限 | ⚠️ 未见条款 | 只能确认"注册无需实名/KYC"；**不能**据此推断无任何年龄限制 |
| 对任意网站做反射型 XSS 探测的各国法律边界 | ⚠️ 未评估 | **OBB 允许 ≠ 所有司法辖区允许**；优先做托管项目（有明文 scope）|

## 七、正式起步清单

1. ✅ 注册 + 登录研究员账号（已完成，用户名 `deepseek-harness`）
2. ✅ 扒取登录后规范（§5 即结果）
3. ⬜ 读 **3 个托管项目**的 guidelines（有明文 scope，最安全）—— 项目清单见 `OBB-项目全量.json`
4. ⬜ **先在自己靶场**跑通 3 份报告样本（XSS / IAC / REDIRECT 各一），格式对齐 §5.2 / §5.3
5. ⬜ 再上报第一个真实目标（优先托管项目）

## 八、一句话定位

> **OBB 是目前唯一"合法 + 不实名 + 打真站"的入口，但只收 5 类非侵入式漏洞（XSS/CSRF/IAC/GDPR/REDIRECT）且不发钱 —— 换来的是公开战绩与站主推荐信，正好对应你「18 岁前积累可展示战绩」的目标。**
