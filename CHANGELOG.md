# Changelog

## v1.0.0 — 2026-10-16

首个公开版本。

- 四步流水线：爬虫 → AI 判定 → 非破坏性验证 → 报告
- 安全护栏：guard.py（仅回环/内网）+ intercept.py（三条禁令写死）
- 结构化证据：阳性阴性都留证，逐条 sha256
- 自带烟测靶场 labtest/app.py（6 类洞）
- 新增：SECURITY.md、requirements.txt、KNOWN-ISSUES.md（透明记录历史问题）
- 新增 CI：语法编译 + 凭据扫描

