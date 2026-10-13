"""经验数据库（SQLite）：每轮攻防后写入总结，持续迭代攻击手段。

用法:
  python kdb.py init                     建库建表
  python kdb.py seed                     把已有成果（靶场体检/假阳性/技术库）导入
  python kdb.py add campaign ...         新增一轮战役
  python kdb.py add lesson "..."         新增一条教训
  python kdb.py add technique ...        新增一项技术
  python kdb.py report                   打印汇总
"""
import json
import pathlib
import sqlite3
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

HERE = pathlib.Path(__file__).resolve().parent
DB = HERE / "knowledge.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, name TEXT, target TEXT,
  fingerprint TEXT, hits INTEGER, total INTEGER, fp INTEGER, notes TEXT);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INT, vuln_id TEXT, category TEXT,
  name TEXT, evidence TEXT, tool TEXT, severity TEXT);
CREATE TABLE IF NOT EXISTS techniques(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, category TEXT, name TEXT,
  howto TEXT, source TEXT, tool TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS lessons(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, lesson TEXT, root_cause TEXT,
  fix TEXT, tool TEXT);
"""


def conn():
    c = sqlite3.connect(DB)
    c.executescript(SCHEMA)
    return c


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


cmd = sys.argv[1] if len(sys.argv) > 1 else "report"
c = conn()

if cmd == "init":
    print(f"已建库: {DB}")

elif cmd == "seed":
    # 1) 两轮战役
    cur = c.execute("INSERT INTO campaigns(ts,name,target,fingerprint,hits,total,fp,notes) VALUES(?,?,?,?,?,?,?,?)",
                    ("2026-10-09 00:04", "round-1 加固版站", "http://127.0.0.1:8091",
                     "3D74DDB8", 0, 0, 0, "三轮攻击全被挡；发现 2 个低危存在性枚举（后由对手修复）"))
    r1 = cur.lastrowid
    cur = c.execute("INSERT INTO campaigns(ts,name,target,fingerprint,hits,total,fp,notes) VALUES(?,?,?,?,?,?,?,?)",
                    ("2026-10-09 00:22", "round-2 加固版站（修复后）", "http://127.0.0.1:8091",
                     "0946836F", 0, 0, 0, "对手修好枚举；新增登录POST限速(20/5min/IP)把我锁住"))
    r2 = cur.lastrowid
    cur = c.execute("INSERT INTO campaigns(ts,name,target,fingerprint,hits,total,fp,notes) VALUES(?,?,?,?,?,?,?,?)",
                    ("2026-10-09 00:46", "靶场盲测（26 个植入漏洞）", "http://127.0.0.1:8095",
                     "-", 26, 26, 0, "首轮 18/26(69%)；升级三件工具后 26/26(100%)"))
    r3 = cur.lastrowid
    # 2) 靶场发现
    fp = HERE / "lab_findings.json"
    if fp.exists():
        for d in json.loads(fp.read_text(encoding="utf-8")):
            if d.get("hit"):
                c.execute("INSERT INTO findings(campaign_id,vuln_id,category,name,evidence,tool,severity) VALUES(?,?,?,?,?,?,?)",
                          (r3, d["id"], d.get("cat", ""), d.get("name", ""), d.get("evidence", "")[:300],
                           "lab_attack/logic_verify/session_strength", ""))
    # 3) 教训（我自查出的假阳性 + 流程错误）
    for lesson, rc, fix in [
        ("把 HTTP 401(需登录) 当成攻破", "判定逻辑错：非 200 即视为攻破", "401/403/404 一律判为'被防住'"),
        ("硬编码 id=1=自己、id=2=他人", "假设用户 id 顺序固定", "用不变量判定 + 从响应 user_id 推属主"),
        ("PII 正则匹配到表单标签", "用关键词而非数据形态匹配", "改为匹配真实值形态（邮箱/手机号/键值对）"),
        ("枚举检查拿'自己'与'不存在'对照", "对照选错：自己本来就该返回 200", "改用'他人的存在资源 vs 不存在资源'"),
        ("注入检测匹配登录页导航栏的 /profile", "用子串判'登录成功'", "改为看会话是否真建立（退出表单）"),
        ("X-HTTP-Method-Override 被忽略也算'被接受'", "忽略≠生效", "与普通请求对比响应差异"),
        ("session_strength 方案名含时间戳导致无法跨用户复用", "方案标签写成含具体值的字符串", "方案名改为模板 md5(user-ts)"),
        ("在对手仍改代码时开打，结论作废", "目标未冻结", "先核 sha256+mtime 静止，再重启实例确认跑新代码"),
        ("把我的 prompt 文本当成对手的回答", "扫全文匹配关键词会命中自己发的内容", "只读对方新消息，或用进度计数"),
    ]:
        c.execute("INSERT INTO lessons(ts,lesson,root_cause,fix,tool) VALUES(?,?,?,?,?)", (now(), lesson, rc, fix, ""))
    # 4) 技术库（从 攻击方法库v2 精选）
    techs = [
        ("授权", "越权 IDOR（水平/垂直）", "换对象 id / 低权访问管理接口，属主由响应推导", "先知社区 xz.aliyun.com/news/18457", "auth_attack.py"),
        ("会话", "会话 token 可预测性", "多次登录收集 token→熵分析→时间窗枚举 md5(user-ts) 等弱方案→伪造 admin token 验证", "HackTricks", "session_strength.py"),
        ("业务逻辑", "金额/数量篡改", "提交客户端可控 price/qty，读余额前后对比", "OWASP WSTG", "logic_verify.py"),
        ("业务逻辑", "并发竞态 TOCTOU", "N 并发同一请求，比较最终余额是否超支为负", "DEF CON31 Smashing the state machine", "logic_verify.py"),
        ("业务逻辑", "状态机绕过", "直接调用状态变更接口跳过支付步骤，再读状态确认", "OWASP WSTG", "logic_verify.py"),
        ("业务逻辑", "幂等性缺失", "同一动作重复提交，看效果是否叠加", "OWASP WSTG", "logic_verify.py"),
        ("注入", "SQL 注入（报错/布尔/UNION）", "只读载荷；或用 ' OR 1=1-- 绕过登录（判据=会话真建立）", "HackTricks", "verify.py/targeted_attack.py"),
        ("注入", "SSTI/命令注入/路径穿越", "{{7*7}} 回显 49；;echo MARK；file=app.py 读源码", "PayloadsAllTheThings", "lab_attack.py"),
        ("客户端", "CORS 配置错误", "恶意 Origin 看 ACAO 是否反射 + ACAC=true", "HackTricks cors-bypass", "advanced_probe.py"),
        ("客户端", "Host 头注入", "X-Forwarded-Host 拼进重置链接并回显", "OWASP WSTG Host Header", "advanced_probe.py"),
        ("发现", "端点与参数自动发现", "首页链接/表单/JS 提取，替代猜测", "cnvd-skill", "param_discover.py"),
        ("服务端", "SSRF / 文件上传", "fetch 内网 URL 回显；上传后直接访问", "OWASP WSTG", "lab_attack.py"),
    ]
    for cat, name, how, src, tool in techs:
        c.execute("INSERT INTO techniques(ts,category,name,howto,source,tool,status) VALUES(?,?,?,?,?,?,?)",
                  (now(), cat, name, how, src, tool, "已实现"))
    c.commit()
    print(f"已导入：战役 3 轮、靶场发现、教训、技术 {len(techs)} 项")

elif cmd == "add":
    kind = sys.argv[2] if len(sys.argv) > 2 else ""
    if kind == "lesson" and len(sys.argv) > 3:
        c.execute("INSERT INTO lessons(ts,lesson,root_cause,fix,tool) VALUES(?,?,?,?,?)",
                  (now(), sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "", sys.argv[5] if len(sys.argv) > 5 else "", ""))
        c.commit(); print("已加教训")
    elif kind == "technique" and len(sys.argv) > 5:
        c.execute("INSERT INTO techniques(ts,category,name,howto,source,tool,status) VALUES(?,?,?,?,?,?,?)",
                  (now(), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6] if len(sys.argv) > 6 else "", sys.argv[7] if len(sys.argv) > 7 else "", "已实现"))
        c.commit(); print("已加技术")
    elif kind == "campaign" and len(sys.argv) > 5:
        c.execute("INSERT INTO campaigns(ts,name,target,fingerprint,hits,total,fp,notes) VALUES(?,?,?,?,?,?,?,?)",
                  (now(), sys.argv[3], sys.argv[4], sys.argv[5], int(sys.argv[6]), int(sys.argv[7]), 0, sys.argv[8] if len(sys.argv) > 8 else ""))
        c.commit(); print("已加战役")
    else:
        print("用法: add lesson|technique|campaign ...")

else:  # report
    print(f"经验数据库: {DB}")
    for t in ("campaigns", "findings", "techniques", "lessons"):
        n = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"  {t}: {n} 条")
    print("\n最近教训：")
    for r in c.execute("SELECT lesson FROM lessons ORDER BY id DESC LIMIT 5"):
        print(f"  - {r[0]}")
    print("\n技术库（按类别）：")
    for r in c.execute("SELECT category, COUNT(*) FROM techniques GROUP BY category ORDER BY 2 DESC"):
        print(f"  {r[0]}: {r[1]}")
