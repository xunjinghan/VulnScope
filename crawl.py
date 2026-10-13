"""爬虫：同源 BFS 抓取 + 抽取「攻击面候选点」。

只用标准库 + lxml（本机已装，不需要联网装包）。
产出的是"候选点"，不是漏洞结论 —— 结论交给 LLM 判定，最终由人验证。
"""
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque

from lxml import html as LH

from guard import assert_target_allowed

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

UA = "DSH-VulnHunt/0.1 (authorized-lab-only)"
MAX_BYTES = 300_000
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def fetch(url: str, timeout: float = 12.0):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/json,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
            raw = r.read(MAX_BYTES)
            return r.status, r.headers.get("Content-Type", ""), raw, None
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", "") if e.headers else "", e.read(64_000), None
    except Exception as e:  # noqa: BLE001
        return None, "", b"", str(e)


def parse(base_url: str, raw: bytes):
    try:
        doc = LH.fromstring(raw)
    except Exception:  # noqa: BLE001
        return set(), [], [], None
    links = {urllib.parse.urljoin(base_url, a.get("href")) for a in doc.xpath("//a[@href]")}
    scripts = [urllib.parse.urljoin(base_url, s.get("src")) for s in doc.xpath("//script[@src]")]
    forms = []
    for f in doc.xpath("//form"):
        inputs = []
        for i in f.xpath(".//input|.//textarea|.//select"):
            inputs.append({"name": i.get("name") or "", "type": (i.get("type") or "text").lower()})
        forms.append({
            "action": urllib.parse.urljoin(base_url, f.get("action") or base_url),
            "method": (f.get("method") or "get").upper(),
            "inputs": inputs,
            "has_csrf_token": any("token" in (i["name"] or "").lower() or "csrf" in (i["name"] or "").lower() for i in inputs),
        })
    title = (doc.findtext(".//title") or "").strip()[:120]
    return links, forms, scripts, title


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urllib.parse.urlparse(a), urllib.parse.urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def crawl(start_url: str, max_pages: int = 25, delay: float = 0.15, verbose: bool = True):
    assert_target_allowed(start_url)
    base = urllib.parse.urlparse(start_url)
    root = f"{base.scheme}://{base.netloc}"

    seen, queue = set(), deque([start_url])
    pages, candidates = [], []
    while queue and len(pages) < max_pages:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        status, ctype, raw, err = fetch(url)
        if verbose:
            print(f"  [{status if status else 'ERR'}] {url}" + (f"  ({err})" if err else ""))
        if err:
            continue

        links, forms, scripts, title = parse(url, raw)
        pages.append({"url": url, "status": status, "ctype": ctype, "title": title,
                      "forms": forms, "scripts": scripts, "bytes": len(raw)})

        # 候选点 1：URL 查询参数
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        for name, vals in q.items():
            candidates.append({
                "kind": "url_param", "url": url, "method": "GET", "name": name,
                "sample": (vals[0] if vals else "")[:60],
                "source": f"页面 {url}",
            })
        # 候选点 2：表单字段
        for f in forms:
            for i in f["inputs"]:
                if i["type"] in ("submit", "button", "file") or not i["name"]:
                    continue
                candidates.append({
                    "kind": "form_field", "url": f["action"], "method": f["method"], "name": i["name"],
                    "sample": "", "source": f"表单 {f['method']} {f['action']}" + ("" if f["has_csrf_token"] else "（无 CSRF token）"),
                })

        for l in links:
            if _same_origin(l, root) and l not in seen and not l.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".css", ".ico", ".woff", ".woff2")):
                queue.append(l)
        time.sleep(delay)

    # 去重
    uniq, k = [], set()
    for c in candidates:
        key = (c["kind"], c["url"], c["method"], c["name"])
        if key not in k:
            k.add(key)
            uniq.append(c)
    return {"root": root, "pages": pages, "candidates": uniq}


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/"
    print(f"爬取 {target}")
    r = crawl(target)
    print(f"\n页面 {len(r['pages'])} 个，候选点 {len(r['candidates'])} 个")
    print(json.dumps(r["candidates"][:10], ensure_ascii=False, indent=1))
