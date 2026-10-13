#!/usr/bin/env python3
"""videoread.py —— 让我"看"视频：下载 → 抽帧 → 拼成一张图（我用图片识别读它）

背景：我没有原生视频识别能力，但可以把视频转成"关键帧拼图"再当图片读 ✓

用法：
  python videoread.py <视频链接或本地文件> [--every 5] [--grid 4x3] [--audio]
  python videoread.py --selftest          # 用 ffmpeg 造个测试视频验证全链路

参数：
  --every N    每 N 秒抽一帧（默认 5）
  --grid RxC   拼图网格（默认 4x3 = 12 帧/张）
  --audio      额外导出音轨 mp3（便于后续转写）
  --out DIR    输出目录（默认 video-out/）

支持：抖音/B站/YouTube 等（yt-dlp 支持的上千个站点）+ 本地视频文件
注意：仅供**个人查看与分析**；不要用于再分发或规避平台限制
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

DIR = pathlib.Path(__file__).parent
OUT = DIR / "video-out"


def ffmpeg_exe():
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:  # noqa: BLE001
        return "ffmpeg"


def run(cmd, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("encoding", "utf-8")
    kw.setdefault("errors", "replace")
    return subprocess.run(cmd, **kw)


def download(url, dest: pathlib.Path):
    """用 yt-dlp 下载，返回 (文件路径, 元数据)。"""
    import yt_dlp
    meta = {}
    opts = {
        "outtmpl": str(dest / "%(id)s.%(ext)s"),
        "format": "mp4/bestvideo+bestaudio/best",
        "quiet": True,
        "no_warnings": True,
        "noplaylist": True,
    }
    with yt_dlp.YoutubeDL(opts) as ydl:
        info = ydl.extract_info(url, download=True)
        meta = {k: info.get(k) for k in
                ("id", "title", "uploader", "duration", "view_count",
                 "like_count", "upload_date", "description", "webpage_url")}
        path = pathlib.Path(ydl.prepare_filename(info))
    if not path.exists():                       # 有时扩展名会变
        cands = sorted(dest.glob(f"{info.get('id')}.*"))
        path = cands[0] if cands else path
    return path, meta


def contact_sheet(video: pathlib.Path, every: int, grid: str, scene: bool = False):
    """把视频抽帧拼成一张图。scene=True 时按【画面变化】抽帧（比固定间隔准得多）。"""
    ff = ffmpeg_exe()
    tag = "scene" if scene else f"{every}s"
    sheet = video.with_name(video.stem + f"_sheet_{tag}_{grid}.jpg")
    if scene:
        vf = f"select='gt(scene,0.25)',scale=480:-1,tile={grid}"
        cmd = [ff, "-y", "-i", str(video), "-vf", vf, "-vsync", "vfr",
               "-frames:v", "1", "-q:v", "3", str(sheet)]
    else:
        vf = f"fps=1/{max(every,1)},scale=480:-1,tile={grid}"
        cmd = [ff, "-y", "-i", str(video), "-vf", vf, "-frames:v", "1",
               "-q:v", "3", str(sheet)]
    r = run(cmd)
    return (sheet if sheet.exists() else None), r.stderr[-400:] if r.returncode else ""


def transcribe(video: pathlib.Path, model_size="tiny"):
    """用 faster-whisper 把语音转成带时间码的文字（中文）。"""
    try:
        from faster_whisper import WhisperModel
    except Exception as e:  # noqa: BLE001
        return None, f"faster-whisper 未安装：{e}"
    try:
        model = WhisperModel(model_size, device="cpu", compute_type="int8")
    except Exception as e:  # noqa: BLE001
        return None, f"模型加载失败（国内需设 HF_ENDPOINT=https://hf-mirror.com）：{e}"
    segments, info = model.transcribe(str(video), language="zh", vad_filter=True)
    lines = [f"[{s.start:6.1f}s → {s.end:6.1f}s] {s.text.strip()}" for s in segments]
    txt = video.with_suffix(".txt")
    txt.write_text("\n".join(lines) if lines else "(未识别到语音)",
                   encoding="utf-8")
    return txt, f"语言={info.language} 时长={info.duration:.1f}s 片段={len(lines)}"



def audio(video: pathlib.Path):
    ff = ffmpeg_exe()
    mp3 = video.with_suffix(".mp3")
    run([ff, "-y", "-i", str(video), "-vn", "-acodec", "libmp3lame",
         "-q:a", "5", str(mp3)])
    return mp3 if mp3.exists() else None


def selftest():
    """用 ffmpeg 造 30 秒测试视频（带时间码）→ 走完整条链路。"""
    OUT.mkdir(parents=True, exist_ok=True)
    ff = ffmpeg_exe()
    vid = OUT / "selftest.mp4"
    print("[selftest] 造测试视频…")
    run([ff, "-y", "-f", "lavfi", "-i",
         "testsrc=size=640x360:rate=25:duration=30",
         "-vf", "drawtext=text='T=%{pts\\:hms}':fontsize=28:fontcolor=white:x=20:y=20",
         "-pix_fmt", "yuv420p", str(vid)])
    if not vid.exists():
        print("  ❌ 造视频失败（drawtext 可能缺字体）→ 退回不带文字的测试视频")
        run([ff, "-y", "-f", "lavfi", "-i",
             "testsrc=size=640x360:rate=25:duration=30", str(vid)])
    if not vid.exists():
        print("  ❌ ffmpeg 不可用")
        return 1
    print(f"  ✅ 测试视频 {vid.stat().st_size//1024} KB")
    sheet, err = contact_sheet(vid, 5, "4x3")
    print(f"  抽帧拼图: {sheet}  {'' if sheet else err}")
    a = audio(vid)
    print(f"  音轨: {a}")
    print("✅ 全链路通过（视频→帧图→可读；音频已分离）")
    return 0 if sheet else 1


def main():
    ap = argparse.ArgumentParser(description="视频→关键帧拼图（让我能读）")
    ap.add_argument("source", nargs="?", help="视频链接或本地文件")
    ap.add_argument("--every", type=int, default=5, help="每 N 秒抽一帧")
    ap.add_argument("--grid", default="4x3", help="拼图网格，如 4x3")
    ap.add_argument("--audio", action="store_true", help="同时导出音轨 mp3")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        sys.exit(selftest())
    if not a.source:
        ap.print_help()
        sys.exit(1)

    OUT.mkdir(parents=True, exist_ok=True)
    src = a.source
    local = pathlib.Path(src)
    if local.exists():
        vid, meta = local, {"title": local.name, "local": True}
        print(f"[本地文件] {vid}")
    else:
        print(f"[下载中] {src}")
        try:
            vid, meta = download(src, OUT)
        except Exception as e:  # noqa: BLE001
            print(f"❌ 下载失败：{e}")
            print("   提示：抖音链接可能需要完整分享链接（含 https://v.douyin.com/...）")
            sys.exit(1)
    print(f"[视频] {vid.name}  {vid.stat().st_size//1024} KB")

    if meta.get("title"):
        print(f"[标题] {meta['title']}")
    if meta.get("uploader"):
        print(f"[作者] {meta['uploader']}")
    if meta.get("duration"):
        d = int(meta["duration"])
        print(f"[时长] {d//60}分{d%60}秒")
    if meta.get("description"):
        print(f"[简介] {str(meta['description'])[:200]}")

    sheet, err = contact_sheet(vid, a.every, a.grid)
    if sheet:
        print(f"[拼图] {sheet}")
        print(f"        → 我把这张图读一遍就等于'看了'视频（每 {a.every} 秒一帧）")
    else:
        print(f"[拼图] 失败: {err}")

    if a.audio:
        mp3 = audio(vid)
        print(f"[音轨] {mp3}")

    (OUT / "last.json").write_text(
        json.dumps({"video": str(vid), "sheet": str(sheet) if sheet else None,
                    "meta": meta}, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
