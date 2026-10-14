#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_remote.py — 从 KaringX/karing-ruleset 拉最新 .srs，解出规则，
生成 clash_rules/*.yaml（远程 payload）+ 手机/电脑两份 http 版配置。

用法（在本仓库根目录执行）：
    python3 tools/build_remote.py                       # 只重建 clash_rules/
    python3 tools/build_remote.py --repo 用户名/仓库名    # 额外生成两份客户端配置

产出：
    clash_rules/<slug>-domain.yaml          21 个域名规则文件
    clash_rules/<slug>-ip.yaml              11 个 IP 规则文件（仅对含 IP 的组）
    clash-verge-config.yaml                 电脑版（Clash Verge / mihomo）
    clash-meta-android.yaml                 手机版（Clash Meta for Android）
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import srs_to_lists as S  # noqa: E402

ROOT = os.path.dirname(HERE)
CDN = "https://fastly.jsdelivr.net/gh/KaringX/karing-ruleset@sing"
# Actions 跑在境外，jsDelivr 偶尔抽风；按顺序兜底
CDNS = [
    CDN,
    "https://cdn.jsdelivr.net/gh/KaringX/karing-ruleset@sing",
    "https://raw.githubusercontent.com/KaringX/karing-ruleset/sing",
]
CACHE = os.path.join(ROOT, ".cache")

# 组名 → 文件名用的 ASCII slug（URL 里不能有 emoji/空格，所以文件名用英文，
# 但 Clash 里显示的 provider 名仍保留 emoji 中文）
SLUG = {
    "🛑 广告拦截": "adblock",
    "🍃 应用净化": "app-clean",
    "Ⓜ️ 微软Bing": "bing",
    "Ⓜ️ 微软云盘": "onedrive",
    "Ⓜ️ 微软服务": "microsoft",
    "🍎 苹果服务": "apple",
    "🌏 Google": "google",
    "📢 谷歌FCM": "gcm",
    "📲 电报消息": "telegram",
    "💬 OpenAI": "openai",
    "♊ Gemini": "gemini",
    "🐱 GitHub": "github",
    "🎮 游戏平台": "gaming",
    "🎧 TikTok": "tiktok",
    "📸 Instagram": "instagram",
    "📹 油管视频": "youtube",
    "🎥 奈飞视频": "netflix",
    "📺 哔哩哔哩": "bilibili",
    "🎶 网易音乐": "netease",
    "🎯 国内直连": "cn-direct",
    "🌏 国外穿墙": "gfw",
}

OMAP = {"block": "REJECT", "direct": "DIRECT", "currentSelected": "🚀 节点选择"}
INTERVAL = 86400  # 秒；每天拉一次


def src_of(ref: str) -> str:
    kind, val = ref.split(":", 1)
    return {"acl": "ACL4SSR", "geosite": "geo/geosite", "geoip": "geo/geoip"}[kind] + "/" + val + ".srs"


def fetch(url: str, dest: str, min_size: int = 32, magic: bytes = None) -> bytes:
    """cURL 串行下载（并发会让 jsDelivr 批量 404），带本地缓存 + CDN 兜底。

    jsDelivr 找不到文件时返回 200 + 一段 "Couldn't find the requested file" 文本，
    所以只靠大小判断不够，必须校验 magic bytes。
    某个 CDN 抽风时自动换下一个。
    """
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.exists(dest) and os.path.getsize(dest) >= min_size:
        return open(dest, "rb").read()

    # 同一个文件在多个 CDN 上的备选地址（只换前缀，路径不变）
    variants = []
    for prefix in CDNS:
        variants.append(prefix + url[len(CDN):] if url.startswith(CDN) else None)
    variants = [v for v in variants if v] or [url]
    if url in variants:
        variants = [url] + [v for v in variants if v != url]

    last = ""
    for variant in variants:
        for attempt in range(3):
            subprocess.run(["curl", "-sL", "--retry", "3", "--retry-delay", "2",
                            "--max-time", "60", "-o", dest, variant], check=False)
            try:
                blob = open(dest, "rb").read()
            except FileNotFoundError:
                blob = b""
            if len(blob) >= min_size and (magic is None or blob[: len(magic)] == magic):
                return blob
            last = blob[:80].decode("utf-8", "replace")
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"下载失败（已试 {len(variants)} 个 CDN）: {url} -> {dest} 最后内容: {last!r}")


def merge_group(refs) -> S.RuleSet:
    m = S.RuleSet()
    for ref in refs:
        path = src_of(ref)
        blob = fetch(CDN + "/" + path, os.path.join(CACHE, path.replace("/", "__")), magic=b"SRS")
        rs = S.parse_srs(blob, ref)
        m.domain |= rs.domain
        m.domain_suffix |= rs.domain_suffix
        m.domain_keyword |= rs.domain_keyword
        m.domain_regex |= rs.domain_regex
        m.ip_cidr |= rs.ip_cidr
    return m


def domain_lines(m):
    out = [f"  - DOMAIN,{x}" for x in sorted(m.domain)]
    out += [f"  - DOMAIN-SUFFIX,{x.lstrip('.')}" for x in sorted(m.domain_suffix)]
    out += [f"  - DOMAIN-KEYWORD,{x}" for x in sorted(m.domain_keyword)]
    return out


def ip_lines(m):
    return [f"  - IP-CIDR,{x}" for x in sorted(m.ip_cidr)]


def main():
    # GitHub Actions 的容器里 LANG/PYTHONIOENCODING 可能不是 UTF-8，
    # print 含 emoji 的规则组名会 UnicodeEncodeError，这里强制覆盖。
    for var in ("PYTHONIOENCODING", "PYTHONUTF8"):
        os.environ.setdefault(var, "1" if var == "PYTHONUTF8" else "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", help="GitHub 用户名/仓库名，用于生成客户端配置里的 jsDelivr 地址")
    ap.add_argument("--branch", default="main")
    args = ap.parse_args()

    cn = json.loads(fetch(CDN + "/recommend/cn.json", os.path.join(CACHE, "cn.json"), min_size=1000))

    outdir = os.path.join(ROOT, "clash_rules")
    os.makedirs(outdir, exist_ok=True)

    spec = []  # (组名, outbound, slug, domain条数, ip条数)
    for g in cn["rules"]:
        name = g["name"]
        slug = SLUG.get(name)
        if slug is None:
            raise RuntimeError(f"未知规则组: {name!r}，请在 SLUG 里补一条")
        m = merge_group(g["rule_set"])
        dl, il = domain_lines(m), ip_lines(m)
        with open(os.path.join(outdir, f"{slug}-domain.yaml"), "w", encoding="utf-8") as f:
            f.write("payload:\n" + "\n".join(dl) + "\n")
        if il:
            with open(os.path.join(outdir, f"{slug}-ip.yaml"), "w", encoding="utf-8") as f:
                f.write("payload:\n" + "\n".join(il) + "\n")
        spec.append((name, g["outbound"], slug, len(dl), len(il)))
        print(f"  {name:<14} -> {slug:<10} dom={len(dl)} ip={len(il)}")

    total = sum(a[3] + a[4] for a in spec)
    print(f"\nclash_rules/: {len(os.listdir(outdir))} 个文件, {total} 条规则")

    if not args.repo:
        print("（未给 --repo，跳过客户端配置生成）")
        return 0

    base = f"https://fastly.jsdelivr.net/gh/{args.repo}@{args.branch}/clash_rules"

    def providers():
        L = ["rule-providers:"]
        for name, ob, slug, dl, il in spec:
            for suffix, n in (("domain", dl), ("ip", il)):
                if not n:
                    continue
                L.append(f"  {name}-{suffix}:")
                L.append("    type: http")
                L.append("    behavior: classical")
                L.append(f"    url: {base}/{slug}-{suffix}.yaml")
                L.append(f"    path: ./ruleset/{slug}-{suffix}.yaml")
                L.append(f"    interval: {INTERVAL}")
        return L

    def rules():
        L = ["rules:"]
        for band, title in (("block", "广告拦截（必须最前）"),
                            ("currentSelected", "走代理"),
                            ("direct", "国内直连（必须在走代理之后）")):
            L.append(f"  # === {title} ===")
            for name, ob, slug, dl, il in spec:
                if ob != band:
                    continue
                if dl:
                    L.append(f"  - RULE-SET,{name}-domain,{OMAP[ob]}")
                if il:
                    L.append(f"  - RULE-SET,{name}-ip,{OMAP[ob]}")
        L.append("  # === 兜底 ===")
        L.append("  - MATCH,🐟 漏网之鱼")
        return L

    header = [
        "KaringX/karing-ruleset 分流规则 —— 远程自动更新版",
        "规则来源: recommend/cn.json 的 21 个规则组，由 tools/build_remote.py 从 .srs 解出",
        f"远程地址: {base}/<slug>-domain.yaml",
        f"更新间隔: {INTERVAL} 秒（每天自动拉一次）",
        "",
        "⚠️ 本文件只有 rule-providers + rules，不含节点。整段贴进你自己的配置即可。",
        "⚠️ 你的配置里必须有两个策略组（名字不一样就全文替换）：",
        "     🚀 节点选择   走代理",
        "     🐟 漏网之鱼   兜底",
        "   DIRECT / REJECT 是 Clash 内置，不用定义。",
        "⚠️ 规则从上到下匹配，命中即停。顺序已按 karing 原版排好，别乱调。",
    ]

    for path, extra in (
        (os.path.join(ROOT, "clash-verge-config.yaml"),
         ["适用: Clash Verge / Clash Meta (mihomo) 桌面版 —— Windows / macOS / Linux",
          "用法: 配置 → 右键当前配置 → 编辑 → 把本文件两段整段粘贴进去"]),
        (os.path.join(ROOT, "clash-meta-android.yaml"),
         ["适用: Clash Meta for Android 手机版",
          "用法: 配置 → 你的订阅 → 覆写(Override) → 粘贴本文件 → 启用 → 启动"]),
    ):
        lines = ["# " + t if t else "#" for t in header[:1] + extra + header[1:]]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
            f.write("\n".join(providers()) + "\n\n")
            f.write("\n".join(rules()) + "\n")
        print(f"{os.path.basename(path)}: {os.path.getsize(path)} B")

    return 0


if __name__ == "__main__":
    sys.exit(main())
