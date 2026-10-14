#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
srs_to_lists.py — 把 KaringX/karing-ruleset 的 sing-box 规则集导出成通用文本/CSV 列表

用途:
    1. sing-box / karing / clash / mihomo / Shadowrocket / Quantumult X / v2ray 系列 (.srs/.json 直接用或转 .mrs/.list/.yaml)
    2. Cloudflare Zero Trust Gateway Lists（域名/URL/IP 列表，CSV 上传或直接写 YAML/文本）
    3. 其它不支持 .srs 的客户端（AdGuard Home、hosts 文件、dnsmasq、Surge 等）

支持输入:
    - .srs  sing-box 二进制规则集。完整实现 sing-box 二进制布局：
            magic "SRS" + version(u8) + zlib(deflate)，内含 varint 条目、domain succinct-set
            Matcher、ipset(ranges)、AdGuard Matcher。
    - .json sing-box 规则集源格式（同一份数据的明文版）
    - .list Shadowrocket / Clash 文本规则（DOMAIN-SUFFIX,xxx / DOMAIN-KEYWORD,xxx / IP-CIDR,xxx）

依赖: 仅 Python 3.8+ 标准库（zlib / json / csv / argparse），无第三方包。

二进制格式依据（已核对源码）:
    sing-box  common/srs/binary.go        容器 / item 枚举
    sing      common/domain/matcher.go    domain Matcher（succinct set）
    sing      common/domain/set.go        succinctSet 编解码与 keys() 遍历
    sing      common/domain/adguard_matcher.go
    sing      common/varbin/slices.go     ReadSlice = uvarint count + 定长大端元素

用法示例:
    # 下载并转换去广告规则，输出到 ./out
    python3 srs_to_lists.py --url https://raw.githubusercontent.com/KaringX/karing-ruleset/sing/ACL4SSR/BanAD.srs out

    # 转换本地文件，格式为 Cloudflare 域名清单（纯文本，一行一个）
    python3 srs_to_lists.py --format cloudflare-domain ACL4SSR/BanAD.srs out

    # 生成 Cloudflare CSV（带表头，符合 Zero Trust Lists 上传要求）
    python3 srs_to_lists.py --format cloudflare-csv --list-type DOMAIN BanAD.srs out

    # 生成 mihomo/clash yaml payload（domain 或 classical behavior）
    python3 srs_to_lists.py --format mihomo-domain BanAD.srs out
    python3 srs_to_lists.py --format classical BanAD.srs out

    # 生成 IP 列表（CIDR）
    python3 srs_to_lists.py --format ipcidr ChinaIp.srs out

    # 解析结果与同名 .json 逐条比对（自检，需同目录有同名 .json）
    python3 srs_to_lists.py --verify BanAD.srs out

    # 批量转换多个 URL
    python3 srs_to_lists.py --url-list urls.txt outdir
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import os
import struct
import sys
import urllib.request
import zlib
from typing import Dict, Iterable, List, Optional, Set, Tuple

UA = "Mozilla/5.0 (compatible; srs_to_lists/2.0)"

# ================================================================ 数据结构


class RuleSet:
    """解析后的规则集：分类存放，避免丢失语义"""

    def __init__(self, name: str = "rule") -> None:
        self.name = name
        self.domain: Set[str] = set()          # 精确域名
        self.domain_suffix: Set[str] = set()   # 后缀域名（已去掉前导点）
        self.domain_keyword: Set[str] = set()  # 关键字
        self.domain_regex: Set[str] = set()    # 正则
        self.ip_cidr: Set[str] = set()         # IPv4/IPv6 CIDR
        self.adguard: Set[str] = set()         # AdGuard 规则串（||x^ / |x / x^）
        self.notes: List[str] = []
        # 无法用域名/IP 列表表达的维度计数（端口、进程名、网络类型…），仅提示用
        self.discarded: Dict[str, int] = {}

    def drop(self, itype: int) -> None:
        label = DISCARD_LABELS.get(itype, hex(itype))
        self.discarded[label] = self.discarded.get(label, 0) + 1

    def total(self) -> int:
        return (
            len(self.domain)
            + len(self.domain_suffix)
            + len(self.domain_keyword)
            + len(self.domain_regex)
            + len(self.ip_cidr)
            + len(self.adguard)
        )

    def as_domains(self) -> List[str]:
        """精确域名 + 后缀域名（无前导点）"""
        out = list(self.domain)
        out.extend(s.lstrip(".") for s in self.domain_suffix if s.strip())
        return sorted(set(d for d in out if d))

    def as_keywords(self) -> List[str]:
        return sorted(self.domain_keyword)

    def as_regex(self) -> List[str]:
        return sorted(self.domain_regex)

    def as_ipcidr(self) -> List[str]:
        return sorted(self.ip_cidr)


# ================================================================ 字节流读取


class ByteReader:
    """对应 sing common/varbin.Reader"""

    def __init__(self, data: bytes) -> None:
        self.d = data
        self.i = 0

    def _need(self, n: int) -> None:
        if self.i + n > len(self.d):
            raise EOFError(f"需要 {n} 字节，剩余 {len(self.d) - self.i}")

    def u8(self) -> int:
        self._need(1)
        v = self.d[self.i]
        self.i += 1
        return v

    def take(self, n: int) -> bytes:
        self._need(n)
        v = self.d[self.i : self.i + n]
        self.i += n
        return v

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def uvarint(self) -> int:
        """Go encoding/binary Uvarint"""
        val = 0
        shift = 0
        while True:
            b = self.u8()
            if shift == 63 and b > 1:
                raise ValueError("uvarint 溢出")
            val |= (b & 0x7F) << shift
            if not (b & 0x80):
                return val
            shift += 7
            if shift > 63:
                raise ValueError("uvarint 过长")

    # ---- varbin.ReadSlice[T](reader, BigEndian) ----
    def slice_u16(self) -> List[int]:
        n = self.uvarint()
        out = []
        for _ in range(n):
            out.append(self.u16())
        return out

    def slice_u64(self) -> List[int]:
        n = self.uvarint()
        if n == 0:
            return []
        raw = self.take(8 * n)
        return list(struct.unpack(">%dQ" % n, raw))

    def slice_u8(self) -> List[int]:
        n = self.uvarint()
        return list(self.take(n))

    # ---- readRuleItemString: uvarint count + 每个 ReadSlice[byte] ----
    def item_strings(self) -> List[str]:
        n = self.uvarint()
        out = []
        for _ in range(n):
            out.append(bytes(self.slice_u8()).decode("utf-8", "replace"))
        return out

    # ---- srs.ReadPrefix: uvarint addrLen(4|16) + addr + u8 bits ----
    def prefix(self) -> str:
        addr_len = self.uvarint()
        if addr_len not in (4, 16):
            raise ValueError(f"非法地址长度 {addr_len}")
        raw = self.take(addr_len)
        bits = self.u8()
        ip = ipaddress.ip_address(bytes(raw))
        return f"{ip}/{bits}"


# ================================================================ succinct set
#
# 布局（sing common/domain/set.go）:
#     u8 0                          (保留)
#     ReadSlice[uint64] leaves      uvarint n + n*8 字节大端
#     ReadSlice[uint64] labelBitmap
#     ReadSlice[byte]   labels
# 校验: ones == zeros + 1 且 len(labels) == zeros


class SuccinctSet:
    def __init__(self, leaves: List[int], label_bitmap: List[int], labels: bytes) -> None:
        self.leaves = leaves
        self.bm = label_bitmap
        self.labels = labels
        # 累积 popcount: cum[k] = bm[0:k] 中 1 的个数
        cum = [0]
        acc = 0
        for w in self.bm:
            acc += bin(w).count("1")
            cum.append(acc)
        self.cum = cum

    def _get_bit(self, bm: List[int], i: int) -> int:
        if i >> 6 >= len(bm):
            return 0
        return (bm[i >> 6] >> (i & 63)) & 1

    def _get_bit_leaves(self, i: int) -> int:
        return self._get_bit(self.leaves, i)

    def count_zeros(self, i: int) -> int:
        """bm[0:i] 中 0 的个数"""
        return i - self._rank1(i)

    def _rank1(self, i: int) -> int:
        """bm[0:i] 中 1 的个数"""
        w_i = i >> 6
        j = i & 63
        if w_i >= len(self.bm):
            return self.cum[-1] if self.cum else 0
        n = self.cum[w_i]
        w = self.bm[w_i] & ((1 << j) - 1)
        return n + bin(w).count("1")

    def select_ith_one(self, i: int) -> int:
        """第 i 个 1 的绝对位下标（0-based）— 对应 Go select32R64 的第一个返回值"""
        # 二分找所在 word
        lo, hi = 0, len(self.bm) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.cum[mid] <= i:
                lo = mid
            else:
                hi = mid - 1
        w_i = lo
        remaining = i - self.cum[w_i]
        w = self.bm[w_i]
        for b in range(64):
            if (w >> b) & 1:
                if remaining == 0:
                    return (w_i << 6) + b
                remaining -= 1
        raise ValueError("select 越界")

    def keys(self) -> List[str]:
        """对应 Go (*succinctSet).keys()，迭代式遍历"""
        result: List[str] = []
        current: bytearray = bytearray()
        if self._get_bit_leaves(0):
            result.append("")
        # stack 元素 [nodeId, bmIdx]
        stack: List[List[int]] = [[0, 0]]
        while stack:
            top = stack[-1]
            if self._get_bit(self.bm, top[1]):
                stack.pop()
                if stack:
                    del current[len(current) - 1 :]
                    stack[-1][1] += 1
                continue
            current.append(self.labels[top[1] - top[0]])
            next_node_id = self.count_zeros(top[1] + 1)
            next_bm_idx = self.select_ith_one(next_node_id - 1) + 1
            if self._get_bit_leaves(next_node_id):
                result.append(bytes(current).decode("utf-8", "replace"))
            stack.append([next_node_id, next_bm_idx])
        return result


def read_succinct_set(r: ByteReader) -> SuccinctSet:
    r.u8()  # 保留字节，必须为 0
    leaves = r.slice_u64()
    label_bitmap = r.slice_u64()
    labels = bytes(r.slice_u8())

    # Go: lastOneIndex = wordIndex<<6 | (63 - bits.LeadingZeros64(word))
    # 即该 word 内最高位 1 的下标 = word.bit_length() - 1
    ones = 0
    last_one = -1
    for wi, w in enumerate(label_bitmap):
        ones += bin(w).count("1")
        if w != 0:
            last_one = (wi << 6) | (w.bit_length() - 1)
    zeros = last_one + 1 - ones
    if ones != zeros + 1 or len(labels) != zeros:
        raise ValueError("domain: malformed succinct set")
    return SuccinctSet(leaves, label_bitmap, labels)


def reverse_domain(s: str) -> str:
    """sing reverseDomain: 按 UTF-8 字符反转"""
    return s[::-1]


PREFIX_LABEL = "\r"
ROOT_LABEL = "\n"
SUFFIX_LABEL = "\b"


def matcher_dump(keys: List[str]) -> Tuple[List[str], List[str]]:
    """对应 sing domain.Matcher.Dump(): 返回 (domainList, prefixList)"""
    domain_map: Dict[str, bool] = {}
    prefix_map: Dict[str, bool] = {}
    prefix_list: List[str] = []
    for key in keys:
        key = reverse_domain(key)
        if not key:
            continue
        if key[0] == PREFIX_LABEL:
            prefix_map[key[1:]] = True
        elif key[0] == ROOT_LABEL:
            prefix_list.append(key[1:])
        else:
            domain_map[key] = True
    for raw_prefix in prefix_map:
        if raw_prefix[:1] == ".":
            root_domain = raw_prefix[1:]
            if root_domain in domain_map:
                del domain_map[root_domain]
                prefix_list.append(root_domain)
                continue
        prefix_list.append(raw_prefix)
    return sorted(domain_map.keys()), sorted(prefix_list)


def adguard_dump(keys: List[str]) -> List[str]:
    """对应 sing domain.AdGuardMatcher.Dump(): 还原 ||x^ / |x / x^ 规则行"""
    out: List[str] = []
    for key in keys:
        key = reverse_domain(key)
        if not key:
            continue
        is_suffix = False
        has_start = False
        has_end = False
        if key[0] == PREFIX_LABEL:
            key = key[1:]
        elif key[0] == ROOT_LABEL:
            key = key[1:]
            is_suffix = True
        else:
            has_start = True
        if key[-1:] == SUFFIX_LABEL:
            key = key[:-1]
        else:
            has_end = True
        if is_suffix:
            key = "||" + key
        elif has_start:
            key = "|" + key
        if has_end:
            key += "^"
        out.append(key)
    return sorted(out)


# ================================================================ .srs 解析
#
# 文件头: b"SRS" + u8 version(1..5) + zlib 流
# 解压后: uvarint ruleCount, 然后 ruleCount 条 rule

# item 类型（sing-box common/srs/binary.go iota）
IT_QUERY_TYPE = 0
IT_NETWORK = 1
IT_DOMAIN = 2
IT_DOMAIN_KEYWORD = 3
IT_DOMAIN_REGEX = 4
IT_SOURCE_IPCIDR = 5
IT_IPCIDR = 6
IT_SOURCE_PORT = 7
IT_SOURCE_PORT_RANGE = 8
IT_PORT = 9
IT_PORT_RANGE = 10
IT_PROCESS_NAME = 11
IT_PROCESS_PATH = 12
IT_PACKAGE_NAME = 13
IT_WIFI_SSID = 14
IT_WIFI_BSSID = 15
IT_ADGUARD_DOMAIN = 16
IT_PROCESS_PATH_REGEX = 17
IT_NETWORK_TYPE = 18
IT_NETWORK_IS_EXPENSIVE = 19
IT_NETWORK_IS_CONSTRAINED = 20
IT_NETWORK_INTERFACE_ADDRESS = 21
IT_DEFAULT_INTERFACE_ADDRESS = 22
IT_PACKAGE_NAME_REGEX = 23
IT_FINAL = 0xFF


def _int_to_ip(v: int, bits: int) -> str:
    """整数 → IP 字符串，按 bits 决定 v4/v6"""
    return str(ipaddress.ip_address(v.to_bytes(4, "big") if bits == 32 else v.to_bytes(16, "big")))


def _range_to_cidrs(start: int, end: int, bits: int) -> List[str]:
    """闭区间 [start,end] 分解为最少的 CIDR 列表"""
    out: List[str] = []
    while start <= end:
        # start 能对齐的最大块
        step = start & -start
        if step == 0:
            step = 1 << bits
        size = step
        while start + size - 1 > end:
            size >>= 1
        plen = bits - (size.bit_length() - 1)
        out.append(f"{_int_to_ip(start, bits)}/{plen}")
        start += size
    return out


def _ranges_to_cidrs(ranges4: List[Tuple[int, int]], ranges6: List[Tuple[int, int]]) -> List[str]:
    out: List[str] = []
    for s, e in ranges4:
        out.extend(_range_to_cidrs(s, e, 32))
    for s, e in ranges6:
        out.extend(_range_to_cidrs(s, e, 128))
    return out


def _read_ipset(r: ByteReader, rs: RuleSet) -> None:
    """sing-box common/srs/ip_set.go readIPSet"""
    version = r.u8()
    if version != 1:
        raise ValueError(f"不支持的 ipset 版本 {version}")
    length = r.u64()  # 注意：是定长 uint64 大端，不是 uvarint
    ranges4: List[Tuple[int, int]] = []
    ranges6: List[Tuple[int, int]] = []
    for _ in range(length):
        frm, f_len = _read_ipset_addr(r)
        to, t_len = _read_ipset_addr(r)
        if f_len != t_len:
            raise ValueError("ipset: from/to 长度不一致")
        if f_len == 4:
            ranges4.append((frm, to))
        else:
            ranges6.append((frm, to))
    for c in _ranges_to_cidrs(ranges4, ranges6):
        rs.ip_cidr.add(c)


def _read_ipset_addr(r: ByteReader) -> Tuple[int, int]:
    addr_len = r.uvarint()
    if addr_len not in (4, 16):
        raise ValueError(f"ipset: 非法地址长度 {addr_len}")
    raw = r.take(addr_len)
    return int.from_bytes(raw, "big"), addr_len


# 无法用域名/IP 列表表达的维度：读取后丢弃，但计数并在 --stats 里提示
DISCARD_LABELS = {
    IT_QUERY_TYPE: "query_type",
    IT_NETWORK: "network",
    IT_SOURCE_PORT: "source_port",
    IT_PORT: "port",
    IT_SOURCE_PORT_RANGE: "source_port_range",
    IT_PORT_RANGE: "port_range",
    IT_PROCESS_NAME: "process_name",
    IT_PROCESS_PATH: "process_path",
    IT_PACKAGE_NAME: "package_name",
    IT_WIFI_SSID: "wifi_ssid",
    IT_WIFI_BSSID: "wifi_bssid",
    IT_PROCESS_PATH_REGEX: "process_path_regex",
    IT_PACKAGE_NAME_REGEX: "package_name_regex",
    IT_NETWORK_TYPE: "network_type",
    IT_NETWORK_IS_EXPENSIVE: "network_is_expensive",
    IT_NETWORK_IS_CONSTRAINED: "network_is_constrained",
    IT_NETWORK_INTERFACE_ADDRESS: "network_interface_address",
    IT_DEFAULT_INTERFACE_ADDRESS: "default_interface_address",
}


def _read_default_rule(r: ByteReader, rs: RuleSet) -> None:
    while True:
        itype = r.u8()
        if itype == IT_FINAL:
            r.u8()  # invert
            return
        if itype == IT_QUERY_TYPE:
            r.slice_u16()
            rs.drop(itype)
        elif itype == IT_NETWORK:
            r.item_strings()
            rs.drop(itype)
        elif itype == IT_DOMAIN:
            _domain_item(r, rs)
        elif itype == IT_DOMAIN_KEYWORD:
            rs.domain_keyword.update(r.item_strings())
        elif itype == IT_DOMAIN_REGEX:
            rs.domain_regex.update(r.item_strings())
        elif itype in (IT_SOURCE_IPCIDR, IT_IPCIDR):
            _read_ipset(r, rs)
        elif itype in (IT_SOURCE_PORT, IT_PORT):
            r.slice_u16()
            rs.drop(itype)
        elif itype in (
            IT_SOURCE_PORT_RANGE,
            IT_PORT_RANGE,
            IT_PROCESS_NAME,
            IT_PROCESS_PATH,
            IT_PACKAGE_NAME,
            IT_WIFI_SSID,
            IT_WIFI_BSSID,
            IT_PROCESS_PATH_REGEX,
            IT_PACKAGE_NAME_REGEX,
        ):
            r.item_strings()
            rs.drop(itype)
        elif itype == IT_ADGUARD_DOMAIN:
            rs.adguard.update(adguard_dump(read_succinct_set(r).keys()))
        elif itype == IT_NETWORK_TYPE:
            r.slice_u8()
            rs.drop(itype)
        elif itype in (IT_NETWORK_IS_EXPENSIVE, IT_NETWORK_IS_CONSTRAINED):
            rs.drop(itype)
        elif itype == IT_NETWORK_INTERFACE_ADDRESS:
            for _ in range(r.uvarint()):
                r.u8()                       # key: InterfaceType
                for _j in range(r.uvarint()):
                    r.prefix()
            rs.drop(itype)
        elif itype == IT_DEFAULT_INTERFACE_ADDRESS:
            for _j in range(r.uvarint()):
                r.prefix()
            rs.drop(itype)
        else:
            raise ValueError(f"未知 rule item type: {itype}")


def _domain_item(r: ByteReader, rs: RuleSet) -> None:
    """domain item → Matcher.Dump() → domain / domain_suffix"""
    m = read_succinct_set(r)
    domains, prefixes = matcher_dump(m.keys())
    rs.domain.update(domains)
    rs.domain_suffix.update(p.lstrip(".") for p in prefixes)


def _read_logical_rule_body(r: ByteReader, rs: RuleSet, count: int) -> None:
    for _ in range(count):
        _read_rule_dispatch(r, rs)
    r.u8()  # invert


def _read_rule_dispatch(r: ByteReader, rs: RuleSet) -> None:
    rtype = r.u8()
    if rtype == 0:
        _read_default_rule(r, rs)
    elif rtype == 1:
        mode = r.u8()
        count = r.uvarint()
        _read_logical_rule_body(r, rs, count)
        rs.notes.append(f"含 logical(mode={mode}) 子规则，已按普通条目展开")
    else:
        raise ValueError(f"未知 rule type: {rtype}")


def decompress_srs(blob: bytes) -> Tuple[int, bytes]:
    if len(blob) < 4 or blob[:3] != b"SRS":
        raise ValueError("不是 sing-box .srs 文件（缺少 SRS magic）")
    version = blob[3]
    if not 1 <= version <= 5:
        raise ValueError(f"不支持的规则集版本: {version}")
    try:
        return version, zlib.decompress(blob[4:])
    except zlib.error as e:
        raise ValueError(f"zlib 解压失败: {e}")


def parse_srs(blob: bytes, name: str = "rule") -> RuleSet:
    version, payload = decompress_srs(blob)
    rs = RuleSet(name)
    rs.notes.append(f"srs version={version}")
    r = ByteReader(payload)
    count = r.uvarint()
    for i in range(count):
        _read_rule_dispatch(r, rs)
    return rs


# ================================================================ .json 解析


def parse_json(blob: bytes, name: str = "rule") -> RuleSet:
    data = json.loads(blob.decode("utf-8", "replace"))
    rs = RuleSet(name)
    rules = data.get("rules")
    if rules is None:
        rs.notes.append("该 json 无 rules 字段（可能是 karing 规则组配置，非规则集）")
        return rs
    rs.notes.append(f"json version={data.get('version')}")
    for rule in rules:
        if rule.get("type") == "logical":
            _walk_logical(rule, rs)
        else:
            _collect(rule, rs)
    return rs


def _walk_logical(node: dict, rs: RuleSet) -> None:
    for sub in node.get("rules", []) or []:
        if sub.get("type") == "logical":
            _walk_logical(sub, rs)
        else:
            _collect(sub, rs)


def _as_list(v) -> List[str]:
    """仓库里部分 json 的字段写成字符串而非数组，统一成列表"""
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return [str(x) for x in v]


def _collect(rule: dict, rs: RuleSet) -> None:
    rs.domain.update(_as_list(rule.get("domain")))
    rs.domain_suffix.update(s.lstrip(".") for s in _as_list(rule.get("domain_suffix")))
    rs.domain_keyword.update(_as_list(rule.get("domain_keyword")))
    rs.domain_regex.update(_as_list(rule.get("domain_regex")))
    rs.ip_cidr.update(_as_list(rule.get("ip_cidr")))
    rs.adguard.update(_as_list(rule.get("adguard_domain")))


# ================================================================ .list 解析


def parse_list(blob: bytes, name: str = "rule") -> RuleSet:
    rs = RuleSet(name)
    for line in blob.decode("utf-8", "replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        parts = [p.strip() for p in s.split(",", 2)]
        if len(parts) < 2:
            continue
        kind, val = parts[0].upper(), parts[1]
        if not val:
            continue
        if kind == "DOMAIN":
            rs.domain.add(val)
        elif kind in ("DOMAIN-SUFFIX", "HOST-SUFFIX", "HOST"):
            rs.domain_suffix.add(val.lstrip("."))
        elif kind in ("DOMAIN-KEYWORD", "HOST-KEYWORD"):
            rs.domain_keyword.add(val)
        elif kind in ("IP-CIDR", "IP-CIDR6"):
            rs.ip_cidr.add(val)
        elif kind == "DOMAIN-REGEX":
            rs.domain_regex.add(val)
        elif kind in ("USER-AGENT", "URL-REGEX", "PROCESS-NAME"):
            rs.notes.append(f"忽略不支持的类型: {kind}")
    return rs


# ================================================================ 加载入口


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    return urllib.request.urlopen(req, timeout=60).read()


def load_source(path: str, name: str = "", blob: Optional[bytes] = None) -> RuleSet:
    if blob is None:
        if path.startswith("http://") or path.startswith("https://"):
            blob = fetch(path)
        else:
            with open(path, "rb") as f:
                blob = f.read()
    if not name:
        name = os.path.basename(path.split("?")[0])

    low = name.lower()
    if low.endswith(".srs") or blob[:3] == b"SRS":
        return parse_srs(blob, name)
    if low.endswith(".json"):
        return parse_json(blob, name)
    return parse_list(blob, name)


def strip_ext(n: str) -> str:
    for e in (".srs", ".json", ".list", ".txt", ".yaml", ".yml"):
        if n.lower().endswith(e):
            return n[: -len(e)]
    return n


# ================================================================ 自检（与 json 比对）


def _cidr_canonical(cidrs: Set[str]) -> Set[str]:
    """把 CIDR 集合归一化成最小等价集合，便于比较"""
    v4: List[Tuple[int, int]] = []
    v6: List[Tuple[int, int]] = []
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        s = int(net.network_address)
        e = int(net.broadcast_address)
        (v4 if net.version == 4 else v6).append((s, e))
    out = set()
    for ranges, bits in ((v4, 32), (v6, 128)):
        if not ranges:
            continue
        ranges.sort()
        merged = [list(ranges[0])]
        for s, e in ranges[1:]:
            if s <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        for s, e in merged:
            out.update(_range_to_cidrs(s, e, bits))
    return out


def verify(blob_srs: bytes, blob_json: bytes, name: str) -> List[str]:
    msgs: List[str] = []
    a = parse_srs(blob_srs, name)
    b = parse_json(blob_json, name)
    for field in ("domain", "domain_suffix", "domain_keyword", "domain_regex", "adguard"):
        sa, sb = getattr(a, field), getattr(b, field)
        if sa == sb:
            msgs.append(f"  ✓ {field}: {len(sa)} 条一致")
        elif sb <= sa:
            # 仓库里部分 .json 比 .srs 旧，只是少了后加的条目，并非解析错误
            msgs.append(f"  ⚠ {field}: json {len(sb)} 条是解析结果 {len(sa)} 条的子集（json 较旧，非解析错误）")
        else:
            only_a = sorted(sa - sb)
            only_b = sorted(sb - sa)
            msgs.append(
                f"  ✗ {field}: 解析 {len(sa)} / json {len(sb)}；"
                f"仅解析有 {len(only_a)}（例 {only_a[:3]}）；仅 json 有 {len(only_b)}（例 {only_b[:3]}）"
            )
    ca, cb = _cidr_canonical(a.ip_cidr), _cidr_canonical(b.ip_cidr)
    if ca == cb:
        msgs.append(f"  ✓ ip_cidr: 归一化后 {len(ca)} 个前缀一致（原始写法 {len(b.ip_cidr)} 条）")
    elif cb <= ca:
        msgs.append(f"  ⚠ ip_cidr: json {len(cb)} 个前缀是解析结果 {len(ca)} 个的子集（json 较旧）")
    else:
        msgs.append(
            f"  ✗ ip_cidr: 归一化 {len(ca)} vs {len(cb)}；"
            f"仅解析有 {len(ca - cb)}（例 {sorted(ca - cb)[:3]}）；仅 json 有 {len(cb - ca)}（例 {sorted(cb - ca)[:3]}）"
        )
    return msgs


# ================================================================ 输出格式


def fmt_plain(rs: RuleSet) -> str:
    return "\n".join(rs.as_domains()) + "\n"


def fmt_ipcidr(rs: RuleSet) -> str:
    return "\n".join(rs.as_ipcidr()) + "\n"


def fmt_cloudflare_domain(rs: RuleSet) -> str:
    seen: Set[str] = set()
    out: List[str] = []
    for d in rs.as_domains():
        d = d.strip().strip(".")
        if not d or d in seen:
            continue
        seen.add(d)
        out.append(d)
    return "\n".join(out) + "\n"


def fmt_cloudflare_csv(rs: RuleSet, list_type: str = "DOMAIN") -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["value", "description"])
    if list_type.upper() == "IP":
        for v in rs.as_ipcidr():
            w.writerow([v, f"from {rs.name}"])
    else:
        for v in fmt_cloudflare_domain(rs).splitlines():
            if v.strip():
                w.writerow([v.strip(), f"from {rs.name}"])
    return buf.getvalue()


def fmt_mihomo_domain(rs: RuleSet) -> str:
    lines = ["payload:"]
    for d in rs.as_domains():
        lines.append(f"  - '{d}'")
    return "\n".join(lines) + "\n"


def fmt_classical(rs: RuleSet) -> str:
    lines = ["payload:"]
    for d in sorted(rs.domain):
        lines.append(f"  - DOMAIN,{d}")
    for s in sorted(rs.domain_suffix):
        lines.append(f"  - DOMAIN-SUFFIX,{s.lstrip('.')}")
    for k in rs.as_keywords():
        lines.append(f"  - DOMAIN-KEYWORD,{k}")
    for c in rs.as_ipcidr():
        lines.append(f"  - IP-CIDR,{c}")
    return "\n".join(lines) + "\n"


def fmt_shadowrocket(rs: RuleSet) -> str:
    lines: List[str] = []
    for d in sorted(rs.domain):
        lines.append(f"DOMAIN,{d}")
    for s in sorted(rs.domain_suffix):
        lines.append(f"DOMAIN-SUFFIX,{s.lstrip('.')}")
    for k in rs.as_keywords():
        lines.append(f"DOMAIN-KEYWORD,{k}")
    for c in rs.as_ipcidr():
        lines.append(f"IP-CIDR,{c}")
    return "\n".join(lines) + "\n"


def fmt_surge(rs: RuleSet) -> str:
    lines = ["[Rule]"]
    lines.extend(fmt_shadowrocket(rs).rstrip("\n").split("\n"))
    return "\n".join(lines) + "\n"


def fmt_hosts(rs: RuleSet) -> str:
    lines = ["# generated from " + rs.name]
    for d in fmt_cloudflare_domain(rs).splitlines():
        if d.strip():
            lines.append(f"0.0.0.0 {d.strip()}")
    return "\n".join(lines) + "\n"


def fmt_adguard(rs: RuleSet) -> str:
    """AdGuard / AdGuard Home 规则（保留 ||x^ 语法）"""
    lines = ["! generated from " + rs.name]
    lines.extend(rs.adguard)
    for d in sorted(rs.domain):
        lines.append(f"||{d}^")
    for s in sorted(rs.domain_suffix):
        lines.append(f"||{s.lstrip('.')}^")
    for k in rs.as_keywords():
        lines.append(k)
    return "\n".join(lines) + "\n"


def fmt_qx(rs: RuleSet) -> str:
    """Quantumult X 过滤分规则 begindns / beginfilter part"""
    lines: List[str] = []
    # 精确域名 + 后缀都走 host-suffix-like：host 为精确，host-suffix 为后缀
    for d in sorted(rs.domain):
        lines.append(f"host, {d}, reject")
    for s in sorted(rs.domain_suffix):
        lines.append(f"host-suffix, {s.lstrip('.')}, reject")
    for k in rs.as_keywords():
        lines.append(f"host-keyword, {k}, reject")
    for c in rs.as_ipcidr():
        lines.append(f"ip-cidr, {c}, reject")
    return "\n".join(lines) + "\n"


FORMATS: Dict[str, Tuple[str, str]] = {
    "plain":             ("纯域名列表（一行一个，suffix 无前导点）", ".txt"),
    "cloudflare-domain": ("Cloudflare ZT 域名清单（纯文本，精确域名）", ".txt"),
    "cloudflare-csv":    ("Cloudflare ZT Lists CSV（value,description）", ".csv"),
    "ipcidr":            ("CIDR 列表", ".txt"),
    "mihomo-domain":     ("mihomo/clash behavior:domain payload", ".yaml"),
    "classical":         ("mihomo/clash behavior:classical payload", ".yaml"),
    "shadowrocket":      ("Shadowrocket/Quantumult X 规则", ".list"),
    "surge":             ("Surge/Loon [Rule] 段", ".list"),
    "hosts":             ("hosts / AdGuard Home 拦截格式", ".txt"),
    "adguard":           ("AdGuard 规则（保留 ||x^ 语法）", ".txt"),
    "qx":                ("Quantumult X 重写/拒绝规则", ".list"),
}

BUILDERS = {
    "plain":             lambda rs, lt: fmt_plain(rs),
    "cloudflare-domain": lambda rs, lt: fmt_cloudflare_domain(rs),
    "cloudflare-csv":    lambda rs, lt: fmt_cloudflare_csv(rs, lt),
    "ipcidr":            lambda rs, lt: fmt_ipcidr(rs),
    "mihomo-domain":     lambda rs, lt: fmt_mihomo_domain(rs),
    "classical":         lambda rs, lt: fmt_classical(rs),
    "shadowrocket":      lambda rs, lt: fmt_shadowrocket(rs),
    "surge":             lambda rs, lt: fmt_surge(rs),
    "hosts":             lambda rs, lt: fmt_hosts(rs),
    "adguard":           lambda rs, lt: fmt_adguard(rs),
    "qx":                lambda rs, lt: fmt_qx(rs),
}


# ================================================================ CLI


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="把 karing-ruleset 规则集导出成各代理客户端 / Cloudflare Zero Trust 可用的列表",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="可用格式:\n" + "\n".join(f"  {k:<20} {v[0]}" for k, v in FORMATS.items()),
    )
    p.add_argument("sources", nargs="*", help="本地 .srs/.json/.list 文件（可省略，仅用 --url/--url-list）")
    p.add_argument("-o", "--outdir", default="out", help="输出目录（默认 out）")
    p.add_argument("--url", action="append", default=[], help="直接下载的规则 URL（可多次）")
    p.add_argument("--url-list", help="包含多个 URL 的文本文件（一行一个）")
    p.add_argument("--format", default="plain", choices=sorted(FORMATS), help="输出格式")
    p.add_argument("--list-type", default="DOMAIN", help="cloudflare-csv 的 List type: DOMAIN / IP")
    p.add_argument("--stats", action="store_true", help="只打印统计，不写文件")
    p.add_argument("--verify", action="store_true", help="把 .srs 解析结果与同名 .json 逐条比对（自检）")
    p.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="Cloudflare ZT 单列表条数上限，超出自动拆成多份（Standard 1000 / Enterprise 5000，默认 1000）",
    )
    p.add_argument(
        "--no-split",
        action="store_true",
        help="不按 --limit 拆分（超限时仅给出警告）",
    )
    args = p.parse_args(argv)

    targets: List[str] = list(args.sources) + list(args.url)
    if args.url_list:
        with open(args.url_list, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    if not targets:
        p.error("至少需要一个源（本地文件或 --url/--url-list）")

    if not args.stats:
        os.makedirs(args.outdir, exist_ok=True)
    desc, ext = FORMATS[args.format]
    builder = BUILDERS[args.format]
    print(f"输出格式: {args.format} — {desc}\n")

    ok = 0
    for src in targets:
        raw_name = os.path.basename(src.split("?")[0])
        name = strip_ext(raw_name)
        blob: Optional[bytes] = None
        try:
            if src.startswith("http"):
                blob = fetch(src)          # 下载一次，供解析与自检复用
            rs = load_source(src, raw_name, blob)
        except Exception as e:
            print(f"[跳过] {src}: {type(e).__name__}: {e}")
            continue

        print(
            f"{name}: 总 {rs.total()} 条 | 精确域名 {len(rs.domain)} | 后缀 {len(rs.domain_suffix)} "
            f"| 关键字 {len(rs.domain_keyword)} | 正则 {len(rs.domain_regex)} "
            f"| CIDR {len(rs.ip_cidr)} | AdGuard {len(rs.adguard)}"
        )
        if args.format.startswith("cloudflare") and (rs.domain_keyword or rs.domain_regex):
            print(
                f"    ⚠ 含 {len(rs.domain_keyword)} 条关键字 / {len(rs.domain_regex)} 条正则，"
                "Cloudflare Lists 不支持通配与正则，已排除；代理客户端请用 classical/shadowrocket/adguard 格式保留"
            )
        if rs.discarded:
            items = "、".join(f"{k}×{v}" for k, v in sorted(rs.discarded.items()))
            print(
                f"    ⚠ 该规则含 {sum(rs.discarded.values())} 个非域名/IP 条件（{items}），"
                "无法用列表表达，已丢弃；这类规则请用 --format classical 并在支持进程/端口的客户端里手工配置"
            )
        if rs.notes:
            print(f"    备注: {'; '.join(sorted(set(rs.notes)))}")

        # ---- 自检 ----
        if args.verify:
            jurl = None
            if src.startswith("http"):
                jurl = src.rsplit(".", 1)[0] + ".json"
            else:
                cand = src.rsplit(".", 1)[0] + ".json"
                jurl = cand if os.path.exists(cand) else None
            if jurl:
                try:
                    jb = fetch(jurl) if jurl.startswith("http") else open(jurl, "rb").read()
                    print(f"  [verify] 对比 {os.path.basename(jurl)}:")
                    for m in verify(_blob_of(src, blob), jb, name):
                        print(m)
                except Exception as e:
                    print(f"  [verify] 跳过: {e}")
            else:
                print("  [verify] 未找到同名 .json，跳过")

        if args.stats:
            ok += 1
            continue

        content = builder(rs, args.list_type)
        header, body = _split_header(content, args.format)

        # Cloudflare ZT 有硬性条数上限，超限自动拆成多份
        if (
            args.format.startswith("cloudflare")
            and not args.no_split
            and args.limit > 0
            and len(body) > args.limit
        ):
            parts = [body[i : i + args.limit] for i in range(0, len(body), args.limit)]
            for idx, part in enumerate(parts, 1):
                out_path = os.path.join(args.outdir, f"{name}-{idx:02d}of{len(parts):02d}{ext}")
                with open(out_path, "w", encoding="utf-8", newline="") as f:
                    if header:
                        f.write(header)
                    f.write("".join(l + "\n" for l in part))
                print(f"    → {out_path} ({len(part)} 行)")
            print(
                f"    ⚠ 共 {len(body)} 条，超过 Cloudflare 单列表上限 {args.limit}，"
                f"已拆成 {len(parts)} 份（需分别建 {len(parts)} 个 List，或用 Enterprise 5000 条上限）\n"
            )
        else:
            out_path = os.path.join(args.outdir, f"{name}{ext}")
            with open(out_path, "w", encoding="utf-8", newline="") as f:
                f.write(content)
            warn = ""
            if args.format.startswith("cloudflare") and len(body) > args.limit:
                warn = f"  ⚠ 超过 Cloudflare 列表上限 {args.limit} 条（--no-split 已保留单文件）"
            print(f"    → {out_path} ({len(body)} 行){warn}\n")
        ok += 1

    print(f"完成 {ok}/{len(targets)} 个源")
    return 0 if ok else 1


NON_ENTRY_PREFIX = ("#", "!", "payload:")


def _split_header(content: str, fmt: str) -> Tuple[str, List[str]]:
    """分出文件头（表头 / 注释 / yaml 键）与真正的条目行，便于按条数拆分"""
    lines = content.splitlines()
    if fmt == "cloudflare-csv":
        return lines[0] + "\n", lines[1:]
    header: List[str] = []
    i = 0
    while i < len(lines) and lines[i].strip().startswith(NON_ENTRY_PREFIX):
        header.append(lines[i])
        i += 1
    return ("\n".join(header) + "\n") if header else "", lines[i:]


def _blob_of(src: str, cached: Optional[bytes]) -> bytes:
    if cached is not None:
        return cached
    with open(src, "rb") as f:
        return f.read()


if __name__ == "__main__":
    sys.exit(main())
