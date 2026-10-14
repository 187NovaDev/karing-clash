# karing-ruleset → Clash 远程规则（自动更新）

把 [KaringX/karing-ruleset](https://github.com/KaringX/karing-ruleset) 的 `recommend/cn.json`
（21 个规则组）从 sing-box 的 `.srs` 二进制解出，转成 Clash / mihomo 的
`rule-providers` payload，托管在 GitHub + jsDelivr 上，供**手机和电脑自动更新**。

- 规则条数：**58169 条**
- payload 文件：**32 个**（21 个 `-domain` + 11 个 `-ip`）
- 更新频率：GitHub Actions 每天 UTC 16:30（北京时间 00:30）重建一次

## 目录

```
clash_rules/                32 个 payload，客户端实际拉的就是这些
clash-verge-config.yaml     电脑版配置片段（Clash Verge / mihomo）
clash-meta-android.yaml     手机版配置片段（Clash Meta for Android）
tools/srs_to_lists.py       .srs 二进制解析器（纯标准库）
tools/build_remote.py       构建脚本
.github/workflows/build.yml 每日自动构建
```

## 引用地址格式

```
https://fastly.jsdelivr.net/gh/<你的用户名>/<仓库名>@main/clash_rules/<文件名>.yaml
```

例如 `adblock-domain.yaml`、`gfw-domain.yaml`、`cn-direct-ip.yaml`。
完整文件名列表就是 `clash_rules/` 目录下的 32 个文件。
