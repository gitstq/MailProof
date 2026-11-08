# 📦 更新日志 / Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/) 与 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 规范。

## [1.0.0] — 2026-11-09

首个正式版本 🎉 完成「离线 SPF / DKIM / DMARC 审计 + DMARC 策略推演」全链路。

### ✨ 新增

- **SPF 解析器**：完整支持 `all/include/a/mx/ip4/ip6/ptr/exists/redirect/exp`、qualifier、CIDR 与宏；校验 RFC 7208 §4.6.4 的 10 次 DNS 查询上限、多记录、`+all`、弃用的 `ptr`、循环 include。
- **DMARC 解析器**：完整标签集 `v/p/sp/rua/ruf/pct/adkim/aspf/fo/ri/rf/np`，含跨组织域报告地址授权提示。
- **DKIM 解析器**：RSA / Ed25519 公钥记录，**纯标准库 ASN.1 DER 读取 RSA modulus 位数**（无需 `cryptography`），识别撤销密钥与 `t=y` 测试模式。
- **31 条审计规则**：覆盖 SPF、DMARC、DKIM、跨记录关联、传输层加固与基线合规，附可执行修复建议与 RFC 链接。
- **5 套合规基线**：`default`、`google-yahoo-2024`、`microsoft-2025`、`strict`、`relaxed`。
- **策略推演引擎**：离线评估 `p=none → quarantine → reject` 的升级风险、对齐路径冗余度、阻断项与四阶段上线路线。
- **5 种报告格式**：终端文本、Markdown、JSON、**SARIF 2.1.0**（可直接接入 GitHub Code Scanning）、自包含 HTML。
- **CI 门禁**：`--fail-on` 按严重级别返回退出码 1。
- **离线快照输入**：自动识别 JSON、`{"domains": [...]}`、BIND zone 文本与 `name=value` 行格式，支持多域名批量审计。
- **工程化**：`pyproject.toml`、零依赖 `requirements.txt`、跨平台 `scripts/build.py` 一键构建（含 SHA256）、Makefile、MIT 协议、三语言 README。
- **99 个单元测试**，全部基于标准库 `unittest`，无需安装 pytest 即可运行。

### 🛡️ 设计约束

- 运行时依赖 **0**，仅依赖 Python ≥ 3.8 标准库。
- **永不发起 DNS 查询、永不联网、永不发送邮件**，全部结论来自用户提供的离线快照。

[1.0.0]: https://github.com/gitstq/MailProof/releases/tag/v1.0.0
