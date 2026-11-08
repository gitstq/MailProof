<div align="center">

# 📮 MailProof

**零依赖 · 离线优先的邮件域名身份认证审计与策略推演引擎**

`SPF` · `DKIM` · `DMARC` · `MTA-STS` · `TLS-RPT`

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · [English](README.en.md)

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)
![Network](https://img.shields.io/badge/network%20calls-0-blue)
![License](https://img.shields.io/badge/license-MIT-orange)
![Rules](https://img.shields.io/badge/audit%20rules-31-blueviolet)

</div>

> 🛡️ **一句话**：把 `dig` 导出的 DNS TXT 记录丢进来，MailProof 就能告诉你 SPF / DKIM / DMARC 哪里配错了、能不能安全地把 `p=none` 升到 `p=reject`——**全程不联网、不发邮件、不装任何第三方包**。

---

## 🎉 1. 项目介绍

### 我们解决什么痛点？

邮件域名伪造（钓鱼、冒名发信）至今仍是最主要的攻击入口之一。运维同学配置 SPF / DKIM / DMARC 时通常会遇到四件事：

| 痛点 | 现状 | MailProof 的做法 |
| --- | --- | --- |
| 🔍 **看不清** | 在线检查器一次只能查一个域名，结果不进代码库、无法版本化 | 一份**离线快照**即完整输入，可提交 Git、可做 diff、可进 CI |
| 🚫 **不敢改** | 谁都知道 `p=reject` 最安全，但没人敢直接上线，怕误杀业务邮件 | **策略推演引擎**给出阻断项、路径冗余度与四阶段灰度路线 |
| 🧩 **查不全** | 单个工具往往只查 SPF，忽略 DMARC 与 SPF 的**策略矛盾** | 31 条规则做 SPF / DKIM / DMARC **跨记录关联**校验 |
| 🔌 **进不了 CI** | 网页工具没有退出码，也没法上传 Code Scanning | `--fail-on` 门禁 + **SARIF 2.1.0** 原生输出 |

### 自研差异化亮点

- 🧬 **纯标准库读取 RSA 密钥位数**：自带一个最小 ASN.1 DER 解析器，不需要 `cryptography` 就能识别 1024 位弱密钥。
- 🕸️ **include 环检测**：把快照里的 SPF 记录建成有向图，离线找出 `include:` / `redirect=` 循环引用。
- 🧭 **离线 what-if 推演**：升级 DMARC 策略前，先算清楚有几条对齐路径、有哪些硬阻断、该怎么分阶段灰度。
- 📐 **5 套合规基线**：同一份配置，一键对比 Google/Yahoo 2024、Microsoft 2025、严格强化与宽松监控要求。
- 📤 **5 种报告格式**：终端、Markdown、JSON、SARIF、自包含 HTML，覆盖人读、机读与代码扫描平台。

### 灵感来源

灵感来自 GitHub Trending 上**规范驱动 / 安全审计类工具**的产品逻辑，以及主流在线 DMARC 检查器所解决的真实痛点。代码 **100% 独立自研**，未复制任何现有项目代码；协议解析严格依据 RFC 7208 / RFC 6376 / RFC 7489 重新实现。

> ⚠️ **边界说明**：MailProof 是**静态配置审计**工具，不替代真实投递验证。它不发起 DNS 查询，因此无法验证 `exists` 宏展开、`mx` 展开后的实际查询次数等运行时行为；相关规则会明确提示需在真实环境复核。

---

## ✨ 2. 核心特性

- 🧱 **零运行时依赖**：只用 Python 标准库，`pip install` 不拉任何第三方包，供应链面积极小。
- 🔌 **完全离线**：**0 次 DNS 查询、0 次网络请求、0 封测试邮件**，机场、内网、隔离环境都能跑。
- 📜 **完整 SPF 解析**：`all / include / a / mx / ip4 / ip6 / ptr / exists / redirect / exp`、qualifier、CIDR、宏；校验 **RFC 7208 §4.6.4 的 10 次查询上限**、多记录、`+all` 敞口、弃用的 `ptr`。
- 🏷️ **完整 DMARC 解析**：`v / p / sp / rua / ruf / pct / adkim / aspf / fo / ri / rf / np`，含**跨组织域报告地址授权**提醒。
- 🔑 **完整 DKIM 解析**：RSA / Ed25519 公钥、密钥位数、撤销状态（`p=` 为空）、`t=y` 测试标志。
- 🔗 **31 条关联规则**：不仅查单条记录，还能发现「DMARC 已 reject 但 SPF 还是 `+all`」这类**配置矛盾**。
- 🎯 **5 套合规基线**：`default` / `google-yahoo-2024` / `microsoft-2025` / `strict` / `relaxed`。
- 🧭 **DMARC 策略推演**：路径冗余度、阻断项、风险等级、四阶段上线路线，全部离线计算。
- 📊 **量化评分**：0–100 分 + A–F 等级，按严重级别加权扣分，便于长期追踪。
- 📤 **多格式报告**：`text` / `markdown` / `json` / `sarif` / `html`，**SARIF 可直接喂给 GitHub Code Scanning**。
- 🚦 **CI 门禁**：`--fail-on high` 让高危问题直接失败流水线。
- 📥 **三种快照格式**：JSON、`{"domains": [...]}`、BIND zone 文本（含 `name=value` 简写），自动识别、支持多域名批量。
- 🧪 **99 个单元测试**：标准库 `unittest`，`make test` 一键全绿。

---

## 🚀 3. 快速开始

### 环境要求

| 项目 | 要求 |
| --- | --- |
| 🐍 Python | **≥ 3.8**（3.8 / 3.9 / 3.10 / 3.11 / 3.12 / 3.13 均通过 CI） |
| 💻 操作系统 | Windows / macOS / Linux 全平台（纯 Python，无编译产物） |
| 📦 第三方依赖 | **无** |
| 🌐 网络 | **不需要** |

### 方式一：免安装，克隆即用 ⚡（推荐）

```bash
git clone https://github.com/gitstq/MailProof.git
cd MailProof

python -m mailproof --version
python -m mailproof demo > demo.zone
python -m mailproof audit demo.zone
```

> 💡 在仓库根目录执行时，`python -m mailproof` 无需设置 `PYTHONPATH`。Windows 把 `python` 换成 `py` 即可。

### 方式二：安装为全局命令

```bash
pip install "git+https://github.com/gitstq/MailProof.git"
mailproof --version

# 没有快照文件？先用内置演示数据体验
mailproof audit --demo
mailproof demo > demo.zone && mailproof audit demo.zone
```

### 三条命令走完主流程

```bash
# 1️⃣ 准备一份 DNS 快照（BIND zone 文本，或用 dig 导出后整理）
mailproof demo > demo.zone

# 2️⃣ 用严格基线审计，输出终端报告
mailproof audit demo.zone --baseline strict

# 3️⃣ 升级策略前先离线推演
mailproof simulate demo.zone --policy reject
```

### 作为 Python 库调用

```python
from mailproof import audit_file, render

bundle = audit_file("examples/sample.zone", baseline_key="strict")
print(bundle.results[0].score)        # 100
print(render(bundle, "markdown"))     # 也可选 json / sarif / html / text
```

### 一分钟看到效果

```bash
python -m mailproof audit --demo --format markdown --quiet
```

```
📮 域名：example.com
   评分：41/100   等级：E（高风险 / High risk）
   🟠 [MP104] DMARC 处于 p=none 监控模式
   🟠 [MP204] DKIM RSA 密钥强度不足（1024 位）
   🟠 [MP401] 未满足所选合规基线
   🟡 [MP006] SPF 未使用 -all 硬失败
   ...
```

> 📷 *终端彩色输出 / HTML 报告截图占位：运行 `make report` 后见 `report.html`。*

---

## 📖 4. 详细使用指南

### 4.1 准备 DNS 快照 🗂️

MailProof **不查 DNS**，你需要先导出记录。三种格式任选，工具自动识别：

**① BIND zone 文本（推荐，最贴近 `dig` 输出）**

```bash
cat > records.zone <<'EOF'
example.com. IN TXT "v=spf1 ip4:203.0.113.0/24 include:_spf.mail.example -all"
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
sel2026._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
_mta-sts.example.com. IN TXT "v=STSv1; id=20261109001"
_smtp._tls.example.com. IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
EOF
```

**② 简写 `name=value` 行**

```text
example.com = v=spf1 -all
_dmarc.example.com = v=DMARC1; p=reject; rua=mailto:d@example.com
```

**③ JSON（最适合 IaC / 配置管理生成）**

```json
{
  "domains": [
    {
      "domain": "example.com",
      "records": [
        { "name": "example.com", "type": "TXT", "value": "v=spf1 -all" },
        { "name": "_dmarc.example.com", "type": "TXT", "value": "v=DMARC1; p=reject; rua=mailto:d@example.com" }
      ]
    },
    {
      "domain": "second.example",
      "records": [{ "name": "second.example", "value": "v=spf1 -all" }]
    }
  ]
}
```

> 📌 字段名兼容：`name`/`host`、`value`/`text`/`txt`、`type`/`rtype` 均可；`ttl` 可选。`_dmarc.`、`_mta-sts.`、`_smtp._tls.`、`._domainkey.` 会自动归到对应 apex 域名。**同一快照可含多个域名**，`--domain` 可只看其中一个。

### 4.2 完整命令与参数 🛠️

```bash
mailproof <command> [options]
```

| 命令 | 作用 |
| --- | --- |
| `audit` | 🔍 审计离线 DNS 快照（核心命令） |
| `simulate` | 🧭 DMARC 策略升级离线推演 |
| `parse` | 🧬 单独解析一条 SPF / DMARC / DKIM 记录 |
| `rules` | 📋 列出全部 31 条规则（text / json / csv） |
| `baselines` | 🛡️ 列出 5 套合规基线 |
| `demo` | 📦 导出内置演示快照 |

**`mailproof audit` 参数表**

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `path` | 内置演示数据 | 快照文件路径（`.json` / `.zone` / `.txt`） |
| `--demo` | 关 | 强制使用内置演示快照 |
| `--baseline` | `default` | 合规基线，见 `mailproof baselines` |
| `--format` | `text` | `text` / `markdown` / `json` / `sarif` / `html` |
| `-o, --output` | 标准输出 | 写入文件 |
| `--fail-on` | `none` | CI 门禁，`none` / `info` / `low` / `medium` / `high` / `critical`；命中即退出码 1 |
| `--domain` | 全部 | 只审计指定域名 |
| `--quiet` | 关 | 抑制提示信息 |

**典型场景速查**

```bash
# 📤 接入 GitHub Code Scanning
mailproof audit records.json --format sarif -o mailproof.sarif

# 🚦 CI 门禁：出现高危及以上直接失败
mailproof audit records.json --baseline microsoft-2025 --fail-on high

# 🌐 生成可直接打开的自包含 HTML 报告
mailproof audit records.json --format html -o report.html

# 🔬 只调试一条记录
mailproof parse --spf "v=spf1 a mx -all" --dmarc "v=DMARC1; p=none"

# 📋 导出规则目录给安全团队评审
mailproof rules --format csv > rules.csv

# 🧭 推演升级到 p=reject（JSON 便于程序消费）
mailproof simulate records.json --policy reject --format json
```

### 4.3 五套合规基线 🛡️

| 基线 | 适用场景 | 关键要求 |
| --- | --- | --- |
| `default` | 一般域名最佳实践 | DMARC ≥ `quarantine`、SPF `-all`、DKIM ≥ 2048 位、要求 `rua` |
| `google-yahoo-2024` | 日发 ≈ 5000 封以上的批量发件人 | SPF + DKIM + DMARC `p≥none`，DKIM ≥ 1024 位，不强制 `-all` / `rua` |
| `microsoft-2025` | Outlook 高容量发件人 | 三者齐备、DMARC ≥ `quarantine`、`rua`、DKIM ≥ 2048 位 |
| `strict` | 金融 / 政企强化 | `p=reject`、`pct=100`、`-all`、严格对齐、禁用测试标志 |
| `relaxed` | 刚起步部署 DMARC | 只要求记录存在且语法正确，便于分阶段上线 |

```bash
mailproof baselines           # 查看完整定义与参考链接
mailproof audit records.zone --baseline strict
```

### 4.4 评分与规则 📊

评分从 100 分起按严重级别加权扣分，钳制到 0–100：

| 级别 | 扣分 | 等级 |
| --- | ---: | --- |
| 🔴 致命 `critical` | −30 | `A` ≥ 90，`B` ≥ 80，`C` ≥ 70 |
| 🟠 高危 `high` | −15 | `D` ≥ 60，`E` ≥ 40，`F` < 40 |
| 🟡 中危 `medium` | −7 | |
| 🔵 低危 `low` | −3 | |
| ⚪ 提示 `info` | 0 | |

31 条规则按 ID 分组：`MP0xx` SPF、`MP1xx` DMARC、`MP2xx` DKIM、`MP3xx` 跨记录关联与传输加固、`MP4xx` 基线合规。每条都带**可执行的修复建议**与 RFC 参考链接。

```bash
mailproof rules              # 完整目录
mailproof rules --format json | python -c "import json,sys; print(len(json.load(sys.stdin)))"
```

### 4.5 CI / CD 集成示例 🚦

```yaml
- name: 邮件认证配置门禁
  run: |
    pip install "git+https://github.com/gitstq/MailProof.git"
    mailproof audit dns/records.json \
      --baseline microsoft-2025 \
      --format sarif --output mailproof.sarif
    mailproof audit dns/records.json --fail-on high
```

完整可复制的 workflow（含 SARIF 上传）见 👉 [`examples/github-actions.yml`](examples/github-actions.yml)。

### 4.6 常见问题 ❓

<details>
<summary><b>Q：为什么不直接查 DNS？</b></summary>

离线设计是刻意的：① 快照可提交 Git、可 review、可 diff；② 能审计**尚未发布**的 IaC 配置；③ 隔离网络可用；④ 结果完全可复现，不受 DNS 缓存/地理位置影响。代价是无法验证宏展开等运行时行为，工具会明确提示。
</details>

<details>
<summary><b>Q：TXT 记录被分成多段引号怎么办？</b></summary>

`parse_zone_snapshot()` 会自动拼接同一行的多个引号块，例如 `"v=spf1" " -all"` → `v=spf1 -all`。
</details>

<details>
<summary><b>Q：DKIM 公钥解析失败？</b></summary>

`p=` 需是 base64 编码的 DER `SubjectPublicKeyInfo`。若你的 DNS 面板把密钥截断了，规则 `MP202` 会报出具体原因；`p=` 为空是合法的**密钥撤销**标记（触发 `MP203`）。
</details>

<details>
<summary><b>Q：会不会误报？</b></summary>

`info` 级别（MTA-STS / TLS-RPT / 外部报告地址）属于加固建议，不扣分；所有规则都可通过 `--baseline relaxed` 降低约束。请以 `rua` 聚合报告为准做最终决策。
</details>

---

## 💡 5. 设计思路与迭代规划

### 为什么这样设计？

| 决策 | 原因 |
| --- | --- |
| **快照输入而非在线查询** | 配置审计的本质是「代码化」；可版本化、可 CI、可复现，比一次性网页检查更有工程价值 |
| **解析器容错而非抛异常** | 审计工具必须先完整说出「哪里错了」，再谈评分；所有解析错误都进 `errors` 列表 |
| **规则与基线解耦** | 规则描述客观事实，基线描述组织要求；同一配置换基线即得不同结论，便于分阶段治理 |
| **零第三方依赖** | 安全工具自身必须是可信的；把供应链攻击面压到 0，也让它能在最精简的容器里运行 |
| **纯函数规则引擎** | 易测试、易并发、易扩展；99 个测试无需 mock 即可覆盖 |
| **SARIF 一等公民** | 让结果进入开发者已有的工作流（Code Scanning），而不是又多一个孤立报告 |

架构与数据流详见 👉 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

### 🗺️ 迭代路线

- [ ] 📥 原生解析 `dig +short`、`nslookup`、Route53 / Cloudflare 导出文本（仍离线，只解析文本）
- [ ] 📨 解析 DMARC 聚合报告（rua XML），用真实投递数据驱动策略推演
- [ ] 🏷️ 新增 BIMI、MTA-STS 策略文件一致性、ARC 链路规则
- [ ] ⚙️ `.mailproof.toml`：规则白名单与严重级别覆盖
- [ ] 🌐 多语言 CLI 输出（当前三语言覆盖在文档层）
- [ ] 📈 跨版本配置 diff 与评分趋势追踪

---

## 📦 6. 打包与部署指南

MailProof 属于**工具库 / CLI 类项目**，按发布规范**无需上传二进制 Release 附件**：纯 Python、跨平台、无编译产物，`pip install` 即可开箱使用。

### 一键构建（跨平台，纯标准库）

```bash
python scripts/build.py
# 等价于：make build
```

脚本会依次：运行 99 个单元测试 → 构建 wheel 到 `dist/` → 生成 `dist/SHA256SUMS`。Windows / macOS / Linux 通用，无需 `make`、无需额外 build 前端。

```bash
python scripts/build.py --sdist     # 同时产出源码分发包
python scripts/build.py --no-test   # 跳过测试（不推荐）
```

### 本地安装验证

```bash
pip install --no-deps --force-reinstall dist/mailproof-1.0.0-py3-none-any.whl
mailproof --version
mailproof audit examples/sample.zone --baseline strict
```

### 容器化部署

```dockerfile
FROM python:3.11-alpine
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY mailproof/ ./mailproof/
RUN pip install --no-cache-dir .
ENTRYPOINT ["mailproof"]
CMD ["audit", "--demo"]
```

```bash
docker build -t mailproof:1.0.0 .
docker run --rm -v "$PWD/dns:/dns:ro" mailproof:1.0.0 audit /dns/records.json --fail-on high
```

### 兼容环境矩阵

| 环境 | 状态 |
| --- | --- |
| Python 3.8 – 3.13 | ✅ CI 覆盖 |
| Ubuntu / macOS / Windows | ✅ CI 覆盖 |
| 无网络 / 隔离内网 | ✅ 完全可用 |
| Alpine 容器 | ✅ 无编译依赖 |
| PyInstaller / zipapp | ✅ 纯 Python，可自行打包为单文件 |

> 📌 发布校验清单：仓库可公开访问 ✅、代码可 `pip install` ✅、文档三语言可查看 ✅、wheel + SHA256 产物完整 ✅、核心功能自测通过 ✅。

---

## 🤝 7. 贡献指南

非常欢迎 PR！🌱 请先阅读 👉 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

```bash
git clone https://github.com/gitstq/MailProof.git
cd MailProof
pip install -e ".[dev]"
make test          # python -m unittest discover -s tests -v
make lint          # python -m compileall -q mailproof tests scripts
```

**提交规范（Angular Convention）**：`feat:` / `fix:` / `docs:` / `refactor:` / `test:` / `perf:` / `chore:`

```bash
git commit -m "feat: 新增 BIMI 记录存在性检查规则 MP307"
git commit -m "fix: 修正 a/24 CIDR 机制的参数解析"
```

**三条硬性约定**：① 不引入任何第三方运行时依赖；② 不引入任何网络调用；③ 新增规则必须同步补测试、补三语言文档。

提交 Issue 时请附版本、复现命令与**脱敏后**的快照；请勿粘贴私钥或 Token。🐛

---

## 📄 8. 开源协议说明

本项目采用 **MIT License** —— 可自由使用、复制、修改、合并、发布、分发、再授权及商业销售，只需保留版权声明与许可声明。

```
MIT License · Copyright (c) 2026 MailProof contributors
```

完整文本见 👉 [`LICENSE`](LICENSE)。

- ✅ 允许商用、允许修改、允许闭源集成
- ✅ 无需署名以外的额外义务
- ⚠️ 软件按「原样」提供，不含任何明示或默示担保

---

<div align="center">

**📮 MailProof — 让邮件域名配置像代码一样可审计、可推演、可进 CI。**

[⬆ 回到顶部](#-mailproof) · [📖 架构文档](docs/ARCHITECTURE.md) · [🐛 提交 Issue](https://github.com/gitstq/MailProof/issues)

</div>
