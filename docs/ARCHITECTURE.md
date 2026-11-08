# 🏗️ MailProof 架构设计

> 本文说明 MailProof 的模块划分、数据流与关键取舍，便于二次开发与规则扩展。

## 🎯 三条不可动摇的约束

| 约束 | 含义 | 落地方式 |
| --- | --- | --- |
| **零依赖** | 运行时不安装任何第三方包 | 仅 `import` 标准库（`argparse`、`ipaddress`、`base64`、`dataclasses`、`json`、`re`…） |
| **离线优先** | 不发起 DNS 查询、不联网、不发邮件 | 输入永远是用户导出的 *DNS 快照*；没有 `socket` / `urllib` 调用 |
| **纯函数规则** | 审计结果可复现、易测试 | 每条规则是 `(ctx) -> List[Finding]`，不修改上下文 |

## 🧬 模块分层

```
┌──────────────────────────────────────────────────────────┐
│  CLI (cli.py)  ·  Library API (__init__.py)               │  接入层
├──────────────────────────────────────────────────────────┤
│  audit.py        编排：解析 → 关联 → 规则 → 评分          │  编排层
├──────────────────┬───────────────────┬───────────────────┤
│ spf.py           │ dmarc.py          │ dkim.py           │  协议解析层
│ (RFC 7208)       │ (RFC 7489)        │ (RFC 6376 + DER)  │
├──────────────────┴───────────────────┴───────────────────┤
│  rules.py (31 条)  ·  presets.py (5 基线)  ·  scoring.py   │  判定层
├──────────────────────────────────────────────────────────┤
│  bundle.py (快照加载)  ·  models.py (数据类)              │  数据层
├──────────────────────────────────────────────────────────┤
│  report.py (text/md/json/sarif/html)  ·  simulate.py      │  输出层
└──────────────────────────────────────────────────────────┘
```

## 🔄 一次审计的数据流

```
快照文件 (.zone / .json)
   │  bundle.load_snapshot()  ← 自动识别 3 种格式
   ▼
List[DomainSnapshot]           ← 一个域名一组 DnsRecord
   │  audit.audit_snapshot()
   ├─ collect_spf()      → List[SPFRecord]
   ├─ collect_dmarc()    → List[DMARCRecord]
   ├─ collect_dkim()     → List[DKIMRecord]
   ├─ build_include_graph() + detect_include_loops()  ← 跨记录环检测
   ▼
AuditContext (snapshot + 解析结果 + 基线 + include 环)
   │  rules.run_rules()   ← 按注册顺序执行 31 条纯函数
   ▼
List[Finding]
   │  scoring.compute_score() → 0–100 分 / A–F 等级
   ▼
AuditResult → AuditBundle
   │  report.render(bundle, fmt)
   ▼
text / markdown / json / SARIF 2.1.0 / HTML
```

## 🔍 关键实现细节

### 1. 纯标准库读取 RSA 密钥位数

DKIM 的 `p=` 是 base64 编码的 DER `SubjectPublicKeyInfo`。`dkim.py` 实现了一个最小 ASN.1 DER TLV 读取器：

```
SEQUENCE (SPKI)
 ├─ SEQUENCE (AlgorithmIdentifier)  ← 跳过
 └─ BIT STRING
     └─ SEQUENCE (RSAPublicKey)
         ├─ INTEGER (modulus)   ← 取有效字节数 × 8 + 首字节 bit_length()
         └─ INTEGER (exponent)
```

因此无需 `cryptography` / `openssl` 就能判定 1024 位弱密钥；Ed25519 通过 DER 长度直接判定为 256 位。

### 2. include 环检测

`build_include_graph()` 把快照里所有 `v=spf1` 记录按 owner name 索引成有向图（`include:` 与 `redirect=` 均为边），`detect_include_loops()` 用 DFS 找环。快照中不存在的目标被视为叶子——**工具绝不猜测外部 DNS 内容**，这是离线设计的必然取舍，报告中会明确提示宏/`exists` 等无法离线完全验证的机制。

### 3. 基线与评分解耦

`Baseline` 只描述"最低要求"，规则引擎读取基线决定是否触发（例如 `p=none` 在 `relaxed` 下不报 MP104、在 `strict` 下必报）。评分是**独立的加权扣分**：致命 −30、高危 −15、中危 −7、低危 −3、提示 0，钳制到 0–100。这样同一份配置在不同基线下分数不同，但单条规则的严重级别保持一致，便于跨基线对比。

### 4. SARIF 输出

规则目录（含 `helpUri`、category、默认 level）一次性写入 `tool.driver.rules`，每条 finding 映射为一个 `result`，`locations` 指向域名。GitHub Code Scanning 可直接消费，无需额外转换。

## 🧪 可测试性

所有核心逻辑都是纯函数，输入是 `DomainSnapshot`，输出是 dataclass。99 个单元测试用标准库 `unittest` 编写，`python -m unittest discover -s tests -v` 即可全量运行，无需安装 pytest。测试中使用的 1024/2048 位 RSA 公钥是真实生成的 DER，用于验证密钥位数解析的正确性。

## 🗺️ 后续迭代方向

- 支持 `dig` / `nslookup` 输出与 Route53 / Cloudflare 导出的原生解析器（仍保持离线：只解析文本）。
- 增加 BIMI、MTA-STS 策略文件一致性、ARC 链路的规则。
- 规则白名单 / 严重级别覆盖配置（`.mailproof.toml`）。
- 多语言 CLI 输出（当前 CLI 为中文，三语言覆盖在 README 层）。
- 聚合报告（rua XML）解析，用真实投递数据驱动策略推演。
