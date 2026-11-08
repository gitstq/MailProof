<div align="center">

# 📮 MailProof

**零相依 · 離線優先的郵件網域身份認證稽核與策略推演引擎**

`SPF` · `DKIM` · `DMARC` · `MTA-STS` · `TLS-RPT`

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · [English](README.en.md)

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)
![Network](https://img.shields.io/badge/network%20calls-0-blue)
![License](https://img.shields.io/badge/license-MIT-orange)
![Rules](https://img.shields.io/badge/audit%20rules-31-blueviolet)

</div>

> 🛡️ **一句話**：把 `dig` 匯出的 DNS TXT 記錄丟進來，MailProof 就會告訴你 SPF / DKIM / DMARC 哪裡設錯了、能不能安全地把 `p=none` 升到 `p=reject`——**全程不連網、不寄信、不裝任何第三方套件**。

---

## 🎉 1. 專案介紹

### 我們解決什麼痛點？

郵件網域偽造（釣魚、冒名寄信）至今仍是最主要的攻擊入口之一。維運同仁在設定 SPF / DKIM / DMARC 時，通常會卡在四件事：

| 痛點 | 現況 | MailProof 的做法 |
| --- | --- | --- |
| 🔍 **看不清** | 線上檢查器一次只能查一個網域，結果無法進版控、無法版本化 | 一份**離線快照**就是完整輸入，可提交 Git、可 diff、可進 CI |
| 🚫 **不敢改** | 大家都知道 `p=reject` 最安全，但沒人敢直接上線，怕誤殺業務信件 | **策略推演引擎**給出阻斷項、路徑備援度與四階段漸進路線 |
| 🧩 **查不全** | 單一工具往往只查 SPF，忽略 DMARC 與 SPF 的**策略矛盾** | 31 條規則做 SPF / DKIM / DMARC **跨記錄關聯**驗證 |
| 🔌 **進不了 CI** | 網頁工具沒有結束碼，也無法上傳 Code Scanning | `--fail-on` 門檻 + **SARIF 2.1.0** 原生輸出 |

### 自研差異化亮點

- 🧬 **純標準函式庫讀取 RSA 金鑰位數**：內建最小 ASN.1 DER 剖析器，不需要 `cryptography` 就能辨識 1024 位元弱金鑰。
- 🕸️ **include 環偵測**：把快照中的 SPF 記錄建成有向圖，離線找出 `include:` / `redirect=` 循環參照。
- 🧭 **離線 what-if 推演**：升級 DMARC 策略前，先算清楚有幾條對齊路徑、有哪些硬阻斷、該怎麼分階段上線。
- 📐 **5 套合規基準**：同一份設定，一鍵比對 Google/Yahoo 2024、Microsoft 2025、嚴格強化與寬鬆監控要求。
- 📤 **5 種報告格式**：終端機、Markdown、JSON、SARIF、自包含 HTML，涵蓋人讀、機讀與程式碼掃描平台。

### 靈感來源

靈感來自 GitHub Trending 上**規範驅動 / 安全稽核類工具**的產品邏輯，以及主流線上 DMARC 檢查器所解決的真實痛點。程式碼 **100% 獨立自研**，未複製任何現有專案程式碼；協定剖析嚴格依據 RFC 7208 / RFC 6376 / RFC 7489 重新實作。

> ⚠️ **邊界說明**：MailProof 是**靜態設定稽核**工具，不取代真實投遞驗證。它不發起 DNS 查詢，因此無法驗證 `exists` 巨集展開、`mx` 展開後的實際查詢次數等執行期行為；相關規則會明確提示需在真實環境複核。

---

## ✨ 2. 核心特性

- 🧱 **零執行期相依**：只用 Python 標準函式庫，`pip install` 不拉任何第三方套件，供應鏈面積極小。
- 🔌 **完全離線**：**0 次 DNS 查詢、0 次網路請求、0 封測試信件**，機房、內網、隔離環境都能跑。
- 📜 **完整 SPF 剖析**：`all / include / a / mx / ip4 / ip6 / ptr / exists / redirect / exp`、qualifier、CIDR、巨集；驗證 **RFC 7208 §4.6.4 的 10 次查詢上限**、多筆記錄、`+all` 敞口、已棄用的 `ptr`。
- 🏷️ **完整 DMARC 剖析**：`v / p / sp / rua / ruf / pct / adkim / aspf / fo / ri / rf / np`，含**跨組織網域報告地址授權**提醒。
- 🔑 **完整 DKIM 剖析**：RSA / Ed25519 公鑰、金鑰位數、撤銷狀態（`p=` 為空）、`t=y` 測試旗標。
- 🔗 **31 條關聯規則**：不只查單筆記錄，還能揪出「DMARC 已 reject 但 SPF 仍是 `+all`」這類**設定矛盾**。
- 🎯 **5 套合規基準**：`default` / `google-yahoo-2024` / `microsoft-2025` / `strict` / `relaxed`。
- 🧭 **DMARC 策略推演**：路徑備援度、阻斷項、風險等級、四階段上線路線，全部離線計算。
- 📊 **量化評分**：0–100 分 + A–F 等級，按嚴重層級加權扣分，便於長期追蹤。
- 📤 **多格式報告**：`text` / `markdown` / `json` / `sarif` / `html`，**SARIF 可直接餵給 GitHub Code Scanning**。
- 🚦 **CI 門檻**：`--fail-on high` 讓高危問題直接讓流水線失敗。
- 📥 **三種快照格式**：JSON、`{"domains": [...]}`、BIND zone 文字（含 `name=value` 簡寫），自動辨識、支援多網域批次處理。
- 🧪 **99 個單元測試**：標準函式庫 `unittest`，`make test` 一鍵全綠。

---

## 🚀 3. 快速開始

### 環境需求

| 項目 | 需求 |
| --- | --- |
| 🐍 Python | **≥ 3.8**（3.8 / 3.9 / 3.10 / 3.11 / 3.12 / 3.13 均通過 CI） |
| 💻 作業系統 | Windows / macOS / Linux 全平台（純 Python，無編譯產物） |
| 📦 第三方套件 | **無** |
| 🌐 網路 | **不需要** |

### 方式一：免安裝，複製即用 ⚡（推薦）

```bash
git clone https://github.com/gitstq/MailProof.git
cd MailProof

python -m mailproof --version
python -m mailproof demo > demo.zone
python -m mailproof audit demo.zone
```

> 💡 在專案根目錄執行時，`python -m mailproof` 無需設定 `PYTHONPATH`。Windows 請把 `python` 換成 `py`。

### 方式二：安裝成全域指令

```bash
pip install "git+https://github.com/gitstq/MailProof.git"
mailproof --version

# 手上沒有快照？先用內建展示資料體驗
mailproof audit --demo
mailproof demo > demo.zone && mailproof audit demo.zone
```

### 三條指令走完主流程

```bash
# 1️⃣ 準備一份 DNS 快照（BIND zone 文字，或用 dig 匯出後整理）
mailproof demo > demo.zone

# 2️⃣ 用嚴格基準稽核，輸出終端機報告
mailproof audit demo.zone --baseline strict

# 3️⃣ 升級策略前先離線推演
mailproof simulate demo.zone --policy reject
```

### 當成 Python 函式庫呼叫

```python
from mailproof import audit_file, render

bundle = audit_file("examples/sample.zone", baseline_key="strict")
print(bundle.results[0].score)        # 100
print(render(bundle, "markdown"))     # 也可選 json / sarif / html / text
```

### 一分鐘看到效果

```bash
python -m mailproof audit --demo --format markdown --quiet
```

```
📮 網域：example.com
   評分：41/100   等級：E（高風險 / High risk）
   🟠 [MP104] DMARC 處於 p=none 監控模式
   🟠 [MP204] DKIM RSA 金鑰強度不足（1024 位元）
   🟠 [MP401] 未符合所選合規基準
   🟡 [MP006] SPF 未使用 -all 硬失敗
   ...
```

> 📷 *終端機彩色輸出 / HTML 報告截圖預留位置：執行 `make report` 後見 `report.html`。*

---

## 📖 4. 詳細使用指南

### 4.1 準備 DNS 快照 🗂️

MailProof **不查 DNS**，你需要先匯出記錄。三種格式任選，工具自動辨識：

**① BIND zone 文字（推薦，最貼近 `dig` 輸出）**

```bash
cat > records.zone <<'EOF'
example.com. IN TXT "v=spf1 ip4:203.0.113.0/24 include:_spf.mail.example -all"
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
sel2026._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
_mta-sts.example.com. IN TXT "v=STSv1; id=20261109001"
_smtp._tls.example.com. IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
EOF
```

**② 簡寫 `name=value` 行**

```text
example.com = v=spf1 -all
_dmarc.example.com = v=DMARC1; p=reject; rua=mailto:d@example.com
```

**③ JSON（最適合 IaC / 組態管理產生）**

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

> 📌 欄位名稱相容：`name`/`host`、`value`/`text`/`txt`、`type`/`rtype` 皆可；`ttl` 選填。`_dmarc.`、`_mta-sts.`、`_smtp._tls.`、`._domainkey.` 會自動歸到對應的 apex 網域。**同一份快照可含多個網域**，`--domain` 可只看其中一個。

### 4.2 完整指令與參數 🛠️

```bash
mailproof <command> [options]
```

| 指令 | 作用 |
| --- | --- |
| `audit` | 🔍 稽核離線 DNS 快照（核心指令） |
| `simulate` | 🧭 DMARC 策略升級離線推演 |
| `parse` | 🧬 單獨剖析一筆 SPF / DMARC / DKIM 記錄 |
| `rules` | 📋 列出全部 31 條規則（text / json / csv） |
| `baselines` | 🛡️ 列出 5 套合規基準 |
| `demo` | 📦 匯出內建展示快照 |

**`mailproof audit` 參數表**

| 參數 | 預設值 | 說明 |
| --- | --- | --- |
| `path` | 內建展示資料 | 快照檔案路徑（`.json` / `.zone` / `.txt`） |
| `--demo` | 關 | 強制使用內建展示快照 |
| `--baseline` | `default` | 合規基準，見 `mailproof baselines` |
| `--format` | `text` | `text` / `markdown` / `json` / `sarif` / `html` |
| `-o, --output` | 標準輸出 | 寫入檔案 |
| `--fail-on` | `none` | CI 門檻，`none` / `info` / `low` / `medium` / `high` / `critical`；命中即結束碼 1 |
| `--domain` | 全部 | 只稽核指定網域 |
| `--quiet` | 關 | 抑制提示訊息 |

**常見情境速查**

```bash
# 📤 接入 GitHub Code Scanning
mailproof audit records.json --format sarif -o mailproof.sarif

# 🚦 CI 門檻：出現高危以上直接失敗
mailproof audit records.json --baseline microsoft-2025 --fail-on high

# 🌐 產生可直接開啟的自包含 HTML 報告
mailproof audit records.json --format html -o report.html

# 🔬 只除錯一筆記錄
mailproof parse --spf "v=spf1 a mx -all" --dmarc "v=DMARC1; p=none"

# 📋 匯出規則目錄給資安團隊審查
mailproof rules --format csv > rules.csv

# 🧭 推演升級到 p=reject（JSON 便於程式消費）
mailproof simulate records.json --policy reject --format json
```

### 4.3 五套合規基準 🛡️

| 基準 | 適用情境 | 關鍵要求 |
| --- | --- | --- |
| `default` | 一般網域最佳實務 | DMARC ≥ `quarantine`、SPF `-all`、DKIM ≥ 2048 位元、要求 `rua` |
| `google-yahoo-2024` | 日寄 ≈ 5000 封以上的批次寄件者 | SPF + DKIM + DMARC `p≥none`，DKIM ≥ 1024 位，不強制 `-all` / `rua` |
| `microsoft-2025` | Outlook 高容量寄件者 | 三者齊備、DMARC ≥ `quarantine`、`rua`、DKIM ≥ 2048 位元 |
| `strict` | 金融 / 政企強化 | `p=reject`、`pct=100`、`-all`、嚴格對齊、禁用測試旗標 |
| `relaxed` | 剛開始部署 DMARC | 只要求記錄存在且語法正確，便於分階段上線 |

```bash
mailproof baselines           # 查看完整定義與參考連結
mailproof audit records.zone --baseline strict
```

### 4.4 評分與規則 📊

評分從 100 分起按嚴重層級加權扣分，限制在 0–100：

| 層級 | 扣分 | 等級 |
| --- | ---: | --- |
| 🔴 致命 `critical` | −30 | `A` ≥ 90，`B` ≥ 80，`C` ≥ 70 |
| 🟠 高危 `high` | −15 | `D` ≥ 60，`E` ≥ 40，`F` < 40 |
| 🟡 中危 `medium` | −7 | |
| 🔵 低危 `low` | −3 | |
| ⚪ 提示 `info` | 0 | |

31 條規則依 ID 分組：`MP0xx` SPF、`MP1xx` DMARC、`MP2xx` DKIM、`MP3xx` 跨記錄關聯與傳輸層加固、`MP4xx` 基準合規。每條都附**可執行的修復建議**與 RFC 參考連結。

```bash
mailproof rules              # 完整目錄
mailproof rules --format json | python -c "import json,sys; print(len(json.load(sys.stdin)))"
```

### 4.5 CI / CD 整合範例 🚦

```yaml
- name: 郵件認證設定門檻
  run: |
    pip install "git+https://github.com/gitstq/MailProof.git"
    mailproof audit dns/records.json \
      --baseline microsoft-2025 \
      --format sarif --output mailproof.sarif
    mailproof audit dns/records.json --fail-on high
```

完整可複製的 workflow（含 SARIF 上傳）請見 👉 [`examples/github-actions.yml`](examples/github-actions.yml)。

### 4.6 常見問題 ❓

<details>
<summary><b>Q：為什麼不直接查 DNS？</b></summary>

離線設計是刻意的：① 快照可提交 Git、可 review、可 diff；② 能稽核**尚未發布**的 IaC 設定；③ 隔離網路可用；④ 結果完全可重現，不受 DNS 快取／地理位置影響。代價是無法驗證巨集展開等執行期行為，工具會明確提示。
</details>

<details>
<summary><b>Q：TXT 記錄被切成多段引號怎麼辦？</b></summary>

`parse_zone_snapshot()` 會自動串接同一行的多個引號區塊，例如 `"v=spf1" " -all"` → `v=spf1 -all`。
</details>

<details>
<summary><b>Q：DKIM 公鑰剖析失敗？</b></summary>

`p=` 需為 base64 編碼的 DER `SubjectPublicKeyInfo`。若 DNS 面板把金鑰截斷了，規則 `MP202` 會報出具體原因；`p=` 為空是合法的**金鑰撤銷**標記（觸發 `MP203`）。
</details>

<details>
<summary><b>Q：會不會誤報？</b></summary>

`info` 層級（MTA-STS / TLS-RPT / 外部報告地址）屬於加固建議，不扣分；所有規則都可透過 `--baseline relaxed` 降低約束。最終決策請以 `rua` 彙總報告為準。
</details>

---

## 💡 5. 設計思路與迭代規劃

### 為什麼這樣設計？

| 決策 | 原因 |
| --- | --- |
| **快照輸入而非線上查詢** | 設定稽核的本質是「程式碼化」；可版本化、可 CI、可重現，比一次性網頁檢查更有工程價值 |
| **剖析器容錯而非丟例外** | 稽核工具必須先完整說出「哪裡錯了」，再談評分；所有剖析錯誤都進 `errors` 清單 |
| **規則與基準解耦** | 規則描述客觀事實，基準描述組織要求；同一份設定換基準即得不同結論，便於分階段治理 |
| **零第三方相依** | 資安工具本身必須可信；把供應鏈攻擊面壓到 0，也讓它能在最精簡的容器裡執行 |
| **純函式規則引擎** | 好測試、好並行、好擴充；99 個測試不需 mock 即可覆蓋 |
| **SARIF 一等公民** | 讓結果進入開發者既有的工作流程（Code Scanning），而不是又多一份孤立報告 |

架構與資料流詳見 👉 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

### 🗺️ 迭代路線

- [ ] 📥 原生剖析 `dig +short`、`nslookup`、Route53 / Cloudflare 匯出文字（仍離線，只剖析文字）
- [ ] 📨 剖析 DMARC 彙總報告（rua XML），用真實投遞資料驅動策略推演
- [ ] 🏷️ 新增 BIMI、MTA-STS 政策檔一致性、ARC 鏈路規則
- [ ] ⚙️ `.mailproof.toml`：規則白名單與嚴重層級覆寫
- [ ] 🌐 多語系 CLI 輸出（目前三語覆蓋在文件層）
- [ ] 📈 跨版本設定 diff 與評分趨勢追蹤

---

## 📦 6. 打包與部署指南

MailProof 屬於**工具庫 / CLI 類專案**，依發布規範**無需上傳二進位 Release 附件**：純 Python、跨平台、無編譯產物，`pip install` 即可開箱使用。

### 一鍵建置（跨平台，純標準函式庫）

```bash
python scripts/build.py
# 等價於：make build
```

腳本會依序：執行 99 個單元測試 → 建置 wheel 到 `dist/` → 產生 `dist/SHA256SUMS`。Windows / macOS / Linux 通用，不需要 `make`、不需要額外 build frontend。

```bash
python scripts/build.py --sdist     # 同時產出原始碼散佈包
python scripts/build.py --no-test   # 跳過測試（不建議）
```

### 本機安裝驗證

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

### 相容環境矩陣

| 環境 | 狀態 |
| --- | --- |
| Python 3.8 – 3.13 | ✅ CI 覆蓋 |
| Ubuntu / macOS / Windows | ✅ CI 覆蓋 |
| 無網路 / 隔離內網 | ✅ 完全可用 |
| Alpine 容器 | ✅ 無編譯相依 |
| PyInstaller / zipapp | ✅ 純 Python，可自行打包成單檔 |

> 📌 發布檢核清單：儲存庫可公開存取 ✅、程式可 `pip install` ✅、文件三語可檢視 ✅、wheel + SHA256 產物完整 ✅、核心功能自測通過 ✅。

---

## 🤝 7. 貢獻指南

非常歡迎 PR！🌱 請先閱讀 👉 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

```bash
git clone https://github.com/gitstq/MailProof.git
cd MailProof
pip install -e ".[dev]"
make test          # python -m unittest discover -s tests -v
make lint          # python -m compileall -q mailproof tests scripts
```

**提交規範（Angular Convention）**：`feat:` / `fix:` / `docs:` / `refactor:` / `test:` / `perf:` / `chore:`

```bash
git commit -m "feat: 新增 BIMI 記錄存在性檢查規則 MP307"
git commit -m "fix: 修正 a/24 CIDR 機制的參數剖析"
```

**三條硬性約定**：① 不引入任何第三方執行期相依；② 不引入任何網路呼叫；③ 新增規則必須同步補測試、補三語文件。

提交 Issue 時請附版本、重現指令與**去識別化後**的快照；請勿貼上私鑰或 Token。🐛

---

## 📄 8. 開源授權說明

本專案採用 **MIT License** —— 可自由使用、複製、修改、合併、發布、散佈、再授權及商業銷售，只需保留版權聲明與授權聲明。

```
MIT License · Copyright (c) 2026 MailProof contributors
```

完整條文請見 👉 [`LICENSE`](LICENSE)。

- ✅ 允許商用、允許修改、允許閉源整合
- ✅ 除署名外無額外義務
- ⚠️ 軟體按「現狀」提供，不含任何明示或默示擔保

---

<div align="center">

**📮 MailProof — 讓郵件網域設定像程式碼一樣可稽核、可推演、可進 CI。**

[⬆ 回到頂部](#-mailproof) · [📖 架構文件](docs/ARCHITECTURE.md) · [🐛 提交 Issue](https://github.com/gitstq/MailProof/issues)

</div>
