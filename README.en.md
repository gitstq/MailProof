<div align="center">

# 📮 MailProof

**A zero-dependency, offline-first auditor for email domain authentication — with DMARC policy rollout simulation**

`SPF` · `DKIM` · `DMARC` · `MTA-STS` · `TLS-RPT`

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · [English](README.en.md)

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)
![Network](https://img.shields.io/badge/network%20calls-0-blue)
![License](https://img.shields.io/badge/license-MIT-orange)
![Rules](https://img.shields.io/badge/audit%20rules-31-blueviolet)

</div>

> 🛡️ **In one line**: hand MailProof the DNS TXT records you exported with `dig`, and it tells you exactly what is wrong with your SPF / DKIM / DMARC setup — and whether it is safe to move from `p=none` to `p=reject`. **No network access, no test emails, no third-party packages.**

---

## 🎉 1. What is MailProof?

### The problem it solves

Email domain spoofing (phishing, impersonation) is still one of the most common attack vectors. Anyone who has configured SPF / DKIM / DMARC has run into these four frustrations:

| Pain point | Status quo | What MailProof does |
| --- | --- | --- |
| 🔍 **No visibility** | Online checkers look up one domain at a time; the result never lands in your repo and cannot be versioned | An **offline snapshot** is the complete input — commit it to Git, diff it, put it in CI |
| 🚫 **No confidence to change** | Everyone knows `p=reject` is the safest policy, but nobody dares to ship it for fear of blocking legitimate mail | The **rollout simulator** surfaces blockers, alignment path redundancy and a four-stage gradual rollout plan |
| 🧩 **Incomplete checks** | Most tools only inspect SPF and miss **contradictions** between SPF and DMARC | 31 rules perform **cross-record correlation** across SPF / DKIM / DMARC |
| 🔌 **No CI story** | Web tools have no exit codes and cannot feed Code Scanning | `--fail-on` gating plus native **SARIF 2.1.0** output |

### What makes it different

- 🧬 **RSA key length read with the standard library alone**: a minimal ASN.1 DER reader recovers the modulus size, so 1024-bit weak keys are flagged without pulling in `cryptography`.
- 🕸️ **SPF include-loop detection**: the snapshot's SPF records become a directed graph, and `include:` / `redirect=` cycles are found offline.
- 🧭 **Offline what-if simulation**: before tightening DMARC, compute how many alignment paths exist, what the hard blockers are, and how to roll out in stages.
- 📐 **Five compliance baselines**: compare one configuration against Google/Yahoo 2024, Microsoft 2025, strict hardening and relaxed monitoring in a single flag.
- 📤 **Five report formats**: terminal, Markdown, JSON, SARIF and a self-contained HTML page — for humans, machines and code-scanning platforms alike.

### Where the idea came from

Inspired by the product logic of **spec-driven / security-auditing tools** on GitHub Trending, and by the real problems that mainstream online DMARC checkers try to solve. The code is **100% independently written** — no existing project's source was copied; the protocol parsers were implemented from scratch against RFC 7208 / RFC 6376 / RFC 7489.

> ⚠️ **Scope and limits**: MailProof is a **static configuration auditor**, not a substitute for real delivery testing. It never issues DNS queries, so it cannot verify runtime behaviour such as `exists` macro expansion or the actual number of lookups after `mx` expansion. The relevant rules explicitly tell you to re-check those in a live environment.

---

## ✨ 2. Core features

- 🧱 **Zero runtime dependencies**: Python standard library only; `pip install` pulls in nothing, which keeps the supply-chain surface tiny.
- 🔌 **Fully offline**: **0 DNS queries, 0 network requests, 0 test emails** — works on a plane, inside an intranet, or in an air-gapped environment.
- 📜 **Complete SPF parsing**: `all / include / a / mx / ip4 / ip6 / ptr / exists / redirect / exp`, qualifiers, CIDR and macros; validates the **RFC 7208 §4.6.4 ten-lookup limit**, multiple records, `+all` open relays and the deprecated `ptr` mechanism.
- 🏷️ **Complete DMARC parsing**: `v / p / sp / rua / ruf / pct / adkim / aspf / fo / ri / rf / np`, including the **external reporting address authorisation** caveat.
- 🔑 **Complete DKIM parsing**: RSA / Ed25519 public keys, key length, revocation (empty `p=`) and the `t=y` testing flag.
- 🔗 **31 correlation rules**: goes beyond single records to catch contradictions such as "DMARC is already at `reject` but SPF still says `+all`".
- 🎯 **Five compliance baselines**: `default` / `google-yahoo-2024` / `microsoft-2025` / `strict` / `relaxed`.
- 🧭 **DMARC policy simulation**: path redundancy, blockers, risk level and a four-stage rollout plan — all computed offline.
- 📊 **Quantified scoring**: a 0–100 score plus an A–F grade, weighted by severity, so progress can be tracked over time.
- 📤 **Multiple report formats**: `text` / `markdown` / `json` / `sarif` / `html`; **SARIF feeds straight into GitHub Code Scanning**.
- 🚦 **CI gating**: `--fail-on high` fails the pipeline on high-severity findings.
- 📥 **Three snapshot formats**: JSON, `{"domains": [...]}`, and BIND zone text (including `name=value` shorthand) — auto-detected, with multi-domain batches.
- 🧪 **99 unit tests**: standard-library `unittest`, all green with `make test`.

---

## 🚀 3. Quick start

### Requirements

| Item | Requirement |
| --- | --- |
| 🐍 Python | **≥ 3.8** (3.8 / 3.9 / 3.10 / 3.11 / 3.12 / 3.13 covered by CI) |
| 💻 OS | Windows / macOS / Linux — pure Python, no compiled artifacts |
| 📦 Third-party packages | **None** |
| 🌐 Network | **Not required** |

### Option 1 — clone and run, no install ⚡ (recommended)

```bash
git clone https://github.com/gitstq/MailProof.git
cd MailProof

python -m mailproof --version
python -m mailproof demo > demo.zone
python -m mailproof audit demo.zone
```

> 💡 Run from the repository root and `python -m mailproof` needs no `PYTHONPATH`. On Windows, substitute `py` for `python`.

### Option 2 — install as a global command

```bash
pip install "git+https://github.com/gitstq/MailProof.git"
mailproof --version

# No snapshot file yet? Try the built-in demo data
mailproof audit --demo
mailproof demo > demo.zone && mailproof audit demo.zone
```

### Three commands through the whole workflow

```bash
# 1️⃣ Prepare a DNS snapshot (BIND zone text, or tidy up a dig export)
mailproof demo > demo.zone

# 2️⃣ Audit against the strict baseline, print a terminal report
mailproof audit demo.zone --baseline strict

# 3️⃣ Simulate the policy change before you ship it
mailproof simulate demo.zone --policy reject
```

### Use it as a Python library

```python
from mailproof import audit_file, render

bundle = audit_file("examples/sample.zone", baseline_key="strict")
print(bundle.results[0].score)        # 100
print(render(bundle, "markdown"))     # also json / sarif / html / text
```

### See it working in under a minute

```bash
python -m mailproof audit --demo --format markdown --quiet
```

```
# 📮 MailProof 审计报告        (MailProof Audit Report)

| `example.com` | 41/100 | E | 0 | 3 | 2 | 0 | 2 | default |

🟠 [MP104] DMARC is in p=none monitoring mode
🟠 [MP204] DKIM RSA key strength is insufficient (1024 bits)
🟠 [MP401] Selected compliance baseline not satisfied
🟡 [MP006] SPF does not use a hard -all fail
...
```

> 📷 *Coloured terminal output / HTML report screenshot placeholder: run `make report` and open `report.html`.*

---

## 📖 4. Detailed usage guide

### 4.1 Prepare a DNS snapshot 🗂️

MailProof **does not query DNS**, so export the records first. Pick any of the three formats — they are auto-detected:

**① BIND zone text (recommended — closest to `dig` output)**

```bash
cat > records.zone <<'EOF'
example.com. IN TXT "v=spf1 ip4:203.0.113.0/24 include:_spf.mail.example -all"
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
sel2026._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
_mta-sts.example.com. IN TXT "v=STSv1; id=20261109001"
_smtp._tls.example.com. IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
EOF
```

**② `name=value` shorthand lines**

```text
example.com = v=spf1 -all
_dmarc.example.com = v=DMARC1; p=reject; rua=mailto:d@example.com
```

**③ JSON (best generated by IaC / config management)**

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

> 📌 Field aliases are accepted: `name`/`host`, `value`/`text`/`txt`, `type`/`rtype`; `ttl` is optional. `_dmarc.`, `_mta-sts.`, `_smtp._tls.` and `._domainkey.` records are mapped to their apex domain automatically. **A single snapshot may contain multiple domains**; use `--domain` to focus on one.

### 4.2 Commands and flags 🛠️

```bash
mailproof <command> [options]
```

| Command | Purpose |
| --- | --- |
| `audit` | 🔍 Audit an offline DNS snapshot (the core command) |
| `simulate` | 🧭 Offline simulation of a DMARC policy upgrade |
| `parse` | 🧬 Parse a single SPF / DMARC / DKIM record |
| `rules` | 📋 List all 31 rules (text / json / csv) |
| `baselines` | 🛡️ List the five compliance baselines |
| `demo` | 📦 Export the built-in demo snapshot |

**`mailproof audit` flags**

| Flag | Default | Description |
| --- | --- | --- |
| `path` | built-in demo data | Snapshot file path (`.json` / `.zone` / `.txt`) |
| `--demo` | off | Force the built-in demo snapshot |
| `--baseline` | `default` | Compliance baseline, see `mailproof baselines` |
| `--format` | `text` | `text` / `markdown` / `json` / `sarif` / `html` |
| `-o, --output` | stdout | Write to a file |
| `--fail-on` | `none` | CI gate: `none` / `info` / `low` / `medium` / `high` / `critical`; exit code 1 on a match |
| `--domain` | all | Audit only the given domain |
| `--quiet` | off | Suppress informational output |

**Common recipes**

```bash
# 📤 Feed GitHub Code Scanning
mailproof audit records.json --format sarif -o mailproof.sarif

# 🚦 CI gate: fail on high severity and above
mailproof audit records.json --baseline microsoft-2025 --fail-on high

# 🌐 Produce a self-contained HTML report you can just open
mailproof audit records.json --format html -o report.html

# 🔬 Debug a single record
mailproof parse --spf "v=spf1 a mx -all" --dmarc "v=DMARC1; p=none"

# 📋 Export the rule catalog for a security review
mailproof rules --format csv > rules.csv

# 🧭 Simulate moving to p=reject (JSON for programmatic use)
mailproof simulate records.json --policy reject --format json
```

### 4.3 The five compliance baselines 🛡️

| Baseline | Use case | Key requirements |
| --- | --- | --- |
| `default` | General best practice | DMARC ≥ `quarantine`, SPF `-all`, DKIM ≥ 2048 bits, `rua` required |
| `google-yahoo-2024` | Bulk senders (≈ 5,000+ messages/day) | SPF + DKIM + DMARC `p≥none`, DKIM ≥ 1024 bits, `-all` and `rua` not enforced |
| `microsoft-2025` | High-volume Outlook senders | All three present, DMARC ≥ `quarantine`, `rua`, DKIM ≥ 2048 bits |
| `strict` | Financial / government hardening | `p=reject`, `pct=100`, `-all`, strict alignment, testing flag disallowed |
| `relaxed` | Just starting a DMARC rollout | Only requires records to exist and parse, for staged deployment |

```bash
mailproof baselines           # full definitions and reference links
mailproof audit records.zone --baseline strict
```

### 4.4 Scoring and rules 📊

The score starts at 100, deducts a weighted penalty per severity, and is clamped to 0–100:

| Severity | Penalty | Grades |
| --- | ---: | --- |
| 🔴 `critical` | −30 | `A` ≥ 90, `B` ≥ 80, `C` ≥ 70 |
| 🟠 `high` | −15 | `D` ≥ 60, `E` ≥ 40, `F` < 40 |
| 🟡 `medium` | −7 | |
| 🔵 `low` | −3 | |
| ⚪ `info` | 0 | |

The 31 rules are grouped by ID: `MP0xx` SPF, `MP1xx` DMARC, `MP2xx` DKIM, `MP3xx` cross-record correlation and transport hardening, `MP4xx` baseline compliance. Every finding ships with an **actionable fix** and an RFC reference link.

```bash
mailproof rules              # full catalog
mailproof rules --format json | python -c "import json,sys; print(len(json.load(sys.stdin)))"
```

### 4.5 CI / CD integration 🚦

```yaml
- name: Email authentication gate
  run: |
    pip install "git+https://github.com/gitstq/MailProof.git"
    mailproof audit dns/records.json \
      --baseline microsoft-2025 \
      --format sarif --output mailproof.sarif
    mailproof audit dns/records.json --fail-on high
```

A complete copy-paste workflow (including SARIF upload) lives in 👉 [`examples/github-actions.yml`](examples/github-actions.yml).

### 4.6 FAQ ❓

<details>
<summary><b>Q: Why not just query DNS directly?</b></summary>

The offline design is deliberate: ① snapshots can be committed, reviewed and diffed; ② you can audit IaC configurations **before** they are published; ③ it works in isolated networks; ④ results are fully reproducible and unaffected by DNS caching or geography. The trade-off is that runtime behaviour such as macro expansion cannot be verified — the tool says so explicitly.
</details>

<details>
<summary><b>Q: What if a TXT record is split across several quoted strings?</b></summary>

`parse_zone_snapshot()` joins quoted chunks on the same line automatically, e.g. `"v=spf1" " -all"` → `v=spf1 -all`.
</details>

<details>
<summary><b>Q: DKIM public key fails to parse?</b></summary>

`p=` must be a base64-encoded DER `SubjectPublicKeyInfo`. If your DNS panel truncated the key, rule `MP202` reports the exact reason; an empty `p=` is a legitimate **key revocation** marker (triggering `MP203`).
</details>

<details>
<summary><b>Q: Will it produce false positives?</b></summary>

`info`-level findings (MTA-STS / TLS-RPT / external reporting addresses) are hardening suggestions and carry no penalty; all rules can be relaxed with `--baseline relaxed`. Treat the `rua` aggregate reports as the source of truth for the final decision.
</details>

---

## 💡 5. Design rationale & roadmap

### Why it is built this way

| Decision | Reason |
| --- | --- |
| **Snapshot input, not live lookups** | Configuration auditing is fundamentally about treating config as code: versionable, CI-friendly, reproducible — more engineering value than a one-off web check |
| **Parsers tolerate errors instead of raising** | An auditor must first describe *everything that is wrong* before it scores anything; all parse errors go into an `errors` list |
| **Rules decoupled from baselines** | Rules state objective facts, baselines state organisational requirements; switching baselines yields a different verdict for the same config, enabling staged governance |
| **No third-party dependencies** | A security tool must itself be trustworthy; shrinking the supply-chain surface to zero also lets it run in the leanest containers |
| **Pure-function rule engine** | Easy to test, easy to parallelise, easy to extend — 99 tests need no mocks |
| **SARIF as a first-class citizen** | Results land in a workflow developers already have (Code Scanning) instead of yet another isolated report |

Architecture and data flow: 👉 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### 🗺️ Roadmap

- [ ] 📥 Native parsing of `dig +short`, `nslookup`, and Route53 / Cloudflare export text (still offline — text parsing only)
- [ ] 📨 Parse DMARC aggregate reports (`rua` XML) to drive simulation with real delivery data
- [ ] 🏷️ Add BIMI, MTA-STS policy-file consistency and ARC chain rules
- [ ] ⚙️ `.mailproof.toml`: rule allowlists and severity overrides
- [ ] 🌐 Localised CLI output (the three languages currently cover the documentation layer)
- [ ] 📈 Cross-version config diffs and score trend tracking

---

## 📦 6. Packaging & deployment

MailProof is a **library / CLI project**, so per the release policy it **needs no binary Release assets**: pure Python, cross-platform, no compiled artifacts — `pip install` is all it takes.

### One-shot build (cross-platform, standard library only)

```bash
python scripts/build.py
# equivalent to: make build
```

The script runs the 99 unit tests → builds a wheel into `dist/` → writes `dist/SHA256SUMS`. It works identically on Windows / macOS / Linux, with no `make` and no extra build frontend.

```bash
python scripts/build.py --sdist     # also produce a source distribution
python scripts/build.py --no-test   # skip tests (not recommended)
```

### Verify a local install

```bash
pip install --no-deps --force-reinstall dist/mailproof-1.0.0-py3-none-any.whl
mailproof --version
mailproof audit examples/sample.zone --baseline strict
```

### Container deployment

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

### Compatibility matrix

| Environment | Status |
| --- | --- |
| Python 3.8 – 3.13 | ✅ covered by CI |
| Ubuntu / macOS / Windows | ✅ covered by CI |
| Air-gapped / isolated intranet | ✅ fully usable |
| Alpine container | ✅ no build toolchain needed |
| PyInstaller / zipapp | ✅ pure Python, package it as a single file yourself |

> 📌 Release checklist: repo publicly reachable ✅, installable with `pip` ✅, docs readable in three languages ✅, wheel + SHA256 artifacts complete ✅, core functionality self-tested ✅.

---

## 🤝 7. Contributing

PRs are very welcome! 🌱 Please start with 👉 [`CONTRIBUTING.md`](CONTRIBUTING.md).

```bash
git clone https://github.com/gitstq/MailProof.git
cd MailProof
pip install -e ".[dev]"
make test          # python -m unittest discover -s tests -v
make lint          # python -m compileall -q mailproof tests scripts
```

**Commit convention (Angular)**: `feat:` / `fix:` / `docs:` / `refactor:` / `test:` / `perf:` / `chore:`

```bash
git commit -m "feat: add BIMI record presence rule MP307"
git commit -m "fix: correct a/24 CIDR mechanism argument parsing"
```

**Three non-negotiables**: ① never add a third-party runtime dependency; ② never add a network call; ③ every new rule must come with tests and updates to all three language docs.

When filing an issue, include the version, a reproduction command and a **redacted** snapshot; never paste private keys or tokens. 🐛

---

## 📄 8. License

Released under the **MIT License** — you may use, copy, modify, merge, publish, distribute, sublicense and sell copies of the software, provided the copyright and permission notices are retained.

```
MIT License · Copyright (c) 2026 MailProof contributors
```

Full text: 👉 [`LICENSE`](LICENSE).

- ✅ Commercial use, modification and closed-source integration allowed
- ✅ No obligation beyond attribution
- ⚠️ Provided "as is", without warranty of any kind, express or implied

---

<div align="center">

**📮 MailProof — make your email domain configuration as auditable, simulatable and CI-ready as your code.**

[⬆ Back to top](#-mailproof) · [📖 Architecture](docs/ARCHITECTURE.md) · [🐛 Open an issue](https://github.com/gitstq/MailProof/issues)

</div>
