"""Report renderers: text, Markdown, JSON, SARIF 2.1.0 and standalone HTML."""

from __future__ import annotations

import html
import json
from typing import Dict, List

from . import __version__
from .models import AuditBundle, AuditResult, Finding, Severity
from .rules import catalog
from .scoring import grade_label

_SEVERITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}
_SEVERITY_LABEL = {
    "critical": "致命",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

FORMATS = ("text", "markdown", "json", "sarif", "html")


def _ordered(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: -f.severity.rank)


def render_text(bundle: AuditBundle) -> str:
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append(f"  MailProof v{__version__} · 邮件域名身份认证审计报告")
    lines.append("=" * 72)
    lines.append(f"数据源：{bundle.source or '(内存快照)'}    域名数：{len(bundle.results)}")
    for r in bundle.results:
        lines.append("")
        lines.append(f"📮 域名：{r.domain}")
        lines.append(f"   评分：{r.score}/100   等级：{r.grade}（{r.metadata.get('grade_label','')}）")
        lines.append(f"   基线：{r.metadata.get('baseline_name','')}")
        c = r.count_by_severity()
        lines.append(
            "   发现："
            + "  ".join(f"{_SEVERITY_ICON[k]}{_SEVERITY_LABEL[k]} {v}" for k, v in c.items())
        )
        lines.append("-" * 72)
        if not r.findings:
            lines.append("   ✅ 未发现问题，配置符合所选基线。")
        for f in _ordered(r.findings):
            lines.append(
                f"   {_SEVERITY_ICON[f.severity.value]} [{f.rule_id}] {f.title} "
                f"({_SEVERITY_LABEL[f.severity.value]})"
            )
            lines.append(f"      {f.message}")
            if f.recommendation:
                lines.append(f"      💡 建议：{f.recommendation}")
            if f.reference:
                lines.append(f"      📎 {f.reference}")
            lines.append("")
    lines.append("=" * 72)
    return "\n".join(lines)


def render_markdown(bundle: AuditBundle) -> str:
    out = [
        f"# 📮 MailProof 审计报告",
        "",
        f"> 工具版本：`{__version__}`　数据源：`{bundle.source or '内存快照'}`　域名数：**{len(bundle.results)}**",
        "",
        "## 📊 总览",
        "",
        "| 域名 | 评分 | 等级 | 致命 | 高危 | 中危 | 低危 | 提示 | 基线 |",
        "| --- | ---: | :---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for r in bundle.results:
        c = r.count_by_severity()
        out.append(
            f"| `{r.domain}` | {r.score}/100 | {r.grade} | {c['critical']} | {c['high']} | "
            f"{c['medium']} | {c['low']} | {c['info']} | {r.baseline} |"
        )
    out.append("")
    for r in bundle.results:
        out += [f"## 🔍 {r.domain}（{r.score}/100 · {r.grade} {r.metadata.get('grade_label','')}）", ""]
        if not r.findings:
            out += ["✅ 未发现问题，配置符合所选基线。", ""]
        for f in _ordered(r.findings):
            out += [
                f"### {_SEVERITY_ICON[f.severity.value]} `{f.rule_id}` {f.title}",
                "",
                f"- **级别**：{_SEVERITY_LABEL[f.severity.value]} (`{f.severity.value}`)",
                f"- **说明**：{f.message}",
            ]
            if f.recommendation:
                out.append(f"- **修复建议**：{f.recommendation}")
            if f.reference:
                out.append(f"- **参考**：{f.reference}")
            if f.context:
                out.append(f"- **上下文**：`{f.context[:200]}`")
            out.append("")
    return "\n".join(out)


def render_json(bundle: AuditBundle) -> str:
    return json.dumps(bundle.to_dict(), ensure_ascii=False, indent=2)


def render_sarif(bundle: AuditBundle) -> str:
    rules_meta = [
        {
            "id": r.rule_id,
            "name": r.rule_id,
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.description},
            "defaultConfiguration": {"level": _SARIF_LEVEL[r.severity.value]},
            "properties": {
                "category": r.category,
                "severity": r.severity.value,
                "helpUri": r.reference,
            },
        }
        for r in catalog()
    ]
    results = []
    for domain in bundle.results:
        for f in domain.findings:
            results.append(
                {
                    "ruleId": f.rule_id,
                    "level": _SARIF_LEVEL[f.severity.value],
                    "message": {"text": f.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": domain.domain},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "properties": {
                        "recommendation": f.recommendation,
                        "context": f.context[:300],
                        "score": domain.score,
                        "grade": domain.grade,
                    },
                }
            )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MailProof",
                        "version": __version__,
                        "informationUri": "https://github.com/gitstq/MailProof",
                        "rules": rules_meta,
                    }
                },
                "results": results,
                "properties": {"source": bundle.source},
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)


_CSS = """
:root{color-scheme:light dark}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"PingFang SC","Microsoft YaHei",sans-serif;
margin:0;padding:32px;background:#f6f7f9;color:#1f2430;line-height:1.65}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin-top:36px;border-bottom:2px solid #e3e6ec;padding-bottom:8px}
.meta{color:#6b7280;font-size:14px;margin-bottom:24px}
.card{background:#fff;border:1px solid #e3e6ec;border-radius:12px;padding:20px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.badge{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:700;color:#fff}
.g-A,.g-B{background:#16a34a}.g-C{background:#ca8a04}.g-D,.g-E{background:#ea580c}.g-F{background:#dc2626}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{border:1px solid #e5e7eb;padding:8px 10px;text-align:left;vertical-align:top}
th{background:#f3f4f6}code{background:#f3f4f6;padding:1px 5px;border-radius:4px;font-size:13px}
.sev{font-weight:700;white-space:nowrap}.s-critical{color:#dc2626}.s-high{color:#ea580c}.s-medium{color:#ca8a04}.s-low{color:#2563eb}.s-info{color:#6b7280}
.finding{padding:12px 0;border-bottom:1px dashed #e5e7eb}.finding:last-child{border-bottom:0}
.footer{color:#9ca3af;font-size:13px;text-align:center;margin-top:40px}
@media (prefers-color-scheme:dark){body{background:#111318;color:#e5e7eb}.card{background:#1a1d24;border-color:#2c313c}
.meta,.footer{color:#9ca3af}th{background:#22262f}td,th{border-color:#2c313c}code{background:#22262f}}
"""


def render_html(bundle: AuditBundle) -> str:
    e = html.escape
    parts = [
        "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>MailProof 审计报告</title><style>{_CSS}</style></head><body><div class='wrap'>",
        "<h1>📮 MailProof 邮件域名身份认证审计报告</h1>",
        f"<div class='meta'>版本 {e(__version__)} · 数据源 {e(bundle.source or '内存快照')} · 共 {len(bundle.results)} 个域名</div>",
    ]
    for r in bundle.results:
        c = r.count_by_severity()
        parts.append("<div class='card'>")
        parts.append(
            f"<h2>🔍 {e(r.domain)} <span class='badge g-{e(r.grade)}'>{r.score}/100 · {e(r.grade)}</span></h2>"
        )
        parts.append(
            f"<div class='meta'>{e(r.metadata.get('grade_label',''))} · 基线：{e(r.metadata.get('baseline_name',''))} "
            f"· TXT 记录 {r.metadata.get('record_count',0)} 条 · SPF {r.metadata.get('spf_count',0)} / "
            f"DMARC {r.metadata.get('dmarc_count',0)} / DKIM {r.metadata.get('dkim_count',0)}</div>"
        )
        parts.append("<table><tr><th>级别</th><th>数量</th></tr>")
        for k in ("critical", "high", "medium", "low", "info"):
            parts.append(
                f"<tr><td class='sev s-{k}'>{_SEVERITY_ICON[k]} {_SEVERITY_LABEL[k]}</td><td>{c[k]}</td></tr>"
            )
        parts.append("</table></div>")

        parts.append("<div class='card'><h2>🧾 审计发现</h2>")
        if not r.findings:
            parts.append("<p>✅ 未发现问题，配置符合所选基线。</p>")
        for f in _ordered(r.findings):
            parts.append("<div class='finding'>")
            parts.append(
                f"<div><span class='sev s-{f.severity.value}'>{_SEVERITY_ICON[f.severity.value]} "
                f"[{e(f.rule_id)}] {e(f.title)}</span></div>"
            )
            parts.append(f"<div>{e(f.message)}</div>")
            if f.recommendation:
                parts.append(f"<div>💡 建议：{e(f.recommendation)}</div>")
            if f.reference:
                parts.append(f"<div>📎 <a href='{e(f.reference)}'>{e(f.reference)}</a></div>")
            if f.context:
                parts.append(f"<div><code>{e(f.context[:200])}</code></div>")
            parts.append("</div>")
        parts.append("</div>")
    parts.append(
        f"<div class='footer'>Generated by MailProof v{__version__} · 离线审计，不发起任何 DNS 查询</div>"
    )
    parts.append("</div></body></html>")
    return "".join(parts)


def render(bundle: AuditBundle, fmt: str = "text") -> str:
    if fmt not in FORMATS:
        raise ValueError(f"不支持的报告格式 {fmt!r}，可选：{', '.join(FORMATS)}")
    return {
        "text": render_text,
        "markdown": render_markdown,
        "json": render_json,
        "sarif": render_sarif,
        "html": render_html,
    }[fmt](bundle)
