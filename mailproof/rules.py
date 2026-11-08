"""The MailProof rule engine.

Rules are small pure functions over an :class:`AuditContext`. Registering via
the ``@rule`` decorator keeps the catalog introspectable so the CLI can print
it (``mailproof rules``) and so SARIF reports can embed rule metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple

from .dmarc import DMARCRecord, policy_rank
from .dkim import DKIMRecord
from .models import DomainSnapshot, Finding, Rule, Severity
from .presets import Baseline
from .spf import SPFRecord


@dataclass
class AuditContext:
    """Everything a rule is allowed to look at."""

    snapshot: DomainSnapshot
    spf: List[SPFRecord] = field(default_factory=list)
    dmarc: List[DMARCRecord] = field(default_factory=list)
    dkim: List[DKIMRecord] = field(default_factory=list)
    baseline: Baseline = None  # type: ignore[assignment]
    include_loops: List[Tuple[str, ...]] = field(default_factory=list)

    @property
    def primary_spf(self) -> SPFRecord | None:
        return self.spf[0] if self.spf else None

    @property
    def primary_dmarc(self) -> DMARCRecord | None:
        return self.dmarc[0] if self.dmarc else None


RuleFn = Callable[[AuditContext], List[Finding]]

RULES: List[Rule] = []
_FUNCS: Dict[str, RuleFn] = {}


def rule(
    rule_id: str,
    title: str,
    severity: Severity,
    category: str,
    description: str,
    reference: str = "",
):
    """Register a rule function in the global catalog."""

    def deco(fn: RuleFn) -> RuleFn:
        if rule_id in _FUNCS:
            raise ValueError(f"重复的规则 ID：{rule_id}")
        RULES.append(
            Rule(rule_id, title, severity, category, description, reference)
        )
        _FUNCS[rule_id] = fn
        return fn

    return deco


def _f(
    ctx: AuditContext,
    rule_id: str,
    title: str,
    severity: Severity,
    message: str,
    recommendation: str = "",
    reference: str = "",
    context: str = "",
) -> Finding:
    meta = next((r for r in RULES if r.rule_id == rule_id), None)
    return Finding(
        rule_id=rule_id,
        title=title or (meta.title if meta else ""),
        severity=severity,
        message=message,
        recommendation=recommendation,
        reference=reference or (meta.reference if meta else ""),
        context=context,
    )


def _spf_severity(ctx: AuditContext, sev: Severity) -> Severity:
    return sev


RFC_SPF = "https://datatracker.ietf.org/doc/html/rfc7208"
RFC_DMARC = "https://datatracker.ietf.org/doc/html/rfc7489"
RFC_DKIM = "https://datatracker.ietf.org/doc/html/rfc6376"


# --------------------------------------------------------------------------
# SPF rules (MP0xx)
# --------------------------------------------------------------------------

@rule("MP001", "缺少 SPF 记录", Severity.CRITICAL, "SPF",
      "域名未发布任何 v=spf1 记录，接收方无法校验发件服务器。", RFC_SPF)
def r_missing_spf(ctx: AuditContext) -> List[Finding]:
    if ctx.spf:
        return []
    return [_f(ctx, "MP001", "", Severity.CRITICAL,
               "未发现 SPF（v=spf1）TXT 记录。",
               "在域名 apex 发布一条 SPF 记录，例如 v=spf1 include:_spf.example.com -all",
               context=ctx.snapshot.domain)]


@rule("MP002", "存在多条 SPF 记录", Severity.HIGH, "SPF",
      "RFC 7208 要求每个域名只能有一条 SPF 记录。", RFC_SPF)
def r_multiple_spf(ctx: AuditContext) -> List[Finding]:
    if len(ctx.spf) <= 1:
        return []
    return [_f(ctx, "MP002", "", Severity.HIGH,
               f"检测到 {len(ctx.spf)} 条 SPF 记录，接收方会直接判定为 PermError。",
               "合并为一条记录后删除多余的 TXT 记录。")]


@rule("MP003", "SPF 记录存在语法错误", Severity.HIGH, "SPF",
      "解析过程中发现非法术语或错误版本标记。", RFC_SPF)
def r_spf_syntax(ctx: AuditContext) -> List[Finding]:
    out = []
    for rec in ctx.spf:
        if rec.errors:
            out.append(_f(ctx, "MP003", "", Severity.HIGH,
                          "SPF 解析错误：" + "；".join(rec.errors),
                          "按 RFC 7208 修正记录后重新发布。", context=rec.raw))
    return out


@rule("MP004", "SPF DNS 查询次数超过 10", Severity.HIGH, "SPF",
      "RFC 7208 §4.6.4 限制 SPF 求值最多 10 次 DNS 查询。", RFC_SPF)
def r_spf_lookups(ctx: AuditContext) -> List[Finding]:
    out = []
    for rec in ctx.spf:
        n = rec.lookup_count
        if n > ctx.baseline.max_spf_lookups:
            out.append(_f(ctx, "MP004", "", Severity.HIGH,
                          f"SPF 含 {n} 个会触发 DNS 查询的术语，超过上限 "
                          f"{ctx.baseline.max_spf_lookups}（include/a/mx/ptr/exists/redirect 各计 1 次，"
                          "实际 mx/ptr 展开可能产生更多）。",
                          "扁平化 SPF（用 ip4/ip6 替换 include），或移除冗余机制。",
                          context=rec.raw))
    return out


@rule("MP005", "SPF 使用 +all 允许任意发件人", Severity.CRITICAL, "SPF",
      "+all 使 SPF 形同虚设，任何服务器都能通过校验。", RFC_SPF)
def r_spf_plus_all(ctx: AuditContext) -> List[Finding]:
    out = []
    for rec in ctx.spf:
        m = rec.all_mechanism
        if m and m.qualifier == "+":
            out.append(_f(ctx, "MP005", "", Severity.CRITICAL,
                          "SPF 以 +all 结尾（pass），等价于允许互联网上任意主机代发邮件。",
                          "立即改为 -all（硬失败）或 ~all（软失败）。", context=rec.raw))
    return out


@rule("MP006", "SPF 未使用 -all 硬失败", Severity.MEDIUM, "SPF",
      "软失败/中性策略降低 SPF 的防护强度。", RFC_SPF)
def r_spf_soft_all(ctx: AuditContext) -> List[Finding]:
    if not ctx.baseline.require_spf_hardfail:
        return []
    out = []
    for rec in ctx.spf:
        m = rec.all_mechanism
        if m and m.qualifier in ("~", "?"):
            out.append(_f(ctx, "MP006", "", Severity.MEDIUM,
                          f"SPF 以 {m.raw} 结尾；基线要求 -all 硬失败。",
                          "在确认所有合法发件源均已列入后升级为 -all。", context=rec.raw))
        elif m is None:
            out.append(_f(ctx, "MP006", "", Severity.MEDIUM,
                          "SPF 记录缺少 all 机制，未匹配的发件源会得到 neutral 结果。",
                          "在记录末尾追加 -all。", context=rec.raw))
    return out


@rule("MP007", "SPF 使用已弃用的 ptr 机制", Severity.MEDIUM, "SPF",
      "RFC 7208 明确不建议使用 ptr。", RFC_SPF)
def r_spf_ptr(ctx: AuditContext) -> List[Finding]:
    if ctx.baseline.allow_spf_ptr:
        return []
    out = []
    for rec in ctx.spf:
        if any(m.kind == "ptr" for m in rec.mechanisms):
            out.append(_f(ctx, "MP007", "", Severity.MEDIUM,
                          "SPF 使用 ptr 机制，该机制已被 RFC 7208 弃用且查询开销大。",
                          "改用 ip4/ip6 或 include 显式声明发件源。", context=rec.raw))
    return out


@rule("MP008", "SPF include/redirect 存在循环", Severity.HIGH, "SPF",
      "循环引用会导致 SPF 求值耗尽查询预算并 PermError。", RFC_SPF)
def r_spf_loop(ctx: AuditContext) -> List[Finding]:
    if not ctx.include_loops:
        return []
    chains = "；".join(" → ".join(c) for c in ctx.include_loops)
    return [_f(ctx, "MP008", "", Severity.HIGH,
               f"检测到 SPF 引用环：{chains}。",
               "打断循环，或把共享发件源抽取为一条扁平的 ip4/ip6 记录。",
               context=chains)]


@rule("MP009", "SPF redirect 与 all 冲突", Severity.HIGH, "SPF",
      "redirect 在存在 all 时不会生效。", RFC_SPF)
def r_spf_redirect_conflict(ctx: AuditContext) -> List[Finding]:
    out = []
    for rec in ctx.spf:
        if "redirect" in rec.modifiers and rec.all_mechanism:
            out.append(_f(ctx, "MP009", "", Severity.HIGH,
                          "记录同时包含 redirect 与 all，redirect 修饰符将被忽略。",
                          "二选一：保留 redirect 并删除 all，或删除 redirect。", context=rec.raw))
    return out


@rule("MP010", "SPF 含宏或复杂 exists 机制", Severity.LOW, "SPF",
      "复杂宏降低可读性并容易被错误配置。", RFC_SPF)
def r_spf_macros(ctx: AuditContext) -> List[Finding]:
    out = []
    for rec in ctx.spf:
        if any(m.kind == "exists" or "%{" in m.value for m in rec.mechanisms):
            out.append(_f(ctx, "MP010", "", Severity.LOW,
                          "SPF 使用了 exists/宏展开，离线审计无法完全验证其运行时行为。",
                          "尽量改用静态机制，并在真实投递环境做一次验证。", context=rec.raw))
    return out


# --------------------------------------------------------------------------
# DMARC rules (MP1xx)
# --------------------------------------------------------------------------

@rule("MP101", "缺少 DMARC 记录", Severity.CRITICAL, "DMARC",
      "未发布 DMARC 策略，SPF/DKIM 失败时接收方无处置依据。", RFC_DMARC)
def r_missing_dmarc(ctx: AuditContext) -> List[Finding]:
    if ctx.dmarc:
        return []
    return [_f(ctx, "MP101", "", Severity.CRITICAL,
               f"未在 _dmarc.{ctx.snapshot.domain} 发现 DMARC 记录。",
               "从 p=none 开始发布 DMARC，收集聚合报告后再逐步升级到 quarantine / reject。")]


@rule("MP102", "存在多条 DMARC 记录", Severity.HIGH, "DMARC",
      "同一域名只能有一条 DMARC 记录。", RFC_DMARC)
def r_multiple_dmarc(ctx: AuditContext) -> List[Finding]:
    if len(ctx.dmarc) <= 1:
        return []
    return [_f(ctx, "MP102", "", Severity.HIGH,
               f"检测到 {len(ctx.dmarc)} 条 DMARC 记录，接收方会视为无策略。",
               "仅保留一条记录。")]


@rule("MP103", "DMARC 记录存在语法错误", Severity.HIGH, "DMARC",
      "标签非法或缺失必需字段。", RFC_DMARC)
def r_dmarc_syntax(ctx: AuditContext) -> List[Finding]:
    out = []
    for rec in ctx.dmarc:
        if rec.errors:
            out.append(_f(ctx, "MP103", "", Severity.HIGH,
                          "DMARC 解析错误：" + "；".join(rec.errors),
                          "按 RFC 7489 修正标签。", context=rec.raw))
    return out


@rule("MP104", "DMARC 处于 p=none 监控模式", Severity.HIGH, "DMARC",
      "p=none 不拦截伪造邮件，仅用于收集报告。", RFC_DMARC)
def r_dmarc_none(ctx: AuditContext) -> List[Finding]:
    need = policy_rank(ctx.baseline.min_dmarc_policy)
    out = []
    for rec in ctx.dmarc:
        if policy_rank(rec.policy) < need:
            out.append(_f(ctx, "MP104", "", Severity.HIGH,
                          f"当前策略 p={rec.policy or '缺失'}，低于基线要求的 "
                          f"p={ctx.baseline.min_dmarc_policy}；伪造邮件仍会被投递。",
                          "分析 rua 聚合报告、确认合法发件源全部对齐后升级策略。",
                          context=rec.raw))
    return out


@rule("MP105", "DMARC pct 未覆盖 100% 流量", Severity.MEDIUM, "DMARC",
      "pct<100 会让部分伪造邮件绕过策略。", RFC_DMARC)
def r_dmarc_pct(ctx: AuditContext) -> List[Finding]:
    if not ctx.baseline.require_dmarc_pct_100:
        return []
    out = []
    for rec in ctx.dmarc:
        if rec.pct < 100:
            out.append(_f(ctx, "MP105", "", Severity.MEDIUM,
                          f"pct={rec.pct}，仅对部分邮件应用策略。",
                          "完成灰度后移除 pct 标签或设为 100。", context=rec.raw))
    return out


@rule("MP106", "DMARC 未配置 rua 聚合报告", Severity.MEDIUM, "DMARC",
      "没有报告就无法安全地升级策略。", RFC_DMARC)
def r_dmarc_rua(ctx: AuditContext) -> List[Finding]:
    if not ctx.baseline.require_rua:
        return []
    out = []
    for rec in ctx.dmarc:
        if not rec.aggregate_uris:
            out.append(_f(ctx, "MP106", "", Severity.MEDIUM,
                          "未配置 rua 聚合报告地址，无法观测对齐失败情况。",
                          "添加 rua=mailto:dmarc-report@example.com。", context=rec.raw))
    return out


@rule("MP107", "子域策略 sp 弱于主域策略", Severity.MEDIUM, "DMARC",
      "未设置 sp 时子域继承 p；显式弱化的 sp 会打开子域伪造缺口。", RFC_DMARC)
def r_dmarc_sp(ctx: AuditContext) -> List[Finding]:
    out = []
    for rec in ctx.dmarc:
        if "sp" in rec.tags and policy_rank(rec.subdomain_policy) < policy_rank(rec.policy):
            out.append(_f(ctx, "MP107", "", Severity.MEDIUM,
                          f"sp={rec.subdomain_policy} 弱于 p={rec.policy}，攻击者可伪造任意子域。",
                          "将 sp 提升到与 p 一致，或删除 sp 让其继承主域策略。", context=rec.raw))
    return out


@rule("MP108", "DMARC 使用宽松对齐模式", Severity.LOW, "DMARC",
      "adkim/aspf=r 允许组织域级别的宽松对齐。", RFC_DMARC)
def r_dmarc_alignment(ctx: AuditContext) -> List[Finding]:
    out = []
    for rec in ctx.dmarc:
        loose = [t for t in ("adkim", "aspf") if rec.tags.get(t, "r").lower() == "r"]
        if loose and policy_rank(rec.policy) >= 1:
            out.append(_f(ctx, "MP108", "", Severity.LOW,
                          f"{'/'.join(loose)} 采用宽松(r)对齐，子域可被用于对齐。",
                          "高安全场景建议设为 s（严格对齐）。", context=rec.raw))
    return out


@rule("MP109", "外部域报告地址需要授权验证", Severity.INFO, "DMARC",
      "跨组织域的 rua/ruf 需要外部域发布授权记录。", RFC_DMARC)
def r_dmarc_external_uri(ctx: AuditContext) -> List[Finding]:
    out = []
    domain = ctx.snapshot.domain.rstrip(".").lower()
    for rec in ctx.dmarc:
        external = []
        for uri in rec.aggregate_uris + rec.forensic_uris:
            addr = uri.split(":", 1)[-1]
            dest = addr.rsplit("@", 1)[-1].lower()
            if dest and dest != domain and not domain.endswith("." + dest):
                external.append(dest)
        if external:
            uniq = sorted(set(external))
            out.append(_f(ctx, "MP109", "", Severity.INFO,
                          f"报告将发送到外部域 {', '.join(uniq)}；这些域必须发布 DMARC 授权记录，"
                          "否则报告会被丢弃。",
                          "在目标域发布 <domain>._report._dmarc.<外部域> TXT 授权记录。",
                          context=rec.raw))
    return out


# --------------------------------------------------------------------------
# DKIM rules (MP2xx)
# --------------------------------------------------------------------------

@rule("MP201", "缺少 DKIM 公钥记录", Severity.HIGH, "DKIM",
      "没有 DKIM 就只剩 SPF 单条对齐路径。", RFC_DKIM)
def r_missing_dkim(ctx: AuditContext) -> List[Finding]:
    if not ctx.baseline.require_dkim or ctx.dkim:
        return []
    return [_f(ctx, "MP201", "", Severity.HIGH,
               "快照中未发现任何 DKIM 公钥记录（<selector>._domainkey）。",
               "为发件系统配置 DKIM 签名，并发布 2048 位 RSA 或 Ed25519 公钥。")]


@rule("MP202", "DKIM 记录存在语法错误", Severity.HIGH, "DKIM",
      "公钥或标签非法会导致验签失败。", RFC_DKIM)
def r_dkim_syntax(ctx: AuditContext) -> List[Finding]:
    out = []
    for rec in ctx.dkim:
        if rec.errors:
            out.append(_f(ctx, "MP202", "", Severity.HIGH,
                          f"选择器 {rec.selector or '(未命名)'} 解析错误：" + "；".join(rec.errors),
                          "按 RFC 6376 修正记录。", context=rec.raw))
    return out


@rule("MP203", "DKIM 密钥已撤销", Severity.MEDIUM, "DKIM",
      "p= 为空表示该选择器不再有效。", RFC_DKIM)
def r_dkim_revoked(ctx: AuditContext) -> List[Finding]:
    out = []
    for rec in ctx.dkim:
        if rec.revoked:
            out.append(_f(ctx, "MP203", "", Severity.MEDIUM,
                          f"选择器 {rec.selector} 的 p 标签为空，密钥已被撤销。",
                          "若仍在使用该选择器，请重新发布公钥；否则删除该残留记录。",
                          context=rec.raw))
    return out


@rule("MP204", "DKIM RSA 密钥强度不足", Severity.HIGH, "DKIM",
      "1024 位 RSA 已不满足主流接收方要求。", RFC_DKIM)
def r_dkim_weak_key(ctx: AuditContext) -> List[Finding]:
    out = []
    for rec in ctx.dkim:
        if rec.key_bits and rec.key_bits < ctx.baseline.min_dkim_bits:
            out.append(_f(ctx, "MP204", "", Severity.HIGH,
                          f"选择器 {rec.selector} 的 RSA 密钥为 {rec.key_bits} 位，"
                          f"低于基线要求的 {ctx.baseline.min_dkim_bits} 位。",
                          "轮换为 2048 位 RSA 密钥（或迁移到 Ed25519）。", context=rec.raw))
    return out


@rule("MP205", "DKIM 处于 t=y 测试模式", Severity.MEDIUM, "DKIM",
      "测试标志会让部分接收方忽略验签失败。", RFC_DKIM)
def r_dkim_testing(ctx: AuditContext) -> List[Finding]:
    if not ctx.baseline.forbid_dkim_testing:
        return []
    out = []
    for rec in ctx.dkim:
        if rec.testing:
            out.append(_f(ctx, "MP205", "", Severity.MEDIUM,
                          f"选择器 {rec.selector} 带 t=y 测试标志。",
                          "验证签名正常后移除 t 标签。", context=rec.raw))
    return out


# --------------------------------------------------------------------------
# Cross-record / correlation rules (MP3xx)
# --------------------------------------------------------------------------

@rule("MP301", "DMARC 缺少任何对齐来源", Severity.CRITICAL, "CORRELATION",
      "DMARC 需要 SPF 或 DKIM 至少一方通过且对齐。", RFC_DMARC)
def r_no_alignment_source(ctx: AuditContext) -> List[Finding]:
    if not ctx.dmarc:
        return []
    if ctx.spf or ctx.dkim:
        return []
    return [_f(ctx, "MP301", "", Severity.CRITICAL,
               "已发布 DMARC，但 SPF 与 DKIM 均缺失，所有邮件都无法通过 DMARC 对齐。",
               "至少部署 SPF 或 DKIM 之一（建议两者都部署）。")]


@rule("MP302", "DMARC 严格策略与 +all SPF 矛盾", Severity.HIGH, "CORRELATION",
      "SPF 允许任意主机，会绕过 DMARC 的 SPF 对齐路径。", RFC_DMARC)
def r_policy_contradiction(ctx: AuditContext) -> List[Finding]:
    out = []
    for d in ctx.dmarc:
        if policy_rank(d.policy) < 1:
            continue
        for s in ctx.spf:
            m = s.all_mechanism
            if m and m.qualifier == "+":
                out.append(_f(ctx, "MP302", "", Severity.HIGH,
                              "DMARC 已启用拦截策略，但 SPF 仍为 +all；攻击者可利用 SPF 对齐路径绕过拦截。",
                              "立即把 SPF 收紧到 -all。", context=s.raw))
    return out


@rule("MP303", "严格 SPF 对齐但 SPF 缺失", Severity.HIGH, "CORRELATION",
      "aspf=s 时缺少 SPF 会削弱 DMARC 的冗余度。", RFC_DMARC)
def r_aspf_strict_no_spf(ctx: AuditContext) -> List[Finding]:
    out = []
    for d in ctx.dmarc:
        if d.tags.get("aspf", "r").lower() == "s" and not ctx.spf:
            out.append(_f(ctx, "MP303", "", Severity.HIGH,
                          "DMARC 要求严格 SPF 对齐 (aspf=s)，但域名未发布 SPF 记录。",
                          "发布 SPF 记录，或把 aspf 调整为 r 并强化 DKIM。", context=d.raw))
    return out


@rule("MP304", "严格 DKIM 对齐但 DKIM 缺失", Severity.MEDIUM, "CORRELATION",
      "adkim=s 时缺少 DKIM 会削弱 DMARC 的冗余度。", RFC_DMARC)
def r_adkim_strict_no_dkim(ctx: AuditContext) -> List[Finding]:
    out = []
    for d in ctx.dmarc:
        if d.tags.get("adkim", "r").lower() == "s" and not ctx.dkim:
            out.append(_f(ctx, "MP304", "", Severity.MEDIUM,
                          "DMARC 要求严格 DKIM 对齐 (adkim=s)，但快照中没有 DKIM 公钥。",
                          "部署 DKIM，或把 adkim 调整为 r。", context=d.raw))
    return out


@rule("MP305", "未发布 MTA-STS 策略", Severity.INFO, "TRANSPORT",
      "MTA-STS 可强制入站 SMTP 使用 TLS。",
      "https://datatracker.ietf.org/doc/html/rfc8461")
def r_mta_sts(ctx: AuditContext) -> List[Finding]:
    name = f"_mta-sts.{ctx.snapshot.domain.rstrip('.')}"
    if any(r.name.rstrip(".").lower() == name.lower() for r in ctx.snapshot.all_txt()):
        return []
    return [_f(ctx, "MP305", "", Severity.INFO,
               "未发现 _mta-sts TXT 记录，入站邮件可能降级为明文 SMTP。",
               "部署 MTA-STS 策略与 HTTPS 策略文件（建议配合 TLS-RPT）。")]


@rule("MP306", "未发布 TLS-RPT 报告地址", Severity.INFO, "TRANSPORT",
      "TLS-RPT 用于收集 SMTP TLS 失败报告。",
      "https://datatracker.ietf.org/doc/html/rfc8460")
def r_tls_rpt(ctx: AuditContext) -> List[Finding]:
    name = f"_smtp._tls.{ctx.snapshot.domain.rstrip('.')}"
    if any(r.name.rstrip(".").lower() == name.lower() for r in ctx.snapshot.all_txt()):
        return []
    return [_f(ctx, "MP306", "", Severity.INFO,
               "未发现 _smtp._tls TXT 记录，无法收到 TLS 协商失败报告。",
               "添加 v=TLSRPTv1; rua=mailto:tlsrpt@example.com。")]


# --------------------------------------------------------------------------
# Baseline compliance (MP4xx)
# --------------------------------------------------------------------------

@rule("MP401", "未满足所选合规基线", Severity.HIGH, "BASELINE",
      "按所选基线汇总所有硬性缺口。", "")
def r_baseline(ctx: AuditContext) -> List[Finding]:
    b = ctx.baseline
    missing: List[str] = []
    s = ctx.primary_spf
    d = ctx.primary_dmarc

    if b.require_spf and not s:
        missing.append("SPF 记录")
    if s and b.require_spf_hardfail:
        m = s.all_mechanism
        if not m or m.qualifier != "-":
            missing.append("SPF -all 硬失败")
    if b.require_dmarc and not d:
        missing.append("DMARC 记录")
    if d and policy_rank(d.policy) < policy_rank(b.min_dmarc_policy):
        missing.append(f"DMARC p≥{b.min_dmarc_policy}")
    if d and b.require_dmarc_pct_100 and d.pct < 100:
        missing.append("DMARC pct=100")
    if d and b.require_rua and not d.aggregate_uris:
        missing.append("DMARC rua 聚合报告")
    if b.require_dkim and not ctx.dkim:
        missing.append("DKIM 公钥")
    if ctx.dkim and any(
        (r.key_bits or 0) < b.min_dkim_bits
        for r in ctx.dkim
        if r.key_bits is not None
    ):
        missing.append(f"DKIM 密钥 ≥{b.min_dkim_bits} 位")

    if not missing:
        return []
    return [_f(ctx, "MP401", "", Severity.HIGH,
               f"基线「{b.name}」存在 {len(missing)} 项未满足：" + "、".join(missing) + "。",
               "逐项修复后重新运行 `mailproof audit --baseline " + b.key + "`。",
               reference=b.reference,
               context=b.key)]


def run_rules(ctx: AuditContext) -> List[Finding]:
    """Execute every registered rule and return findings in catalog order."""
    findings: List[Finding] = []
    for meta in RULES:
        findings.extend(_FUNCS[meta.rule_id](ctx))
    return findings


def catalog() -> List[Rule]:
    return list(RULES)
