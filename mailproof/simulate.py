"""Offline DMARC policy rollout simulation (what-if engine).

Online checkers can tell you what your record says today. They cannot answer
"what breaks if I move from p=none to p=reject?". MailProof answers that
question from the snapshot alone: available alignment paths, rollout blockers,
a staged roadmap and a risk estimate — all without sending a single packet.
"""

from __future__ import annotations

from typing import Dict, List

from .dmarc import collect_dmarc, policy_rank
from .dkim import collect_dkim
from .models import DomainSnapshot
from .presets import get_baseline
from .spf import collect_spf

_POLICY_ORDER = {"none": 0, "quarantine": 1, "reject": 2}


def _spf_path(snapshot: DomainSnapshot) -> Dict[str, object]:
    records = collect_spf(snapshot)
    if not records:
        return {"available": False, "reason": "未发布 SPF 记录", "hardfail": False}
    rec = records[0]
    m = rec.all_mechanism
    plus_all = bool(m and m.qualifier == "+")
    return {
        "available": not plus_all and rec.valid,
        "reason": (
            "SPF 为 +all，可被任意主机利用" if plus_all
            else "SPF 记录存在语法错误" if not rec.valid
            else "SPF 路径可用"
        ),
        "hardfail": bool(m and m.qualifier == "-"),
        "lookup_count": rec.lookup_count,
        "multiple_records": len(records) > 1,
    }


def _dkim_path(snapshot: DomainSnapshot) -> Dict[str, object]:
    records = collect_dkim(snapshot)
    usable = [r for r in records if r.valid and not r.revoked and not r.testing]
    weak = [r for r in usable if r.key_bits and r.key_bits < 2048]
    return {
        "available": bool(usable),
        "reason": (
            "未发现 DKIM 公钥" if not records
            else "所有 DKIM 选择器均处于测试/撤销/错误状态" if not usable
            else "DKIM 路径可用"
        ),
        "selector_count": len(records),
        "usable_count": len(usable),
        "weak_key_selectors": [r.selector for r in weak],
    }


def simulate(
    snapshot: DomainSnapshot,
    target_policy: str = "reject",
    baseline_key: str = "default",
) -> Dict[str, object]:
    """Simulate a staged rollout to ``target_policy`` for one domain."""
    if target_policy not in _POLICY_ORDER:
        raise ValueError("target_policy 必须是 none / quarantine / reject")

    baseline = get_baseline(baseline_key)
    dmarc_records = collect_dmarc(snapshot)
    dmarc = dmarc_records[0] if dmarc_records else None
    spf = _spf_path(snapshot)
    dkim = _dkim_path(snapshot)

    paths = int(bool(spf["available"])) + int(bool(dkim["available"]))
    current_policy = dmarc.policy if dmarc else "none"
    current_pct = dmarc.pct if dmarc else 100

    blockers: List[str] = []
    if not dmarc:
        blockers.append("尚未发布 DMARC 记录")
    elif dmarc.errors:
        blockers.append("DMARC 记录存在语法错误，必须先修复")
    if len(dmarc_records) > 1:
        blockers.append("存在多条 DMARC 记录，接收方会视为无策略")
    if dmarc and not dmarc.aggregate_uris:
        blockers.append("缺少 rua 聚合报告地址，升级后无法观测误杀")
    if spf.get("multiple_records"):
        blockers.append("存在多条 SPF 记录")
    if spf.get("lookup_count", 0) and int(spf["lookup_count"]) > 10:
        blockers.append("SPF DNS 查询次数超过 10，可能导致 PermError")
    if not paths:
        blockers.append("SPF 与 DKIM 对齐路径均不可用，升级后所有邮件都会被拦截")

    if blockers:
        risk = "critical"
    elif paths == 1:
        risk = "high"
    elif target_policy == "reject" and current_policy == "none":
        risk = "medium"
    else:
        risk = "low"

    roadmap: List[Dict[str, object]] = [
        {
            "phase": 1,
            "policy": "none",
            "pct": 100,
            "name": "监控期",
            "duration_hint": "至少 2–4 周",
            "action": "发布 p=none 并配置 rua，收集聚合报告；逐一登记所有合法发件源。",
            "verify": "连续 2 周报告中未对齐的来源占比 < 0.1%，且全部来源可解释。",
        },
        {
            "phase": 2,
            "policy": "quarantine",
            "pct": 5,
            "name": "灰度隔离 5%",
            "duration_hint": "3–7 天",
            "action": "p=quarantine; pct=5，观察隔离区与投诉量。",
            "verify": "隔离区无合法业务邮件，退信率无明显上升。",
        },
        {
            "phase": 3,
            "policy": "quarantine",
            "pct": 100,
            "name": "全量隔离",
            "duration_hint": "1–2 周",
            "action": "移除 pct 标签（或设为 100），保持 p=quarantine。",
            "verify": "所有第三方代发平台（营销、工单、账单）均已通过 DKIM/SPF 对齐。",
        },
        {
            "phase": 4,
            "policy": "reject",
            "pct": 100,
            "name": "全量拒绝",
            "duration_hint": "长期",
            "action": "提升到 p=reject；可考虑 sp=reject、adkim/aspf=s 严格对齐。",
            "verify": "持续审阅 rua 报告，新增发件源上线前先做对齐自检。",
        },
    ]
    # Trim the roadmap when the requested target is lower than reject.
    if target_policy == "quarantine":
        roadmap = [s for s in roadmap if _POLICY_ORDER[str(s["policy"])] <= 1]
    elif target_policy == "none":
        roadmap = roadmap[:1]

    recommendations: List[str] = []
    if paths < 2:
        recommendations.append("补齐 SPF 与 DKIM 双路径，避免单点故障导致合法邮件被拒。")
    if spf.get("hardfail") is False:
        recommendations.append("确认发件源清单后把 SPF 收紧为 -all。")
    if dkim.get("weak_key_selectors"):
        recommendations.append(
            "轮换以下弱密钥选择器为 2048 位："
            + ", ".join(str(x) for x in dkim["weak_key_selectors"])
        )
    if not blockers:
        recommendations.append("每次变更 TTL 生效后再进入下一阶段，并保留回滚快照。")

    return {
        "domain": snapshot.domain,
        "target_policy": target_policy,
        "baseline": baseline.key,
        "current": {
            "policy": current_policy,
            "pct": current_pct,
            "has_dmarc": bool(dmarc),
            "has_rua": bool(dmarc and dmarc.aggregate_uris),
            "aspf": dmarc.tags.get("aspf", "r") if dmarc else "r",
            "adkim": dmarc.tags.get("adkim", "r") if dmarc else "r",
        },
        "alignment": {
            "spf": spf,
            "dkim": dkim,
            "available_paths": paths,
            "redundant": paths >= 2,
        },
        "blockers": blockers,
        "risk": risk,
        "estimated_impact": {
            "current_policy_reach_pct": current_pct,
            "target_policy": target_policy,
            "note": (
                "离线推演：真实影响取决于接收方实现与邮件流量分布，"
                "请以 rua 聚合报告为准，本工具不联网、不发送任何邮件。"
            ),
        },
        "roadmap": roadmap,
        "recommendations": recommendations,
    }


def render_simulation_text(sim: Dict[str, object]) -> str:
    cur = sim["current"]  # type: ignore[index]
    al = sim["alignment"]  # type: ignore[index]
    lines = [
        "=" * 72,
        f"  MailProof · DMARC 策略推演：{sim['domain']} → p={sim['target_policy']}",
        "=" * 72,
        f"当前策略：p={cur['policy']}  pct={cur['pct']}  aspf={cur['aspf']}  adkim={cur['adkim']}",
        f"对齐路径：SPF {'✅' if al['spf']['available'] else '❌'} / "
        f"DKIM {'✅' if al['dkim']['available'] else '❌'}  可用路径数 {al['available_paths']}/2"
        f"  {'（有冗余 ✅）' if al['redundant'] else '（无冗余 ⚠️）'}",
        f"风险等级：{str(sim['risk']).upper()}",
        "",
        "🚧 升级前置阻断项：" if sim["blockers"] else "✅ 无阻断项，可以开始灰度。",
    ]
    for b in sim["blockers"]:  # type: ignore[union-attr]
        lines.append(f"   • {b}")
    lines += ["", "🗺️  分阶段上线路线："]
    for s in sim["roadmap"]:  # type: ignore[union-attr]
        lines.append(f"   阶段 {s['phase']} · {s['name']}  [p={s['policy']}, pct={s['pct']}]  ⏱ {s['duration_hint']}")
        lines.append(f"      动作：{s['action']}")
        lines.append(f"      验收：{s['verify']}")
    lines += ["", "💡 建议："]
    for r in sim["recommendations"]:  # type: ignore[union-attr]
        lines.append(f"   • {r}")
    lines += ["", str(sim["estimated_impact"]["note"]), "=" * 72]  # type: ignore[index]
    return "\n".join(lines)
