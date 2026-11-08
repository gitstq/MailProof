"""Compliance baselines for mail-domain authentication.

Baselines encode published bulk-sender requirements so a single CLI flag can
answer "would this domain pass Google/Yahoo/Microsoft's current rules?".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Baseline:
    """A named set of minimum requirements."""

    key: str
    name: str
    description: str
    require_spf: bool = True
    require_spf_hardfail: bool = False
    max_spf_lookups: int = 10
    allow_spf_ptr: bool = False
    require_dmarc: bool = True
    min_dmarc_policy: str = "quarantine"
    require_dmarc_pct_100: bool = False
    require_rua: bool = False
    require_dkim: bool = True
    min_dkim_bits: int = 2048
    forbid_dkim_testing: bool = False
    reference: str = ""


BASELINES: Dict[str, Baseline] = {
    "default": Baseline(
        key="default",
        name="MailProof 默认基线",
        description="面向一般域名的最佳实践：DMARC 至少 quarantine、SPF 使用 -all、DKIM 2048 位。",
        require_spf=True,
        require_spf_hardfail=True,
        max_spf_lookups=10,
        allow_spf_ptr=False,
        require_dmarc=True,
        min_dmarc_policy="quarantine",
        require_dmarc_pct_100=False,
        require_rua=True,
        require_dkim=True,
        min_dkim_bits=2048,
        forbid_dkim_testing=True,
        reference="https://datatracker.ietf.org/doc/html/rfc7489",
    ),
    "google-yahoo-2024": Baseline(
        key="google-yahoo-2024",
        name="Google / Yahoo 批量发件人要求（2024）",
        description="日发送量约 5000 封以上的域名：必须 SPF + DKIM + DMARC p≥none，并有对齐。",
        require_spf=True,
        require_spf_hardfail=False,
        max_spf_lookups=10,
        allow_spf_ptr=True,
        require_dmarc=True,
        min_dmarc_policy="none",
        require_dmarc_pct_100=False,
        require_rua=False,
        require_dkim=True,
        min_dkim_bits=1024,
        forbid_dkim_testing=False,
        reference="https://support.google.com/a/answer/81126",
    ),
    "microsoft-2025": Baseline(
        key="microsoft-2025",
        name="Microsoft Outlook 高容量发件人要求（2025）",
        description="日发送 5000 封以上：SPF、DKIM、DMARC 三者齐备且至少一方对齐，DMARC 建议 quarantine/reject。",
        require_spf=True,
        require_spf_hardfail=False,
        max_spf_lookups=10,
        allow_spf_ptr=False,
        require_dmarc=True,
        min_dmarc_policy="quarantine",
        require_dmarc_pct_100=False,
        require_rua=True,
        require_dkim=True,
        min_dkim_bits=2048,
        forbid_dkim_testing=True,
        reference="https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/strengthening-email-ecosystem-outlook%E2%80%99s-new-requirements-for-high%E2%80%90volume-senders/4399730",
    ),
    "strict": Baseline(
        key="strict",
        name="严格强化基线",
        description="面向金融/政企：p=reject、pct=100、严格对齐、SPF -all、DKIM ≥2048、禁用测试标志。",
        require_spf=True,
        require_spf_hardfail=True,
        max_spf_lookups=10,
        allow_spf_ptr=False,
        require_dmarc=True,
        min_dmarc_policy="reject",
        require_dmarc_pct_100=True,
        require_rua=True,
        require_dkim=True,
        min_dkim_bits=2048,
        forbid_dkim_testing=True,
    ),
    "relaxed": Baseline(
        key="relaxed",
        name="宽松监控基线",
        description="适合刚开始部署 DMARC 的域名，只要求记录存在且语法正确，便于分阶段上线。",
        require_spf=True,
        require_spf_hardfail=False,
        max_spf_lookups=10,
        allow_spf_ptr=True,
        require_dmarc=True,
        min_dmarc_policy="none",
        require_dmarc_pct_100=False,
        require_rua=False,
        require_dkim=False,
        min_dkim_bits=1024,
        forbid_dkim_testing=False,
    ),
}


def get_baseline(key: str) -> Baseline:
    if key not in BASELINES:
        raise KeyError(
            f"未知基线 {key!r}，可选值：{', '.join(BASELINES)}"
        )
    return BASELINES[key]
