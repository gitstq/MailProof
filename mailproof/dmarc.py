"""DMARC (RFC 7489) record parser and semantic validator."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import DomainSnapshot

_POLICIES = {"none", "quarantine", "reject"}
_ALIGNMENTS = {"r", "s"}
_KNOWN_TAGS = {
    "v", "p", "sp", "rua", "ruf", "pct", "adkim", "aspf",
    "fo", "ri", "rf", "np",
}
_URI_RE = re.compile(r"^mailto:[^\s,]+@[^\s,]+\.[^\s,]+$", re.IGNORECASE)


@dataclass
class DMARCRecord:
    """Parsed representation of one DMARC TXT record."""

    raw: str
    tags: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def policy(self) -> str:
        return self.tags.get("p", "").lower()

    @property
    def subdomain_policy(self) -> str:
        return self.tags.get("sp", self.policy).lower()

    @property
    def pct(self) -> int:
        try:
            return int(self.tags.get("pct", "100"))
        except ValueError:
            return 100

    @property
    def aggregate_uris(self) -> List[str]:
        return [u.strip() for u in self.tags.get("rua", "").split(",") if u.strip()]

    @property
    def forensic_uris(self) -> List[str]:
        return [u.strip() for u in self.tags.get("ruf", "").split(",") if u.strip()]

    def to_dict(self) -> Dict[str, object]:
        return {
            "raw": self.raw,
            "tags": dict(self.tags),
            "errors": list(self.errors),
            "effective": {
                "policy": self.policy,
                "subdomain_policy": self.subdomain_policy,
                "pct": self.pct,
                "adkim": self.tags.get("adkim", "r"),
                "aspf": self.tags.get("aspf", "r"),
            },
        }


def parse_dmarc(value: str) -> DMARCRecord:
    """Parse a DMARC TXT string into tags + errors (never raises)."""
    raw = " ".join(value.strip().split())
    rec = DMARCRecord(raw=raw)
    if not raw:
        rec.errors.append("DMARC 记录为空")
        return rec

    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        rec.errors.append("DMARC 记录不含任何标签")
        return rec

    first_key = parts[0].split("=", 1)[0].strip().lower()
    if first_key != "v":
        rec.errors.append("DMARC 记录的第一个标签必须是 v=DMARC1")

    for part in parts:
        if "=" not in part:
            rec.errors.append(f"非法标签（缺少 '='）：{part!r}")
            continue
        key, val = part.split("=", 1)
        key, val = key.strip().lower(), val.strip()
        if not key:
            rec.errors.append(f"标签名为空：{part!r}")
            continue
        if key in rec.tags:
            rec.errors.append(f"标签 {key!r} 重复出现")
            continue
        if key not in _KNOWN_TAGS:
            rec.errors.append(f"未知 DMARC 标签：{key!r}")
        rec.tags[key] = val

    _validate_semantics(rec)
    return rec


def _validate_semantics(rec: DMARCRecord) -> None:
    t = rec.tags
    if t.get("v", "").upper() != "DMARC1":
        rec.errors.append("v 标签值必须为 DMARC1")

    if "p" not in t:
        rec.errors.append("缺少必需的 p（策略）标签")
    elif t["p"].lower() not in _POLICIES:
        rec.errors.append(f"非法的 p 策略值：{t['p']!r}（应为 none/quarantine/reject）")

    if "sp" in t and t["sp"].lower() not in _POLICIES:
        rec.errors.append(f"非法的 sp 子域策略值：{t['sp']!r}")

    if "pct" in t:
        try:
            n = int(t["pct"])
            if not 0 <= n <= 100:
                rec.errors.append("pct 必须在 0–100 之间")
        except ValueError:
            rec.errors.append(f"pct 不是整数：{t['pct']!r}")

    for tag in ("adkim", "aspf"):
        if tag in t and t[tag].lower() not in _ALIGNMENTS:
            rec.errors.append(f"{tag} 必须为 r（宽松）或 s（严格）")

    if "fo" in t and not re.fullmatch(r"[01ds:]+", t["fo"]):
        rec.errors.append(f"fo 标签值非法：{t['fo']!r}")

    if "ri" in t:
        try:
            if int(t["ri"]) < 0:
                rec.errors.append("ri 不能为负数")
        except ValueError:
            rec.errors.append(f"ri 不是整数：{t['ri']!r}")

    if "rf" in t and t["rf"].lower() not in {"afrf", "iodef"}:
        rec.errors.append(f"rf 报告格式非法：{t['rf']!r}")

    for tag in ("rua", "ruf"):
        for uri in [u.strip() for u in t.get(tag, "").split(",") if u.strip()]:
            if not _URI_RE.match(uri):
                rec.errors.append(f"{tag} 中的报告地址格式非法：{uri!r}（应为 mailto:user@domain）")


def collect_dmarc(snapshot: DomainSnapshot, domain: Optional[str] = None) -> List[DMARCRecord]:
    """Return all DMARC records published at ``_dmarc.<domain>``."""
    d = (domain or snapshot.domain).rstrip(".")
    name = f"_dmarc.{d}"
    return [
        parse_dmarc(v)
        for v in snapshot.txt_values(name)
        if v.lower().startswith("v=dmarc1") or "v=dmarc1" in v.lower()
    ]


def policy_rank(policy: str) -> int:
    return {"none": 0, "quarantine": 1, "reject": 2}.get(policy.lower(), -1)
