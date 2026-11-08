"""Core data models for MailProof.

All types in this module are plain standard-library dataclasses so that the
library stays dependency-free and can be imported in constrained CI runners.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Ordered severity levels used by the rule engine."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.value


_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class DnsRecord:
    """One DNS TXT record from an offline snapshot."""

    name: str
    value: str
    rtype: str = "TXT"
    ttl: Optional[int] = None

    @property
    def normalized_value(self) -> str:
        # TXT records may be split into multiple quoted chunks; join them.
        return " ".join(self.value.strip().split())


@dataclass
class DomainSnapshot:
    """All records belonging to one domain (or one delegated subdomain)."""

    domain: str
    records: List[DnsRecord] = field(default_factory=list)

    def txt_values(self, name: Optional[str] = None) -> List[str]:
        target = (name or self.domain).rstrip(".").lower()
        out: List[str] = []
        for rec in self.records:
            if rec.rtype.upper() != "TXT":
                continue
            if rec.name.rstrip(".").lower() == target:
                out.append(rec.normalized_value)
        return out

    def all_txt(self) -> List[DnsRecord]:
        return [r for r in self.records if r.rtype.upper() == "TXT"]


@dataclass(frozen=True)
class Finding:
    """A single audit result produced by a rule."""

    rule_id: str
    title: str
    severity: Severity
    message: str
    recommendation: str = ""
    reference: str = ""
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "message": self.message,
            "recommendation": self.recommendation,
            "reference": self.reference,
            "context": self.context,
        }


@dataclass
class Rule:
    """Metadata for a registered audit rule."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    reference: str = ""


@dataclass
class AuditResult:
    """Aggregated result for one domain snapshot."""

    domain: str
    findings: List[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    parsed: Dict[str, Any] = field(default_factory=dict)
    baseline: str = "default"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.rank).severity

    def count_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "score": self.score,
            "grade": self.grade,
            "baseline": self.baseline,
            "summary": self.count_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
            "parsed": self.parsed,
            "metadata": self.metadata,
        }


@dataclass
class AuditBundle:
    """Collection of domain results produced by one CLI run."""

    results: List[AuditResult] = field(default_factory=list)
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        from . import __version__  # local import avoids a circular dependency

        return {
            "tool": "MailProof",
            "version": __version__,
            "source": self.source,
            "domain_count": len(self.results),
            "results": [r.to_dict() for r in self.results],
        }


