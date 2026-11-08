"""MailProof — offline-first mail domain authentication auditor.

Zero runtime dependencies. Pure standard library. Never touches the network.

Quick start (library)::

    from mailproof import audit_file, render
    bundle = audit_file("records.zone", baseline_key="microsoft-2025")
    print(render(bundle, "markdown"))
"""

__version__ = "1.0.0"

from .models import (
    AuditBundle,
    AuditResult,
    DnsRecord,
    DomainSnapshot,
    Finding,
    Rule,
    Severity,
)
from .bundle import DEMO_SNAPSHOT, load_snapshot, parse_json_snapshot, parse_zone_snapshot
from .spf import Mechanism, SPFRecord, build_include_graph, detect_include_loops, parse_spf
from .dmarc import DMARCRecord, parse_dmarc
from .dkim import DKIMRecord, parse_dkim, rsa_modulus_bits
from .presets import BASELINES, Baseline, get_baseline
from .rules import AuditContext, catalog, run_rules
from .scoring import compute_score, grade_label, score_to_grade
from .audit import audit_file, audit_snapshot, audit_snapshots
from .report import FORMATS, render
from .simulate import simulate

__all__ = [
    "__version__",
    # models
    "AuditBundle", "AuditResult", "DnsRecord", "DomainSnapshot", "Finding",
    "Rule", "Severity",
    # parsing
    "DEMO_SNAPSHOT", "load_snapshot", "parse_json_snapshot", "parse_zone_snapshot",
    "parse_spf", "SPFRecord", "Mechanism", "build_include_graph", "detect_include_loops",
    "parse_dmarc", "DMARCRecord",
    "parse_dkim", "DKIMRecord", "rsa_modulus_bits",
    # engine
    "BASELINES", "Baseline", "get_baseline", "AuditContext", "catalog", "run_rules",
    "compute_score", "score_to_grade", "grade_label",
    # high level
    "audit_snapshot", "audit_file", "audit_snapshots", "FORMATS", "render", "simulate",
]
