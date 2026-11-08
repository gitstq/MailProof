"""Top-level audit pipeline: parse -> correlate -> run rules -> score."""

from __future__ import annotations

from typing import Dict, List

from . import __version__
from .bundle import load_snapshot
from .dkim import collect_dkim
from .dmarc import collect_dmarc
from .models import AuditBundle, AuditResult, DomainSnapshot
from .presets import get_baseline
from .rules import AuditContext, run_rules
from .scoring import compute_score, grade_label, score_to_grade
from .spf import build_include_graph, collect_spf, detect_include_loops


def audit_snapshot(snapshot: DomainSnapshot, baseline_key: str = "default") -> AuditResult:
    """Run the full offline audit for one domain snapshot."""
    baseline = get_baseline(baseline_key)

    spf_records = collect_spf(snapshot)
    dmarc_records = collect_dmarc(snapshot)
    dkim_records = collect_dkim(snapshot)
    graph = build_include_graph(snapshot)
    loops = detect_include_loops(graph)

    ctx = AuditContext(
        snapshot=snapshot,
        spf=spf_records,
        dmarc=dmarc_records,
        dkim=dkim_records,
        baseline=baseline,
        include_loops=loops,
    )
    findings = run_rules(ctx)
    score = compute_score(findings)
    grade = score_to_grade(score)

    parsed: Dict[str, object] = {
        "spf": [r.to_dict() for r in spf_records],
        "dmarc": [r.to_dict() for r in dmarc_records],
        "dkim": [r.to_dict() for r in dkim_records],
        "include_loop_chains": [" -> ".join(c) for c in loops],
    }
    return AuditResult(
        domain=snapshot.domain,
        findings=findings,
        score=score,
        grade=grade,
        parsed=parsed,
        baseline=baseline_key,
        metadata={
            "record_count": len(snapshot.records),
            "spf_count": len(spf_records),
            "dmarc_count": len(dmarc_records),
            "dkim_count": len(dkim_records),
            "grade_label": grade_label(grade),
            "baseline_name": baseline.name,
            "version": __version__,
        },
    )


def audit_file(path: str, baseline_key: str = "default") -> AuditBundle:
    """Load a snapshot file and audit every domain it contains."""
    snapshots = load_snapshot(path)
    results = [audit_snapshot(s, baseline_key) for s in snapshots]
    return AuditBundle(results=results, source=str(path))


def audit_snapshots(
    snapshots: List[DomainSnapshot], baseline_key: str = "default", source: str = ""
) -> AuditBundle:
    """Audit an in-memory list of domain snapshots."""
    results = [audit_snapshot(s, baseline_key) for s in snapshots]
    return AuditBundle(results=results, source=source)
