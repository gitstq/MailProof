"""Scoring: turn a list of findings into a 0–100 score and letter grade."""

from __future__ import annotations

from typing import Dict, List

from .models import Finding, Severity

_PENALTY: Dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 3,
    Severity.MEDIUM.value: 7,
    Severity.HIGH.value: 15,
    Severity.CRITICAL.value: 30,
}


def compute_score(findings: List[Finding]) -> int:
    """Start at 100 and subtract weighted penalties, clamped to [0, 100]."""
    score = 100
    for f in findings:
        score -= _PENALTY.get(f.severity.value, 0)
    return max(0, min(100, score))


def score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    if score >= 40:
        return "E"
    return "F"


def grade_label(grade: str) -> str:
    return {
        "A": "优秀 / Excellent",
        "B": "良好 / Good",
        "C": "及格 / Fair",
        "D": "需改进 / Needs work",
        "E": "高风险 / High risk",
        "F": "严重不合格 / Critical",
    }.get(grade, grade)
