"""Tests for the rule engine, baselines and scoring."""

import unittest
from pathlib import Path

from mailproof.audit import audit_snapshot
from mailproof.models import DnsRecord, DomainSnapshot, Severity
from mailproof.presets import BASELINES, get_baseline
from mailproof.rules import catalog, run_rules
from mailproof.scoring import compute_score, grade_label, score_to_grade

_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _ids(result):
    return {f.rule_id for f in result.findings}


def _snap(*pairs):
    return DomainSnapshot(
        domain="example.com",
        records=[DnsRecord(n, v) for n, v in pairs],
    )


class TestRuleCatalog(unittest.TestCase):
    def test_ids_are_unique(self):
        ids = [r.rule_id for r in catalog()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_at_least_30_rules(self):
        self.assertGreaterEqual(len(catalog()), 30)

    def test_every_rule_has_reference_or_description(self):
        for r in catalog():
            self.assertTrue(r.title and r.description)


class TestScoring(unittest.TestCase):
    def test_penalty_is_monotonic(self):
        f = lambda s: [type("F", (), {"severity": Severity(s)})()]
        self.assertGreater(compute_score(f("low")), compute_score(f("high")))
        self.assertGreater(compute_score(f("high")), compute_score(f("critical")))

    def test_score_clamped(self):
        many = [type("F", (), {"severity": Severity("critical")})() for _ in range(50)]
        self.assertEqual(compute_score(many), 0)

    def test_grades(self):
        self.assertEqual(score_to_grade(100), "A")
        self.assertEqual(score_to_grade(85), "B")
        self.assertEqual(score_to_grade(0), "F")
        self.assertIn("优秀", grade_label("A"))


class TestEmptyDomain(unittest.TestCase):
    def setUp(self):
        self.result = audit_snapshot(_snap(), "default")

    def test_reports_missing_core_records(self):
        ids = _ids(self.result)
        self.assertIn("MP001", ids)  # no SPF
        self.assertIn("MP101", ids)  # no DMARC
        self.assertIn("MP201", ids)  # no DKIM
        self.assertIn("MP401", ids)  # baseline gaps

    def test_reports_transport_hints(self):
        ids = _ids(self.result)
        self.assertIn("MP305", ids)
        self.assertIn("MP306", ids)

    def test_low_score(self):
        self.assertLess(self.result.score, 40)
        self.assertEqual(self.result.grade, "F")


class TestCompliantDomain(unittest.TestCase):
    def setUp(self):
        from mailproof.bundle import load_snapshot
        snaps = load_snapshot(_EXAMPLES / "sample.zone")
        self.result = audit_snapshot(snaps[0], "strict")

    def test_perfect_score(self):
        self.assertEqual(self.result.score, 100)
        self.assertEqual(self.result.grade, "A")

    def test_no_findings(self):
        self.assertEqual(self.result.findings, [])


class TestSpecificRules(unittest.TestCase):
    def test_plus_all_is_critical(self):
        r = audit_snapshot(
            _snap(
                ("example.com", "v=spf1 +all"),
                ("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"),
                ("sel._domainkey.example.com", "v=DKIM1; p="),
            ),
            "default",
        )
        self.assertIn("MP005", _ids(r))
        self.assertIn("MP302", _ids(r))  # policy contradiction

    def test_multiple_spf_records(self):
        r = audit_snapshot(
            _snap(
                ("example.com", "v=spf1 -all"),
                ("example.com", "v=spf1 ~all"),
                ("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"),
            ),
            "default",
        )
        self.assertIn("MP002", _ids(r))

    def test_spf_lookup_limit(self):
        terms = " ".join(f"include:s{i}.example.com" for i in range(11))
        r = audit_snapshot(
            _snap(
                ("example.com", f"v=spf1 {terms} -all"),
                ("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"),
            ),
            "default",
        )
        self.assertIn("MP004", _ids(r))

    def test_include_loop_rule(self):
        r = audit_snapshot(
            _snap(
                ("example.com", "v=spf1 include:b.example -all"),
                ("b.example", "v=spf1 include:example.com -all"),
                ("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"),
            ),
            "default",
        )
        self.assertIn("MP008", _ids(r))

    def test_ptr_mechanism_flagged(self):
        r = audit_snapshot(
            _snap(
                ("example.com", "v=spf1 ptr -all"),
                ("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"),
            ),
            "default",
        )
        self.assertIn("MP007", _ids(r))

    def test_no_alignment_source(self):
        r = audit_snapshot(
            _snap(("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com")),
            "default",
        )
        self.assertIn("MP301", _ids(r))

    def test_sp_weaker_than_p(self):
        r = audit_snapshot(
            _snap(
                ("example.com", "v=spf1 -all"),
                ("_dmarc.example.com", "v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"),
            ),
            "default",
        )
        self.assertIn("MP107", _ids(r))

    def test_external_report_uri(self):
        r = audit_snapshot(
            _snap(
                ("example.com", "v=spf1 -all"),
                ("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@other.org"),
            ),
            "default",
        )
        self.assertIn("MP109", _ids(r))

    def test_relaxed_vs_strict_baseline(self):
        snap = _snap(
            ("example.com", "v=spf1 -all"),
            ("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:d@example.com"),
        )
        relaxed = audit_snapshot(snap, "relaxed")
        strict = audit_snapshot(snap, "strict")
        self.assertGreaterEqual(relaxed.score, strict.score)
        self.assertIn("MP104", _ids(strict))

    def test_revoked_dkim(self):
        r = audit_snapshot(
            _snap(
                ("example.com", "v=spf1 -all"),
                ("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"),
                ("old._domainkey.example.com", "v=DKIM1; p="),
            ),
            "default",
        )
        self.assertIn("MP203", _ids(r))


class TestBaselines(unittest.TestCase):
    def test_expected_keys(self):
        self.assertIn("google-yahoo-2024", BASELINES)
        self.assertIn("microsoft-2025", BASELINES)
        self.assertIn("strict", BASELINES)

    def test_unknown_key_raises(self):
        with self.assertRaises(KeyError):
            get_baseline("does-not-exist")


if __name__ == "__main__":
    unittest.main()
