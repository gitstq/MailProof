"""Tests for snapshot loading, report rendering and the CLI."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from mailproof.audit import audit_file, audit_snapshots
from mailproof.bundle import (
    DEMO_SNAPSHOT,
    load_snapshot,
    parse_json_snapshot,
    parse_zone_snapshot,
)
from mailproof.cli import main
from mailproof.report import FORMATS, render
from mailproof.simulate import simulate

_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLES = _ROOT / "examples"


class TestSnapshotLoading(unittest.TestCase):
    def test_zone_file(self):
        snaps = load_snapshot(_EXAMPLES / "sample.zone")
        self.assertEqual(len(snaps), 1)
        self.assertEqual(snaps[0].domain, "example.com")
        self.assertEqual(len(snaps[0].records), 5)

    def test_json_file(self):
        snaps = load_snapshot(_EXAMPLES / "sample-records.json")
        self.assertEqual(len(snaps), 1)
        self.assertEqual(len(snaps[0].records), 5)

    def test_zone_and_json_agree(self):
        a = audit_file(str(_EXAMPLES / "sample.zone"), "strict").results[0]
        b = audit_file(str(_EXAMPLES / "sample-records.json"), "strict").results[0]
        self.assertEqual(a.score, b.score)
        self.assertEqual(_ids(a), _ids(b))

    def test_key_value_lines(self):
        snaps = parse_zone_snapshot(
            "example.com = v=spf1 -all\n"
            "_dmarc.example.com = v=DMARC1; p=reject; rua=mailto:d@example.com\n"
        )
        self.assertEqual(len(snaps), 1)
        self.assertEqual(snaps[0].domain, "example.com")

    def test_multi_domain_json(self):
        data = {
            "a.example": [{"name": "a.example", "value": "v=spf1 -all"}],
            "b.example": [{"name": "b.example", "value": "v=spf1 -all"}],
        }
        snaps = parse_json_snapshot(data)
        self.assertEqual({s.domain for s in snaps}, {"a.example", "b.example"})

    def test_quoted_txt_chunks(self):
        snaps = parse_zone_snapshot(
            'example.com. IN TXT "v=spf1" " -all"\n'
        )
        self.assertEqual(snaps[0].records[0].normalized_value, "v=spf1 -all")

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            load_snapshot("/definitely/not/here.zone")

    def test_invalid_zone_raises(self):
        with self.assertRaises(ValueError):
            parse_zone_snapshot("; 只有注释\n")

    def test_demo_snapshot_parses(self):
        snaps = parse_zone_snapshot(DEMO_SNAPSHOT)
        self.assertEqual(snaps[0].domain, "example.com")
        self.assertEqual(len(snaps[0].records), 3)


def _ids(result):
    return {f.rule_id for f in result.findings}


class TestReports(unittest.TestCase):
    def setUp(self):
        self.bundle = audit_file(str(_EXAMPLES / "sample.zone"), "strict")

    def test_all_formats_render(self):
        for fmt in FORMATS:
            out = render(self.bundle, fmt)
            self.assertIsInstance(out, str)
            self.assertGreater(len(out), 20)

    def test_invalid_format_raises(self):
        with self.assertRaises(ValueError):
            render(self.bundle, "pdf")

    def test_json_structure(self):
        d = json.loads(render(self.bundle, "json"))
        self.assertEqual(d["tool"], "MailProof")
        self.assertEqual(d["domain_count"], 1)
        self.assertEqual(d["results"][0]["score"], 100)

    def test_sarif_structure(self):
        s = json.loads(render(self.bundle, "sarif"))
        self.assertEqual(s["version"], "2.1.0")
        self.assertGreater(len(s["runs"][0]["tool"]["driver"]["rules"]), 30)
        self.assertEqual(s["runs"][0]["results"], [])

    def test_html_escapes_domain(self):
        from mailproof.models import DomainSnapshot, DnsRecord
        evil = DomainSnapshot("evil.example", [DnsRecord("evil.example", "v=spf1 -all")])
        bundle = audit_snapshots([DomainSnapshot("<script>x</script>", [])])
        out = render(bundle, "html")
        self.assertNotIn("<script>x</script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_markdown_contains_table(self):
        out = render(self.bundle, "markdown")
        self.assertIn("| 域名 |", out)
        self.assertIn("MailProof", out)


class TestSimulation(unittest.TestCase):
    def test_compliant_domain_has_two_paths(self):
        snaps = load_snapshot(_EXAMPLES / "sample.zone")
        sim = simulate(snaps[0], "reject", "strict")
        self.assertEqual(sim["alignment"]["available_paths"], 2)
        self.assertEqual(sim["blockers"], [])
        self.assertEqual(sim["risk"], "low")

    def test_demo_domain_has_blockers(self):
        snaps = parse_zone_snapshot(DEMO_SNAPSHOT)
        sim = simulate(snaps[0], "reject", "default")
        self.assertIn("risk", sim)
        self.assertEqual(len(sim["roadmap"]), 4)

    def test_unknown_policy_raises(self):
        with self.assertRaises(ValueError):
            simulate(parse_zone_snapshot(DEMO_SNAPSHOT)[0], "block")

    def test_roadmap_trimmed_for_quarantine(self):
        sim = simulate(parse_zone_snapshot(DEMO_SNAPSHOT)[0], "quarantine")
        self.assertTrue(all(s["policy"] != "reject" for s in sim["roadmap"]))


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_version(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_rules_command(self):
        code, out, _ = self._run(["rules", "--format", "csv"])
        self.assertEqual(code, 0)
        self.assertIn("rule_id,severity", out)
        self.assertGreater(len(out.splitlines()), 30)

    def test_rules_json(self):
        code, out, _ = self._run(["rules", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertIsInstance(json.loads(out), list)

    def test_baselines(self):
        code, out, _ = self._run(["baselines"])
        self.assertEqual(code, 0)
        self.assertIn("google-yahoo-2024", out)

    def test_demo_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "demo.zone"
            code, _, _ = self._run(["demo", "-o", str(p)])
            self.assertEqual(code, 0)
            self.assertTrue(p.exists())
            self.assertIn("v=spf1", p.read_text(encoding="utf-8"))

    def test_audit_all_formats(self):
        for fmt in FORMATS:
            code, out, _ = self._run(
                ["audit", "--demo", "--format", fmt, "--quiet"]
            )
            self.assertEqual(code, 0, fmt)

    def test_audit_file_and_domain_filter(self):
        code, out, _ = self._run(
            ["audit", str(_EXAMPLES / "sample.zone"), "--baseline", "strict", "--quiet"]
        )
        self.assertEqual(code, 0)
        self.assertIn("100/100", out)

    def test_ci_gate_fails_on_high(self):
        code, _, _ = self._run(
            ["audit", "--demo", "--format", "json", "--fail-on", "high", "--quiet"]
        )
        self.assertEqual(code, 1)

    def test_ci_gate_passes_on_critical(self):
        code, _, _ = self._run(
            ["audit", "--demo", "--format", "json", "--fail-on", "critical", "--quiet"]
        )
        self.assertEqual(code, 0)

    def test_parse_subcommand(self):
        code, out, _ = self._run(["parse", "--spf", "v=spf1 -all"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["spf"]["version"], "spf1")

    def test_parse_without_args_fails(self):
        code, _, _ = self._run(["parse"])
        self.assertEqual(code, 2)

    def test_simulate_subcommand(self):
        code, out, _ = self._run(["simulate", "--demo", "--policy", "quarantine"])
        self.assertEqual(code, 0)
        self.assertIn("分阶段上线路线", out)

    def test_simulate_json(self):
        code, out, _ = self._run(["simulate", "--demo", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertIn("roadmap", json.loads(out))

    def test_missing_file_returns_error(self):
        code, _, err = self._run(["audit", "/no/such/file.zone"])
        self.assertEqual(code, 2)
        self.assertIn("读取快照失败", err)

    def test_bad_baseline_is_rejected(self):
        with self.assertRaises(SystemExit):
            self._run(["audit", "--demo", "--baseline", "nope"])


if __name__ == "__main__":
    unittest.main()
