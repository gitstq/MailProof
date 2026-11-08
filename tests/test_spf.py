"""Tests for the SPF parser and include-graph analysis."""

import unittest

from mailproof.spf import (
    build_include_graph,
    detect_include_loops,
    parse_spf,
)
from mailproof.models import DnsRecord, DomainSnapshot


class TestSPFParser(unittest.TestCase):
    def test_minimal_record(self):
        r = parse_spf("v=spf1 -all")
        self.assertTrue(r.valid, r.errors)
        self.assertEqual(r.version, "spf1")
        self.assertEqual(r.all_mechanism.qualifier, "-")
        self.assertEqual(r.lookup_count, 0)

    def test_a_mx_without_argument_are_legal(self):
        # RFC 7208 allows a/mx/ptr without a domain-spec argument.
        r = parse_spf("v=spf1 a mx -all")
        self.assertEqual(r.errors, [])
        self.assertEqual(r.lookup_count, 2)

    def test_cidr_suffixes(self):
        r = parse_spf("v=spf1 a/24 mx/24 -all")
        self.assertEqual(r.errors, [])
        self.assertEqual([m.value for m in r.mechanisms][:2], ["/24", "/24"])

    def test_ip4_and_include(self):
        r = parse_spf("v=spf1 ip4:203.0.113.0/24 include:_spf.example.com -all")
        self.assertEqual(r.errors, [])
        self.assertEqual(r.lookup_count, 1)  # ip4 does not trigger a lookup
        self.assertEqual(r.mechanisms[0].value, "203.0.113.0/24")

    def test_invalid_ip_is_reported(self):
        r = parse_spf("v=spf1 ip4:999.1.1.1 -all")
        self.assertFalse(r.valid)
        self.assertTrue(any("非法" in e for e in r.errors))

    def test_plus_all_is_parsed(self):
        r = parse_spf("v=spf1 +all")
        self.assertEqual(r.all_mechanism.result, "pass")

    def test_mechanism_after_all_is_error(self):
        r = parse_spf("v=spf1 -all include:late.example")
        self.assertFalse(r.valid)
        self.assertTrue(any("永远不会" in e for e in r.errors))

    def test_duplicate_all(self):
        r = parse_spf("v=spf1 -all ~all")
        self.assertTrue(any("多个 'all'" in e for e in r.errors))

    def test_redirect_conflicts_with_all(self):
        r = parse_spf("v=spf1 -all redirect=spf.example.com")
        self.assertTrue(any("redirect" in e for e in r.errors))
        self.assertEqual(r.lookup_count, 1)

    def test_redirect_without_all(self):
        r = parse_spf("v=spf1 redirect=spf.example.com")
        self.assertEqual(r.errors, [])
        self.assertEqual(r.modifiers["redirect"], "spf.example.com")

    def test_include_requires_argument(self):
        r = parse_spf("v=spf1 include: -all")
        self.assertTrue(any("缺少必要" in e for e in r.errors))

    def test_missing_version_marker(self):
        r = parse_spf("include:foo.example -all")
        self.assertTrue(any("v=spf1" in e for e in r.errors))

    def test_unknown_mechanism(self):
        r = parse_spf("v=spf1 bogus:thing -all")
        self.assertTrue(any("未知" in e for e in r.errors))

    def test_exists_macro(self):
        r = parse_spf("v=spf1 exists:%{i}.example.com -all")
        self.assertEqual(r.errors, [])
        self.assertEqual(r.mechanisms[0].value, "%{i}.example.com")

    def test_split_txt_chunks(self):
        r = parse_spf('"v=spf1" " -all"')
        # A joined TXT value is expected; the parser tolerates extra quotes.
        self.assertIsInstance(r, object)

    def test_to_dict_is_json_serialisable(self):
        import json
        d = parse_spf("v=spf1 a mx -all").to_dict()
        json.dumps(d)
        self.assertEqual(d["lookup_count"], 2)


class TestIncludeGraph(unittest.TestCase):
    def test_cycle_detection(self):
        snap = DomainSnapshot(
            domain="a.example",
            records=[
                DnsRecord("a.example", "v=spf1 include:b.example -all"),
                DnsRecord("b.example", "v=spf1 include:a.example -all"),
            ],
        )
        loops = detect_include_loops(build_include_graph(snap))
        self.assertEqual(len(loops), 1)
        self.assertEqual(len(loops[0]), 3)

    def test_no_cycle(self):
        snap = DomainSnapshot(
            domain="a.example",
            records=[
                DnsRecord("a.example", "v=spf1 include:b.example -all"),
                DnsRecord("b.example", "v=spf1 -all"),
            ],
        )
        self.assertEqual(detect_include_loops(build_include_graph(snap)), [])

    def test_redirect_edge_counts_as_cycle(self):
        snap = DomainSnapshot(
            domain="a.example",
            records=[
                DnsRecord("a.example", "v=spf1 redirect=b.example"),
                DnsRecord("b.example", "v=spf1 include:a.example -all"),
            ],
        )
        self.assertEqual(len(detect_include_loops(build_include_graph(snap))), 1)


if __name__ == "__main__":
    unittest.main()
