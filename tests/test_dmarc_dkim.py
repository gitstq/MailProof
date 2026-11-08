"""Tests for DMARC and DKIM record parsers."""

import unittest
from pathlib import Path

from mailproof.bundle import _DEMO_RSA_1024
from mailproof.dkim import decode_key_bits, parse_dkim, rsa_modulus_bits
from mailproof.dmarc import parse_dmarc, policy_rank

_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _rsa2048_b64() -> str:
    text = (_EXAMPLES / "sample.zone").read_text(encoding="utf-8")
    for line in text.splitlines():
        if "p=" in line and "DKIM" in line:
            return line.split("p=", 1)[1].rstrip('"')
    raise RuntimeError("示例文件中缺少 DKIM 公钥")


class TestDMARC(unittest.TestCase):
    def test_valid_record(self):
        r = parse_dmarc("v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; pct=100")
        self.assertEqual(r.errors, [])
        self.assertEqual(r.policy, "reject")
        self.assertEqual(r.subdomain_policy, "reject")
        self.assertEqual(r.pct, 100)
        self.assertEqual(r.aggregate_uris, ["mailto:d@example.com"])

    def test_sp_inherits_p(self):
        r = parse_dmarc("v=DMARC1; p=quarantine")
        self.assertEqual(r.subdomain_policy, "quarantine")

    def test_missing_version(self):
        r = parse_dmarc("p=reject; rua=mailto:d@example.com")
        self.assertTrue(any("第一个标签" in e for e in r.errors))

    def test_bad_version(self):
        r = parse_dmarc("v=DMARC2; p=reject")
        self.assertTrue(any("DMARC1" in e for e in r.errors))

    def test_missing_p(self):
        r = parse_dmarc("v=DMARC1; rua=mailto:d@example.com")
        self.assertTrue(any("缺少必需的 p" in e for e in r.errors))

    def test_invalid_p(self):
        r = parse_dmarc("v=DMARC1; p=block")
        self.assertTrue(any("非法的 p" in e for e in r.errors))

    def test_pct_out_of_range(self):
        r = parse_dmarc("v=DMARC1; p=none; pct=150")
        self.assertTrue(any("0–100" in e for e in r.errors))

    def test_invalid_rua(self):
        r = parse_dmarc("v=DMARC1; p=none; rua=dmarc@example.com")
        self.assertTrue(any("rua" in e for e in r.errors))

    def test_duplicate_tag(self):
        r = parse_dmarc("v=DMARC1; p=none; p=reject")
        self.assertTrue(any("重复" in e for e in r.errors))

    def test_unknown_tag(self):
        r = parse_dmarc("v=DMARC1; p=none; wat=1")
        self.assertTrue(any("未知" in e for e in r.errors))

    def test_bad_alignment_value(self):
        r = parse_dmarc("v=DMARC1; p=none; adkim=x")
        self.assertTrue(any("adkim" in e for e in r.errors))

    def test_policy_rank(self):
        self.assertLess(policy_rank("none"), policy_rank("quarantine"))
        self.assertLess(policy_rank("quarantine"), policy_rank("reject"))

    def test_to_dict(self):
        import json
        json.dumps(parse_dmarc("v=DMARC1; p=none").to_dict())


class TestDKIM(unittest.TestCase):
    def test_rsa_1024_bits(self):
        r = parse_dkim(f"v=DKIM1; k=rsa; p={_DEMO_RSA_1024}", "sel1")
        self.assertEqual(r.errors, [])
        self.assertEqual(r.key_bits, 1024)

    def test_rsa_2048_bits(self):
        r = parse_dkim(f"v=DKIM1; k=rsa; p={_rsa2048_b64()}", "sel2026")
        self.assertEqual(r.errors, [])
        self.assertEqual(r.key_bits, 2048)

    def test_ed25519_bits(self):
        import base64
        raw = base64.b64encode(b"\x01" * 32).decode()
        r = parse_dkim(f"v=DKIM1; k=ed25519; p={raw}")
        self.assertEqual(r.errors, [])
        self.assertEqual(r.key_bits, 256)

    def test_revoked_key(self):
        r = parse_dkim("v=DKIM1; p=", "old")
        self.assertTrue(r.revoked)
        self.assertEqual(r.errors, [])

    def test_testing_flag(self):
        r = parse_dkim(f"v=DKIM1; t=y; p={_DEMO_RSA_1024}")
        self.assertTrue(r.testing)

    def test_conflicting_t_flags(self):
        r = parse_dkim(f"v=DKIM1; t=y:s; p={_DEMO_RSA_1024}")
        self.assertTrue(any("冲突" in e for e in r.errors))

    def test_invalid_base64(self):
        r = parse_dkim("v=DKIM1; p=!!!not-base64!!!")
        self.assertFalse(r.valid)
        self.assertTrue(any("base64" in e for e in r.errors))

    def test_missing_p(self):
        r = parse_dkim("v=DKIM1; k=rsa")
        self.assertTrue(any("缺少必需的 p" in e for e in r.errors))

    def test_der_reader_on_garbage(self):
        with self.assertRaises(ValueError):
            rsa_modulus_bits(b"\x00\x01\x02")

    def test_decode_key_bits_invalid(self):
        self.assertIsNone(decode_key_bits("###", "rsa"))


if __name__ == "__main__":
    unittest.main()
