"""DKIM (RFC 6376) public-key record parser.

Includes a small, dependency-free ASN.1/DER reader that recovers the RSA
modulus size from a base64-encoded SubjectPublicKeyInfo blob. That lets
MailProof flag weak 1024-bit keys without pulling in ``cryptography``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .models import DomainSnapshot

_KNOWN_TAGS = {"v", "k", "p", "t", "s", "h", "n", "g"}
_KEY_TYPES = {"rsa", "ed25519"}


@dataclass
class DKIMRecord:
    """Parsed representation of one DKIM TXT record."""

    raw: str
    selector: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    key_bits: Optional[int] = None
    errors: List[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def revoked(self) -> bool:
        return self.tags.get("p", None) == ""

    @property
    def key_type(self) -> str:
        return self.tags.get("k", "rsa").lower()

    @property
    def testing(self) -> bool:
        return "y" in self.tags.get("t", "").lower().split(":")

    def to_dict(self) -> Dict[str, object]:
        return {
            "raw": self.raw,
            "selector": self.selector,
            "tags": dict(self.tags),
            "key_bits": self.key_bits,
            "revoked": self.revoked,
            "testing": self.testing,
            "errors": list(self.errors),
        }


def _read_der_length(data: bytes, pos: int) -> Tuple[int, int]:
    """Return (length, new_pos) for a DER length field."""
    if pos >= len(data):
        raise ValueError("DER 长度字段越界")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7F
    if n == 0 or n > 4 or pos + n > len(data):
        raise ValueError("非法的 DER 长格式长度")
    length = int.from_bytes(data[pos : pos + n], "big")
    return length, pos + n


def _read_der_tlv(data: bytes, pos: int) -> Tuple[int, bytes, int]:
    """Read one DER TLV. Returns (tag, value_bytes, new_pos)."""
    if pos + 2 > len(data):
        raise ValueError("DER TLV 越界")
    tag = data[pos]
    length, pos = _read_der_length(data, pos + 1)
    end = pos + length
    if end > len(data):
        raise ValueError("DER TLV 内容越界")
    return tag, data[pos:end], end


def rsa_modulus_bits(der: bytes) -> int:
    """Extract RSA modulus bit length from a DER SubjectPublicKeyInfo blob."""
    tag, spki, _ = _read_der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("SubjectPublicKeyInfo 不是 SEQUENCE")
    # AlgorithmIdentifier SEQUENCE
    _, _, pos = _read_der_tlv(spki, 0)
    # BIT STRING holding the RSAPublicKey DER
    tag, bitstring, _ = _read_der_tlv(spki, pos)
    if tag != 0x03:
        raise ValueError("缺少 subjectPublicKey BIT STRING")
    if not bitstring:
        raise ValueError("BIT STRING 为空")
    pk_der = bitstring[1:]  # skip "unused bits" octet
    tag, pk, _ = _read_der_tlv(pk_der, 0)
    if tag != 0x30:
        raise ValueError("RSAPublicKey 不是 SEQUENCE")
    tag, modulus, _ = _read_der_tlv(pk, 0)
    if tag != 0x02:
        raise ValueError("缺少 RSA modulus INTEGER")
    # Strip leading sign byte and count significant bits.
    i = 0
    while i < len(modulus) and modulus[i] == 0:
        i += 1
    if i >= len(modulus):
        return 0
    significant = modulus[i:]
    return (len(significant) - 1) * 8 + significant[0].bit_length()


def decode_key_bits(p_value: str, key_type: str) -> Optional[int]:
    """Best-effort key size detection. Returns ``None`` when undeterminable."""
    if not p_value:
        return None
    try:
        der = base64.b64decode(p_value, validate=True)
    except Exception:
        return None
    if key_type == "ed25519":
        return 256 if len(der) >= 32 else None
    try:
        return rsa_modulus_bits(der)
    except Exception:
        return None


def parse_dkim(value: str, selector: str = "") -> DKIMRecord:
    """Parse one DKIM TXT record string (never raises)."""
    raw = " ".join(value.strip().split())
    rec = DKIMRecord(raw=raw, selector=selector)
    if not raw:
        rec.errors.append("DKIM 记录为空")
        return rec

    # An empty p= is a legal revocation marker; keep it distinguishable.
    for part in [p.strip() for p in raw.split(";") if p.strip()]:
        if "=" not in part:
            rec.errors.append(f"非法标签（缺少 '='）：{part!r}")
            continue
        key, val = part.split("=", 1)
        key, val = key.strip().lower(), val.strip()
        if key in rec.tags:
            rec.errors.append(f"标签 {key!r} 重复出现")
            continue
        if key not in _KNOWN_TAGS:
            rec.errors.append(f"未知 DKIM 标签：{key!r}")
        rec.tags[key] = val

    _validate_semantics(rec)
    return rec


def _validate_semantics(rec: DKIMRecord) -> None:
    t = rec.tags
    if "v" in t and t["v"].upper() != "DKIM1":
        rec.errors.append(f"v 标签值应为 DKIM1，实际为 {t['v']!r}")
    if "k" in t and t["k"].lower() not in _KEY_TYPES:
        rec.errors.append(f"未知的密钥类型 k={t['k']!r}")

    if "p" not in t:
        rec.errors.append("缺少必需的 p（公钥）标签")
    elif t["p"] == "":
        pass  # explicit key revocation, legal per RFC 6376
    else:
        rec.key_bits = decode_key_bits(t["p"], rec.key_type)
        if rec.key_bits is None:
            rec.errors.append("p 标签不是合法的 base64 DER 公钥，无法解析密钥长度")

    if "t" in t:
        flags = [f.strip().lower() for f in t["t"].split(":") if f.strip()]
        unknown = [f for f in flags if f not in {"y", "s"}]
        if unknown:
            rec.errors.append(f"t 标签含未知标志：{unknown}")
        if "y" in flags and "s" in flags:
            rec.errors.append("t 标签中 y 与 s 同时出现，语义冲突")

    if "s" in t and not all(x.strip() in {"*", "email"} for x in t["s"].split(":")):
        rec.errors.append(f"s 服务类型标签值异常：{t['s']!r}")


def collect_dkim(snapshot: DomainSnapshot) -> List[DKIMRecord]:
    """Find DKIM records anywhere in the snapshot.

    Recognises the conventional ``<selector>._domainkey.<domain>`` owner name
    and also any TXT record whose value carries DKIM tags.
    """
    out: List[DKIMRecord] = []
    seen = set()
    for r in snapshot.all_txt():
        name = r.name.rstrip(".").lower()
        v = r.normalized_value
        is_dkim_name = "._domainkey." in name or name.endswith("._domainkey")
        has_dkim_tags = "p=" in v and ("v=dkim1" in v.lower() or "k=" in v.lower())
        if not (is_dkim_name or has_dkim_tags):
            continue
        key = (name, v)
        if key in seen:
            continue
        seen.add(key)
        selector = name.split("._domainkey.")[0] if "._domainkey." in name else name
        out.append(parse_dkim(v, selector=selector))
    return out
