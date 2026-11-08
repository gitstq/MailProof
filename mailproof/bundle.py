"""Load offline DNS snapshots from JSON, BIND-style zone text, or key=value.

MailProof never queries the network. A "snapshot" is simply a set of TXT
records you already exported (dig, nslookup, Route53 export, Terraform state,
...). Three input shapes are supported and auto-detected.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Union

from .models import DnsRecord, DomainSnapshot

_ZONE_RE = re.compile(
    r"^\s*(\S+)\s+(?:\d+\s+)?(?:IN\s+)?(?:TXT|SPF)\s+(.+?)\s*$",
    re.IGNORECASE,
)
_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_KV_RE = re.compile(r"^\s*([^\s=]+)\s*=\s*(.+?)\s*$")


def _unquote_zone_value(raw: str) -> str:
    chunks = _QUOTED_RE.findall(raw)
    if chunks:
        return "".join(c.replace('\\"', '"') for c in chunks)
    return raw.strip().strip('"')


def _guess_domain(records: List[DnsRecord]) -> str:
    """Pick the shortest TXT owner name as the apex domain."""
    names = [r.name.rstrip(".").lower() for r in records]
    if not names:
        return "unknown"
    for n in sorted(names, key=len):
        if all(x == n or x.endswith("." + n) for x in names):
            if not n.startswith("_") and "._domainkey" not in n:
                return n
    return min(names, key=len)


def _records_from_list(items: List[dict], default_name: str) -> List[DnsRecord]:
    out: List[DnsRecord] = []
    for item in items:
        if isinstance(item, str):
            out.append(DnsRecord(name=default_name, value=item, rtype="TXT"))
            continue
        if not isinstance(item, dict):
            continue
        out.append(
            DnsRecord(
                name=str(item.get("name") or item.get("host") or default_name),
                value=str(item.get("value") or item.get("text") or item.get("txt") or ""),
                rtype=str(item.get("type") or item.get("rtype") or "TXT"),
                ttl=item.get("ttl"),
            )
        )
    return out


def parse_json_snapshot(data: Union[dict, list]) -> List[DomainSnapshot]:
    """Parse a JSON snapshot into domain snapshots."""
    snapshots: List[DomainSnapshot] = []

    if isinstance(data, list):
        entries: List[tuple] = [(None, x) for x in data]
    elif isinstance(data, dict) and "domains" in data:
        entries = [
            (d.get("domain"), d.get("records", []))
            for d in data["domains"]
            if isinstance(d, dict)
        ]
    elif isinstance(data, dict):
        entries = list(data.items())
    else:
        raise ValueError("无法识别的 JSON 快照结构")

    for domain, value in entries:
        if isinstance(value, dict):
            domain = value.get("domain", domain)
            value = value.get("records", [])
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            raise ValueError(f"域名 {domain!r} 的记录必须是数组")
        recs = _records_from_list(value, str(domain or "unknown"))
        d = str(domain or _guess_domain(recs))
        snapshots.append(DomainSnapshot(domain=d, records=recs))
    return snapshots


def parse_zone_snapshot(text: str) -> List[DomainSnapshot]:
    """Parse BIND-style zone lines (and simple ``name=value`` lines)."""
    by_domain: Dict[str, List[DnsRecord]] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(";") or s.startswith("#") or s.startswith("$") or s.startswith("//"):
            continue
        m = _ZONE_RE.match(s)
        if m:
            name, val = m.group(1), _unquote_zone_value(m.group(2))
        else:
            kv = _KV_RE.match(s)
            if not kv:
                continue
            name, val = kv.group(1), kv.group(2).strip().strip('"')
        if not val:
            continue
        rec = DnsRecord(name=name.rstrip("."), value=val, rtype="TXT")
        lower = rec.name.lower()
        apex = lower
        for prefix in ("_dmarc.", "_mta-sts.", "_smtp._tls."):
            if lower.startswith(prefix):
                apex = lower[len(prefix) :]
                break
        if "._domainkey." in lower:
            apex = lower.split("._domainkey.", 1)[1]
        by_domain.setdefault(apex, []).append(rec)

    if not by_domain:
        raise ValueError("快照中未解析到任何 TXT 记录")
    return [DomainSnapshot(domain=d, records=r) for d, r in by_domain.items()]


def load_snapshot(path: Union[str, Path]) -> List[DomainSnapshot]:
    """Load a snapshot file, auto-detecting JSON vs zone-text format."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"快照文件不存在：{p}")
    text = p.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return parse_json_snapshot(json.loads(text))
    return parse_zone_snapshot(text)


# A real 1024-bit RSA SubjectPublicKeyInfo (base64/DER) used by the demo
# snapshot on purpose: it exercises the weak-key rule without any network.
_DEMO_RSA_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5yGMyjMjcU8NlIMLdvz5ytXH8rEpTkwO74"
    "Opfka57IFFYLRzNd2pxZ0+kNOe2YlnczBjBvJ+b18xaPYwMlxVYZA/3+kc8HEPwIexDM9ggTl"
    "nhckJM1FVOadP/AKbFdtahUPxtIOpKSbdj5CIhMgoGw14FLBWj0wmiZU3+vP1mEwIDAQAB"
)

DEMO_SNAPSHOT = f"""\
; MailProof 内置演示快照 —— 一个「看起来配齐了、其实漏洞不少」的域名
; 用法：mailproof demo > demo.zone && mailproof audit demo.zone
example.com. IN TXT "v=spf1 include:_spf.mail.example.com ip4:203.0.113.0/24 ~all"
_dmarc.example.com. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com; pct=50"
sel1._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; t=y; p={_DEMO_RSA_1024}"
"""
