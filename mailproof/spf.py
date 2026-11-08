"""SPF (RFC 7208) record parser and semantic validator.

MailProof is offline-first: it never resolves DNS itself. Instead it parses a
snapshot of TXT records and evaluates the SPF policy *as written*, including
the infamous "10 DNS lookup" limit and include-loop detection.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .models import DnsRecord, DomainSnapshot

_VALID_QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
_MECHANISMS = {"all", "include", "a", "mx", "ip4", "ip6", "ptr", "exists"}
_MODIFIERS = {"redirect", "exp"}
_VERSION_RE = re.compile(r"^v=spf1(?:\s|$)", re.IGNORECASE)


@dataclass
class Mechanism:
    """A single SPF mechanism term."""

    qualifier: str
    kind: str
    value: str = ""
    raw: str = ""

    @property
    def result(self) -> str:
        return _VALID_QUALIFIERS.get(self.qualifier, "pass")

    def to_dict(self) -> Dict[str, str]:
        return {
            "qualifier": self.qualifier,
            "result": self.result,
            "kind": self.kind,
            "value": self.value,
            "raw": self.raw,
        }


@dataclass
class SPFRecord:
    """Parsed representation of one SPF TXT record."""

    raw: str
    version: str = ""
    mechanisms: List[Mechanism] = field(default_factory=list)
    modifiers: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def all_mechanism(self) -> Optional[Mechanism]:
        for m in reversed(self.mechanisms):
            if m.kind == "all":
                return m
        return None

    @property
    def lookup_count(self) -> int:
        """Number of terms that trigger DNS lookups (RFC 7208 4.6.4)."""
        return sum(1 for m in self.mechanisms if m.kind in _LOOKUP_KINDS) + (
            1 if "redirect" in self.modifiers else 0
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "raw": self.raw,
            "version": self.version,
            "mechanisms": [m.to_dict() for m in self.mechanisms],
            "modifiers": dict(self.modifiers),
            "errors": list(self.errors),
            "lookup_count": self.lookup_count,
        }


_LOOKUP_KINDS = {"include", "a", "mx", "ptr", "exists", "redirect"}


def _split_terms(body: str) -> List[str]:
    return [t for t in re.split(r"\s+", body.strip()) if t]


def parse_spf(value: str) -> SPFRecord:
    """Parse a single TXT string into an :class:`SPFRecord`.

    The parser is deliberately tolerant: malformed terms are recorded as
    errors instead of raising, so an audit can report *why* a record is bad.
    """
    raw = " ".join(value.strip().split())
    rec = SPFRecord(raw=raw)

    if not raw:
        rec.errors.append("SPF 记录为空")
        return rec

    match = _VERSION_RE.match(raw)
    if not match:
        rec.errors.append("缺少 v=spf1 版本标记（必须以 v=spf1 开头）")
        # Keep going: we still want to report the terms.
        body = raw
    else:
        rec.version = "spf1"
        body = raw[match.end() :]

    for term in _split_terms(body):
        qualifier = "+"
        core = term
        if term and term[0] in _VALID_QUALIFIERS:
            qualifier, core = term[0], term[1:]

        if not core:
            rec.errors.append(f"术语 {term!r} 缺少机制名称")
            continue

        # Modifiers use '=' (redirect=, exp=); mechanisms never do.
        if "=" in core:
            key, v = core.split("=", 1)
            _add_modifier(rec, key.lower(), v, term)
            continue

        # Split a mechanism into its name and optional argument. A ':' prefix
        # (ip4:..., include:..., a:host/24) is kept verbatim; a bare '/'
        # introduces a CIDR suffix for a/mx (a/24, mx/24).
        if ":" in core:
            kind, value = core.split(":", 1)
        elif "/" in core:
            kind, cidr = core.split("/", 1)
            value = "/" + cidr
        else:
            kind, value = core, ""

        kind = kind.lower()
        if kind not in _MECHANISMS:
            rec.errors.append(f"未知 SPF 机制：{kind!r}（术语 {term!r}）")
            continue

        _add_mechanism(rec, qualifier, kind, value, term)

    _validate_semantics(rec)
    return rec


def _add_modifier(rec: SPFRecord, key: str, value: str, term: str) -> None:
    if key not in _MODIFIERS:
        rec.errors.append(f"未知 SPF 修饰符：{key!r}（术语 {term!r}）")
        return
    if key in rec.modifiers:
        rec.errors.append(f"修饰符 {key!r} 重复出现")
    rec.modifiers[key] = value


def _add_mechanism(
    rec: SPFRecord, qualifier: str, kind: str, value: str, term: str
) -> None:
    mech = Mechanism(qualifier=qualifier, kind=kind, value=value, raw=term)

    if kind in ("ip4", "ip6"):
        _validate_ip(mech, rec)
    elif kind == "all" and value:
        rec.errors.append("'all' 机制不接受参数")
    elif kind in ("include", "exists") and not value:
        # RFC 7208: include / exists require a domain-spec argument.
        rec.errors.append(f"'{kind}' 机制缺少必要的域名参数")
    # 'a', 'mx', 'ptr' may legitimately omit the argument (current domain).
    # 'a:host/24' and 'mx/24' carry an optional domain/CIDR suffix.

    rec.mechanisms.append(mech)


def _validate_ip(mech: Mechanism, rec: SPFRecord) -> None:
    if not mech.value:
        rec.errors.append(f"'{mech.kind}' 机制缺少地址参数")
        return
    try:
        if mech.kind == "ip4":
            ipaddress.IPv4Network(mech.value, strict=False)
        else:
            ipaddress.IPv6Network(mech.value, strict=False)
    except ValueError:
        rec.errors.append(f"非法的 {mech.kind} 地址/CIDR：{mech.value!r}")


def _validate_semantics(rec: SPFRecord) -> None:
    seen_all = False
    for i, m in enumerate(rec.mechanisms):
        if m.kind == "all":
            if seen_all:
                rec.errors.append("存在多个 'all' 机制")
            seen_all = True
        elif seen_all:
            rec.errors.append(f"'all' 之后仍存在机制 {m.raw!r}（永远不会被执行）")

    if "redirect" in rec.modifiers and seen_all:
        rec.errors.append("'redirect' 修饰符与 'all' 机制同时存在，redirect 不会生效")
    if "redirect" in rec.modifiers and not rec.modifiers["redirect"]:
        rec.errors.append("'redirect' 修饰符缺少目标域名")


def collect_spf(snapshot: DomainSnapshot, name: Optional[str] = None) -> List[SPFRecord]:
    """Return all parsed SPF records found at ``name`` (default: domain apex)."""
    return [
        parse_spf(v)
        for v in snapshot.txt_values(name)
        if v.lower().startswith("v=spf1")
    ]


def detect_include_loops(
    records: Dict[str, SPFRecord],
) -> List[Tuple[str, ...]]:
    """Detect cycles in include/redirect chains across a snapshot.

    ``records`` maps a DNS name to the SPF record published there. Only edges
    present in the supplied snapshot are followed; unknown targets are treated
    as leaves (MailProof never guesses from the network).
    """
    graph: Dict[str, List[str]] = {}
    for host, rec in records.items():
        edges = [m.value.lower().rstrip(".") for m in rec.mechanisms if m.kind == "include"]
        redirect = rec.modifiers.get("redirect")
        if redirect:
            edges.append(redirect.lower().rstrip("."))
        graph[host.lower().rstrip(".")] = edges

    loops: List[Tuple[str, ...]] = []
    seen: set = set()

    def walk(node: str, path: List[str]) -> None:
        if node in path:
            cycle = tuple(path[path.index(node) :] + [node])
            key = frozenset(cycle)
            if key not in seen:
                seen.add(key)
                loops.append(cycle)
            return
        for nxt in graph.get(node, []):
            walk(nxt, path + [node])

    for start in graph:
        walk(start, [])
    return loops


def build_include_graph(snapshot: DomainSnapshot) -> Dict[str, SPFRecord]:
    """Index every SPF-ish TXT record in a snapshot by its owner name."""
    graph: Dict[str, SPFRecord] = {}
    for rec in snapshot.all_txt():
        v = rec.normalized_value
        if v.lower().startswith("v=spf1"):
            graph[rec.name.rstrip(".").lower()] = parse_spf(v)
    return graph
