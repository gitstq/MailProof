"""Command-line interface for MailProof."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .audit import audit_snapshots
from .bundle import DEMO_SNAPSHOT, load_snapshot, parse_zone_snapshot
from .dkim import parse_dkim
from .dmarc import parse_dmarc
from .models import AuditBundle, Severity
from .presets import BASELINES
from .report import FORMATS, render
from .rules import catalog
from .simulate import render_simulation_text, simulate
from .spf import parse_spf

_EXIT_OK = 0
_EXIT_GATE = 1
_EXIT_ERROR = 2


def _snapshots(path: Optional[str], use_demo: bool) -> tuple:
    if use_demo or not path:
        return parse_zone_snapshot(DEMO_SNAPSHOT), "(内置演示快照)"
    return load_snapshot(path), path


def _filter_domains(snaps, only: Optional[str]):
    if not only:
        return snaps
    return [s for s in snaps if s.domain.lower() == only.rstrip(".").lower()]


def cmd_audit(args: argparse.Namespace) -> int:
    try:
        snaps, source = _snapshots(args.path, args.demo)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"❌ 读取快照失败：{exc}", file=sys.stderr)
        return _EXIT_ERROR
    if not args.path and not args.demo:
        print("ℹ️  未指定快照文件，已使用内置演示数据（--demo 可静默）。", file=sys.stderr)

    snaps = _filter_domains(snaps, args.domain)
    if not snaps:
        print(f"❌ 快照中没有匹配的域名：{args.domain}", file=sys.stderr)
        return _EXIT_ERROR

    bundle = audit_snapshots(snaps, args.baseline, source=source)
    try:
        output = render(bundle, args.format)
    except ValueError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return _EXIT_ERROR

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if not args.quiet:
            print(f"✅ 报告已写入：{args.output}", file=sys.stderr)
    else:
        print(output)

    if args.fail_on != "none":
        threshold = Severity(args.fail_on).rank
        worst = max(
            (f.severity.rank for r in bundle.results for f in r.findings),
            default=-1,
        )
        if worst >= threshold:
            if not args.quiet:
                print(
                    f"🚫 CI 门禁触发：发现级别 >= {args.fail_on} 的问题。",
                    file=sys.stderr,
                )
            return _EXIT_GATE
    return _EXIT_OK


def cmd_parse(args: argparse.Namespace) -> int:
    payload: dict = {}
    if args.spf:
        payload["spf"] = parse_spf(args.spf).to_dict()
    if args.dmarc:
        payload["dmarc"] = parse_dmarc(args.dmarc).to_dict()
    if args.dkim:
        payload["dkim"] = parse_dkim(args.dkim, selector=args.selector).to_dict()
    if not payload:
        print("❌ 至少指定 --spf / --dmarc / --dkim 之一", file=sys.stderr)
        return _EXIT_ERROR
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return _EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    rules = catalog()
    if args.format == "json":
        rows = [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "severity": r.severity.value,
                "category": r.category,
                "description": r.description,
                "reference": r.reference,
            }
            for r in rules
        ]
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    elif args.format == "csv":
        print("rule_id,severity,category,title")
        for r in rules:
            print(f"{r.rule_id},{r.severity.value},{r.category},{r.title}")
    else:
        print(f"MailProof 规则目录（共 {len(rules)} 条）")
        print("-" * 78)
        for r in rules:
            print(f"{r.rule_id}  [{r.severity.value:<8}] [{r.category:<12}] {r.title}")
            print(f"          {r.description}")
            if r.reference:
                print(f"          {r.reference}")
    return _EXIT_OK


def cmd_baselines(args: argparse.Namespace) -> int:
    if args.format == "json":
        print(json.dumps(
            {k: b.__dict__ for k, b in BASELINES.items()},
            ensure_ascii=False, indent=2,
        ))
        return _EXIT_OK
    print("MailProof 合规基线")
    print("=" * 78)
    for b in BASELINES.values():
        print(f"🛡️  {b.key}  —  {b.name}")
        print(f"    {b.description}")
        print(
            f"    DMARC p≥{b.min_dmarc_policy} · SPF -all={'要求' if b.require_spf_hardfail else '不强制'}"
            f" · DKIM≥{b.min_dkim_bits}位 · rua={'要求' if b.require_rua else '不强制'}"
            f" · pct=100={'要求' if b.require_dmarc_pct_100 else '不强制'}"
        )
        if b.reference:
            print(f"    {b.reference}")
        print()
    return _EXIT_OK


def cmd_simulate(args: argparse.Namespace) -> int:
    try:
        snaps, _ = _snapshots(args.path, args.demo)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"❌ 读取快照失败：{exc}", file=sys.stderr)
        return _EXIT_ERROR
    snaps = _filter_domains(snaps, args.domain)
    if not snaps:
        print("❌ 快照中没有匹配的域名", file=sys.stderr)
        return _EXIT_ERROR
    sims = [simulate(s, args.policy, args.baseline) for s in snaps]
    if args.format == "json":
        print(json.dumps(sims if len(sims) > 1 else sims[0], ensure_ascii=False, indent=2))
    else:
        for s in sims:
            print(render_simulation_text(s))
    return _EXIT_OK


def cmd_demo(args: argparse.Namespace) -> int:
    if args.output:
        Path(args.output).write_text(DEMO_SNAPSHOT, encoding="utf-8")
        print(f"✅ 演示快照已写入：{args.output}")
    else:
        print(DEMO_SNAPSHOT, end="")
    return _EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mailproof",
        description="📮 MailProof — 零依赖·离线优先的邮件域名身份认证审计与策略推演引擎 (SPF/DKIM/DMARC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  mailproof demo > demo.zone\n"
            "  mailproof audit demo.zone --baseline microsoft-2025\n"
            "  mailproof audit records.json --format sarif --output report.sarif\n"
            "  mailproof audit demo.zone --format html -o report.html --fail-on high\n"
            "  mailproof simulate demo.zone --policy reject\n"
            "  mailproof parse --spf 'v=spf1 ip4:203.0.113.0/24 -all'\n"
        ),
    )
    p.add_argument("--version", action="version", version=f"MailProof {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="审计离线 DNS 快照")
    a.add_argument("path", nargs="?", help="快照文件（.json / .zone / .txt），缺省使用内置演示数据")
    a.add_argument("--demo", action="store_true", help="强制使用内置演示快照")
    a.add_argument("--baseline", default="default", choices=list(BASELINES), help="合规基线")
    a.add_argument("--format", default="text", choices=list(FORMATS), help="报告格式")
    a.add_argument("-o", "--output", help="写入文件而非标准输出")
    a.add_argument("--fail-on", default="none",
                    choices=["none"] + [s.value for s in Severity],
                    help="CI 门禁：存在不低于该级别的问题时退出码为 1")
    a.add_argument("--domain", help="仅审计指定域名")
    a.add_argument("--quiet", action="store_true", help="抑制提示信息")
    a.set_defaults(func=cmd_audit)

    ps = sub.add_parser("parse", help="解析单条 SPF/DMARC/DKIM 记录")
    ps.add_argument("--spf", help="SPF TXT 字符串")
    ps.add_argument("--dmarc", help="DMARC TXT 字符串")
    ps.add_argument("--dkim", help="DKIM TXT 字符串")
    ps.add_argument("--selector", default="", help="DKIM 选择器名")
    ps.set_defaults(func=cmd_parse)

    r = sub.add_parser("rules", help="列出全部审计规则")
    r.add_argument("--format", default="text", choices=["text", "json", "csv"])
    r.set_defaults(func=cmd_rules)

    b = sub.add_parser("baselines", help="列出全部合规基线")
    b.add_argument("--format", default="text", choices=["text", "json"])
    b.set_defaults(func=cmd_baselines)

    s = sub.add_parser("simulate", help="DMARC 策略升级离线推演")
    s.add_argument("path", nargs="?", help="快照文件，缺省使用内置演示数据")
    s.add_argument("--demo", action="store_true", help="强制使用内置演示快照")
    s.add_argument("--policy", default="reject", choices=["none", "quarantine", "reject"])
    s.add_argument("--baseline", default="default", choices=list(BASELINES))
    s.add_argument("--domain", help="仅推演指定域名")
    s.add_argument("--format", default="text", choices=["text", "json"])
    s.set_defaults(func=cmd_simulate)

    d = sub.add_parser("demo", help="导出内置演示快照")
    d.add_argument("-o", "--output", help="输出文件路径")
    d.set_defaults(func=cmd_demo)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130
    except (ValueError, KeyError) as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return _EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
