#!/usr/bin/env python3
"""Cross-platform one-shot build for MailProof.

Runs the test suite, builds a wheel into ``dist/`` and writes SHA256SUMS.
Uses only the standard library plus whatever setuptools/pip is already
installed — no network access and no extra build frontend required.

Usage::

    python scripts/build.py            # test + wheel + checksums
    python scripts/build.py --no-test  # skip tests
    python scripts/build.py --sdist    # also build an sdist
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def run(cmd: list[str], label: str) -> None:
    print(f"\n▶ {label}\n  $ {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, cwd=str(ROOT), check=False)
    if result.returncode != 0:
        raise SystemExit(f"❌ {label} 失败（退出码 {result.returncode}）")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="MailProof 一键构建")
    ap.add_argument("--no-test", action="store_true", help="跳过单元测试")
    ap.add_argument("--sdist", action="store_true", help="同时构建源码分发包")
    args = ap.parse_args()

    if sys.version_info < (3, 8):
        raise SystemExit("❌ 需要 Python >= 3.8")
    print(f"📮 MailProof 构建 · Python {sys.version.split()[0]} · {ROOT}")

    if not args.no_test:
        run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            "运行单元测试",
        )

    DIST.mkdir(exist_ok=True)
    for stale in DIST.glob("*"):
        if stale.is_file():
            stale.unlink()

    run(
        [sys.executable, "-m", "pip", "wheel", ".", "--no-deps",
         "--no-build-isolation", "-w", str(DIST)],
        "构建 wheel",
    )

    if args.sdist:
        # ``pip download --no-binary :all:`` does NOT produce a tarball for a
        # local directory. Use the PEP 517 hook directly instead: setuptools is
        # already present (it is the build backend for the wheel above), so this
        # stays dependency-free and works offline.
        run(
            [sys.executable, "-c",
             "from setuptools import build_meta; "
             "n = build_meta.build_sdist(%r); "
             "print('sdist ->', n)" % str(DIST)],
            "构建 sdist",
        )

    artifacts = sorted(p for p in DIST.iterdir() if p.is_file() and not p.name.startswith("SHA"))
    if not artifacts:
        raise SystemExit("❌ 未生成任何构建产物")

    lines = [f"{sha256(p)}  {p.name}" for p in artifacts]
    (DIST / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n✅ 构建完成，产物：")
    for p in artifacts:
        print(f"   • dist/{p.name}  ({p.stat().st_size} bytes)")
    print(f"   • dist/SHA256SUMS")
    print("\n安装验证： pip install --no-deps --force-reinstall dist/*.whl && mailproof --version")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
