from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from .engine import generate_findings_from_paths


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="generic-findings",
        description="SecureChain Generic Findings generator (SBOM+VEX+TIX -> DefectDojo Generic Findings Import JSON).",
    )
    p.add_argument("--sbom", required=True, help="Path to CycloneDX SBOM JSON")
    p.add_argument("--vex", required=True, help="Path to VEX JSON (OpenVEX-like)")
    p.add_argument("--tix", required=True, help="Path to TIX JSON (SecureChain TIX v0.1)")
    p.add_argument("--owner", default=None, help="Repo owner/org (optional)")
    p.add_argument("--repo", default=None, help="Repo name (optional)")
    p.add_argument("--sbom-name", default=None, help="SBOM label/name (optional)")
    p.add_argument("-o", "--out", default="-", help="Output JSON path (default: stdout)")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    payload = generate_findings_from_paths(
        sbom_path=args.sbom,
        vex_path=args.vex,
        tix_path=args.tix,
        owner=args.owner,
        repo=args.repo,
        sbom_name=args.sbom_name,
    )

    out_json = json.dumps(payload, indent=2, ensure_ascii=False)

    if args.out == "-" or args.out.strip() == "":
        sys.stdout.write(out_json + "\n")
        return 0

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(out_json + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
