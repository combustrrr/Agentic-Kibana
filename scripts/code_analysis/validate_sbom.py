#!/usr/bin/env python3
"""Validate CycloneDX/SPDX inventories and emit structured license-policy evidence."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

DENIED_LICENSES = {
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
}
SPDX_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")


def _denied_license(expression: str) -> bool:
    """Match complete SPDX identifiers, never substrings such as LGPL containing GPL."""
    return any(token in DENIED_LICENSES for token in SPDX_TOKEN.findall(expression))


def _licenses(document: dict[str, Any]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if document.get("bomFormat") == "CycloneDX":
        for component in document.get("components", []):
            name = str(component.get("name") or "unknown")
            for item in component.get("licenses", []):
                value = item.get("license", {}).get("id") or item.get("expression")
                if value:
                    rows.append((name, str(value)))
    elif str(document.get("spdxVersion", "")).startswith("SPDX-"):
        for package in document.get("packages", []):
            name = str(package.get("name") or "unknown")
            for key in ("licenseConcluded", "licenseDeclared"):
                value = str(package.get(key) or "")
                if value and value not in {"NOASSERTION", "NONE"}:
                    rows.append((name, value))
    else:
        raise ValueError("unsupported SBOM format")
    return rows


def evaluate(paths: list[Path]) -> tuple[dict[str, Any], dict[str, Any]]:
    observed: list[tuple[str, str, str]] = []
    package_count = 0
    formats: set[str] = set()
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("bomFormat") == "CycloneDX":
            formats.add("CycloneDX")
            package_count += len(document.get("components", []))
        elif str(document.get("spdxVersion", "")).startswith("SPDX-"):
            formats.add("SPDX")
            package_count += len(document.get("packages", []))
        else:
            raise ValueError(f"unsupported SBOM format: {path}")
        observed.extend((path.name, name, license_id) for name, license_id in _licenses(document))
    # SPDX commonly repeats the same value in declared and concluded fields. Preserve
    # cross-format evidence but do not manufacture duplicate findings within one SBOM.
    observed = list(dict.fromkeys(observed))
    denied = [row for row in observed if _denied_license(row[2])]
    status = {
        "schema_version": "1", "scanner_family": "SBOM Policy",
        "status": "POLICY_FINDINGS" if denied else "COMPLETED_OPTIONAL",
        "reason": "Denied license identifiers require operator review" if denied else "",
        "formats": sorted(formats), "package_count": package_count,
        "license_observation_count": len(observed), "finding_count": len(denied),
        "observation_count": len(denied),
    }
    results = [{
        "ruleId": "denied-license", "level": "error",
        "message": {"text": f"{name} declares denied license expression {license_id}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": source},
                                              "region": {"startLine": 1}}}],
    } for source, name, license_id in denied]
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "SBOM Policy", "rules": []}},
                       "results": results}]}
    return status, sarif


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", nargs="+", type=Path)
    parser.add_argument("--status", required=True, type=Path)
    parser.add_argument("--sarif", required=True, type=Path)
    args = parser.parse_args()
    status, sarif = evaluate(args.sbom)
    args.status.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.sarif.write_text(json.dumps(sarif, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
