#!/usr/bin/env python3
"""Reproduce a known wireless defect, then verify the fix.

Scenario WLAN-114: clients on the WPA2 SSID could be knocked off the network by
an unprotected deauthentication frame, because Protected Management Frames were
not negotiated. The fix moves the SSID to WPA3-SAE, where the deauthentication
is protected.

This script reproduces the bad behaviour from a capture, then checks the fixed
capture no longer shows it. That is the reproduce-and-validate loop, run the
same way every time.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "tools"))

from generate_fixtures import generate  # noqa: E402
from wlan_model import analyze_pcap_dict  # noqa: E402

DEFECT = "WLAN-114"


def unprotected_deauths(analysis: dict) -> list[dict]:
    return [event for event in analysis["deauthentication_events"] if not event["protected"]]


def run(fixtures: Path) -> dict:
    generate(fixtures)
    before = analyze_pcap_dict(fixtures / "disconnect-event.pcap")
    after = analyze_pcap_dict(fixtures / "pmf-enabled.pcap")

    reproduced = unprotected_deauths(before)
    still_failing = unprotected_deauths(after)
    protected_seen = [e for e in after["deauthentication_events"] if e["protected"]]

    return {
        "defect": DEFECT,
        "title": "Unprotected deauthentication disconnects clients",
        "reproduced_on_affected_build": bool(reproduced),
        "reproduction_evidence": reproduced,
        "fix_verified": not still_failing and bool(protected_seen),
        "verification_evidence": protected_seen,
        "verdict": "FIXED" if reproduced and not still_failing and protected_seen else "NOT VERIFIED",
    }


def main() -> int:
    fixtures = ROOT / "fixtures"
    report = run(fixtures)
    print(f"Defect {report['defect']}: {report['title']}")
    print(f"  reproduced on affected build : {report['reproduced_on_affected_build']}")
    print(f"  fix verified on patched build: {report['fix_verified']}")
    print(f"  verdict: {report['verdict']}")
    out = ROOT / "regression-report.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Report: {out}")
    return 0 if report["verdict"] == "FIXED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
