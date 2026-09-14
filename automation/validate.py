#!/usr/bin/env python3
"""Run feature validation against the working Python 802.11 model.

Pass --cpp to also compare a compiled C++ analyzer against the same JSON.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "python"))

from controller_view import build_controller_view  # noqa: E402
from generate_fixtures import generate  # noqa: E402
from log_correlator import correlate  # noqa: E402
from wlan_model import analyze_pcap_dict  # noqa: E402


@dataclass
class Check:
    name: str
    passed: bool
    evidence: str


def by_ssid(analysis: dict) -> dict:
    return {net["ssid"]: net for net in analysis["networks"]}


def run_cpp(executable: Path, capture: Path) -> dict:
    process = subprocess.run(
        [str(executable), str(capture)],
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise RuntimeError(f"C++ analyzer failed for {capture.name}: {process.stderr.strip()}")
    return json.loads(process.stdout)


def validate(fixtures: Path) -> list[Check]:
    generate(fixtures)
    baseline = analyze_pcap_dict(fixtures / "lab-baseline.pcap")
    disconnect = analyze_pcap_dict(fixtures / "disconnect-event.pcap")
    handshake = analyze_pcap_dict(fixtures / "handshake.pcap")
    probe = analyze_pcap_dict(fixtures / "probe-scan.pcap")
    malformed = analyze_pcap_dict(fixtures / "malformed.pcap")
    nets = by_ssid(baseline)
    station = handshake["stations"][0] if handshake["stations"] else {}
    deauth = disconnect["deauthentication_events"]
    disassoc = disconnect["disassociation_events"]

    return [
        Check(
            "discovers six advertised networks",
            len(baseline["networks"]) == 6,
            f"discovered={len(baseline['networks'])}",
        ),
        Check("classifies open network", nets.get("GuestOpen", {}).get("security") == "OPEN", str(nets.get("GuestOpen"))),
        Check("classifies WPA2-PSK", nets.get("CorpWPA2", {}).get("security") == "WPA2-PSK", str(nets.get("CorpWPA2"))),
        Check("classifies WPA3-SAE", nets.get("SecureWPA3", {}).get("security") == "WPA3-SAE", str(nets.get("SecureWPA3"))),
        Check(
            "classifies WPA2-Enterprise",
            nets.get("CampusDot1X", {}).get("security") == "WPA2-ENTERPRISE",
            str(nets.get("CampusDot1X")),
        ),
        Check(
            "classifies WPA3 transition (PSK+SAE)",
            nets.get("MixedWPA3", {}).get("security") == "WPA3-TRANSITION",
            str(nets.get("MixedWPA3")),
        ),
        Check("reads hidden SSID", nets.get("<hidden>", {}).get("bssid") == "02:00:00:00:00:06", str(nets.get("<hidden>"))),
        Check("reads DS channel from beacon", nets.get("CorpWPA2", {}).get("channel") == 6, str(nets.get("CorpWPA2"))),
        Check(
            "detects deauthentication reason 7",
            len(deauth) == 1 and deauth[0]["reason"] == 7 and deauth[0]["protected"] is False,
            str(deauth),
        ),
        Check(
            "detects disassociation reason 8",
            len(disassoc) == 1 and disassoc[0]["reason"] == 8,
            str(disassoc),
        ),
        Check(
            "tracks open authentication then association",
            station.get("state") == "associated" and station.get("auth_algorithm") == 0,
            str(station),
        ),
        Check(
            "counts handshake management frames",
            handshake["frame_counts"]["authentication"] == 2
            and handshake["frame_counts"]["association_request"] == 1
            and handshake["frame_counts"]["association_response"] == 1
            and handshake["frame_counts"]["data"] == 1,
            str(handshake["frame_counts"]),
        ),
        Check(
            "learns network from probe response",
            any(net["ssid"] == "CafeWiFi" and net["channel"] == 11 for net in probe["networks"]),
            str(probe["networks"]),
        ),
        Check(
            "marks truncated information element as malformed",
            malformed["packets"] == 1 and malformed["malformed"] >= 1,
            str({"packets": malformed["packets"], "malformed": malformed["malformed"]}),
        ),
        Check(
            "baseline fixtures parse cleanly",
            baseline["malformed"] == 0 and handshake["malformed"] == 0,
            f"baseline={baseline['malformed']} handshake={handshake['malformed']}",
        ),
        *controller_checks(fixtures),
        *log_checks(fixtures),
    ]


def controller_checks(fixtures: Path) -> list[Check]:
    view = build_controller_view(
        fixtures / "roaming.pcap",
        {"02:00:00:00:00:02": "AP-1", "02:00:00:00:00:0a": "AP-2"},
    )
    wlan = view["wlans"][0] if view["wlans"] else {}
    return [
        Check(
            "controller view groups both APs under one WLAN",
            len(view["access_points"]) == 2 and wlan.get("ssid") == "CorpWPA2" and len(wlan.get("aps", [])) == 2,
            str(wlan),
        ),
        Check(
            "detects client roam between access points",
            len(view["roam_events"]) == 1
            and view["roam_events"][0]["from_ap"] == "AP-1"
            and view["roam_events"][0]["to_ap"] == "AP-2",
            str(view["roam_events"]),
        ),
    ]


def log_checks(fixtures: Path) -> list[Check]:
    agree = correlate(fixtures / "disconnect-event.pcap", fixtures / "ap-events.log")
    disagree = correlate(fixtures / "disconnect-event.pcap", fixtures / "ap-events-mismatch.log")
    return [
        Check(
            "AP log matches the frames in the capture",
            agree["consistent"] and len(agree["matched"]) == 2,
            f"matched={len(agree['matched'])} log_events={agree['log_events']}",
        ),
        Check(
            "flags a logged disconnect missing from the capture",
            not disagree["consistent"] and len(disagree["logged_but_not_captured"]) == 1,
            str(disagree["logged_but_not_captured"]),
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=ROOT / "fixtures")
    parser.add_argument("--report", type=Path, default=ROOT / "validation-report.json")
    parser.add_argument("--cpp", type=Path, default=None)
    args = parser.parse_args()

    checks = validate(args.fixtures.resolve())
    if args.cpp:
        generate(args.fixtures)
        py = analyze_pcap_dict(args.fixtures / "lab-baseline.pcap")
        cpp = run_cpp(args.cpp.resolve(), args.fixtures / "lab-baseline.pcap")
        same = py["networks"] == cpp.get("networks")
        checks.append(Check("C++ output matches Python networks", same, f"python={py['networks']} cpp={cpp.get('networks')}"))

    passed = sum(check.passed for check in checks)
    report = {
        "result": "PASS" if passed == len(checks) else "FAIL",
        "summary": {"passed": passed, "total": len(checks)},
        "checks": [asdict(check) for check in checks],
        "engine": "python/wlan_model.py",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for check in checks:
        print(f"[{'PASS' if check.passed else 'FAIL'}] {check.name}: {check.evidence}")
    print(f"\nValidation: {report['result']} ({passed}/{len(checks)})")
    print(f"Report: {args.report}")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
