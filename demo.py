#!/usr/bin/env python3
"""Human-readable demo of the working WLAN model."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "tools"))

from controller_view import build_controller_view  # noqa: E402
from generate_fixtures import generate  # noqa: E402
from log_correlator import correlate  # noqa: E402
from wlan_model import analyze_pcap_dict  # noqa: E402


def show(title: str, path: Path) -> None:
    analysis = analyze_pcap_dict(path)
    print(f"\n=== {title} ({path.name}) ===")
    print(f"packets={analysis['packets']} malformed={analysis['malformed']}")
    print("networks:")
    for net in analysis["networks"]:
        print(
            f"  {net['ssid']:16} {net['bssid']}  {net['security']:18} ch={net['channel']}"
        )
    if analysis["stations"]:
        print("stations:")
        for sta in analysis["stations"]:
            print(f"  {sta['mac']} -> {sta['bssid']}  state={sta['state']}")
    if analysis["deauthentication_events"]:
        print("deauth:", analysis["deauthentication_events"])
    print("frames:", {k: v for k, v in analysis["frame_counts"].items() if v})


def main() -> None:
    fixtures = ROOT / "fixtures"
    generate(fixtures)
    show("Lab scan", fixtures / "lab-baseline.pcap")
    show("Client handshake", fixtures / "handshake.pcap")
    show("Disconnect", fixtures / "disconnect-event.pcap")
    show("Probe scan", fixtures / "probe-scan.pcap")
    show("Bad capture", fixtures / "malformed.pcap")

    view = build_controller_view(
        fixtures / "roaming.pcap",
        {"02:00:00:00:00:02": "AP-1", "02:00:00:00:00:0a": "AP-2"},
    )
    print("\n=== Controller view (roaming.pcap) ===")
    for wlan in view["wlans"]:
        print(f"  WLAN {wlan['ssid']} [{wlan['security']}] on {', '.join(wlan['aps'])}")
    for roam in view["roam_events"]:
        print(f"  roam: {roam['station']} {roam['from_ap']} -> {roam['to_ap']}")

    result = correlate(fixtures / "disconnect-event.pcap", fixtures / "ap-events-mismatch.log")
    print("\n=== Log vs capture (ap-events-mismatch.log) ===")
    print(f"  consistent: {result['consistent']}")
    for entry in result["logged_but_not_captured"]:
        print(f"  logged but never on air: line {entry['line']} {entry['station']} reason {entry['reason']}")


if __name__ == "__main__":
    main()
