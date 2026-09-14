#!/usr/bin/env python3
"""Human-readable demo of the working WLAN model."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "tools"))

from generate_fixtures import generate  # noqa: E402
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


if __name__ == "__main__":
    main()
