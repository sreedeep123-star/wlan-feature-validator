#!/usr/bin/env python3
"""Controller-style roll-up across several access points.

A single capture only shows frames. A wireless controller cares about the
WLAN as a whole: which APs serve an SSID, where each client is anchored, and
whether a client roamed between APs. This module builds that view from the
frame-level analysis.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wlan_model import analyze_pcap  # noqa: E402


def build_controller_view(capture: Path, ap_names: dict[str, str] | None = None) -> dict:
    """Aggregate one capture into an AP / WLAN / client roaming summary."""
    analysis = analyze_pcap(capture)
    names = ap_names or {}

    access_points: dict[str, dict] = {}
    for net in analysis.networks.values():
        access_points[net.bssid] = {
            "name": names.get(net.bssid, net.bssid),
            "bssid": net.bssid,
            "ssid": net.ssid,
            "security": net.security,
            "channel": net.channel,
            "clients": [],
        }

    # Order of association per client, used to detect roaming between APs.
    timeline: dict[str, list[str]] = {}
    for record in analysis.associations:
        if record["direction"] != "response" or record["status"] != 0:
            continue
        timeline.setdefault(record["station"], []).append(record["bssid"])

    roam_events = []
    for station, anchors in timeline.items():
        for previous, current in zip(anchors, anchors[1:]):
            if previous != current:
                roam_events.append(
                    {
                        "station": station,
                        "from_ap": names.get(previous, previous),
                        "to_ap": names.get(current, current),
                        "from_bssid": previous,
                        "to_bssid": current,
                    }
                )

    for sta in analysis.stations.values():
        entry = access_points.get(sta.bssid)
        if entry is not None and sta.state in {"associated", "disconnected"}:
            entry["clients"].append({"mac": sta.mac, "state": sta.state})

    wlans: dict[str, dict] = {}
    for ap in access_points.values():
        wlan = wlans.setdefault(
            ap["ssid"],
            {"ssid": ap["ssid"], "security": ap["security"], "aps": [], "client_count": 0},
        )
        wlan["aps"].append(ap["name"])
        wlan["client_count"] += sum(1 for c in ap["clients"] if c["state"] == "associated")

    return {
        "capture": capture.name,
        "access_points": sorted(access_points.values(), key=lambda ap: ap["bssid"]),
        "wlans": sorted(wlans.values(), key=lambda wlan: wlan["ssid"]),
        "roam_events": roam_events,
        "total_clients": len({sta.mac for sta in analysis.stations.values()}),
    }
