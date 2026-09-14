#!/usr/bin/env python3
"""Correlate AP syslog lines with the frames seen in a capture.

Debugging a wireless issue usually means holding two sources side by side:
what the AP logged, and what was actually on the air. This module parses
hostapd-style log lines and reports where the log and the capture disagree.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wlan_model import analyze_pcap  # noqa: E402

MAC = r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})"

PATTERNS = [
    ("authenticated", re.compile(rf"STA {MAC} IEEE 802\.11: authenticated", re.I)),
    ("associated", re.compile(rf"STA {MAC} IEEE 802\.11: associated", re.I)),
    (
        "deauthenticated",
        re.compile(rf"STA {MAC} IEEE 802\.11: deauthenticated due to.*reason (\d+)", re.I),
    ),
    (
        "disassociated",
        re.compile(rf"STA {MAC} IEEE 802\.11: disassociated.*reason (\d+)", re.I),
    ),
]


def parse_log(path: Path) -> list[dict]:
    """Turn a hostapd-style text log into structured events."""
    events: list[dict] = []
    for number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        for kind, pattern in PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            event = {
                "line": number,
                "event": kind,
                "station": match.group(1).lower(),
                "reason": int(match.group(2)) if match.lastindex and match.lastindex >= 2 else None,
            }
            events.append(event)
            break
    return events


def correlate(capture: Path, log: Path) -> dict:
    """Compare logged disconnects against deauth/disassoc frames on the air."""
    analysis = analyze_pcap(capture)
    log_events = parse_log(log)

    frame_disconnects = []
    for event in analysis.deauthentication_events:
        frame_disconnects.append(
            {"station": event.receiver, "reason": event.reason, "event": "deauthenticated"}
        )
    for event in analysis.disassociation_events:
        frame_disconnects.append(
            {"station": event.receiver, "reason": event.reason, "event": "disassociated"}
        )

    logged_disconnects = [e for e in log_events if e["reason"] is not None]

    matched, log_only = [], []
    remaining = frame_disconnects.copy()
    for logged in logged_disconnects:
        hit = next(
            (
                frame
                for frame in remaining
                if frame["station"] == logged["station"]
                and frame["reason"] == logged["reason"]
                and frame["event"] == logged["event"]
            ),
            None,
        )
        if hit is None:
            log_only.append(logged)
        else:
            remaining.remove(hit)
            matched.append({**logged, "confirmed_in_capture": True})

    return {
        "capture": capture.name,
        "log": log.name,
        "log_events": len(log_events),
        "matched": matched,
        "logged_but_not_captured": log_only,
        "captured_but_not_logged": remaining,
        "consistent": not log_only and not remaining,
    }
