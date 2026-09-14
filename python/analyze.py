#!/usr/bin/env python3
"""CLI for the working Python 802.11 analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wlan_model import analyze_pcap_dict, dumps


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a Radiotap 802.11 PCAP")
    parser.add_argument("pcap", type=Path)
    args = parser.parse_args()
    try:
        sys.stdout.write(dumps(analyze_pcap_dict(args.pcap)))
        return 0
    except Exception as error:  # noqa: BLE001 - CLI boundary
        sys.stderr.write(f"error: {error}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
