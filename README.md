# WLAN Feature Validator

[![CI](https://github.com/sreedeep123-star/wlan-feature-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/sreedeep123-star/wlan-feature-validator/actions/workflows/ci.yml)
![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C)
![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB)
![Tests](https://img.shields.io/badge/tests-25%20unit%20%2B%2027%20checks-success)
![Dependencies](https://img.shields.io/badge/dependencies-none-lightgrey)

An IEEE 802.11 frame analyzer and feature-validation harness, written from the
byte level up in **C++17 and Python** with no packet-parsing libraries. It reads
PCAP/Radiotap captures, classifies WLAN security, tracks client state across
access points, correlates AP logs with over-the-air frames, and proves all of it
with an automated test suite that runs in CI.

Everything below is reproducible on a laptop in under a minute. No access point,
no wireless NIC, no monitor mode required.

```bash
git clone https://github.com/sreedeep123-star/wlan-feature-validator
cd wlan-feature-validator
python demo.py
```

## What it does

| Capability | Where | Evidence |
|---|---|---|
| Parse classic PCAP + Radiotap, bounds-checked | `python/wlan_model.py`, `src/main.cpp` | malformed frames counted, never crash |
| Beacon / probe decode: SSID, BSSID, channel | `wlan_model.py` | 6 networks found in the lab scan |
| Security from RSN AKM suites | `classify_rsn()` | Open, WPA2-PSK, WPA2-Enterprise, WPA3-SAE, WPA3 transition |
| WPA2 4-way key exchange | `classify_eapol_key()` | EAPOL-Key M1–M4 tracked; stalled handshakes flagged |
| PHY generation from capability IEs | `wlan_model.py` | 802.11n / ac / ax from HT, VHT and HE elements |
| Radiotap RF metadata | `parse_radiotap()` | 2.4 / 5 / 6 GHz band, channel and per-BSSID RSSI |
| Client state machine | `wlan_model.py` | auth → assoc → key exchange → `disconnected` |
| Protected Management Frames | `wlan_model.py` | reports whether a deauth was protected |
| Multi-AP controller roll-up + roaming | `python/controller_view.py` | detects STA moving AP-1 → AP-2 |
| AP log vs air correlation | `python/log_correlator.py` | finds disconnects logged but never transmitted |
| Defect reproduce-and-verify | `automation/regression.py` | WLAN-114 reproduced, then verified fixed |

Captures are standard `DLT_IEEE802_11_RADIO` (link type 127), so the same files
open in **Wireshark** or `tshark` for side-by-side confirmation.

## Sample output

`python demo.py` on the generated lab scan:

```text
=== Lab scan (lab-baseline.pcap) ===
packets=6 malformed=0
networks:
  GuestOpen        02:00:00:00:00:01  OPEN               ch=1
  CorpWPA2         02:00:00:00:00:02  WPA2-PSK           ch=6
  SecureWPA3       02:00:00:00:00:03  WPA3-SAE           ch=11
  CampusDot1X      02:00:00:00:00:04  WPA2-ENTERPRISE    ch=36
  MixedWPA3        02:00:00:00:00:05  WPA3-TRANSITION    ch=6
  <hidden>         02:00:00:00:00:06  WPA2-PSK           ch=6

=== PHY and RF survey (phy-and-rf.pcap) ===
  LegacyNet    WPA2-PSK   802.11a/b/g  2.4 GHz  ch=6    rssi=-42.0 dBm
  WiFi4Net     WPA2-PSK   802.11n      2.4 GHz  ch=11   rssi=-58.0 dBm
  WiFi5Net     WPA2-PSK   802.11ac     5 GHz    ch=36   rssi=-61.0 dBm
  WiFi6Net     WPA3-SAE   802.11ax     6 GHz    ch=37   rssi=-67.0 dBm

=== WPA2 4-way key exchange ===
  02:00:00:00:10:01 -> 02:00:00:00:00:02  M1M2M3M4  keys installed
  02:00:00:00:10:01 -> 02:00:00:00:00:02  M1M2      INCOMPLETE

=== Controller view (roaming.pcap) ===
  WLAN CorpWPA2 [WPA2-PSK] on AP-1, AP-2
  roam: 02:00:00:00:10:01 AP-1 -> AP-2

=== Log vs capture (ap-events-mismatch.log) ===
  consistent: False
  logged but never on air: line 3 02:00:00:00:99:99 reason 3
```

That last block is the interesting one: the AP logged a deauthentication for a
client that never appears in the capture. On real gear that gap is where you
start looking for the bug.

## Validation

```bash
python tests/test_wlan_model.py      # 25 unit tests
python automation/validate.py        # 27 feature checks -> validation-report.json
python automation/regression.py      # defect WLAN-114 -> regression-report.json
```

**Defect WLAN-114** — clients on the WPA2 SSID could be knocked off by an
unprotected deauthentication frame, because Protected Management Frames were
not negotiated. The runner reproduces it on the affected capture and confirms
it is gone on the WPA3-SAE build:

```text
Defect WLAN-114: Unprotected deauthentication disconnects clients
  reproduced on affected build : True
  fix verified on patched build: True
  verdict: FIXED
```

## Build the C++ analyzer

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
./build/wlan-analyzer fixtures/lab-baseline.pcap
```

Compiled with `-Wall -Wextra -Wpedantic -Werror` (GCC/Clang) or `/W4` (MSVC).
CI builds it on both Linux and Windows.

## Design notes

- **No packet libraries on purpose.** Every offset is computed and length-checked
  by hand, because the point is to understand the frame format rather than call
  someone else's parser.
- **Deterministic fixtures.** Captures are generated from code, so a test failure
  always points at the analyzer and never at a flaky recording.
- **Errors are data.** A truncated information element increments a malformed
  counter and the run continues; it does not throw away the rest of the capture.

## Layout

```text
python/wlan_model.py         802.11 / Radiotap / PCAP parser
python/controller_view.py    multi-AP WLAN and roaming roll-up
python/log_correlator.py     AP log vs capture comparison
python/analyze.py            JSON CLI
src/main.cpp                 C++17 analyzer
tools/generate_fixtures.py   lab captures and AP logs
automation/validate.py       27 feature checks
automation/regression.py     defect reproduce-and-verify
tests/test_wlan_model.py     25 unit tests
demo.py                      readable lab report
```

## Scope

This is a protocol model driven by synthetic captures. It is not vendor firmware,
not a production controller, and it has not been run against a live enterprise
network. It is passive by design: it never transmits frames, deauthenticates
clients, or attempts to recover keys. The 4-way handshake is tracked by its
EAPOL-Key message sequence only; no key material is derived or cracked. Natural
next steps are 802.11r/k/v fast-roaming frames and information-element fuzzing.

## License

MIT
