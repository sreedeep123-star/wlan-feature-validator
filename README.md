# WLAN Feature Validator

A **working Wi-Fi packet model**. It does not need a real access point.

Python creates fake Wi-Fi recordings (PCAP files). The analyzer reads those
files and reports networks, security (Open / WPA2 / WPA3), client connect
state, and disconnects. Automated tests check that the answers are correct.

On this repo the **Python model is the engine that runs today**. The C++
binary is the same idea for when a C++ compiler is installed.

## What the model understands

| 802.11 piece | What the code does |
|---|---|
| Classic PCAP + Radiotap | Finds each packet, skips the radio header |
| Beacon / probe response | SSID, BSSID, channel, RSN security |
| Authentication / association | Client state: authenticated then associated |
| Deauthentication / disassociation | Reason code + disconnected state |
| WPA2-PSK, WPA3-SAE, 802.1X, transition | RSN AKM suites 2, 8, 1, or 2+8 |
| Protected Management Frames | Reports whether a deauthentication was protected |
| Truncated tags | Counted as malformed, no crash |

The captures are standard `DLT_IEEE802_11_RADIO` (link type 127) PCAP files, so
the same fixtures open in Wireshark or `tshark` for side-by-side checking.

## Beyond single frames

- **Controller view** (`python/controller_view.py`) rolls several APs up into one
  WLAN, lists clients per AP, and detects a client roaming from AP-1 to AP-2.
- **Log correlation** (`python/log_correlator.py`) parses hostapd-style AP logs
  and reports disconnects that appear in the log but never on the air, which is
  the usual first step when a client "randomly" drops.
- **Regression runner** (`automation/regression.py`) reproduces defect WLAN-114
  (unprotected deauthentication kicks clients off) and then verifies the fix on
  a Protected Management Frames build.

## Run it (Python 3.9+, no extra packages)

```bash
python demo.py
python tests/test_wlan_model.py      # 16 unit tests
python automation/validate.py        # 19 feature checks
python automation/regression.py      # reproduce and verify defect WLAN-114
```

Analyze one capture:

```bash
python tools/generate_fixtures.py fixtures
python python/analyze.py fixtures/handshake.pcap
```

## Expected handshake result

A client that authenticates and associates should end in state `associated`.
A later deauthentication should move that station to `disconnected`.

## Layout

```text
python/wlan_model.py         working 802.11 parser
python/controller_view.py    multi-AP / WLAN / roaming roll-up
python/log_correlator.py     AP log vs capture comparison
python/analyze.py            JSON CLI
tools/generate_fixtures.py   lab captures and AP logs
automation/validate.py       19 feature checks
automation/regression.py     defect reproduce-and-verify run
tests/test_wlan_model.py     16 unit tests
src/main.cpp                 C++ analyzer (needs a compiler)
demo.py                      prints a readable lab report
```

## Honest scope

This is a protocol model on synthetic packets. It is not Cisco AP firmware,
not a controller, and not live Wireshark on a production network. It is meant
to show C/C++ + Python + 802.11 + test automation on evidence you can rerun.
