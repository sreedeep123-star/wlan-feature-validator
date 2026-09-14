#!/usr/bin/env python3
"""Generate deterministic synthetic 802.11 Radiotap PCAP fixtures."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

RADIOTAP = b"\x00\x00\x08\x00\x00\x00\x00\x00"
BROADCAST = b"\xff" * 6

LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"


def mac(value: str) -> bytes:
    return bytes.fromhex(value.replace(":", ""))


def radiotap_rf(frequency: int, signal_dbm: int) -> bytes:
    """Radiotap header carrying Rate, Channel and dBm antenna signal.

    Channel is 2-byte aligned and the signal is a signed byte, so the layout
    below matches what a real capture from a monitor-mode radio looks like.
    """
    present = (1 << 2) | (1 << 3) | (1 << 5)
    body = b"\x02"  # rate, 1 byte, no alignment padding needed
    body += b"\x00"  # pad so the channel field starts 2-byte aligned
    body += struct.pack("<HH", frequency, 0x0480)
    body += struct.pack("<b", signal_dbm)
    length = 8 + len(body)
    return struct.pack("<BBHI", 0, 0, length, present) + body


def ht_capabilities() -> bytes:
    return bytes([45, 26]) + b"\x00" * 26


def vht_capabilities() -> bytes:
    return bytes([191, 12]) + b"\x00" * 12


def he_capabilities() -> bytes:
    # Element ID 255 (extension) with extension ID 35 = HE Capabilities.
    return bytes([255, 11, 35]) + b"\x00" * 10


def rsn_element(*akm_suites: int) -> bytes:
    oui = b"\x00\x0f\xac"
    body = struct.pack("<H", 1) + oui + b"\x04"
    body += struct.pack("<H", 1) + oui + b"\x04"
    body += struct.pack("<H", len(akm_suites))
    for suite in akm_suites:
        body += oui + bytes([suite])
    return bytes([48, len(body)]) + body


def mgmt_header(subtype: int, da: bytes, sa: bytes, bssid: bytes, protected: bool = False) -> bytes:
    frame_control = (subtype << 4) | (0x4000 if protected else 0)
    return struct.pack("<H", frame_control) + b"\x00\x00" + da + sa + bssid + b"\x00\x00"


def beacon(ssid: str, bssid: str, security: str, channel: int = 6, hidden: bool = False) -> bytes:
    bssid_bytes = mac(bssid)
    header = mgmt_header(8, BROADCAST, bssid_bytes, bssid_bytes)
    capability = 0x0411 if security != "OPEN" else 0x0401
    fixed = b"\x00" * 8 + struct.pack("<HH", 100, capability)
    ssid_bytes = b"" if hidden else ssid.encode("utf-8")
    ssid_tag = bytes([0, len(ssid_bytes)]) + ssid_bytes
    channel_tag = bytes([3, 1, channel])
    security_tag = b""
    if security == "WPA2-PSK":
        security_tag = rsn_element(2)
    elif security == "WPA3-SAE":
        security_tag = rsn_element(8)
    elif security == "WPA2-ENTERPRISE":
        security_tag = rsn_element(1)
    elif security == "WPA3-TRANSITION":
        security_tag = rsn_element(2, 8)
    return RADIOTAP + header + fixed + ssid_tag + channel_tag + security_tag


def rf_beacon(
    ssid: str,
    bssid: str,
    security: str,
    channel: int,
    frequency: int,
    signal_dbm: int,
    phy: str = "802.11a/b/g",
) -> bytes:
    """Beacon with real Radiotap RF metadata and PHY capability elements."""
    bssid_bytes = mac(bssid)
    header = mgmt_header(8, BROADCAST, bssid_bytes, bssid_bytes)
    fixed = b"\x00" * 8 + struct.pack("<HH", 100, 0x0411)
    ssid_tag = bytes([0, len(ssid)]) + ssid.encode("utf-8")
    channel_tag = bytes([3, 1, channel])
    security_tag = rsn_element(8) if security == "WPA3-SAE" else rsn_element(2)
    phy_tags = b""
    if phy in ("802.11n", "802.11ac", "802.11ax"):
        phy_tags += ht_capabilities()
    if phy in ("802.11ac", "802.11ax"):
        phy_tags += vht_capabilities()
    if phy == "802.11ax":
        phy_tags += he_capabilities()
    return (
        radiotap_rf(frequency, signal_dbm)
        + header
        + fixed
        + ssid_tag
        + channel_tag
        + security_tag
        + phy_tags
    )


def eapol_key(bssid: str, station: str, message: int) -> bytes:
    """One message of the WPA2 4-way key exchange, carried in a QoS data frame."""
    key_info = {1: 0x008A, 2: 0x010A, 3: 0x03CA, 4: 0x030A}[message]
    key_data = b"\x30\x14" + b"\x00" * 20 if message == 2 else b""

    body = b"\x02"  # EAPOL-Key descriptor type: RSN
    body += struct.pack(">H", key_info)
    body += struct.pack(">H", 16)  # key length
    body += struct.pack(">Q", message)  # replay counter
    body += bytes([message]) * 32  # nonce
    body += b"\x00" * 16  # key IV
    body += b"\x00" * 8  # RSC
    body += b"\x00" * 8  # reserved
    body += b"\x11" * 16 if key_info & 0x0100 else b"\x00" * 16  # MIC
    body += struct.pack(">H", len(key_data)) + key_data

    eapol = b"\x02\x03" + struct.pack(">H", len(body)) + body

    ap = mac(bssid)
    sta = mac(station)
    from_ap = message in (1, 3)
    frame_control = (2 << 2) | (8 << 4) | (0x0200 if from_ap else 0x0100)
    if from_ap:
        addresses = sta + ap + ap
    else:
        addresses = ap + sta + ap
    header = struct.pack("<H", frame_control) + b"\x00\x00" + addresses + b"\x00\x00"
    qos = b"\x00\x00"
    return RADIOTAP + header + qos + LLC_SNAP_EAPOL + eapol


def probe_request(station: str) -> bytes:
    header = mgmt_header(4, BROADCAST, mac(station), BROADCAST)
    wildcard_ssid = b"\x00\x00"
    return RADIOTAP + header + wildcard_ssid


def probe_response(ssid: str, bssid: str, station: str, security: str, channel: int = 11) -> bytes:
    bssid_bytes = mac(bssid)
    header = mgmt_header(5, mac(station), bssid_bytes, bssid_bytes)
    capability = 0x0411
    fixed = b"\x00" * 8 + struct.pack("<HH", 100, capability)
    ssid_tag = bytes([0, len(ssid)]) + ssid.encode("utf-8")
    channel_tag = bytes([3, 1, channel])
    return RADIOTAP + header + fixed + ssid_tag + channel_tag + rsn_element(2)


def authentication(bssid: str, station: str, seq: int, from_ap: bool, algorithm: int = 0, status: int = 0) -> bytes:
    ap = mac(bssid)
    sta = mac(station)
    if from_ap:
        header = mgmt_header(11, sta, ap, ap)
    else:
        header = mgmt_header(11, ap, sta, ap)
    body = struct.pack("<HHH", algorithm, seq, status)
    return RADIOTAP + header + body


def association_request(ssid: str, bssid: str, station: str) -> bytes:
    ap = mac(bssid)
    sta = mac(station)
    header = mgmt_header(0, ap, sta, ap)
    fixed = struct.pack("<HH", 0x0411, 10)
    ssid_tag = bytes([0, len(ssid)]) + ssid.encode("utf-8")
    return RADIOTAP + header + fixed + ssid_tag


def association_response(bssid: str, station: str, status: int = 0) -> bytes:
    ap = mac(bssid)
    sta = mac(station)
    header = mgmt_header(1, sta, ap, ap)
    body = struct.pack("<HHH", 0x0411, status, 1)
    return RADIOTAP + header + body


def deauthentication(bssid: str, station: str, reason: int, protected: bool = False) -> bytes:
    ap = mac(bssid)
    sta = mac(station)
    header = mgmt_header(12, sta, ap, ap, protected=protected)
    return RADIOTAP + header + struct.pack("<H", reason)


def disassociation(bssid: str, station: str, reason: int) -> bytes:
    ap = mac(bssid)
    sta = mac(station)
    header = mgmt_header(10, sta, ap, ap)
    return RADIOTAP + header + struct.pack("<H", reason)


def qos_data(bssid: str, station: str) -> bytes:
    ap = mac(bssid)
    sta = mac(station)
    # FromDS data: FC type=2 subtype=8 (QoS data), FromDS bit
    frame_control = (2 << 2) | (8 << 4) | 0x0200
    header = struct.pack("<H", frame_control) + b"\x00\x00" + sta + ap + ap + b"\x00\x00"
    qos = b"\x00\x00"
    return RADIOTAP + header + qos + b"payload"


def malformed_beacon(bssid: str) -> bytes:
    bssid_bytes = mac(bssid)
    header = mgmt_header(8, BROADCAST, bssid_bytes, bssid_bytes)
    fixed = b"\x00" * 8 + struct.pack("<HH", 100, 0x0401)
    truncated_ie = b"\x00\x20" + b"AB"  # claims 32-byte SSID, only 2 bytes follow
    return RADIOTAP + header + fixed + truncated_ie


def write_pcap(path: Path, packets: list[bytes]) -> None:
    global_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        127,
    )
    with path.open("wb") as capture:
        capture.write(global_header)
        for index, packet in enumerate(packets):
            capture.write(struct.pack("<IIII", 1_700_000_000 + index, 0, len(packet), len(packet)))
            capture.write(packet)


def generate(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    sta = "02:00:00:00:10:01"
    corp = "02:00:00:00:00:02"

    write_pcap(
        output / "lab-baseline.pcap",
        [
            beacon("GuestOpen", "02:00:00:00:00:01", "OPEN", channel=1),
            beacon("CorpWPA2", corp, "WPA2-PSK", channel=6),
            beacon("SecureWPA3", "02:00:00:00:00:03", "WPA3-SAE", channel=11),
            beacon("CampusDot1X", "02:00:00:00:00:04", "WPA2-ENTERPRISE", channel=36),
            beacon("MixedWPA3", "02:00:00:00:00:05", "WPA3-TRANSITION", channel=6),
            beacon("HiddenNet", "02:00:00:00:00:06", "WPA2-PSK", channel=6, hidden=True),
        ],
    )
    write_pcap(
        output / "disconnect-event.pcap",
        [
            beacon("CorpWPA2", corp, "WPA2-PSK"),
            deauthentication(corp, sta, reason=7, protected=False),
            disassociation(corp, sta, reason=8),
        ],
    )
    write_pcap(
        output / "handshake.pcap",
        [
            beacon("CorpWPA2", corp, "WPA2-PSK", channel=6),
            authentication(corp, sta, seq=1, from_ap=False),
            authentication(corp, sta, seq=2, from_ap=True),
            association_request("CorpWPA2", corp, sta),
            association_response(corp, sta, status=0),
            qos_data(corp, sta),
        ],
    )
    write_pcap(
        output / "probe-scan.pcap",
        [
            probe_request(sta),
            probe_response("CafeWiFi", "02:00:00:00:00:07", sta, "WPA2-PSK", channel=11),
        ],
    )
    write_pcap(
        output / "malformed.pcap",
        [malformed_beacon("02:00:00:00:00:08")],
    )

    # Two APs advertising one SSID: the client associates to AP1, is moved off,
    # then associates to AP2. A controller should report this as a roam.
    ap2 = "02:00:00:00:00:0a"
    write_pcap(
        output / "roaming.pcap",
        [
            beacon("CorpWPA2", corp, "WPA2-PSK", channel=6),
            beacon("CorpWPA2", ap2, "WPA2-PSK", channel=36),
            authentication(corp, sta, seq=1, from_ap=False),
            authentication(corp, sta, seq=2, from_ap=True),
            association_request("CorpWPA2", corp, sta),
            association_response(corp, sta, status=0),
            disassociation(corp, sta, reason=8),
            authentication(ap2, sta, seq=1, from_ap=False),
            authentication(ap2, sta, seq=2, from_ap=True),
            association_request("CorpWPA2", ap2, sta),
            association_response(ap2, sta, status=0),
        ],
    )

    # Full WPA2 join: open auth, association, then the 4-way key exchange.
    write_pcap(
        output / "wpa2-4way.pcap",
        [
            beacon("CorpWPA2", corp, "WPA2-PSK", channel=6),
            authentication(corp, sta, seq=1, from_ap=False),
            authentication(corp, sta, seq=2, from_ap=True),
            association_request("CorpWPA2", corp, sta),
            association_response(corp, sta, status=0),
            eapol_key(corp, sta, 1),
            eapol_key(corp, sta, 2),
            eapol_key(corp, sta, 3),
            eapol_key(corp, sta, 4),
        ],
    )

    # Key exchange that dies after M2: the client never gets keys installed.
    write_pcap(
        output / "wpa2-4way-incomplete.pcap",
        [
            beacon("CorpWPA2", corp, "WPA2-PSK", channel=6),
            eapol_key(corp, sta, 1),
            eapol_key(corp, sta, 2),
        ],
    )

    # Radios on three bands advertising three PHY generations.
    write_pcap(
        output / "phy-and-rf.pcap",
        [
            rf_beacon("LegacyNet", "02:00:00:00:00:20", "WPA2-PSK", 6, 2437, -42),
            rf_beacon("WiFi4Net", "02:00:00:00:00:21", "WPA2-PSK", 11, 2462, -58, "802.11n"),
            rf_beacon("WiFi5Net", "02:00:00:00:00:22", "WPA2-PSK", 36, 5180, -61, "802.11ac"),
            rf_beacon("WiFi6Net", "02:00:00:00:00:23", "WPA3-SAE", 37, 6135, -70, "802.11ax"),
            rf_beacon("WiFi6Net", "02:00:00:00:00:23", "WPA3-SAE", 37, 6135, -64, "802.11ax"),
        ],
    )

    # Protected Management Frames enabled: the deauthentication is protected.
    write_pcap(
        output / "pmf-enabled.pcap",
        [
            beacon("SecureWPA3", "02:00:00:00:00:03", "WPA3-SAE", channel=11),
            deauthentication("02:00:00:00:00:03", sta, reason=7, protected=True),
        ],
    )

    # AP log that agrees with disconnect-event.pcap.
    (output / "ap-events.log").write_text(
        "\n".join(
            [
                "Nov 14 09:21:02 ap1 hostapd: wlan0: STA 02:00:00:00:10:01 IEEE 802.11: authenticated",
                "Nov 14 09:21:02 ap1 hostapd: wlan0: STA 02:00:00:00:10:01 IEEE 802.11: associated (aid 1)",
                "Nov 14 09:24:48 ap1 hostapd: wlan0: STA 02:00:00:00:10:01 IEEE 802.11: "
                "deauthenticated due to inactivity (timer DEAUTH/REMOVE) reason 7",
                "Nov 14 09:24:49 ap1 hostapd: wlan0: STA 02:00:00:00:10:01 IEEE 802.11: "
                "disassociated reason 8",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # Same log with a disconnect the capture never shows: the mismatch case.
    (output / "ap-events-mismatch.log").write_text(
        "\n".join(
            [
                "Nov 14 09:21:02 ap1 hostapd: wlan0: STA 02:00:00:00:10:01 IEEE 802.11: authenticated",
                "Nov 14 09:24:48 ap1 hostapd: wlan0: STA 02:00:00:00:10:01 IEEE 802.11: "
                "deauthenticated due to inactivity (timer DEAUTH/REMOVE) reason 7",
                "Nov 14 09:24:48 ap1 hostapd: wlan0: STA 02:00:00:00:99:99 IEEE 802.11: "
                "deauthenticated due to local deauth request reason 3",
                "Nov 14 09:24:49 ap1 hostapd: wlan0: STA 02:00:00:00:10:01 IEEE 802.11: "
                "disassociated reason 8",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    generate(args.output)
    print(f"Generated synthetic PCAP fixtures in {args.output}")


if __name__ == "__main__":
    main()
