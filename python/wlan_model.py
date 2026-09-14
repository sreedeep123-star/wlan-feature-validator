#!/usr/bin/env python3
"""Working 802.11 / Radiotap / PCAP model.

This is a real parser, not a mock. It reads classic PCAP files whose packets
start with a Radiotap header, then an IEEE 802.11 MAC frame. Every length is
checked before a field is read so truncated captures count as malformed
instead of crashing.
"""

from __future__ import annotations

import json
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

PCAP_MAGIC_LE = 0xA1B2C3D4
DLT_IEEE802_11_RADIO = 127
IEEE_RSN_OUI = b"\x00\x0f\xac"

TYPE_MGMT = 0
TYPE_DATA = 2

ST_ASSOC_REQ = 0
ST_ASSOC_RESP = 1
ST_PROBE_REQ = 4
ST_PROBE_RESP = 5
ST_BEACON = 8
ST_DISASSOC = 10
ST_AUTH = 11
ST_DEAUTH = 12


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def mac_str(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


@dataclass
class Network:
    ssid: str
    bssid: str
    security: str = "OPEN"
    channel: Optional[int] = None
    beacons: int = 0
    probe_responses: int = 0


@dataclass
class Station:
    mac: str
    bssid: str
    state: str = "seen"
    auth_algorithm: Optional[int] = None


@dataclass
class MgmtEvent:
    transmitter: str
    receiver: str
    bssid: str
    reason: int
    protected: bool


@dataclass
class Analysis:
    packets: int = 0
    malformed: int = 0
    frame_counts: Counter = field(default_factory=Counter)
    networks: dict[str, Network] = field(default_factory=dict)
    stations: dict[str, Station] = field(default_factory=dict)
    deauthentication_events: list[MgmtEvent] = field(default_factory=list)
    disassociation_events: list[MgmtEvent] = field(default_factory=list)
    authentications: list[dict] = field(default_factory=list)
    associations: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        counts = {
            "beacon": 0,
            "probe_request": 0,
            "probe_response": 0,
            "authentication": 0,
            "association_request": 0,
            "association_response": 0,
            "deauthentication": 0,
            "disassociation": 0,
            "data": 0,
            "other": 0,
        }
        counts.update(self.frame_counts)
        return {
            "packets": self.packets,
            "malformed": self.malformed,
            "frame_counts": counts,
            "networks": [
                {
                    "ssid": net.ssid,
                    "bssid": net.bssid,
                    "security": net.security,
                    "channel": net.channel,
                    "beacons": net.beacons,
                    "probe_responses": net.probe_responses,
                }
                for net in sorted(self.networks.values(), key=lambda item: item.bssid)
            ],
            "stations": [
                {
                    "mac": sta.mac,
                    "bssid": sta.bssid,
                    "state": sta.state,
                    "auth_algorithm": sta.auth_algorithm,
                }
                for sta in sorted(self.stations.values(), key=lambda item: item.mac)
            ],
            "deauthentication_events": [
                {
                    "transmitter": event.transmitter,
                    "receiver": event.receiver,
                    "bssid": event.bssid,
                    "reason": event.reason,
                    "protected": event.protected,
                }
                for event in self.deauthentication_events
            ],
            "disassociation_events": [
                {
                    "transmitter": event.transmitter,
                    "receiver": event.receiver,
                    "bssid": event.bssid,
                    "reason": event.reason,
                    "protected": event.protected,
                }
                for event in self.disassociation_events
            ],
            "authentications": self.authentications,
            "associations": self.associations,
        }


def classify_rsn(body: bytes) -> str:
    """Classify WPA2/WPA3 from an RSN information element body (tag 48)."""
    if len(body) < 8 or u16(body, 0) != 1:
        return "RSN-UNKNOWN"
    offset = 6  # version + group cipher
    if offset + 2 > len(body):
        return "RSN-UNKNOWN"
    pairwise = u16(body, offset)
    offset += 2 + pairwise * 4
    if offset + 2 > len(body):
        return "RSN-UNKNOWN"
    akm_count = u16(body, offset)
    offset += 2
    has_psk = has_sae = has_dot1x = False
    for _ in range(akm_count):
        if offset + 4 > len(body):
            return "RSN-UNKNOWN"
        if body[offset : offset + 3] == IEEE_RSN_OUI:
            suite = body[offset + 3]
            has_dot1x = has_dot1x or suite == 1
            has_psk = has_psk or suite == 2
            has_sae = has_sae or suite == 8
        offset += 4
    if has_sae and has_psk:
        return "WPA3-TRANSITION"
    if has_sae:
        return "WPA3-SAE"
    if has_psk:
        return "WPA2-PSK"
    if has_dot1x:
        return "WPA2-ENTERPRISE"
    return "RSN-UNKNOWN"


def parse_information_elements(blob: bytes) -> tuple[dict, bool]:
    """Return (fields, malformed). malformed=True if a tag length overruns."""
    fields: dict = {"ssid": None, "channel": None, "security": "OPEN"}
    offset = 0
    while offset + 2 <= len(blob):
        tag = blob[offset]
        length = blob[offset + 1]
        offset += 2
        if offset + length > len(blob):
            return fields, True
        value = blob[offset : offset + length]
        offset += length
        if tag == 0:
            fields["ssid"] = "<hidden>" if length == 0 else value.decode("utf-8", "replace")
        elif tag == 3 and length >= 1:
            fields["channel"] = value[0]
        elif tag == 48:
            fields["security"] = classify_rsn(value)
    if offset != len(blob):
        return fields, True
    return fields, False


def station_key(mac: str, bssid: str) -> str:
    return f"{mac}|{bssid}"


def upsert_station(result: Analysis, mac: str, bssid: str) -> Station:
    key = station_key(mac, bssid)
    if key not in result.stations:
        result.stations[key] = Station(mac=mac, bssid=bssid)
    return result.stations[key]


def upsert_network(result: Analysis, bssid: str, fields: dict, kind: str) -> None:
    net = result.networks.get(bssid)
    if net is None:
        ssid = fields["ssid"] if fields["ssid"] is not None else "<hidden>"
        net = Network(ssid=ssid, bssid=bssid, security=fields["security"], channel=fields["channel"])
        result.networks[bssid] = net
    else:
        if fields["ssid"]:
            net.ssid = fields["ssid"]
        if fields["security"] != "OPEN":
            net.security = fields["security"]
        if fields["channel"] is not None:
            net.channel = fields["channel"]
    if kind == "beacon":
        net.beacons += 1
    elif kind == "probe_response":
        net.probe_responses += 1


def analyze_mgmt(frame: bytes, result: Analysis) -> None:
    if len(frame) < 24:
        result.malformed += 1
        return

    frame_control = u16(frame, 0)
    subtype = (frame_control >> 4) & 0x0F
    protected = bool(frame_control & 0x4000)
    da = mac_str(frame[4:10])
    sa = mac_str(frame[10:16])
    bssid = mac_str(frame[16:22])

    names = {
        ST_ASSOC_REQ: "association_request",
        ST_ASSOC_RESP: "association_response",
        ST_PROBE_REQ: "probe_request",
        ST_PROBE_RESP: "probe_response",
        ST_BEACON: "beacon",
        ST_DISASSOC: "disassociation",
        ST_AUTH: "authentication",
        ST_DEAUTH: "deauthentication",
    }
    result.frame_counts[names.get(subtype, "other")] += 1

    if subtype in (ST_BEACON, ST_PROBE_RESP):
        if len(frame) < 36:
            result.malformed += 1
            return
        fields, bad = parse_information_elements(frame[36:])
        if bad:
            result.malformed += 1
        kind = "beacon" if subtype == ST_BEACON else "probe_response"
        upsert_network(result, bssid, fields, kind)
        return

    if subtype == ST_AUTH:
        if len(frame) < 30:
            result.malformed += 1
            return
        algorithm = u16(frame, 24)
        seq = u16(frame, 26)
        status = u16(frame, 28)
        sta_mac = sa if sa != bssid else da
        record = {
            "station": sta_mac,
            "bssid": bssid,
            "algorithm": algorithm,
            "sequence": seq,
            "status": status,
        }
        result.authentications.append(record)
        station = upsert_station(result, sta_mac, bssid)
        station.auth_algorithm = algorithm
        if status == 0:
            station.state = "authenticated"
        return

    if subtype == ST_ASSOC_REQ:
        if len(frame) < 28:
            result.malformed += 1
            return
        fields, bad = parse_information_elements(frame[28:])
        if bad:
            result.malformed += 1
        upsert_station(result, sa, bssid)
        result.associations.append(
            {
                "direction": "request",
                "station": sa,
                "bssid": bssid,
                "ssid": fields["ssid"],
                "status": None,
            }
        )
        return

    if subtype == ST_ASSOC_RESP:
        if len(frame) < 30:
            result.malformed += 1
            return
        status = u16(frame, 26)
        station = upsert_station(result, da, bssid)
        result.associations.append(
            {
                "direction": "response",
                "station": da,
                "bssid": bssid,
                "ssid": None,
                "status": status,
            }
        )
        if status == 0:
            station.state = "associated"
        return

    if subtype in (ST_DEAUTH, ST_DISASSOC):
        if len(frame) < 26:
            result.malformed += 1
            return
        event = MgmtEvent(
            transmitter=sa,
            receiver=da,
            bssid=bssid,
            reason=u16(frame, 24),
            protected=protected,
        )
        sta_mac = sa if sa != bssid else da
        station = upsert_station(result, sta_mac, bssid)
        station.state = "disconnected"
        if subtype == ST_DEAUTH:
            result.deauthentication_events.append(event)
        else:
            result.disassociation_events.append(event)


def analyze_frame(frame: bytes, result: Analysis) -> None:
    if len(frame) < 2:
        result.malformed += 1
        return
    frame_control = u16(frame, 0)
    frame_type = (frame_control >> 2) & 0x03
    if frame_type == TYPE_MGMT:
        analyze_mgmt(frame, result)
    elif frame_type == TYPE_DATA:
        result.frame_counts["data"] += 1
    else:
        result.frame_counts["other"] += 1


def strip_radiotap(packet: bytes) -> Optional[bytes]:
    if len(packet) < 8:
        return None
    version, pad, length = struct.unpack_from("<BBH", packet, 0)
    if version != 0 or length < 8 or length >= len(packet):
        return None
    return packet[length:]


def analyze_pcap(path: Path) -> Analysis:
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise ValueError("capture is shorter than the PCAP header")
    magic = u32(data, 0)
    if magic != PCAP_MAGIC_LE:
        raise ValueError("only little-endian classic PCAP is supported")
    if u32(data, 20) != DLT_IEEE802_11_RADIO:
        raise ValueError("capture link type must be IEEE 802.11 Radiotap")

    result = Analysis()
    offset = 24
    while offset + 16 <= len(data):
        captured = u32(data, offset + 8)
        offset += 16
        if captured > 1024 * 1024 or offset + captured > len(data):
            result.malformed += 1
            break
        packet = data[offset : offset + captured]
        offset += captured
        result.packets += 1
        frame = strip_radiotap(packet)
        if frame is None:
            result.malformed += 1
            continue
        analyze_frame(frame, result)
    return result


def analyze_pcap_dict(path: Path) -> dict:
    return analyze_pcap(path).to_dict()


def dumps(analysis: dict) -> str:
    return json.dumps(analysis, indent=2) + "\n"
