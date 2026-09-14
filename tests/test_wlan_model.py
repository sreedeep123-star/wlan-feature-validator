#!/usr/bin/env python3
"""Unit tests for the 802.11 model. Run: python tests/test_wlan_model.py"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "tools"))

from controller_view import build_controller_view  # noqa: E402
from generate_fixtures import generate, rsn_element, write_pcap, beacon  # noqa: E402
from log_correlator import correlate, parse_log  # noqa: E402
from wlan_model import (  # noqa: E402
    analyze_pcap_dict,
    channel_from_frequency,
    classify_eapol_key,
    classify_rsn,
)


class RsnTests(unittest.TestCase):
    def test_psk(self):
        body = rsn_element(2)[2:]
        self.assertEqual(classify_rsn(body), "WPA2-PSK")

    def test_sae(self):
        body = rsn_element(8)[2:]
        self.assertEqual(classify_rsn(body), "WPA3-SAE")

    def test_enterprise(self):
        body = rsn_element(1)[2:]
        self.assertEqual(classify_rsn(body), "WPA2-ENTERPRISE")

    def test_transition(self):
        body = rsn_element(2, 8)[2:]
        self.assertEqual(classify_rsn(body), "WPA3-TRANSITION")


class CaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.fixtures = Path(cls.tmp.name)
        generate(cls.fixtures)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_baseline_security_matrix(self):
        analysis = analyze_pcap_dict(self.fixtures / "lab-baseline.pcap")
        mapping = {net["ssid"]: net["security"] for net in analysis["networks"]}
        self.assertEqual(mapping["GuestOpen"], "OPEN")
        self.assertEqual(mapping["CorpWPA2"], "WPA2-PSK")
        self.assertEqual(mapping["SecureWPA3"], "WPA3-SAE")
        self.assertEqual(mapping["CampusDot1X"], "WPA2-ENTERPRISE")
        self.assertEqual(mapping["MixedWPA3"], "WPA3-TRANSITION")
        self.assertEqual(analysis["malformed"], 0)

    def test_handshake_reaches_associated(self):
        analysis = analyze_pcap_dict(self.fixtures / "handshake.pcap")
        self.assertEqual(len(analysis["stations"]), 1)
        self.assertEqual(analysis["stations"][0]["state"], "associated")
        self.assertEqual(analysis["frame_counts"]["data"], 1)

    def test_deauth_then_disconnect_state(self):
        analysis = analyze_pcap_dict(self.fixtures / "disconnect-event.pcap")
        self.assertEqual(analysis["deauthentication_events"][0]["reason"], 7)
        self.assertEqual(analysis["stations"][0]["state"], "disconnected")

    def test_malformed_does_not_crash(self):
        analysis = analyze_pcap_dict(self.fixtures / "malformed.pcap")
        self.assertGreaterEqual(analysis["malformed"], 1)

    def test_rejects_wrong_linktype(self):
        bad = self.fixtures / "bad-link.pcap"
        write_pcap(bad, [beacon("X", "02:00:00:00:00:09", "OPEN")])
        data = bytearray(bad.read_bytes())
        data[20:24] = b"\x01\x00\x00\x00"
        bad.write_bytes(data)
        with self.assertRaises(ValueError):
            analyze_pcap_dict(bad)


class KeyExchangeTests(unittest.TestCase):
    """WPA2/WPA3 4-way handshake decoding from EAPOL-Key frames."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.fixtures = Path(cls.tmp.name)
        generate(cls.fixtures)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_key_info_bits_map_to_message_numbers(self):
        self.assertEqual(classify_eapol_key(0x008A, 0), 1)
        self.assertEqual(classify_eapol_key(0x010A, 22), 2)
        self.assertEqual(classify_eapol_key(0x03CA, 0), 3)
        self.assertEqual(classify_eapol_key(0x030A, 0), 4)

    def test_group_key_frame_is_not_a_4way_message(self):
        self.assertIsNone(classify_eapol_key(0x0382, 0))

    def test_complete_four_way_marks_keys_installed(self):
        analysis = analyze_pcap_dict(self.fixtures / "wpa2-4way.pcap")
        self.assertEqual(analysis["frame_counts"]["eapol_key"], 4)
        shake = analysis["handshakes"][0]
        self.assertEqual(shake["messages"], [1, 2, 3, 4])
        self.assertTrue(shake["complete"])
        self.assertEqual(analysis["stations"][0]["state"], "key-exchange-complete")

    def test_incomplete_four_way_is_flagged(self):
        analysis = analyze_pcap_dict(self.fixtures / "wpa2-4way-incomplete.pcap")
        shake = analysis["handshakes"][0]
        self.assertEqual(shake["messages"], [1, 2])
        self.assertFalse(shake["complete"])


class PhyAndRfTests(unittest.TestCase):
    """PHY generation from capability elements, band/RSSI from Radiotap."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.fixtures = Path(cls.tmp.name)
        generate(cls.fixtures)
        analysis = analyze_pcap_dict(cls.fixtures / "phy-and-rf.pcap")
        cls.nets = {net["ssid"]: net for net in analysis["networks"]}
        cls.malformed = analysis["malformed"]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_radiotap_fields_do_not_corrupt_the_frame(self):
        self.assertEqual(self.malformed, 0)

    def test_detects_phy_generation(self):
        self.assertEqual(self.nets["LegacyNet"]["phy"], "802.11a/b/g")
        self.assertEqual(self.nets["WiFi4Net"]["phy"], "802.11n")
        self.assertEqual(self.nets["WiFi5Net"]["phy"], "802.11ac")
        self.assertEqual(self.nets["WiFi6Net"]["phy"], "802.11ax")

    def test_maps_frequency_to_band(self):
        self.assertEqual(self.nets["WiFi4Net"]["band"], "2.4 GHz")
        self.assertEqual(self.nets["WiFi5Net"]["band"], "5 GHz")
        self.assertEqual(self.nets["WiFi6Net"]["band"], "6 GHz")

    def test_frequency_to_channel_arithmetic(self):
        self.assertEqual(channel_from_frequency(2437), ("2.4 GHz", 6))
        self.assertEqual(channel_from_frequency(2484), ("2.4 GHz", 14))
        self.assertEqual(channel_from_frequency(5180), ("5 GHz", 36))
        self.assertEqual(channel_from_frequency(6135), ("6 GHz", 37))
        self.assertEqual(channel_from_frequency(1000), (None, None))

    def test_aggregates_signal_strength_per_bssid(self):
        signal = self.nets["WiFi6Net"]["signal"]
        self.assertEqual(signal["samples"], 2)
        self.assertEqual(signal["min_dbm"], -70)
        self.assertEqual(signal["max_dbm"], -64)
        self.assertEqual(signal["mean_dbm"], -67.0)


class ControllerViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.fixtures = Path(cls.tmp.name)
        generate(cls.fixtures)
        cls.view = build_controller_view(
            cls.fixtures / "roaming.pcap",
            {"02:00:00:00:00:02": "AP-1", "02:00:00:00:00:0a": "AP-2"},
        )

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_two_aps_one_wlan(self):
        self.assertEqual(len(self.view["access_points"]), 2)
        self.assertEqual(len(self.view["wlans"]), 1)
        self.assertEqual(self.view["wlans"][0]["ssid"], "CorpWPA2")

    def test_roam_direction(self):
        self.assertEqual(len(self.view["roam_events"]), 1)
        self.assertEqual(self.view["roam_events"][0]["from_ap"], "AP-1")
        self.assertEqual(self.view["roam_events"][0]["to_ap"], "AP-2")

    def test_no_roam_without_second_ap(self):
        view = build_controller_view(self.fixtures / "handshake.pcap")
        self.assertEqual(view["roam_events"], [])


class LogCorrelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.fixtures = Path(cls.tmp.name)
        generate(cls.fixtures)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_parses_hostapd_lines(self):
        events = parse_log(self.fixtures / "ap-events.log")
        self.assertEqual(len(events), 4)
        self.assertEqual(events[0]["event"], "authenticated")
        self.assertEqual(events[2]["reason"], 7)

    def test_log_agrees_with_capture(self):
        result = correlate(self.fixtures / "disconnect-event.pcap", self.fixtures / "ap-events.log")
        self.assertTrue(result["consistent"])
        self.assertEqual(len(result["matched"]), 2)

    def test_detects_log_only_disconnect(self):
        result = correlate(
            self.fixtures / "disconnect-event.pcap", self.fixtures / "ap-events-mismatch.log"
        )
        self.assertFalse(result["consistent"])
        self.assertEqual(len(result["logged_but_not_captured"]), 1)
        self.assertEqual(result["logged_but_not_captured"][0]["reason"], 3)


class RegressionTests(unittest.TestCase):
    def test_defect_reproduced_then_fixed(self):
        sys.path.insert(0, str(ROOT / "automation"))
        from regression import run  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            report = run(Path(tmp))
        self.assertTrue(report["reproduced_on_affected_build"])
        self.assertTrue(report["fix_verified"])
        self.assertEqual(report["verdict"], "FIXED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
