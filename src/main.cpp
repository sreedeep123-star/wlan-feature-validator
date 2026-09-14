#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::uint16_t u16le(const std::uint8_t* p) {
  return static_cast<std::uint16_t>(p[0]) |
         (static_cast<std::uint16_t>(p[1]) << 8U);
}

std::uint32_t u32le(const std::uint8_t* p) {
  return static_cast<std::uint32_t>(p[0]) |
         (static_cast<std::uint32_t>(p[1]) << 8U) |
         (static_cast<std::uint32_t>(p[2]) << 16U) |
         (static_cast<std::uint32_t>(p[3]) << 24U);
}

std::string json_escape(const std::string& input) {
  std::ostringstream out;
  for (const char c : input) {
    switch (c) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\n':
        out << "\\n";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20U) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(static_cast<unsigned char>(c));
        } else {
          out << c;
        }
    }
  }
  return out.str();
}

std::string mac_string(const std::uint8_t* mac) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (int i = 0; i < 6; ++i) {
    if (i != 0) {
      out << ':';
    }
    out << std::setw(2) << static_cast<int>(mac[i]);
  }
  return out.str();
}

struct Network {
  std::string ssid;
  std::string bssid;
  std::string security;
};

struct DeauthEvent {
  std::string transmitter;
  std::uint16_t reason{};
  bool protected_frame{};
};

struct Analysis {
  std::size_t packets{};
  std::size_t malformed{};
  std::map<std::string, Network> networks;
  std::vector<DeauthEvent> deauth_events;
};

std::string classify_rsn(const std::uint8_t* data, std::size_t size) {
  if (size < 8 || u16le(data) != 1) {
    return "RSN-UNKNOWN";
  }

  std::size_t offset = 2 + 4;
  if (offset + 2 > size) {
    return "RSN-UNKNOWN";
  }
  const std::uint16_t pairwise_count = u16le(data + offset);
  offset += 2 + static_cast<std::size_t>(pairwise_count) * 4;
  if (offset + 2 > size) {
    return "RSN-UNKNOWN";
  }
  const std::uint16_t akm_count = u16le(data + offset);
  offset += 2;

  bool has_psk = false;
  bool has_sae = false;
  bool has_dot1x = false;
  for (std::uint16_t i = 0; i < akm_count && offset + 4 <= size; ++i) {
    const bool ieee_oui =
        data[offset] == 0x00 && data[offset + 1] == 0x0f &&
        data[offset + 2] == 0xac;
    if (ieee_oui) {
      const std::uint8_t suite = data[offset + 3];
      has_dot1x = has_dot1x || suite == 1;
      has_psk = has_psk || suite == 2;
      has_sae = has_sae || suite == 8;
    }
    offset += 4;
  }

  if (has_sae) {
    return "WPA3-SAE";
  }
  if (has_psk) {
    return "WPA2-PSK";
  }
  if (has_dot1x) {
    return "WPA2-ENTERPRISE";
  }
  return "RSN-UNKNOWN";
}

void analyze_beacon(const std::uint8_t* frame, std::size_t size,
                    Analysis& result) {
  constexpr std::size_t kMacHeader = 24;
  constexpr std::size_t kBeaconFixed = 12;
  if (size < kMacHeader + kBeaconFixed) {
    ++result.malformed;
    return;
  }

  std::string ssid = "<hidden>";
  std::string security = "OPEN";
  std::size_t offset = kMacHeader + kBeaconFixed;
  while (offset + 2 <= size) {
    const std::uint8_t id = frame[offset];
    const std::size_t length = frame[offset + 1];
    offset += 2;
    if (offset + length > size) {
      ++result.malformed;
      return;
    }
    if (id == 0) {
      ssid = length == 0
                 ? "<hidden>"
                 : std::string(reinterpret_cast<const char*>(frame + offset),
                               length);
    } else if (id == 48) {
      security = classify_rsn(frame + offset, length);
    }
    offset += length;
  }

  const std::string bssid = mac_string(frame + 16);
  result.networks[bssid] = Network{ssid, bssid, security};
}

void analyze_frame(const std::uint8_t* frame, std::size_t size,
                   Analysis& result) {
  if (size < 24) {
    ++result.malformed;
    return;
  }
  const std::uint16_t frame_control = u16le(frame);
  const std::uint8_t type = (frame_control >> 2U) & 0x03U;
  const std::uint8_t subtype = (frame_control >> 4U) & 0x0fU;
  const bool protected_frame = (frame_control & 0x4000U) != 0;

  if (type == 0 && subtype == 8) {
    analyze_beacon(frame, size, result);
  } else if (type == 0 && subtype == 12) {
    if (size < 26) {
      ++result.malformed;
      return;
    }
    result.deauth_events.push_back(
        DeauthEvent{mac_string(frame + 10), u16le(frame + 24),
                    protected_frame});
  }
}

Analysis analyze_pcap(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("cannot open capture: " + path);
  }

  std::vector<std::uint8_t> global(24);
  if (!input.read(reinterpret_cast<char*>(global.data()),
                  static_cast<std::streamsize>(global.size()))) {
    throw std::runtime_error("capture is shorter than the PCAP header");
  }
  if (u32le(global.data()) != 0xa1b2c3d4U) {
    throw std::runtime_error("only little-endian classic PCAP is supported");
  }
  if (u32le(global.data() + 20) != 127U) {
    throw std::runtime_error("capture link type must be IEEE 802.11 Radiotap");
  }

  Analysis result;
  std::vector<std::uint8_t> record_header(16);
  while (input.read(reinterpret_cast<char*>(record_header.data()), 16)) {
    const std::uint32_t captured_length = u32le(record_header.data() + 8);
    if (captured_length > 1024U * 1024U) {
      throw std::runtime_error("refusing packet larger than 1 MiB");
    }
    std::vector<std::uint8_t> packet(captured_length);
    if (!input.read(reinterpret_cast<char*>(packet.data()),
                    static_cast<std::streamsize>(packet.size()))) {
      ++result.malformed;
      break;
    }
    ++result.packets;
    if (packet.size() < 8 || packet[0] != 0 || packet[1] != 0) {
      ++result.malformed;
      continue;
    }
    const std::size_t radiotap_length = u16le(packet.data() + 2);
    if (radiotap_length < 8 || radiotap_length >= packet.size()) {
      ++result.malformed;
      continue;
    }
    analyze_frame(packet.data() + radiotap_length,
                  packet.size() - radiotap_length, result);
  }
  return result;
}

void print_json(const Analysis& analysis) {
  std::cout << "{\n"
            << "  \"packets\": " << analysis.packets << ",\n"
            << "  \"malformed\": " << analysis.malformed << ",\n"
            << "  \"networks\": [";
  bool first = true;
  for (const auto& entry : analysis.networks) {
    const Network& network = entry.second;
    std::cout << (first ? "\n" : ",\n")
              << "    {\"ssid\": \"" << json_escape(network.ssid)
              << "\", \"bssid\": \"" << network.bssid
              << "\", \"security\": \"" << network.security << "\"}";
    first = false;
  }
  if (!first) {
    std::cout << '\n';
  }
  std::cout << "  ],\n  \"deauthentication_events\": [";
  first = true;
  for (const auto& event : analysis.deauth_events) {
    std::cout << (first ? "\n" : ",\n")
              << "    {\"transmitter\": \"" << event.transmitter
              << "\", \"reason\": " << event.reason
              << ", \"protected\": "
              << (event.protected_frame ? "true" : "false") << "}";
    first = false;
  }
  if (!first) {
    std::cout << '\n';
  }
  std::cout << "  ]\n}\n";
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: wlan-analyzer <radiotap-capture.pcap>\n";
    return 2;
  }
  try {
    print_json(analyze_pcap(argv[1]));
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "error: " << error.what() << '\n';
    return 1;
  }
}
