#include "wirelens/parser.hpp"

#include "wirelens/byte_reader.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>

namespace wirelens {
namespace {

struct TcpFacts {
  bool valid = false;
  std::string source;
  std::string destination;
  std::uint16_t sourcePort = 0;
  std::uint16_t destinationPort = 0;
  std::uint32_t sequence = 0;
  std::uint32_t acknowledgment = 0;
  std::uint8_t flags = 0;
};

struct ParsedPacket {
  Packet packet;
  TcpFacts tcp;
};

ParseError error(std::string code, std::string message, std::optional<std::size_t> offset = std::nullopt,
                 std::optional<std::size_t> packet = std::nullopt) {
  return ParseError{std::move(code), std::move(message), offset, packet};
}

std::string decimal(const std::uint64_t value) { return std::to_string(value); }

bool checked_timestamp(const std::uint32_t seconds, const std::uint32_t fraction,
                       const std::uint64_t multiplier, std::string& output) {
  constexpr auto max = std::numeric_limits<std::uint64_t>::max();
  const auto whole = static_cast<std::uint64_t>(seconds) * 1000000000ULL;
  if (fraction != 0 && static_cast<std::uint64_t>(fraction) > (max - whole) / multiplier) {
    return false;
  }
  output = decimal(whole + static_cast<std::uint64_t>(fraction) * multiplier);
  return true;
}

std::string mac(const std::span<const std::byte> bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string value;
  value.reserve(17);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    if (i != 0) value.push_back(':');
    const auto octet = std::to_integer<unsigned>(bytes[i]);
    value.push_back(digits[octet >> 4U]);
    value.push_back(digits[octet & 0x0fU]);
  }
  return value;
}

std::string ipv4(const std::span<const std::byte> bytes) {
  return std::to_string(std::to_integer<unsigned>(bytes[0])) + "." +
         std::to_string(std::to_integer<unsigned>(bytes[1])) + "." +
         std::to_string(std::to_integer<unsigned>(bytes[2])) + "." +
         std::to_string(std::to_integer<unsigned>(bytes[3]));
}

ByteRange range(const std::size_t captureOffset, const std::size_t packetOffset,
                const std::size_t length) {
  return ByteRange{captureOffset, packetOffset, length};
}

void add_field(ProtocolLayer& layer, std::string name, std::string value,
               const std::size_t captureOffset, const std::size_t packetOffset,
               const std::size_t length) {
  layer.fields.push_back(ProtocolField{std::move(name), std::move(value),
                                       range(captureOffset + packetOffset, packetOffset, length), std::nullopt});
}

std::string flag_text(const std::uint8_t flags) {
  std::string result;
  if ((flags & 0x02U) != 0) result += "SYN";
  if ((flags & 0x10U) != 0) { if (!result.empty()) result += ", "; result += "ACK"; }
  if ((flags & 0x01U) != 0) { if (!result.empty()) result += ", "; result += "FIN"; }
  if ((flags & 0x04U) != 0) { if (!result.empty()) result += ", "; result += "RST"; }
  return result.empty() ? "none" : result;
}

std::optional<ProtocolLayer> parse_tcp(const std::span<const std::byte> payload,
                                       const std::size_t captureOffset,
                                       const std::size_t packetOffset, TcpFacts& facts) {
  if (payload.size() < 20) return std::nullopt;
  const auto dataOffset = static_cast<std::size_t>(std::to_integer<unsigned>(payload[12]) >> 4U) * 4U;
  if (dataOffset < 20 || dataOffset > payload.size()) return std::nullopt;
  const auto u16be = [&](std::size_t offset) {
    return static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(payload[offset]) << 8U) |
                                      std::to_integer<std::uint8_t>(payload[offset + 1]));
  };
  const auto u32be = [&](std::size_t offset) {
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(payload[offset])) << 24U) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(payload[offset + 1])) << 16U) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(payload[offset + 2])) << 8U) |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(payload[offset + 3]));
  };
  const auto flags = std::to_integer<std::uint8_t>(payload[13]);
  ProtocolLayer layer{"TCP", "TCP", {}, {}, std::nullopt, std::nullopt};
  layer.byteRange = range(captureOffset + packetOffset, packetOffset, dataOffset);
  add_field(layer, "sourcePort", std::to_string(u16be(0)), captureOffset, packetOffset, 2);
  add_field(layer, "destinationPort", std::to_string(u16be(2)), captureOffset, packetOffset + 2, 2);
  add_field(layer, "sequenceNumber", std::to_string(u32be(4)), captureOffset, packetOffset + 4, 4);
  add_field(layer, "acknowledgmentNumber", std::to_string(u32be(8)), captureOffset, packetOffset + 8, 4);
  add_field(layer, "dataOffset", std::to_string(dataOffset), captureOffset, packetOffset + 12, 1);
  add_field(layer, "flags", flag_text(flags), captureOffset, packetOffset + 12, 2);
  add_field(layer, "window", std::to_string(u16be(14)), captureOffset, packetOffset + 14, 2);
  facts = TcpFacts{true, {}, {}, u16be(0), u16be(2), u32be(4), u32be(8), flags};
  return layer;
}

std::optional<ProtocolLayer> parse_ipv4(const std::span<const std::byte> payload,
                                         const std::size_t captureOffset,
                                         const std::size_t packetOffset, TcpFacts& facts,
                                         Packet& packet) {
  if (payload.size() < 20) return std::nullopt;
  const auto version = std::to_integer<unsigned>(payload[0]) >> 4U;
  const auto headerLength = static_cast<std::size_t>(std::to_integer<unsigned>(payload[0]) & 0x0fU) * 4U;
  if (version != 4 || headerLength < 20 || headerLength > payload.size()) return std::nullopt;
  const auto u16be = [&](std::size_t offset) {
    return static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(payload[offset]) << 8U) |
                                      std::to_integer<std::uint8_t>(payload[offset + 1]));
  };
  const auto totalLength = static_cast<std::size_t>(u16be(2));
  if (totalLength < headerLength) return std::nullopt;
  const auto boundedLength = std::min(totalLength, payload.size());
  const auto source = ipv4(payload.subspan(12, 4));
  const auto destination = ipv4(payload.subspan(16, 4));
  const auto protocol = std::to_integer<unsigned>(payload[9]);
  ProtocolLayer layer{"IPV4", "IPv4", {}, {}, std::nullopt, std::nullopt};
  layer.byteRange = range(captureOffset + packetOffset, packetOffset, boundedLength);
  add_field(layer, "version", std::to_string(version), captureOffset, packetOffset, 1);
  add_field(layer, "headerLength", std::to_string(headerLength), captureOffset, packetOffset, 1);
  add_field(layer, "totalLength", std::to_string(totalLength), captureOffset, packetOffset + 2, 2);
  add_field(layer, "ttl", std::to_string(std::to_integer<unsigned>(payload[8])), captureOffset, packetOffset + 8, 1);
  add_field(layer, "protocol", std::to_string(protocol), captureOffset, packetOffset + 9, 1);
  add_field(layer, "source", source, captureOffset, packetOffset + 12, 4);
  add_field(layer, "destination", destination, captureOffset, packetOffset + 16, 4);
  packet.sourceAddress = source;
  packet.destinationAddress = destination;
  if (protocol == 6 && boundedLength >= headerLength) {
    const auto tcp = parse_tcp(payload.subspan(headerLength, boundedLength - headerLength), captureOffset,
                               packetOffset + headerLength, facts);
    if (tcp) {
      facts.source = source;
      facts.destination = destination;
      packet.sourcePort = facts.sourcePort;
      packet.destinationPort = facts.destinationPort;
      layer.children.push_back(*tcp);
    }
  }
  return layer;
}

std::optional<ProtocolLayer> parse_ethernet(const std::span<const std::byte> frame,
                                            const std::size_t captureOffset, Packet& packet,
                                            TcpFacts& facts) {
  if (frame.size() < 14) return std::nullopt;
  ProtocolLayer layer{"ETHERNET", "Ethernet II", {}, {}, std::nullopt, std::nullopt};
  layer.byteRange = range(captureOffset, 0, frame.size());
  add_field(layer, "destinationMac", mac(frame.subspan(0, 6)), captureOffset, 0, 6);
  add_field(layer, "sourceMac", mac(frame.subspan(6, 6)), captureOffset, 6, 6);
  auto etherType = static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(frame[12]) << 8U) |
                                              std::to_integer<std::uint8_t>(frame[13]));
  add_field(layer, "etherType", std::to_string(etherType), captureOffset, 12, 2);
  std::size_t networkOffset = 14;
  while (etherType == 0x8100U || etherType == 0x88a8U) {
    if (frame.size() < networkOffset + 4) return layer;
    const auto vlan = static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(frame[networkOffset]) << 8U) |
                                                 std::to_integer<std::uint8_t>(frame[networkOffset + 1]));
    add_field(layer, "vlanId", std::to_string(vlan & 0x0fffU), captureOffset, networkOffset, 2);
    etherType = static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(frame[networkOffset + 2]) << 8U) |
                                           std::to_integer<std::uint8_t>(frame[networkOffset + 3]));
    networkOffset += 4;
    add_field(layer, "etherType", std::to_string(etherType), captureOffset, networkOffset - 2, 2);
  }
  if (etherType == 0x0800U && frame.size() >= networkOffset) {
    const auto ip = parse_ipv4(frame.subspan(networkOffset), captureOffset, networkOffset, facts, packet);
    if (ip) layer.children.push_back(*ip);
  }
  return layer;
}

void build_flows(CaptureDocument& capture, std::vector<ParsedPacket>& packets) {
  struct FlowState {
    TcpFlow flow;
    TcpFacts first;
    std::uint32_t serverSequence = 0;
    bool sawSyn = false;
    bool sawSynAck = false;
    bool sawFinalAck = false;
  };
  std::vector<FlowState> states;
  for (auto& parsed : packets) {
    if (!parsed.tcp.valid) continue;
    auto& tcp = parsed.tcp;
    auto stateIt = std::find_if(states.begin(), states.end(), [&](const FlowState& state) {
      const auto same = state.first.source == tcp.source && state.first.destination == tcp.destination &&
                        state.first.sourcePort == tcp.sourcePort && state.first.destinationPort == tcp.destinationPort;
      const auto reverse = state.first.source == tcp.destination && state.first.destination == tcp.source &&
                           state.first.sourcePort == tcp.destinationPort && state.first.destinationPort == tcp.sourcePort;
      return same || reverse;
    });
    if (stateIt == states.end()) {
      FlowState state;
      state.first = tcp;
      state.flow.id = "tcp-flow-" + std::to_string(states.size() + 1);
      state.flow.client = {tcp.source, tcp.sourcePort};
      state.flow.server = {tcp.destination, tcp.destinationPort};
      auto find_endpoint = [&](const std::string& address, const std::uint16_t port) {
        const auto it = std::find_if(capture.endpoints.begin(), capture.endpoints.end(), [&](const Endpoint& endpoint) {
          return endpoint.address == address && endpoint.port == port;
        });
        if (it != capture.endpoints.end()) return it->id;
        const auto id = "endpoint-" + std::to_string(capture.endpoints.size() + 1);
        capture.endpoints.push_back({id, address, port, "TCP", "ipv4"});
        return id;
      };
      state.flow.clientEndpointId = find_endpoint(tcp.source, tcp.sourcePort);
      state.flow.serverEndpointId = find_endpoint(tcp.destination, tcp.destinationPort);
      state.serverSequence = 0;
      state.flow.startTimestampNs = parsed.packet.timestampNs;
      stateIt = states.emplace(states.end(), std::move(state));
    }
    auto& state = *stateIt;
    const bool fromClient = tcp.source == state.flow.client.address && tcp.sourcePort == state.flow.client.port;
    parsed.packet.flowId = state.flow.id;
    parsed.packet.sourceEndpointId = fromClient ? state.flow.clientEndpointId : state.flow.serverEndpointId;
    parsed.packet.destinationEndpointId = fromClient ? state.flow.serverEndpointId : state.flow.clientEndpointId;
    state.flow.packetNumbers.push_back(parsed.packet.number);
    state.flow.packetCount++;
    state.flow.capturedBytes += parsed.packet.capturedLength;
    state.flow.originalBytes += parsed.packet.originalLength;
    state.flow.endTimestampNs = parsed.packet.timestampNs;
    std::string label;
    if ((tcp.flags & 0x02U) != 0 && (tcp.flags & 0x10U) == 0 && fromClient) {
      state.sawSyn = true; label = "SYN";
    } else if ((tcp.flags & 0x12U) == 0x12U && !fromClient && state.sawSyn &&
               tcp.acknowledgment == state.first.sequence + 1U) {
      state.sawSynAck = true; label = "SYN + ACK";
      state.serverSequence = tcp.sequence;
    } else if ((tcp.flags & 0x10U) != 0 && fromClient && state.sawSynAck &&
               tcp.acknowledgment == state.serverSequence + 1U) {
      state.sawFinalAck = true; label = "ACK";
    }
    if (!label.empty()) state.flow.events.push_back({parsed.packet.id, parsed.packet.number, label});
  }
  for (auto& state : states) {
    state.flow.handshake = state.sawSyn && state.sawSynAck && state.sawFinalAck
                               ? HandshakeState::complete
                               : (state.sawSyn || state.sawSynAck ? HandshakeState::partial
                                                                   : HandshakeState::unobserved);
    capture.flows.push_back(std::move(state.flow));
  }
}

}  // namespace

ParseResult parse_capture(const std::span<const std::byte> bytes) {
  if (bytes.size() > kMaxCaptureBytes) {
    return error("FILE_TOO_LARGE", "Capture exceeds the 64 MiB limit");
  }
  if (bytes.size() < 24) return error("TRUNCATED_GLOBAL_HEADER", "PCAP global header is truncated");
  const auto magic = std::array<std::uint8_t, 4>{std::to_integer<std::uint8_t>(bytes[0]),
                                                  std::to_integer<std::uint8_t>(bytes[1]),
                                                  std::to_integer<std::uint8_t>(bytes[2]),
                                                  std::to_integer<std::uint8_t>(bytes[3])};
  const bool little = magic == std::array<std::uint8_t, 4>{0xd4, 0xc3, 0xb2, 0xa1} ||
                      magic == std::array<std::uint8_t, 4>{0x4d, 0x3c, 0xb2, 0xa1};
  const bool big = magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0xc3, 0xd4} ||
                   magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0x3c, 0x4d};
  if (!little && !big) return error("UNSUPPORTED_MAGIC", "Unsupported capture magic", 0);
  const bool nanoseconds = magic == std::array<std::uint8_t, 4>{0x4d, 0x3c, 0xb2, 0xa1} ||
                           magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0x3c, 0x4d};
  ByteReader header(bytes);
  (void)header.skip(4);
  const auto major = little ? header.read_u16_le() : header.read_u16_be();
  const auto minor = little ? header.read_u16_le() : header.read_u16_be();
  if (!major || !minor) return error("TRUNCATED_GLOBAL_HEADER", "PCAP global header is truncated");
  if (*major != 2 || *minor != 4) return error("UNSUPPORTED_VERSION", "Only PCAP version 2.4 is supported", 4);
  (void)header.skip(12);
  const auto linkType = little ? header.read_u32_le() : header.read_u32_be();
  if (!linkType) return error("TRUNCATED_GLOBAL_HEADER", "PCAP global header is truncated");
  if (*linkType != 1) return error("UNSUPPORTED_LINK_TYPE", "Only Ethernet link type is supported", 20);
  CaptureDocument capture;
  capture.capture.timestampResolution = nanoseconds ? "nanoseconds" : "microseconds";
  std::vector<ParsedPacket> parsedPackets;
  std::size_t offset = 24;
  std::size_t number = 1;
  while (offset < bytes.size()) {
    if (bytes.size() - offset < 16) return error("TRUNCATED_PACKET_HEADER", "PCAP packet header is truncated", offset, number);
    ByteReader record(bytes.subspan(offset));
    const auto sec = little ? record.read_u32_le() : record.read_u32_be();
    const auto fraction = little ? record.read_u32_le() : record.read_u32_be();
    const auto captured = little ? record.read_u32_le() : record.read_u32_be();
    const auto original = little ? record.read_u32_le() : record.read_u32_be();
    if (!sec || !fraction || !captured || !original) return error("TRUNCATED_PACKET_HEADER", "PCAP packet header is truncated", offset, number);
    if (*captured > *original) return error("INVALID_PACKET_LENGTH", "Captured length exceeds original length", offset + 8, number);
    if (static_cast<std::size_t>(*captured) > bytes.size() - offset - 16) {
      return error("TRUNCATED_PACKET_DATA", "PCAP packet data is truncated", offset + 16, number);
    }
    std::string timestamp;
    if (!checked_timestamp(*sec, *fraction, nanoseconds ? 1ULL : 1000ULL, timestamp)) {
      return error("INVALID_TIMESTAMP", "Packet timestamp overflows nanoseconds", offset, number);
    }
    ParsedPacket packet;
    packet.packet.id = "packet-" + std::to_string(number);
    packet.packet.number = number;
    packet.packet.timestampNs = timestamp;
    packet.packet.capturedLength = *captured;
    packet.packet.originalLength = *original;
    const auto frame = bytes.subspan(offset + 16, *captured);
    const auto ethernet = parse_ethernet(frame, offset + 16, packet.packet, packet.tcp);
    if (ethernet) packet.packet.layers.push_back(*ethernet);
    if (packet.tcp.valid) {
      packet.packet.summary = flag_text(packet.tcp.flags);
    } else {
      packet.packet.summary = packet.packet.layers.empty() ? "Truncated frame" : "Ethernet frame";
    }
    parsedPackets.push_back(std::move(packet));
    if (!capture.capture.startTimestampNs) capture.capture.startTimestampNs = timestamp;
    capture.capture.endTimestampNs = timestamp;
    capture.capture.capturedBytes += *captured;
    capture.capture.originalBytes += *original;
    offset += 16 + static_cast<std::size_t>(*captured);
    ++number;
  }
  capture.capture.packetCount = parsedPackets.size();
  if (capture.capture.startTimestampNs && capture.capture.endTimestampNs) {
    const auto start = std::stoull(*capture.capture.startTimestampNs);
    const auto end = std::stoull(*capture.capture.endTimestampNs);
    capture.capture.durationNs = end >= start ? std::to_string(end - start) : "0";
  }
  build_flows(capture, parsedPackets);
  capture.packets.reserve(parsedPackets.size());
  for (auto& packet : parsedPackets) capture.packets.push_back(std::move(packet.packet));
  return capture;
}

}  // namespace wirelens
