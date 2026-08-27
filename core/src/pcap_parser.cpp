#include "wirelens/parser.hpp"

#include "protocol_internal.hpp"
#include "wirelens/byte_reader.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>

namespace wirelens {
ParseResult parse_pcapng(std::span<const std::byte> bytes);
namespace {
ParseError error(std::string code, std::string message,
                 std::optional<std::size_t> offset = std::nullopt,
                 std::optional<std::size_t> packet = std::nullopt) {
  return {std::move(code), std::move(message), offset, packet};
}
bool timestamp(const std::uint32_t seconds, const std::uint32_t fraction,
               const std::uint64_t multiplier, std::string& output) {
  constexpr auto max = std::numeric_limits<std::uint64_t>::max();
  const auto whole = static_cast<std::uint64_t>(seconds) * 1000000000ULL;
  if (fraction != 0 && static_cast<std::uint64_t>(fraction) > (max - whole) / multiplier)
    return false;
  output = std::to_string(whole + static_cast<std::uint64_t>(fraction) * multiplier);
  return true;
}
} // namespace

ParseResult parse_capture(const std::span<const std::byte> bytes) {
  static_assert(static_cast<std::uint64_t>(kMaxPacketCount) *
                    std::numeric_limits<std::uint32_t>::max() <=
                9007199254740991ULL);
  if (bytes.size() > kMaxCaptureBytes)
    return error("FILE_TOO_LARGE", "Capture exceeds the 64 MiB limit");
  if (bytes.size() < 4)
    return error("TRUNCATED_GLOBAL_HEADER", "Capture global header is truncated");
  const auto magic = std::array<std::uint8_t, 4>{
      std::to_integer<std::uint8_t>(bytes[0]), std::to_integer<std::uint8_t>(bytes[1]),
      std::to_integer<std::uint8_t>(bytes[2]), std::to_integer<std::uint8_t>(bytes[3])};
  if (magic == std::array<std::uint8_t, 4>{0x0a, 0x0d, 0x0d, 0x0a})
    return parse_pcapng(bytes);
  if (bytes.size() < 24)
    return error("TRUNCATED_GLOBAL_HEADER", "PCAP global header is truncated");
  const bool little = magic == std::array<std::uint8_t, 4>{0xd4, 0xc3, 0xb2, 0xa1} ||
                      magic == std::array<std::uint8_t, 4>{0x4d, 0x3c, 0xb2, 0xa1};
  const bool big = magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0xc3, 0xd4} ||
                   magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0x3c, 0x4d};
  if (!little && !big)
    return error("UNSUPPORTED_MAGIC", "Unsupported capture magic", 0);
  const bool nanoseconds = magic == std::array<std::uint8_t, 4>{0x4d, 0x3c, 0xb2, 0xa1} ||
                           magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0x3c, 0x4d};
  ByteReader header(bytes);
  (void)header.skip(4);
  const auto major = little ? header.read_u16_le() : header.read_u16_be();
  const auto minor = little ? header.read_u16_le() : header.read_u16_be();
  if (!major || !minor)
    return error("TRUNCATED_GLOBAL_HEADER", "PCAP global header is truncated");
  if (*major != 2 || *minor != 4)
    return error("UNSUPPORTED_VERSION", "Only PCAP version 2.4 is supported", 4);
  (void)header.skip(8);
  const auto snapLength = little ? header.read_u32_le() : header.read_u32_be();
  const auto linkType = little ? header.read_u32_le() : header.read_u32_be();
  if (!snapLength || !linkType)
    return error("TRUNCATED_GLOBAL_HEADER", "PCAP global header is truncated");
  if (*linkType != 1)
    return error("UNSUPPORTED_LINK_TYPE", "Only Ethernet link type is supported", 20);
  CaptureDocument capture;
  capture.capture.format = "pcap";
  capture.capture.timestampResolution = nanoseconds ? "nanoseconds" : "microseconds";
  capture.capture.interfaces.push_back({0, 1, *snapLength, capture.capture.timestampResolution});
  std::vector<internal::ParsedPacket> parsed;
  std::size_t offset = 24;
  std::size_t number = 1;
  while (offset < bytes.size()) {
    if (number > kMaxPacketCount)
      return error("PACKET_LIMIT_EXCEEDED", "Capture exceeds the 65,536 packet limit", offset,
                   number);
    if (bytes.size() - offset < 16)
      return error("TRUNCATED_PACKET_HEADER", "PCAP packet header is truncated", offset, number);
    ByteReader record(bytes.subspan(offset));
    const auto sec = little ? record.read_u32_le() : record.read_u32_be();
    const auto fraction = little ? record.read_u32_le() : record.read_u32_be();
    const auto captured = little ? record.read_u32_le() : record.read_u32_be();
    const auto original = little ? record.read_u32_le() : record.read_u32_be();
    if (!sec || !fraction || !captured || !original)
      return error("TRUNCATED_PACKET_HEADER", "PCAP packet header is truncated", offset, number);
    if (*captured > *original)
      return error("INVALID_PACKET_LENGTH", "Captured length exceeds original length", offset + 8,
                   number);
    if (*snapLength != 0 && *captured > *snapLength)
      return error("PCAP_PACKET_EXCEEDS_SNAPLEN", "PCAP packet exceeds capture snap length",
                   offset + 8, number);
    if (static_cast<std::size_t>(*captured) > bytes.size() - offset - 16)
      return error("TRUNCATED_PACKET_DATA", "PCAP packet data is truncated", offset + 16, number);
    const auto fractionLimit = nanoseconds ? 1'000'000'000U : 1'000'000U;
    if (*fraction >= fractionLimit)
      return error("INVALID_TIMESTAMP", "PCAP packet timestamp fraction is out of range",
                   offset + 4, number);
    std::string time;
    if (!timestamp(*sec, *fraction, nanoseconds ? 1ULL : 1000ULL, time))
      return error("INVALID_TIMESTAMP", "Packet timestamp overflows nanoseconds", offset, number);
    internal::ParsedPacket packet;
    packet.packet.id = "packet-" + std::to_string(number);
    packet.packet.number = number;
    packet.packet.timestampNs = time;
    packet.packet.capturedLength = *captured;
    packet.packet.originalLength = *original;
    packet.packet.interfaceId = 0;
    packet.sourceRange = {offset + 16, 0, *captured};
    auto protocolDiagnostic =
        internal::decode_ethernet(bytes.subspan(offset + 16, *captured), offset + 16, packet.packet,
                                  packet.tcp, packet.udp, packet.dns);
    if (packet.tcp.valid && *captured < *original)
      packet.tcp.payloadComplete = false;
    if (protocolDiagnostic && capture.diagnostics.size() < kMaxDiagnostics) {
      protocolDiagnostic->packetNumber = number;
      capture.diagnostics.push_back(std::move(*protocolDiagnostic));
    }
    if (packet.dns.diagnostic && capture.diagnostics.size() < kMaxDiagnostics) {
      packet.dns.diagnostic->packetNumber = number;
      capture.diagnostics.push_back(std::move(*packet.dns.diagnostic));
    }
    packet.packet.summary =
        packet.tcp.valid
            ? internal::flag_text(packet.tcp.flags)
            : (packet.udp.valid
                   ? "UDP datagram"
                   : (packet.packet.layers.empty() ? "Truncated frame" : "Ethernet frame"));
    parsed.push_back(std::move(packet));
    capture.packetSourceRanges.push_back({offset + 16, 0, *captured});
    if (!capture.capture.startTimestampNs)
      capture.capture.startTimestampNs = time;
    capture.capture.endTimestampNs = time;
    capture.capture.capturedBytes += *captured;
    capture.capture.originalBytes += *original;
    offset += 16 + static_cast<std::size_t>(*captured);
    ++number;
  }
  capture.capture.packetCount = parsed.size();
  if (capture.capture.startTimestampNs && capture.capture.endTimestampNs) {
    const auto start = std::stoull(*capture.capture.startTimestampNs);
    const auto end = std::stoull(*capture.capture.endTimestampNs);
    capture.capture.durationNs = end >= start ? std::to_string(end - start) : "0";
  }
  internal::build_flows(capture, parsed);
  internal::build_dns(capture, parsed);
  capture.packets.reserve(parsed.size());
  for (auto& packet : parsed)
    capture.packets.push_back(std::move(packet.packet));
  return capture;
}
} // namespace wirelens
