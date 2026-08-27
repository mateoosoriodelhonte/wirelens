#include "wirelens/parser.hpp"

#include "protocol_internal.hpp"
#include "wirelens/byte_reader.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <vector>

namespace wirelens {
namespace {
constexpr std::uint32_t kSectionHeader = 0x0a0d0d0aU;
constexpr std::uint32_t kInterfaceDescription = 1U;
constexpr std::uint32_t kEnhancedPacket = 6U;
constexpr std::size_t kMaxPcapngBlockBytes = 16U * 1024U * 1024U;

ParseError error(std::string code, std::string message, std::optional<std::size_t> offset = {},
                 std::optional<std::size_t> packet = {}) {
  return {std::move(code), std::move(message), offset, packet};
}
std::uint32_t u32(const std::span<const std::byte> bytes, const std::size_t offset,
                  const bool little) {
  const auto a = std::to_integer<std::uint32_t>(bytes[offset]);
  const auto b = std::to_integer<std::uint32_t>(bytes[offset + 1]);
  const auto c = std::to_integer<std::uint32_t>(bytes[offset + 2]);
  const auto d = std::to_integer<std::uint32_t>(bytes[offset + 3]);
  return little ? a | b << 8U | c << 16U | d << 24U : a << 24U | b << 16U | c << 8U | d;
}
std::uint16_t u16(const std::span<const std::byte> bytes, const std::size_t offset,
                  const bool little) {
  const auto a = std::to_integer<std::uint16_t>(bytes[offset]);
  const auto b = std::to_integer<std::uint16_t>(bytes[offset + 1]);
  return little ? static_cast<std::uint16_t>(a | b << 8U) : static_cast<std::uint16_t>(a << 8U | b);
}
bool timestamp(const std::uint64_t ticks, const std::uint8_t resolution, std::string& output) {
  const bool binary = (resolution & 0x80U) != 0;
  const auto exponent = static_cast<unsigned>(resolution & 0x7fU);
  unsigned __int128 denominator = 1;
  if (binary) {
    denominator = static_cast<unsigned __int128>(1) << exponent;
  } else if (exponent <= 28) {
    for (unsigned i = 0; i < exponent; ++i)
      denominator *= 10U;
  } else {
    // A uint64 tick count divided by 10^(exponent-9) is zero for powers
    // above 19. This is exact, not an overflow fallback.
    output = "0";
    return true;
  }
  const unsigned __int128 value =
      (static_cast<unsigned __int128>(ticks) * 1000000000U) / denominator;
  if (value > std::numeric_limits<std::uint64_t>::max())
    return false;
  output = std::to_string(static_cast<std::uint64_t>(value));
  return true;
}
std::size_t padded(const std::size_t value) { return (value + 3U) & ~std::size_t{3U}; }
} // namespace

ParseResult parse_pcapng(const std::span<const std::byte> bytes) {
  CaptureDocument capture;
  capture.capture.format = "pcapng";
  struct InterfaceState {
    CaptureInterface info;
    std::uint8_t resolution = 6;
  };
  std::vector<InterfaceState> interfaces;
  bool little = true;
  bool haveSection = false;
  std::size_t offset = 0;
  std::size_t packetNumber = 1;
  std::size_t globalInterface = 0;
  std::vector<internal::ParsedPacket> parsed;
  std::map<std::uint32_t, std::size_t> unknownBlocks;
  while (offset < bytes.size()) {
    if (bytes.size() - offset < 12) {
      if (bytes.size() - offset >= 4 && u32(bytes, offset, true) == kSectionHeader)
        return error("TRUNCATED_PCAPNG_SECTION", "PCAPNG section header is truncated", offset);
      return error("TRUNCATED_PCAPNG_BLOCK", "PCAPNG block header is truncated", offset);
    }
    const auto blockType = u32(bytes, offset, little);
    if (blockType == kSectionHeader) {
      if (bytes.size() - offset < 12)
        return error("TRUNCATED_PCAPNG_SECTION", "PCAPNG section header is truncated", offset);
      const auto rawLengthLittle = u32(bytes, offset + 4, true);
      const auto rawLengthBig = u32(bytes, offset + 4, false);
      const auto bomLittle =
          bytes.size() - offset >= 12 && u32(bytes, offset + 8, true) == 0x1a2b3c4dU;
      const auto bomBig =
          bytes.size() - offset >= 12 && u32(bytes, offset + 8, false) == 0x1a2b3c4dU;
      if (!bomLittle && !bomBig)
        return error("INVALID_PCAPNG_BYTE_ORDER", "PCAPNG section byte-order magic is invalid",
                     offset + 8);
      little = bomLittle;
      const auto length = little ? rawLengthLittle : rawLengthBig;
      if (length < 28 || length % 4 != 0 || length > kMaxPcapngBlockBytes)
        return error("INVALID_PCAPNG_BLOCK_LENGTH", "PCAPNG section block length is invalid",
                     offset + 4);
      if (length > bytes.size() - offset)
        return error("TRUNCATED_PCAPNG_BLOCK", "PCAPNG section block is truncated", offset);
      if (u32(bytes, offset + length - 4, little) != length)
        return error("MISMATCHED_PCAPNG_BLOCK_LENGTH", "PCAPNG block lengths do not match", offset);
      if (u16(bytes, offset + 12, little) != 1 || u16(bytes, offset + 14, little) != 0)
        return error("UNSUPPORTED_PCAPNG_VERSION", "Only PCAPNG section version 1.0 is supported",
                     offset + 12);
      interfaces.clear();
      haveSection = true;
      offset += length;
      continue;
    }
    if (!haveSection)
      return error("PCAPNG_SECTION_REQUIRED", "PCAPNG must begin with a section header", offset);
    const auto length = u32(bytes, offset + 4, little);
    if (length < 12 || length % 4 != 0)
      return error("INVALID_PCAPNG_BLOCK_LENGTH", "PCAPNG block length is invalid", offset + 4);
    if (length > kMaxPcapngBlockBytes)
      return error("PCAPNG_BLOCK_LIMIT_EXCEEDED", "PCAPNG block exceeds the 16 MiB limit",
                   offset + 4);
    if (length > bytes.size() - offset)
      return error("TRUNCATED_PCAPNG_BLOCK", "PCAPNG block is truncated", offset);
    if (u32(bytes, offset + length - 4, little) != length)
      return error("MISMATCHED_PCAPNG_BLOCK_LENGTH", "PCAPNG block lengths do not match", offset);
    if (blockType == kInterfaceDescription) {
      if (length < 20)
        return error("TRUNCATED_PCAPNG_INTERFACE", "PCAPNG interface block is truncated", offset);
      if (capture.capture.interfaces.size() >= kMaxPcapngInterfaces)
        return error("PCAPNG_INTERFACE_LIMIT_EXCEEDED", "PCAPNG exceeds the 65,536 interface limit",
                     offset);
      const auto linkType = u16(bytes, offset + 8, little);
      const auto snapLength = u32(bytes, offset + 12, little);
      if (linkType != 1)
        return error("UNSUPPORTED_LINK_TYPE", "Only Ethernet link type is supported", offset + 8);
      std::uint8_t resolution = 6;
      std::size_t option = offset + 16;
      const auto optionEnd = offset + length - 4;
      bool sawEnd = option == optionEnd;
      while (option + 4 <= optionEnd) {
        const auto code = u16(bytes, option, little);
        const auto optionLength = u16(bytes, option + 2, little);
        option += 4;
        if (code == 0) {
          if (optionLength != 0)
            return error("INVALID_PCAPNG_OPTION_LENGTH",
                         "PCAPNG option terminator length must be zero", option - 4);
          sawEnd = true;
          if (option != optionEnd)
            return error("MISSING_PCAPNG_OPTION_END", "PCAPNG option terminator is not last",
                         option - 4);
          break;
        }
        if (code == 9 && optionLength != 1)
          return error("INVALID_PCAPNG_OPTION_LENGTH", "PCAPNG if_tsresol option must be one byte",
                       option - 4);
        if (optionLength > optionEnd - option || padded(optionLength) > optionEnd - option)
          return error("TRUNCATED_PCAPNG_OPTION", "PCAPNG option is truncated", option - 4);
        if (code == 9 && optionLength == 1)
          resolution = std::to_integer<std::uint8_t>(bytes[option]);
        option += padded(optionLength);
      }
      if (!sawEnd)
        return error("MISSING_PCAPNG_OPTION_END", "PCAPNG interface options are missing terminator",
                     option);
      const auto resolutionName =
          (resolution & 0x80U) != 0
              ? "binary"
              : (resolution == 6 ? "microseconds" : (resolution == 9 ? "nanoseconds" : "custom"));
      interfaces.push_back({{globalInterface, linkType, snapLength, resolutionName}, resolution});
      capture.capture.interfaces.push_back(interfaces.back().info);
      if (capture.capture.interfaces.size() == 1)
        capture.capture.timestampResolution = resolutionName;
      else if (capture.capture.timestampResolution != resolutionName)
        capture.capture.timestampResolution = "mixed";
      ++globalInterface;
    } else if (blockType == kEnhancedPacket) {
      if (length < 32)
        return error("TRUNCATED_PCAPNG_PACKET", "PCAPNG enhanced packet is truncated", offset,
                     packetNumber);
      const auto localInterface = u32(bytes, offset + 8, little);
      if (localInterface >= interfaces.size())
        return error("INVALID_PCAPNG_INTERFACE", "PCAPNG packet references an unknown interface",
                     offset + 8, packetNumber);
      const auto captured = u32(bytes, offset + 20, little);
      const auto original = u32(bytes, offset + 24, little);
      const auto dataOffset = offset + 28;
      const auto available = length - 32;
      if (captured > available || padded(captured) > available)
        return error("INVALID_PCAPNG_PACKET_LENGTH", "PCAPNG captured length exceeds block data",
                     offset + 20, packetNumber);
      if (captured > original)
        return error("INVALID_PACKET_LENGTH", "Captured length exceeds original length",
                     offset + 20, packetNumber);
      if (interfaces[localInterface].info.snapLength != 0 &&
          captured > interfaces[localInterface].info.snapLength)
        return error("PCAPNG_PACKET_EXCEEDS_SNAPLEN", "PCAPNG packet exceeds interface snap length",
                     offset + 20, packetNumber);
      if (packetNumber > kMaxPacketCount)
        return error("PACKET_LIMIT_EXCEEDED", "Capture exceeds the 65,536 packet limit", offset,
                     packetNumber);
      const auto ticks = (static_cast<std::uint64_t>(u32(bytes, offset + 12, little)) << 32U) |
                         u32(bytes, offset + 16, little);
      const auto resolution = interfaces[localInterface].resolution;
      std::string packetTime;
      if (!timestamp(ticks, resolution, packetTime))
        return error("INVALID_TIMESTAMP", "PCAPNG packet timestamp overflows nanoseconds",
                     offset + 12, packetNumber);
      internal::ParsedPacket packet;
      packet.packet.id = "packet-" + std::to_string(packetNumber);
      packet.packet.number = packetNumber;
      packet.packet.timestampNs = packetTime;
      packet.packet.capturedLength = captured;
      packet.packet.originalLength = original;
      packet.packet.interfaceId = interfaces[localInterface].info.id;
      packet.sourceRange = {dataOffset, 0, captured};
      auto protocolDiagnostic =
          internal::decode_ethernet(bytes.subspan(dataOffset, captured), dataOffset, packet.packet,
                                    packet.tcp, packet.udp, packet.dns);
      if (packet.tcp.valid && captured < original)
        packet.tcp.payloadComplete = false;
      if (protocolDiagnostic && capture.diagnostics.size() < kMaxDiagnostics) {
        protocolDiagnostic->packetNumber = packetNumber;
        capture.diagnostics.push_back(std::move(*protocolDiagnostic));
      }
      if (packet.dns.diagnostic && capture.diagnostics.size() < kMaxDiagnostics) {
        packet.dns.diagnostic->packetNumber = packetNumber;
        capture.diagnostics.push_back(std::move(*packet.dns.diagnostic));
      }
      packet.packet.summary =
          packet.tcp.valid
              ? (packet.tcp.payload.empty() ? internal::flag_text(packet.tcp.flags) : "TCP data")
              : (packet.udp.valid
                     ? "UDP datagram"
                     : (packet.packet.layers.empty() ? "Truncated frame" : "Ethernet frame"));
      if (!capture.capture.startTimestampNs)
        capture.capture.startTimestampNs = packet.packet.timestampNs;
      capture.capture.endTimestampNs = packet.packet.timestampNs;
      capture.capture.capturedBytes += captured;
      capture.capture.originalBytes += original;
      capture.packetSourceRanges.push_back({dataOffset, 0, captured});
      parsed.push_back(std::move(packet));
      // Keep private ranges on the parse result; the serializer omits them.
      ++packetNumber;
    } else {
      const auto existing = unknownBlocks.find(blockType);
      if (existing != unknownBlocks.end())
        ++existing->second;
      else if (unknownBlocks.size() < kMaxDiagnostics)
        unknownBlocks.emplace(blockType, 1);
    }
    offset += length;
  }
  if (capture.capture.startTimestampNs && capture.capture.endTimestampNs) {
    const auto start = std::stoull(*capture.capture.startTimestampNs);
    const auto end = std::stoull(*capture.capture.endTimestampNs);
    capture.capture.durationNs = end >= start ? std::to_string(end - start) : "0";
  }
  internal::build_flows(capture, parsed);
  internal::build_dns(capture, parsed);
  for (const auto& [blockType, count] : unknownBlocks) {
    if (capture.diagnostics.size() >= kMaxDiagnostics)
      break;
    capture.diagnostics.push_back({"warning", "UNKNOWN_PCAPNG_BLOCK",
                                   "Skipped " + std::to_string(count) +
                                       " unknown PCAPNG block(s) of type " +
                                       std::to_string(blockType),
                                   "pcapng", std::nullopt, std::nullopt, count});
  }
  capture.packets.reserve(parsed.size());
  for (auto& packet : parsed)
    capture.packets.push_back(std::move(packet.packet));
  capture.capture.packetCount = capture.packets.size();
  return capture;
}
} // namespace wirelens
