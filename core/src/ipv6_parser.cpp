#include "protocol_internal.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <sstream>
#include <string>

namespace wirelens::internal {
namespace {
ByteRange range(const std::size_t captureOffset, const std::size_t packetOffset,
                const std::size_t length) {
  return {captureOffset + packetOffset, packetOffset, length};
}
std::uint16_t u16be(const std::span<const std::byte> bytes, const std::size_t offset) {
  return static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(bytes[offset]) << 8U) |
                                    std::to_integer<std::uint8_t>(bytes[offset + 1]));
}
std::uint32_t u32be(const std::span<const std::byte> bytes, const std::size_t offset) {
  return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset])) << 24U) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 16U) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 2])) << 8U) |
         std::to_integer<std::uint8_t>(bytes[offset + 3]);
}
void add_field(ProtocolLayer& layer, std::string name, std::string value,
               const std::size_t captureOffset, const std::size_t packetOffset,
               const std::size_t length) {
  layer.fields.push_back({std::move(name), std::move(value),
                          range(captureOffset, packetOffset, length), std::nullopt});
}
std::string address(const std::span<const std::byte> bytes) {
  std::array<std::uint16_t, 8> words{};
  for (std::size_t i = 0; i < words.size(); ++i)
    words[i] = u16be(bytes, i * 2);
  std::size_t bestStart = 8;
  std::size_t bestLength = 0;
  for (std::size_t i = 0; i < 8;) {
    if (words[i] == 0) {
      const auto start = i;
      while (i < 8 && words[i] == 0)
        ++i;
      if (i - start > bestLength) {
        bestStart = start;
        bestLength = i - start;
      }
    } else {
      ++i;
    }
  }
  if (bestLength < 2) {
    bestStart = 8;
    bestLength = 0;
  }
  std::ostringstream out;
  for (std::size_t i = 0; i < 8; ++i) {
    if (i == bestStart) {
      out << "::";
      i += bestLength - 1;
      continue;
    }
    if (i != 0 && i != bestStart + bestLength)
      out << ':';
    out << std::hex << std::nouppercase << words[i];
  }
  return out.str();
}
} // namespace

std::optional<ProtocolLayer> decode_ipv6(const std::span<const std::byte> payload,
                                         const std::size_t captureOffset,
                                         const std::size_t packetOffset, TcpFacts& tcp,
                                         UdpFacts& udp, Packet& packet) {
  if (payload.size() < 40)
    return std::nullopt;
  if ((std::to_integer<unsigned>(payload[0]) >> 4U) != 6)
    return std::nullopt;
  const auto declaredPayload = static_cast<std::size_t>(u16be(payload, 4));
  const auto boundedPayload = std::min(declaredPayload, payload.size() - 40U);
  const auto source = address(payload.subspan(8, 16));
  const auto destination = address(payload.subspan(24, 16));
  ProtocolLayer layer{"IPV6", "IPv6", {}, std::nullopt, std::nullopt};
  layer.byteRange = range(captureOffset, packetOffset, 40U + boundedPayload);
  add_field(layer, "version", "6", captureOffset, packetOffset, 1);
  add_field(layer, "payloadLength", std::to_string(declaredPayload), captureOffset,
            packetOffset + 4, 2);
  add_field(layer, "nextHeader", std::to_string(std::to_integer<unsigned>(payload[6])),
            captureOffset, packetOffset + 6, 1);
  add_field(layer, "hopLimit", std::to_string(std::to_integer<unsigned>(payload[7])), captureOffset,
            packetOffset + 7, 1);
  add_field(layer, "source", source, captureOffset, packetOffset + 8, 16);
  add_field(layer, "destination", destination, captureOffset, packetOffset + 24, 16);
  packet.sourceAddress = source;
  packet.destinationAddress = destination;

  auto next = std::to_integer<unsigned>(payload[6]);
  std::size_t offset = 40;
  bool nonFirstFragment = false;
  std::size_t extensionCount = 0;
  constexpr std::size_t kMaxIpv6ExtensionHeaders = 8;
  for (; extensionCount < kMaxIpv6ExtensionHeaders; ++extensionCount) {
    if (next != 0 && next != 43 && next != 44 && next != 60)
      break;
    if (next == 44) {
      if (boundedPayload < offset - 40U + 8U)
        return layer;
      const auto extension = payload.subspan(offset, 8);
      add_field(layer, "extensionType", "Fragment", captureOffset, packetOffset + offset, 1);
      add_field(layer, "extensionNextHeader", std::to_string(std::to_integer<unsigned>(extension[0])),
                captureOffset, packetOffset + offset, 1);
      add_field(layer, "extensionLength", "8", captureOffset, packetOffset + offset + 1, 1);
      const auto fragment = u16be(extension, 2);
      const auto fragmentOffset = static_cast<unsigned>(fragment >> 3U);
      const bool more = (fragment & 1U) != 0;
      nonFirstFragment = fragmentOffset != 0;
      add_field(layer, "fragmentOffset", std::to_string(fragmentOffset), captureOffset,
                packetOffset + offset + 2, 2);
      add_field(layer, "moreFragments", more ? "true" : "false", captureOffset,
                packetOffset + offset + 2, 2);
      add_field(layer, "fragmentIdentification", std::to_string(u32be(extension, 4)), captureOffset,
                packetOffset + offset + 4, 4);
      next = std::to_integer<unsigned>(extension[0]);
      offset += 8;
      if (fragmentOffset != 0)
        return layer;
      continue;
    }
    if (payload.size() - offset < 2)
      return layer;
    const auto extensionLength = (static_cast<std::size_t>(std::to_integer<unsigned>(payload[offset + 1])) + 1U) * 8U;
    if (extensionLength > payload.size() - offset || extensionLength > 40U + boundedPayload - offset)
      return layer;
    const auto extensionName = next == 0 ? "Hop-by-Hop Options"
                              : (next == 43 ? "Routing" : "Destination Options");
    add_field(layer, "extensionType", extensionName, captureOffset, packetOffset + offset, 1);
    add_field(layer, "extensionNextHeader", std::to_string(std::to_integer<unsigned>(payload[offset])),
              captureOffset, packetOffset + offset, 1);
    add_field(layer, "extensionLength", std::to_string(extensionLength), captureOffset,
              packetOffset + offset + 1, 1);
    next = std::to_integer<unsigned>(payload[offset]);
    offset += extensionLength;
  }
  if (extensionCount == kMaxIpv6ExtensionHeaders && (next == 0 || next == 43 || next == 44 || next == 60)) {
    packet.analysisFlags.push_back("ipv6-extension-limit");
    return layer;
  }
  if (next == 0 || next == 43 || next == 44 || next == 60 || nonFirstFragment || offset > 40U + boundedPayload)
    return layer;
  const auto transport = payload.subspan(offset, 40U + boundedPayload - offset);
  if (next == 6) {
    if (const auto tcpLayer = decode_tcp(transport, captureOffset, packetOffset + offset, tcp)) {
      packet.sourcePort = tcp.sourcePort;
      packet.destinationPort = tcp.destinationPort;
      tcp.source = source;
      tcp.destination = destination;
      packet.layers.push_back(*tcpLayer);
    }
  } else if (next == 17) {
    if (const auto udpLayer = decode_udp(transport, captureOffset, packetOffset + offset, udp)) {
      packet.sourcePort = udp.sourcePort;
      packet.destinationPort = udp.destinationPort;
      udp.source = source;
      udp.destination = destination;
      packet.layers.push_back(*udpLayer);
    }
  }
  return layer;
}
} // namespace wirelens::internal
