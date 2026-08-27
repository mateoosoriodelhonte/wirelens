#include "protocol_internal.hpp"

#include <algorithm>
#include <string>

namespace wirelens::internal {
namespace {
ByteRange range(const std::size_t captureOffset, const std::size_t packetOffset,
                const std::size_t length) {
  return {captureOffset, packetOffset, length};
}
void add_field(ProtocolLayer& layer, std::string name, std::string value,
               const std::size_t captureOffset, const std::size_t packetOffset,
               const std::size_t length) {
  layer.fields.push_back({std::move(name), std::move(value),
                          range(captureOffset + packetOffset, packetOffset, length), std::nullopt});
}
std::uint16_t u16be(const std::span<const std::byte> bytes, const std::size_t offset) {
  return static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(bytes[offset]) << 8U) |
                                    std::to_integer<std::uint8_t>(bytes[offset + 1]));
}
std::string address(const std::span<const std::byte> bytes) {
  return std::to_string(std::to_integer<unsigned>(bytes[0])) + "." +
         std::to_string(std::to_integer<unsigned>(bytes[1])) + "." +
         std::to_string(std::to_integer<unsigned>(bytes[2])) + "." +
         std::to_string(std::to_integer<unsigned>(bytes[3]));
}
} // namespace

std::optional<ProtocolLayer> decode_ipv4(const std::span<const std::byte> payload,
                                         const std::size_t captureOffset,
                                         const std::size_t packetOffset, TcpFacts& facts,
                                         Packet& packet) {
  if (payload.size() < 20)
    return std::nullopt;
  const auto version = std::to_integer<unsigned>(payload[0]) >> 4U;
  const auto headerLength =
      static_cast<std::size_t>(std::to_integer<unsigned>(payload[0]) & 0x0fU) * 4U;
  if (version != 4 || headerLength < 20 || headerLength > payload.size())
    return std::nullopt;
  const auto totalLength = static_cast<std::size_t>(u16be(payload, 2));
  if (totalLength < headerLength)
    return std::nullopt;
  const auto boundedLength = std::min(totalLength, payload.size());
  const auto source = address(payload.subspan(12, 4));
  const auto destination = address(payload.subspan(16, 4));
  const auto protocol = std::to_integer<unsigned>(payload[9]);
  const auto fragmentOffset = u16be(payload, 6) & 0x1fffU;
  ProtocolLayer layer{"IPV4", "IPv4", {}, std::nullopt, std::nullopt};
  layer.byteRange = range(captureOffset + packetOffset, packetOffset, boundedLength);
  add_field(layer, "version", std::to_string(version), captureOffset, packetOffset, 1);
  add_field(layer, "headerLength", std::to_string(headerLength), captureOffset, packetOffset, 1);
  add_field(layer, "totalLength", std::to_string(totalLength), captureOffset, packetOffset + 2, 2);
  add_field(layer, "ttl", std::to_string(std::to_integer<unsigned>(payload[8])), captureOffset,
            packetOffset + 8, 1);
  add_field(layer, "protocol", std::to_string(protocol), captureOffset, packetOffset + 9, 1);
  add_field(layer, "source", source, captureOffset, packetOffset + 12, 4);
  add_field(layer, "destination", destination, captureOffset, packetOffset + 16, 4);
  packet.sourceAddress = source;
  packet.destinationAddress = destination;
  if (protocol == 6 && fragmentOffset == 0) {
    if (const auto tcp = decode_tcp(payload.subspan(headerLength, boundedLength - headerLength),
                                    captureOffset, packetOffset + headerLength, facts)) {
      packet.sourcePort = facts.sourcePort;
      packet.destinationPort = facts.destinationPort;
      packet.layers.push_back(*tcp);
      facts.source = source;
      facts.destination = destination;
    }
  }
  return layer;
}
} // namespace wirelens::internal
