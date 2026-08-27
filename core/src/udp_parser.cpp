#include "protocol_internal.hpp"

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
void add_field(ProtocolLayer& layer, std::string name, std::string value,
               const std::size_t captureOffset, const std::size_t packetOffset,
               const std::size_t length) {
  layer.fields.push_back({std::move(name), std::move(value),
                          range(captureOffset, packetOffset, length), std::nullopt});
}
} // namespace

std::optional<ProtocolLayer> decode_udp(const std::span<const std::byte> payload,
                                        const std::size_t captureOffset,
                                        const std::size_t packetOffset, UdpFacts& facts) {
  if (payload.size() < 8)
    return std::nullopt;
  const auto length = static_cast<std::size_t>(u16be(payload, 4));
  // RFC 768: UDP length includes the eight-byte header. A zero value is not
  // valid for IPv4 and is treated as malformed for this bounded decoder.
  if (length < 8 || length > payload.size())
    return std::nullopt;
  ProtocolLayer layer{"UDP", "UDP", {}, std::nullopt, std::nullopt};
  layer.byteRange = range(captureOffset, packetOffset, length);
  add_field(layer, "sourcePort", std::to_string(u16be(payload, 0)), captureOffset, packetOffset, 2);
  add_field(layer, "destinationPort", std::to_string(u16be(payload, 2)), captureOffset,
            packetOffset + 2, 2);
  add_field(layer, "length", std::to_string(length), captureOffset, packetOffset + 4, 2);
  add_field(layer, "checksum", std::to_string(u16be(payload, 6)), captureOffset,
            packetOffset + 6, 2);
  facts = {true, {}, {}, u16be(payload, 0), u16be(payload, 2), length - 8};
  return layer;
}
} // namespace wirelens::internal
