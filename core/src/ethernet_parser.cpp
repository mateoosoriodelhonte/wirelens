#include "protocol_internal.hpp"

#include <string>

namespace wirelens::internal {
namespace {
ByteRange range(const std::size_t captureOffset, const std::size_t packetOffset, const std::size_t length) {
  return {captureOffset, packetOffset, length};
}
void add_field(ProtocolLayer& layer, std::string name, std::string value, const std::size_t captureOffset,
               const std::size_t packetOffset, const std::size_t length) {
  layer.fields.push_back({std::move(name), std::move(value), range(captureOffset + packetOffset, packetOffset, length), std::nullopt});
}
std::string mac(const std::span<const std::byte> bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string value;
  value.reserve(17);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    if (i != 0) value.push_back(':');
    const auto octet = std::to_integer<unsigned>(bytes[i]);
    value.push_back(digits[octet >> 4U]); value.push_back(digits[octet & 0x0fU]);
  }
  return value;
}
std::uint16_t u16be(const std::span<const std::byte> bytes, const std::size_t offset) {
  return static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(bytes[offset]) << 8U) |
                                    std::to_integer<std::uint8_t>(bytes[offset + 1]));
}
}  // namespace

void decode_ethernet(const std::span<const std::byte> frame, const std::size_t captureOffset,
                     Packet& packet, TcpFacts& facts) {
  if (frame.size() < 14) return;
  ProtocolLayer layer{"ETHERNET", "Ethernet II", {}, std::nullopt, std::nullopt};
  layer.byteRange = range(captureOffset, 0, frame.size());
  add_field(layer, "destinationMac", mac(frame.subspan(0, 6)), captureOffset, 0, 6);
  add_field(layer, "sourceMac", mac(frame.subspan(6, 6)), captureOffset, 6, 6);
  auto etherType = u16be(frame, 12);
  add_field(layer, "etherType", std::to_string(etherType), captureOffset, 12, 2);
  std::size_t networkOffset = 14;
  while (etherType == 0x8100U || etherType == 0x88a8U) {
    if (frame.size() - networkOffset < 4) break;
    const auto vlan = u16be(frame, networkOffset);
    add_field(layer, "vlanId", std::to_string(vlan & 0x0fffU), captureOffset, networkOffset, 2);
    etherType = u16be(frame, networkOffset + 2); networkOffset += 4;
    add_field(layer, "etherType", std::to_string(etherType), captureOffset, networkOffset - 2, 2);
  }
  packet.layers.push_back(std::move(layer));
  if (etherType == 0x0800U && frame.size() >= networkOffset) {
    const auto beforeIp = packet.layers.size();
    if (const auto ip = decode_ipv4(frame.subspan(networkOffset), captureOffset, networkOffset, facts, packet)) {
      std::optional<ProtocolLayer> tcp;
      if (packet.layers.size() > beforeIp) {
        tcp = std::move(packet.layers.back());
        packet.layers.pop_back();
      }
      packet.layers.push_back(*ip);
      if (tcp) packet.layers.push_back(std::move(*tcp));
    }
  }
}
}  // namespace wirelens::internal
