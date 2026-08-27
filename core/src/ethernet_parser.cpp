#include "protocol_internal.hpp"
#include "wirelens/parser.hpp"

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
std::string mac(const std::span<const std::byte> bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string value;
  value.reserve(17);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    if (i != 0)
      value.push_back(':');
    const auto octet = std::to_integer<unsigned>(bytes[i]);
    value.push_back(digits[octet >> 4U]);
    value.push_back(digits[octet & 0x0fU]);
  }
  return value;
}
std::uint16_t u16be(const std::span<const std::byte> bytes, const std::size_t offset) {
  return static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(bytes[offset]) << 8U) |
                                    std::to_integer<std::uint8_t>(bytes[offset + 1]));
}
} // namespace

std::optional<Diagnostic> decode_ethernet(const std::span<const std::byte> frame,
                                          const std::size_t captureOffset, Packet& packet,
                                          TcpFacts& tcp, UdpFacts& udp, DnsFacts& dns) {
  if (frame.size() < 14)
    return std::nullopt;
  ProtocolLayer layer{"ETHERNET", "Ethernet II", {}, std::nullopt, std::nullopt};
  layer.byteRange = range(captureOffset, 0, frame.size());
  add_field(layer, "destinationMac", mac(frame.subspan(0, 6)), captureOffset, 0, 6);
  add_field(layer, "sourceMac", mac(frame.subspan(6, 6)), captureOffset, 6, 6);
  auto etherType = u16be(frame, 12);
  add_field(layer, "etherType", std::to_string(etherType), captureOffset, 12, 2);
  std::size_t networkOffset = 14;
  std::size_t vlanTags = 0;
  std::optional<Diagnostic> diagnostic;
  while (etherType == 0x8100U || etherType == 0x88a8U) {
    if (vlanTags >= kMaxVlanTags) {
      diagnostic = Diagnostic{"warning",
                              "PROTOCOL_NESTING_LIMIT_EXCEEDED",
                              "Stopped decoding after 8 stacked VLAN tags",
                              "ethernet.vlan",
                              captureOffset + networkOffset - 2U,
                              std::nullopt,
                              std::nullopt};
      break;
    }
    if (frame.size() - networkOffset < 4)
      break;
    const auto vlan = u16be(frame, networkOffset);
    add_field(layer, "vlanId", std::to_string(vlan & 0x0fffU), captureOffset, networkOffset, 2);
    etherType = u16be(frame, networkOffset + 2);
    networkOffset += 4;
    ++vlanTags;
    add_field(layer, "etherType", std::to_string(etherType), captureOffset, networkOffset - 2, 2);
  }
  packet.layers.push_back(std::move(layer));
  if (diagnostic)
    return diagnostic;
  if ((etherType == 0x0800U || etherType == 0x86ddU) && frame.size() >= networkOffset) {
    const auto beforeIp = packet.layers.size();
    const auto payload = frame.subspan(networkOffset);
    const auto ip = etherType == 0x0800U
                        ? decode_ipv4(payload, captureOffset, networkOffset, tcp, udp, dns, packet)
                        : decode_ipv6(payload, captureOffset, networkOffset, tcp, udp, dns, packet);
    if (ip) {
      std::optional<ProtocolLayer> tcp;
      if (packet.layers.size() > beforeIp) {
        tcp = std::move(packet.layers.back());
        packet.layers.pop_back();
      }
      packet.layers.push_back(*ip);
      if (tcp)
        packet.layers.push_back(std::move(*tcp));
    }
  }
  return std::nullopt;
}
} // namespace wirelens::internal
