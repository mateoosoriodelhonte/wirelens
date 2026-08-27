#include "protocol_internal.hpp"

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
std::uint32_t u32be(const std::span<const std::byte> bytes, const std::size_t offset) {
  return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset])) << 24U) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 16U) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 2])) << 8U) |
         static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 3]));
}
} // namespace

std::string flag_text(const std::uint8_t flags) {
  if ((flags & 0x12U) == 0x12U)
    return "SYN + ACK";
  std::string result;
  if ((flags & 0x02U) != 0)
    result = "SYN";
  if ((flags & 0x10U) != 0) {
    if (!result.empty())
      result += ", ";
    result += "ACK";
  }
  if ((flags & 0x01U) != 0) {
    if (!result.empty())
      result += ", ";
    result += "FIN";
  }
  if ((flags & 0x04U) != 0) {
    if (!result.empty())
      result += ", ";
    result += "RST";
  }
  return result.empty() ? "none" : result;
}

std::optional<ProtocolLayer> decode_tcp(const std::span<const std::byte> payload,
                                        const std::size_t captureOffset,
                                        const std::size_t packetOffset, const bool payloadComplete,
                                        TcpFacts& facts) {
  if (payload.size() < 20)
    return std::nullopt;
  const auto dataOffset =
      static_cast<std::size_t>(std::to_integer<unsigned>(payload[12]) >> 4U) * 4U;
  if (dataOffset < 20 || dataOffset > payload.size())
    return std::nullopt;
  const auto flags = std::to_integer<std::uint8_t>(payload[13]);
  ProtocolLayer layer{"TCP", "TCP", {}, std::nullopt, std::nullopt};
  layer.explanationKey = "tcp";
  layer.byteRange = range(captureOffset + packetOffset, packetOffset, dataOffset);
  add_field(layer, "sourcePort", std::to_string(u16be(payload, 0)), captureOffset, packetOffset, 2);
  add_field(layer, "destinationPort", std::to_string(u16be(payload, 2)), captureOffset,
            packetOffset + 2, 2);
  add_field(layer, "sequenceNumber", std::to_string(u32be(payload, 4)), captureOffset,
            packetOffset + 4, 4);
  add_field(layer, "acknowledgmentNumber", std::to_string(u32be(payload, 8)), captureOffset,
            packetOffset + 8, 4);
  add_field(layer, "dataOffset", std::to_string(dataOffset), captureOffset, packetOffset + 12, 1);
  add_field(layer, "flags", flag_text(flags), captureOffset, packetOffset + 12, 2);
  add_field(layer, "window", std::to_string(u16be(payload, 14)), captureOffset, packetOffset + 14,
            2);
  if ((flags & 0x12U) == 0x12U) {
    layer.fields.at(5).explanationKey = "tcp.syn-ack";
  } else if ((flags & 0x12U) == 0x02U) {
    layer.fields.at(5).explanationKey = "tcp.syn";
  } else if ((flags & 0x12U) == 0x10U) {
    layer.fields.at(5).explanationKey = "tcp.ack";
  }
  facts.valid = true;
  facts.sourcePort = u16be(payload, 0);
  facts.destinationPort = u16be(payload, 2);
  facts.sequence = u32be(payload, 4);
  facts.acknowledgment = u32be(payload, 8);
  facts.flags = flags;
  facts.headerLength = dataOffset;
  facts.payload = payload.subspan(dataOffset);
  facts.payloadComplete = payloadComplete;
  return layer;
}
} // namespace wirelens::internal
