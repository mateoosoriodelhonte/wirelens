#pragma once

#include "wirelens/model.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace wirelens::internal {

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

std::optional<ProtocolLayer> decode_tcp(std::span<const std::byte> payload,
                                        std::size_t captureOffset,
                                        std::size_t packetOffset, TcpFacts& facts);
std::optional<ProtocolLayer> decode_ipv4(std::span<const std::byte> payload,
                                          std::size_t captureOffset,
                                          std::size_t packetOffset, TcpFacts& facts,
                                          Packet& packet);
void decode_ethernet(std::span<const std::byte> frame, std::size_t captureOffset,
                     Packet& packet, TcpFacts& facts);
void build_flows(CaptureDocument& capture, std::vector<ParsedPacket>& packets);
std::string flag_text(std::uint8_t flags);

}  // namespace wirelens::internal
