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

struct UdpFacts {
  bool valid = false;
  std::string source;
  std::string destination;
  std::uint16_t sourcePort = 0;
  std::uint16_t destinationPort = 0;
  std::size_t payloadLength = 0;
};

struct ParsedPacket {
  Packet packet;
  TcpFacts tcp;
  UdpFacts udp;
  ByteRange sourceRange;
};

std::optional<ProtocolLayer> decode_tcp(std::span<const std::byte> payload,
                                        std::size_t captureOffset, std::size_t packetOffset,
                                        TcpFacts& facts);
std::optional<ProtocolLayer> decode_ipv4(std::span<const std::byte> payload,
                                         std::size_t captureOffset, std::size_t packetOffset,
                                         TcpFacts& tcp, UdpFacts& udp, Packet& packet);
std::optional<ProtocolLayer> decode_ipv6(std::span<const std::byte> payload,
                                         std::size_t captureOffset, std::size_t packetOffset,
                                         TcpFacts& tcp, UdpFacts& udp, Packet& packet);
std::optional<ProtocolLayer> decode_udp(std::span<const std::byte> payload,
                                        std::size_t captureOffset, std::size_t packetOffset,
                                        UdpFacts& facts);
std::optional<Diagnostic> decode_ethernet(std::span<const std::byte> frame,
                                          std::size_t captureOffset, Packet& packet, TcpFacts& tcp,
                                          UdpFacts& udp);
void build_flows(CaptureDocument& capture, std::vector<ParsedPacket>& packets);
std::string flag_text(std::uint8_t flags);

} // namespace wirelens::internal
