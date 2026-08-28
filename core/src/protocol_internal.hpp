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
  std::size_t headerLength = 0;
  std::span<const std::byte> payload;
  bool payloadComplete = false;
};

struct UdpFacts {
  bool valid = false;
  std::string source;
  std::string destination;
  std::uint16_t sourcePort = 0;
  std::uint16_t destinationPort = 0;
  std::size_t payloadLength = 0;
};

struct DnsFacts {
  bool valid = false;
  bool response = false;
  std::uint16_t transactionId = 0;
  std::uint8_t opcode = 0;
  std::uint8_t responseCode = 0;
  std::size_t questionCount = 0;
  DnsQuestion question;
  std::vector<DnsRecord> answers;
  std::string source;
  std::string destination;
  std::uint16_t sourcePort = 0;
  std::uint16_t destinationPort = 0;
  std::optional<Diagnostic> diagnostic;
};

struct ParsedPacket {
  Packet packet;
  TcpFacts tcp;
  UdpFacts udp;
  DnsFacts dns;
  ByteRange sourceRange;
};

struct ApplicationStream {
  std::string flowId;
  bool fromClient = false;
  std::vector<std::byte> bytes;
  std::vector<std::size_t> bytePacketNumbers;
  std::vector<std::size_t> packetNumbers;
  bool complete = false;
  bool gap = false;
  bool ambiguous = false;
  bool truncated = false;
  bool limited = false;
};

std::vector<ApplicationStream> reconstruct_tcp_prefixes(CaptureDocument& capture,
                                                         const std::vector<ParsedPacket>& packets);
void build_http(CaptureDocument& capture, std::vector<ParsedPacket>& packets,
                const std::vector<ApplicationStream>& streams);
void build_tls(CaptureDocument& capture, std::vector<ParsedPacket>& packets,
               const std::vector<ApplicationStream>& streams);

std::optional<ProtocolLayer> decode_tcp(std::span<const std::byte> payload,
                                        std::size_t captureOffset, std::size_t packetOffset,
                                        bool payloadComplete, TcpFacts& facts);
std::optional<ProtocolLayer> decode_ipv4(std::span<const std::byte> payload,
                                         std::size_t captureOffset, std::size_t packetOffset,
                                         TcpFacts& tcp, UdpFacts& udp, DnsFacts& dns,
                                         Packet& packet);
std::optional<ProtocolLayer> decode_ipv6(std::span<const std::byte> payload,
                                         std::size_t captureOffset, std::size_t packetOffset,
                                         TcpFacts& tcp, UdpFacts& udp, DnsFacts& dns,
                                         Packet& packet);
std::optional<ProtocolLayer> decode_udp(std::span<const std::byte> payload,
                                        std::size_t captureOffset, std::size_t packetOffset,
                                        UdpFacts& facts);
std::optional<ProtocolLayer> decode_dns(std::span<const std::byte> payload,
                                        std::size_t captureOffset, std::size_t packetOffset,
                                        const UdpFacts& udp, DnsFacts& facts);
std::optional<Diagnostic> decode_ethernet(std::span<const std::byte> frame,
                                          std::size_t captureOffset, Packet& packet, TcpFacts& tcp,
                                          UdpFacts& udp, DnsFacts& dns);
void build_flows(CaptureDocument& capture, std::vector<ParsedPacket>& packets);
void build_dns(CaptureDocument& capture, const std::vector<ParsedPacket>& packets);
void build_applications(CaptureDocument& capture, std::vector<ParsedPacket>& packets);
void add_observation(CaptureDocument& capture, std::string type, std::string message,
                     std::vector<std::size_t> packetNumbers);
void add_diagnostic(CaptureDocument& capture, Diagnostic diagnostic);
std::string flag_text(std::uint8_t flags);

} // namespace wirelens::internal
