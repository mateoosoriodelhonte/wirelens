#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace wirelens_test {

inline void put16(std::vector<std::byte>& bytes, const std::size_t offset,
                  const std::uint16_t value) {
  bytes[offset] = static_cast<std::byte>(value & 0xffU);
  bytes[offset + 1] = static_cast<std::byte>(value >> 8U);
}
inline void put16be(std::vector<std::byte>& bytes, const std::size_t offset,
                    const std::uint16_t value) {
  bytes[offset] = static_cast<std::byte>(value >> 8U);
  bytes[offset + 1] = static_cast<std::byte>(value);
}
inline void put32be(std::vector<std::byte>& bytes, const std::size_t offset,
                    const std::uint32_t value) {
  bytes[offset] = static_cast<std::byte>(value >> 24U);
  bytes[offset + 1] = static_cast<std::byte>(value >> 16U);
  bytes[offset + 2] = static_cast<std::byte>(value >> 8U);
  bytes[offset + 3] = static_cast<std::byte>(value);
}
inline void put32le(std::vector<std::byte>& bytes, const std::size_t offset,
                    const std::uint32_t value) {
  bytes[offset] = static_cast<std::byte>(value);
  bytes[offset + 1] = static_cast<std::byte>(value >> 8U);
  bytes[offset + 2] = static_cast<std::byte>(value >> 16U);
  bytes[offset + 3] = static_cast<std::byte>(value >> 24U);
}

inline std::vector<std::byte> build_handshake() {
  std::vector<std::byte> bytes(24 + 3 * (16 + 54), std::byte{0});
  bytes[0] = std::byte{0xd4};
  bytes[1] = std::byte{0xc3};
  bytes[2] = std::byte{0xb2};
  bytes[3] = std::byte{0xa1};
  put16(bytes, 4, 2);
  put16(bytes, 6, 4);
  put32le(bytes, 8, 0);
  put32le(bytes, 12, 0);
  put32le(bytes, 16, 65535);
  put32le(bytes, 20, 1);
  constexpr std::uint32_t seqs[] = {1000, 5000, 1001};
  constexpr std::uint32_t acks[] = {0, 1001, 5001};
  constexpr std::uint8_t flags[] = {0x02, 0x12, 0x10};
  for (std::size_t packet = 0; packet < 3; ++packet) {
    const auto record = 24 + packet * 70;
    put32le(bytes, record, 1);
    put32le(bytes, record + 4, static_cast<std::uint32_t>(packet * 10000));
    put32le(bytes, record + 8, 54);
    put32le(bytes, record + 12, 54);
    const auto frame = record + 16;
    constexpr std::array<std::uint8_t, 6> clientMac{2, 0, 0, 0, 0, 1};
    constexpr std::array<std::uint8_t, 6> serverMac{2, 0, 0, 0, 0, 2};
    const auto& destination = packet == 0 ? serverMac : clientMac;
    const auto& source = packet == 1 ? serverMac : clientMac;
    for (std::size_t i = 0; i < 6; ++i) {
      bytes[frame + i] = static_cast<std::byte>(destination[i]);
      bytes[frame + 6 + i] = static_cast<std::byte>(source[i]);
    }
    bytes[frame + 12] = std::byte{0x08};
    bytes[frame + 13] = std::byte{0x00};
    bytes[frame + 14] = std::byte{0x45};
    bytes[frame + 15] = std::byte{0x00};
    bytes[frame + 16] = std::byte{0x00};
    bytes[frame + 17] = std::byte{0x28};
    bytes[frame + 22] = std::byte{64};
    bytes[frame + 23] = std::byte{6};
    const std::array<std::uint8_t, 4> clientIp{192, 0, 2, 10};
    const std::array<std::uint8_t, 4> serverIp{198, 51, 100, 20};
    const auto& sourceIp = packet == 1 ? serverIp : clientIp;
    const auto& destinationIp = packet == 1 ? clientIp : serverIp;
    for (std::size_t i = 0; i < 4; ++i) {
      bytes[frame + 26 + i] = static_cast<std::byte>(sourceIp[i]);
      bytes[frame + 30 + i] = static_cast<std::byte>(destinationIp[i]);
    }
    const auto tcp = frame + 34;
    put16be(bytes, tcp, packet == 1 ? 443 : 51515);
    put16be(bytes, tcp + 2, packet == 1 ? 51515 : 443);
    put32be(bytes, tcp + 4, seqs[packet]);
    put32be(bytes, tcp + 8, acks[packet]);
    bytes[tcp + 12] = std::byte{0x50};
    bytes[tcp + 13] = static_cast<std::byte>(flags[packet]);
  }
  return bytes;
}

struct TcpPacketSpec {
  TcpPacketSpec(bool clientToServerValue = true, std::uint32_t sequenceValue = 0,
                std::uint32_t acknowledgmentValue = 0, std::uint8_t flagsValue = 0x10,
                std::vector<std::byte> payloadValue = {},
                std::optional<std::size_t> declaredPayloadLengthValue = {},
                std::optional<std::size_t> originalFrameLengthValue = {},
                std::uint32_t timestampMicrosecondsValue = 0)
      : clientToServer(clientToServerValue), sequence(sequenceValue),
        acknowledgment(acknowledgmentValue), flags(flagsValue), payload(std::move(payloadValue)),
        declaredPayloadLength(declaredPayloadLengthValue),
        originalFrameLength(originalFrameLengthValue),
        timestampMicroseconds(timestampMicrosecondsValue) {}

  bool clientToServer = true;
  std::uint32_t sequence = 0;
  std::uint32_t acknowledgment = 0;
  std::uint8_t flags = 0x10;
  std::vector<std::byte> payload;
  std::optional<std::size_t> declaredPayloadLength;
  std::optional<std::size_t> originalFrameLength;
  std::uint32_t timestampMicroseconds = 0;
};

inline std::vector<std::byte> byte_payload(const std::string_view value) {
  std::vector<std::byte> result;
  result.reserve(value.size());
  for (const auto character : value)
    result.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  return result;
}

inline std::vector<std::byte> build_tcp_capture(const std::span<const TcpPacketSpec> packets) {
  constexpr std::size_t ethernetLength = 14;
  constexpr std::size_t ipv4Length = 20;
  constexpr std::size_t tcpLength = 20;
  constexpr std::array<std::uint8_t, 6> clientMac{2, 0, 0, 0, 0, 1};
  constexpr std::array<std::uint8_t, 6> serverMac{2, 0, 0, 0, 0, 2};
  constexpr std::array<std::uint8_t, 4> clientIp{192, 0, 2, 10};
  constexpr std::array<std::uint8_t, 4> serverIp{198, 51, 100, 20};

  std::size_t size = 24;
  for (const auto& packet : packets)
    size += 16 + ethernetLength + ipv4Length + tcpLength + packet.payload.size();
  std::vector<std::byte> bytes(size, std::byte{0});
  bytes[0] = std::byte{0xd4};
  bytes[1] = std::byte{0xc3};
  bytes[2] = std::byte{0xb2};
  bytes[3] = std::byte{0xa1};
  put16(bytes, 4, 2);
  put16(bytes, 6, 4);
  put32le(bytes, 16, 65535);
  put32le(bytes, 20, 1);

  std::size_t record = 24;
  for (std::size_t index = 0; index < packets.size(); ++index) {
    const auto& packet = packets[index];
    const auto capturedFrameLength =
        ethernetLength + ipv4Length + tcpLength + packet.payload.size();
    const auto originalFrameLength = packet.originalFrameLength.value_or(capturedFrameLength);
    put32le(bytes, record, 1);
    put32le(bytes, record + 4, packet.timestampMicroseconds);
    put32le(bytes, record + 8, static_cast<std::uint32_t>(capturedFrameLength));
    put32le(bytes, record + 12, static_cast<std::uint32_t>(originalFrameLength));

    const auto frame = record + 16;
    const auto& destinationMac = packet.clientToServer ? serverMac : clientMac;
    const auto& sourceMac = packet.clientToServer ? clientMac : serverMac;
    for (std::size_t byte = 0; byte < destinationMac.size(); ++byte) {
      bytes[frame + byte] = static_cast<std::byte>(destinationMac[byte]);
      bytes[frame + 6 + byte] = static_cast<std::byte>(sourceMac[byte]);
    }
    bytes[frame + 12] = std::byte{0x08};
    bytes[frame + 13] = std::byte{0x00};

    const auto ip = frame + ethernetLength;
    bytes[ip] = std::byte{0x45};
    const auto declaredPayloadLength = packet.declaredPayloadLength.value_or(packet.payload.size());
    put16be(bytes, ip + 2,
            static_cast<std::uint16_t>(ipv4Length + tcpLength + declaredPayloadLength));
    put16be(bytes, ip + 4, static_cast<std::uint16_t>(index + 1));
    bytes[ip + 8] = std::byte{64};
    bytes[ip + 9] = std::byte{6};
    const auto& sourceIp = packet.clientToServer ? clientIp : serverIp;
    const auto& destinationIp = packet.clientToServer ? serverIp : clientIp;
    for (std::size_t byte = 0; byte < sourceIp.size(); ++byte) {
      bytes[ip + 12 + byte] = static_cast<std::byte>(sourceIp[byte]);
      bytes[ip + 16 + byte] = static_cast<std::byte>(destinationIp[byte]);
    }

    const auto tcp = ip + ipv4Length;
    put16be(bytes, tcp, packet.clientToServer ? 51515 : 443);
    put16be(bytes, tcp + 2, packet.clientToServer ? 443 : 51515);
    put32be(bytes, tcp + 4, packet.sequence);
    put32be(bytes, tcp + 8, packet.acknowledgment);
    bytes[tcp + 12] = std::byte{0x50};
    bytes[tcp + 13] = static_cast<std::byte>(packet.flags);
    for (std::size_t byte = 0; byte < packet.payload.size(); ++byte)
      bytes[tcp + tcpLength + byte] = packet.payload[byte];
    record += 16 + capturedFrameLength;
  }
  return bytes;
}

} // namespace wirelens_test
