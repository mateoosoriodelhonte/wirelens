#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <vector>

namespace wirelens_test {

inline void put16(std::vector<std::byte>& bytes, const std::size_t offset, const std::uint16_t value) {
  bytes[offset] = static_cast<std::byte>(value & 0xffU);
  bytes[offset + 1] = static_cast<std::byte>(value >> 8U);
}
inline void put16be(std::vector<std::byte>& bytes, const std::size_t offset, const std::uint16_t value) {
  bytes[offset] = static_cast<std::byte>(value >> 8U);
  bytes[offset + 1] = static_cast<std::byte>(value);
}
inline void put32be(std::vector<std::byte>& bytes, const std::size_t offset, const std::uint32_t value) {
  bytes[offset] = static_cast<std::byte>(value >> 24U);
  bytes[offset + 1] = static_cast<std::byte>(value >> 16U);
  bytes[offset + 2] = static_cast<std::byte>(value >> 8U);
  bytes[offset + 3] = static_cast<std::byte>(value);
}
inline void put32le(std::vector<std::byte>& bytes, const std::size_t offset, const std::uint32_t value) {
  bytes[offset] = static_cast<std::byte>(value);
  bytes[offset + 1] = static_cast<std::byte>(value >> 8U);
  bytes[offset + 2] = static_cast<std::byte>(value >> 16U);
  bytes[offset + 3] = static_cast<std::byte>(value >> 24U);
}

inline std::vector<std::byte> build_handshake() {
  std::vector<std::byte> bytes(24 + 3 * (16 + 54), std::byte{0});
  bytes[0] = std::byte{0xd4}; bytes[1] = std::byte{0xc3}; bytes[2] = std::byte{0xb2}; bytes[3] = std::byte{0xa1};
  put16(bytes, 4, 2); put16(bytes, 6, 4); put32le(bytes, 8, 0); put32le(bytes, 12, 0);
  put16(bytes, 16, 0); put16(bytes, 18, 0); put32le(bytes, 20, 1);
  constexpr std::uint32_t seqs[] = {1000, 5000, 1001};
  constexpr std::uint32_t acks[] = {0, 1001, 5001};
  constexpr std::uint8_t flags[] = {0x02, 0x12, 0x10};
  for (std::size_t packet = 0; packet < 3; ++packet) {
    const auto record = 24 + packet * 70;
    put32le(bytes, record, 1);
    put32le(bytes, record + 4, static_cast<std::uint32_t>(packet * 10000));
    put32le(bytes, record + 8, 54); put32le(bytes, record + 12, 54);
    const auto frame = record + 16;
    constexpr std::array<std::uint8_t, 6> clientMac{2, 0, 0, 0, 0, 1};
    constexpr std::array<std::uint8_t, 6> serverMac{2, 0, 0, 0, 0, 2};
    const auto& destination = packet == 0 ? serverMac : clientMac;
    const auto& source = packet == 1 ? serverMac : clientMac;
    for (std::size_t i = 0; i < 6; ++i) { bytes[frame + i] = static_cast<std::byte>(destination[i]); bytes[frame + 6 + i] = static_cast<std::byte>(source[i]); }
    bytes[frame + 12] = std::byte{0x08}; bytes[frame + 13] = std::byte{0x00};
    bytes[frame + 14] = std::byte{0x45}; bytes[frame + 15] = std::byte{0x00};
    bytes[frame + 16] = std::byte{0x00}; bytes[frame + 17] = std::byte{0x28};
    bytes[frame + 22] = std::byte{64}; bytes[frame + 23] = std::byte{6};
    const std::array<std::uint8_t, 4> clientIp{192, 0, 2, 10};
    const std::array<std::uint8_t, 4> serverIp{198, 51, 100, 20};
    const auto& sourceIp = packet == 1 ? serverIp : clientIp;
    const auto& destinationIp = packet == 1 ? clientIp : serverIp;
    for (std::size_t i = 0; i < 4; ++i) { bytes[frame + 26 + i] = static_cast<std::byte>(sourceIp[i]); bytes[frame + 30 + i] = static_cast<std::byte>(destinationIp[i]); }
    const auto tcp = frame + 34;
    put16be(bytes, tcp, packet == 1 ? 443 : 51515); put16be(bytes, tcp + 2, packet == 1 ? 51515 : 443);
    put32be(bytes, tcp + 4, seqs[packet]); put32be(bytes, tcp + 8, acks[packet]);
    bytes[tcp + 12] = std::byte{0x50}; bytes[tcp + 13] = static_cast<std::byte>(flags[packet]);
  }
  return bytes;
}

}  // namespace wirelens_test
