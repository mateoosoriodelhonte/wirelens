#include "fixture_builder.hpp"
#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"

#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>

namespace {

std::vector<std::byte> build_ipv6_udp_pcapng() {
  constexpr std::size_t frameLength = 62;
  constexpr std::size_t epbLength = 32 + 64;
  std::vector<std::byte> bytes(28 + 20 + epbLength, std::byte{0});
  auto block = [&](std::size_t offset, std::uint32_t type, std::uint32_t length) {
    wirelens_test::put32le(bytes, offset, type);
    wirelens_test::put32le(bytes, offset + 4, length);
    wirelens_test::put32le(bytes, offset + length - 4, length);
  };
  block(0, 0x0a0d0d0a, 28);
  bytes[8] = std::byte{0x4d};
  bytes[9] = std::byte{0x3c};
  bytes[10] = std::byte{0x2b};
  bytes[11] = std::byte{0x1a};
  bytes[12] = std::byte{1};
  block(28, 1, 20);
  wirelens_test::put16(bytes, 36, 1);
  wirelens_test::put32le(bytes, 40, 65535);
  block(48, 6, epbLength);
  wirelens_test::put32le(bytes, 56, 0);
  wirelens_test::put32le(bytes, 60, 0);
  wirelens_test::put32le(bytes, 64, 1000000);
  wirelens_test::put32le(bytes, 68, frameLength);
  wirelens_test::put32le(bytes, 72, frameLength);
  const auto frame = 76U;
  for (std::size_t i = 0; i < 6; ++i) {
    bytes[frame + i] = static_cast<std::byte>(i == 5 ? 2 : 0);
    bytes[frame + 6 + i] = static_cast<std::byte>(i == 5 ? 1 : 0);
  }
  bytes[frame + 12] = std::byte{0x86};
  bytes[frame + 13] = std::byte{0xdd};
  bytes[frame + 14] = std::byte{0x60};
  bytes[frame + 18] = std::byte{0};
  bytes[frame + 19] = std::byte{8};
  bytes[frame + 20] = std::byte{17};
  bytes[frame + 21] = std::byte{64};
  bytes[frame + 14 + 8] = std::byte{0x20};
  bytes[frame + 14 + 9] = std::byte{1};
  bytes[frame + 14 + 10] = std::byte{0x0d};
  bytes[frame + 14 + 11] = std::byte{0xb8};
  bytes[frame + 14 + 24] = std::byte{0x20};
  bytes[frame + 14 + 25] = std::byte{1};
  bytes[frame + 14 + 26] = std::byte{0x0d};
  bytes[frame + 14 + 27] = std::byte{0xb8};
  bytes[frame + 37] = std::byte{1};
  bytes[frame + 53] = std::byte{2};
  const auto udp = frame + 54;
  wirelens_test::put16be(bytes, udp, 53000);
  wirelens_test::put16be(bytes, udp + 2, 53);
  wirelens_test::put16be(bytes, udp + 4, 8);
  return bytes;
}

std::vector<std::byte> build_pcapng_with_nanosecond_option() {
  const auto source = build_ipv6_udp_pcapng();
  std::vector<std::byte> bytes(source.size() + 12U, std::byte{0});
  std::copy(source.begin(), source.begin() + 48, bytes.begin());
  wirelens_test::put32le(bytes, 28, 1);
  wirelens_test::put32le(bytes, 32, 32);
  wirelens_test::put16(bytes, 44, 9);
  wirelens_test::put16(bytes, 46, 1);
  bytes[48] = std::byte{9};
  wirelens_test::put16(bytes, 52, 0);
  wirelens_test::put16(bytes, 54, 0);
  wirelens_test::put32le(bytes, 56, 32);
  std::copy(source.begin() + 48, source.end(), bytes.begin() + 60);
  wirelens_test::put32le(bytes, 76, 1);
  return bytes;
}

std::vector<std::byte> build_big_endian_pcapng() {
  auto bytes = build_ipv6_udp_pcapng();
  const auto be32 = [&](const std::size_t offset, const std::uint32_t value) {
    bytes[offset] = static_cast<std::byte>(value >> 24U);
    bytes[offset + 1] = static_cast<std::byte>(value >> 16U);
    bytes[offset + 2] = static_cast<std::byte>(value >> 8U);
    bytes[offset + 3] = static_cast<std::byte>(value);
  };
  const auto be16 = [&](const std::size_t offset, const std::uint16_t value) {
    bytes[offset] = static_cast<std::byte>(value >> 8U);
    bytes[offset + 1] = static_cast<std::byte>(value);
  };
  bytes[8] = std::byte{0x1a};
  bytes[9] = std::byte{0x2b};
  bytes[10] = std::byte{0x3c};
  bytes[11] = std::byte{0x4d};
  be16(12, 1);
  be16(14, 0);
  for (const auto start : {0U, 28U, 48U}) {
    be32(start, start == 0 ? 0x0a0d0d0aU : (start == 28 ? 1U : 6U));
    be32(start + 4, start == 0 ? 28U : (start == 28 ? 20U : 96U));
    be32(start + (start == 0 ? 24U : (start == 28 ? 16U : 92U)),
         start == 0 ? 28U : (start == 28 ? 20U : 96U));
  }
  be16(36, 1);
  be16(38, 0);
  be32(40, 65535);
  be32(56, 0);
  be32(60, 0);
  be32(64, 1000000);
  be32(68, 62);
  be32(72, 62);
  return bytes;
}

std::vector<std::byte> build_empty_packets(const std::size_t packetCount) {
  std::vector<std::byte> bytes(24U + packetCount * 16U, std::byte{0});
  bytes[0] = std::byte{0xd4};
  bytes[1] = std::byte{0xc3};
  bytes[2] = std::byte{0xb2};
  bytes[3] = std::byte{0xa1};
  bytes[4] = std::byte{2};
  bytes[6] = std::byte{4};
  bytes[20] = std::byte{1};
  return bytes;
}

std::vector<std::byte> build_pcapng_empty_packets(const std::size_t packetCount) {
  constexpr std::size_t blockLength = 32;
  std::vector<std::byte> bytes(48U + packetCount * blockLength, std::byte{0});
  auto block = [&](const std::size_t offset, const std::uint32_t type, const std::uint32_t length) {
    wirelens_test::put32le(bytes, offset, type);
    wirelens_test::put32le(bytes, offset + 4, length);
    wirelens_test::put32le(bytes, offset + length - 4, length);
  };
  block(0, 0x0a0d0d0a, 28);
  bytes[8] = std::byte{0x4d};
  bytes[9] = std::byte{0x3c};
  bytes[10] = std::byte{0x2b};
  bytes[11] = std::byte{0x1a};
  bytes[12] = std::byte{1};
  block(28, 1, 20);
  wirelens_test::put16(bytes, 36, 1);
  wirelens_test::put32le(bytes, 40, 0);
  for (std::size_t i = 0; i < packetCount; ++i) {
    const auto offset = 48U + i * blockLength;
    block(offset, 6, blockLength);
    wirelens_test::put32le(bytes, offset + 8, 0);
    wirelens_test::put32le(bytes, offset + 20, 0);
    wirelens_test::put32le(bytes, offset + 24, 0);
  }
  return bytes;
}

std::vector<std::byte> build_pcapng_interfaces(const std::size_t interfaceCount) {
  constexpr std::size_t blockLength = 20;
  std::vector<std::byte> bytes(28U + interfaceCount * blockLength, std::byte{0});
  wirelens_test::put32le(bytes, 0, 0x0a0d0d0a);
  wirelens_test::put32le(bytes, 4, 28);
  bytes[8] = std::byte{0x4d};
  bytes[9] = std::byte{0x3c};
  bytes[10] = std::byte{0x2b};
  bytes[11] = std::byte{0x1a};
  bytes[12] = std::byte{1};
  wirelens_test::put32le(bytes, 24, 28);
  for (std::size_t i = 0; i < interfaceCount; ++i) {
    const auto offset = 28U + i * blockLength;
    wirelens_test::put32le(bytes, offset, 1);
    wirelens_test::put32le(bytes, offset + 4, blockLength);
    wirelens_test::put16(bytes, offset + 8, 1);
    wirelens_test::put32le(bytes, offset + 12, 0);
    wirelens_test::put32le(bytes, offset + 16, blockLength);
  }
  return bytes;
}

std::vector<std::byte> build_ipv6_variant(const std::vector<std::uint8_t>& extensionTypes,
                                          const std::uint8_t transport,
                                          const std::size_t transportLength = 8,
                                          const std::uint16_t udpLength = 8,
                                          const std::uint16_t fragmentBits = 0,
                                          const std::optional<std::uint16_t> declaredPayload = {}) {
  const auto frameLength = 14U + 40U + extensionTypes.size() * 8U + transportLength;
  const auto blockLength = 32U + ((frameLength + 3U) & ~std::size_t{3U});
  std::vector<std::byte> bytes(48U + blockLength, std::byte{0});
  auto block = [&](const std::size_t offset, const std::uint32_t type, const std::uint32_t length) {
    wirelens_test::put32le(bytes, offset, type);
    wirelens_test::put32le(bytes, offset + 4, length);
    wirelens_test::put32le(bytes, offset + length - 4, length);
  };
  block(0, 0x0a0d0d0a, 28);
  bytes[8] = std::byte{0x4d};
  bytes[9] = std::byte{0x3c};
  bytes[10] = std::byte{0x2b};
  bytes[11] = std::byte{0x1a};
  bytes[12] = std::byte{1};
  block(28, 1, 20);
  wirelens_test::put16(bytes, 36, 1);
  wirelens_test::put32le(bytes, 40, 65535);
  block(48, 6, blockLength);
  wirelens_test::put32le(bytes, 56, 0);
  wirelens_test::put32le(bytes, 60, 0);
  wirelens_test::put32le(bytes, 64, 1);
  wirelens_test::put32le(bytes, 68, frameLength);
  wirelens_test::put32le(bytes, 72, frameLength);
  const auto frame = 76U;
  bytes[frame + 5] = std::byte{2};
  bytes[frame + 11] = std::byte{1};
  bytes[frame + 12] = std::byte{0x86};
  bytes[frame + 13] = std::byte{0xdd};
  bytes[frame + 14] = std::byte{0x60};
  bytes[frame + 21] = std::byte{64};
  bytes[frame + 14 + 8] = std::byte{0x20};
  bytes[frame + 14 + 9] = std::byte{1};
  bytes[frame + 14 + 10] = std::byte{0x0d};
  bytes[frame + 14 + 11] = std::byte{0xb8};
  bytes[frame + 14 + 37] = std::byte{1};
  bytes[frame + 14 + 24] = std::byte{0x20};
  bytes[frame + 14 + 25] = std::byte{1};
  bytes[frame + 14 + 26] = std::byte{0x0d};
  bytes[frame + 14 + 27] = std::byte{0xb8};
  bytes[frame + 53] = std::byte{2};
  bytes[frame + 20] =
      static_cast<std::byte>(extensionTypes.empty() ? transport : extensionTypes.front());
  wirelens_test::put16be(bytes, frame + 18,
                         declaredPayload.value_or(static_cast<std::uint16_t>(frameLength - 54U)));
  auto extensionOffset = frame + 54U;
  for (std::size_t i = 0; i < extensionTypes.size(); ++i) {
    const auto next = i + 1U < extensionTypes.size() ? extensionTypes[i + 1U] : transport;
    bytes[extensionOffset] = static_cast<std::byte>(next);
    if (extensionTypes[i] == 44) {
      bytes[extensionOffset + 2] = static_cast<std::byte>(fragmentBits >> 8U);
      bytes[extensionOffset + 3] = static_cast<std::byte>(fragmentBits);
      wirelens_test::put32be(bytes, extensionOffset + 4, 0x12345678U);
    }
    extensionOffset += 8U;
  }
  if (transport == 17) {
    wirelens_test::put16be(bytes, extensionOffset, 53000);
    wirelens_test::put16be(bytes, extensionOffset + 2, 53);
    wirelens_test::put16be(bytes, extensionOffset + 4, udpLength);
  } else if (transport == 6) {
    wirelens_test::put16be(bytes, extensionOffset, 51515);
    wirelens_test::put16be(bytes, extensionOffset + 2, 443);
    bytes[extensionOffset + 12] = std::byte{0x50};
    bytes[extensionOffset + 13] = std::byte{0x02};
  }
  return bytes;
}

std::vector<std::byte> build_ipv4_udp_pcap() {
  auto bytes = wirelens_test::build_handshake();
  bytes.resize(24U + 16U + 42U);
  wirelens_test::put32le(bytes, 24 + 8, 42);
  wirelens_test::put32le(bytes, 24 + 12, 42);
  const auto frame = 40U;
  wirelens_test::put16be(bytes, frame + 16, 28);
  bytes[frame + 23] = std::byte{17};
  wirelens_test::put16be(bytes, frame + 34, 53000);
  wirelens_test::put16be(bytes, frame + 36, 53);
  wirelens_test::put16be(bytes, frame + 38, 8);
  return bytes;
}

void require_bounded_ranges(const wirelens::Packet& packet) {
  for (const auto& layer : packet.layers) {
    if (layer.byteRange) {
      REQUIRE(layer.byteRange->packetOffset <= packet.capturedLength);
      REQUIRE(layer.byteRange->length <= packet.capturedLength - layer.byteRange->packetOffset);
    }
    for (const auto& field : layer.fields) {
      if (field.byteRange) {
        REQUIRE(field.byteRange->packetOffset <= packet.capturedLength);
        REQUIRE(field.byteRange->length <= packet.capturedLength - field.byteRange->packetOffset);
      }
    }
  }
}

} // namespace

TEST_CASE("parse_capture rejects a truncated global header") {
  const std::array<std::byte, 3> bytes{};
  const auto result = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
  REQUIRE(std::get<wirelens::ParseError>(result).code == "TRUNCATED_GLOBAL_HEADER");
}

TEST_CASE("parse_capture accepts an empty valid capture") {
  std::vector<std::byte> bytes(24, std::byte{0});
  bytes[0] = std::byte{0xd4};
  bytes[1] = std::byte{0xc3};
  bytes[2] = std::byte{0xb2};
  bytes[3] = std::byte{0xa1};
  bytes[4] = std::byte{2};
  bytes[6] = std::byte{4};
  bytes[20] = std::byte{1};
  const auto result = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  REQUIRE(std::get<wirelens::CaptureDocument>(result).packets.empty());
}

TEST_CASE("parse_capture enforces the packet count boundary") {
  SECTION("the configured maximum is accepted") {
    const auto result = wirelens::parse_capture(build_empty_packets(wirelens::kMaxPacketCount));
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    REQUIRE(std::get<wirelens::CaptureDocument>(result).packets.size() ==
            wirelens::kMaxPacketCount);
  }

  SECTION("the first packet above the maximum is rejected") {
    const auto result =
        wirelens::parse_capture(build_empty_packets(wirelens::kMaxPacketCount + 1U));
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    const auto& error = std::get<wirelens::ParseError>(result);
    REQUIRE(error.code == "PACKET_LIMIT_EXCEEDED");
    REQUIRE(error.captureOffset == 24U + wirelens::kMaxPacketCount * 16U);
    REQUIRE(error.packetNumber == wirelens::kMaxPacketCount + 1U);
  }

  SECTION("PCAPNG accepts the configured maximum") {
    const auto result =
        wirelens::parse_capture(build_pcapng_empty_packets(wirelens::kMaxPacketCount));
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    REQUIRE(std::get<wirelens::CaptureDocument>(result).packets.size() ==
            wirelens::kMaxPacketCount);
  }

  SECTION("PCAPNG reports the first packet above the maximum") {
    const auto result =
        wirelens::parse_capture(build_pcapng_empty_packets(wirelens::kMaxPacketCount + 1U));
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    const auto& error = std::get<wirelens::ParseError>(result);
    REQUIRE(error.code == "PACKET_LIMIT_EXCEEDED");
    REQUIRE(error.captureOffset == 48U + wirelens::kMaxPacketCount * 32U);
    REQUIRE(error.packetNumber == wirelens::kMaxPacketCount + 1U);
  }
}

TEST_CASE("parse_capture decodes the deterministic three packet handshake") {
  const auto result = wirelens::parse_capture(wirelens_test::build_handshake());
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.packets.size() == 3);
  REQUIRE(capture.packets[0].timestampNs == "1000000000");
  REQUIRE(capture.packets[1].timestampNs == "1010000000");
  REQUIRE(capture.packets[2].timestampNs == "1020000000");
  REQUIRE(capture.packets[0].sourceAddress == "192.0.2.10");
  REQUIRE(capture.packets[0].destinationAddress == "198.51.100.20");
  REQUIRE(capture.packets[0].sourcePort == 51515);
  REQUIRE(capture.packets[0].destinationPort == 443);
  REQUIRE(capture.packets[1].summary == "SYN + ACK");
  REQUIRE(capture.packets[2].summary == "ACK");
  REQUIRE(capture.packets[1].sourcePort == 443);
  REQUIRE(capture.packets[1].destinationPort == 51515);
  REQUIRE(capture.packets[2].sourcePort == 51515);
  REQUIRE(capture.packets[2].destinationPort == 443);
}

TEST_CASE("parse_capture accepts all classic magic and byte orders") {
  const std::array<std::array<std::uint8_t, 4>, 4> magics{{{0xd4, 0xc3, 0xb2, 0xa1},
                                                           {0xa1, 0xb2, 0xc3, 0xd4},
                                                           {0x4d, 0x3c, 0xb2, 0xa1},
                                                           {0xa1, 0xb2, 0x3c, 0x4d}}};
  for (const auto magic : magics) {
    std::vector<std::byte> bytes(24, std::byte{0});
    for (std::size_t i = 0; i < 4; ++i)
      bytes[i] = static_cast<std::byte>(magic[i]);
    const bool little = magic[0] == 0xd4 || magic[0] == 0x4d;
    if (little) {
      bytes[4] = std::byte{2};
      bytes[6] = std::byte{4};
      bytes[20] = std::byte{1};
    } else {
      bytes[4] = std::byte{0};
      bytes[5] = std::byte{2};
      bytes[6] = std::byte{0};
      bytes[7] = std::byte{4};
      bytes[23] = std::byte{1};
    }
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  }
}

TEST_CASE("classic PCAP validates snap length and timestamp fractions") {
  SECTION("the header snap length is read from bytes 16 through 19") {
    const auto result = wirelens::parse_capture(wirelens_test::build_handshake());
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    REQUIRE(std::get<wirelens::CaptureDocument>(result).capture.interfaces.at(0).snapLength ==
            65'535U);
  }

  SECTION("captured length at the snap length is accepted") {
    auto bytes = wirelens_test::build_handshake();
    wirelens_test::put32le(bytes, 16, 54);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(wirelens::parse_capture(bytes)));
  }

  SECTION("captured length above a nonzero snap length is rejected") {
    auto bytes = wirelens_test::build_handshake();
    wirelens_test::put32le(bytes, 16, 53);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "PCAP_PACKET_EXCEEDS_SNAPLEN");
  }

  SECTION("microsecond fractions below one second are accepted") {
    auto bytes = wirelens_test::build_handshake();
    wirelens_test::put32le(bytes, 28, 999'999U);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    REQUIRE(std::get<wirelens::CaptureDocument>(result).packets.at(0).timestampNs == "1999999000");
  }

  SECTION("one million microseconds is rejected") {
    auto bytes = wirelens_test::build_handshake();
    wirelens_test::put32le(bytes, 28, 1'000'000U);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "INVALID_TIMESTAMP");
    REQUIRE(std::get<wirelens::ParseError>(result).captureOffset == 28U);
  }

  SECTION("nanosecond fractions use the same strict boundary") {
    auto bytes = wirelens_test::build_handshake();
    bytes[0] = std::byte{0x4d};
    bytes[1] = std::byte{0x3c};
    bytes[2] = std::byte{0xb2};
    bytes[3] = std::byte{0xa1};
    wirelens_test::put32le(bytes, 28, 999'999'999U);
    const auto accepted = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(accepted));
    REQUIRE(std::get<wirelens::CaptureDocument>(accepted).packets.at(0).timestampNs ==
            "1999999999");
    wirelens_test::put32le(bytes, 28, 1'000'000'000U);
    const auto rejected = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(rejected));
    REQUIRE(std::get<wirelens::ParseError>(rejected).code == "INVALID_TIMESTAMP");
  }
}

TEST_CASE("parse_capture decodes a bounded PCAPNG IPv6 UDP packet") {
  const auto result = wirelens::parse_capture(build_ipv6_udp_pcapng());
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.capture.format == "pcapng");
  REQUIRE(capture.capture.interfaces.size() == 1);
  REQUIRE(capture.packets.size() == 1);
  const auto& packet = capture.packets.at(0);
  REQUIRE(packet.interfaceId == 0);
  REQUIRE(packet.sourceAddress == "2001:db8::1");
  REQUIRE(packet.destinationAddress == "2001:db8::2");
  REQUIRE(packet.sourcePort == 53000);
  REQUIRE(packet.destinationPort == 53);
  REQUIRE(packet.layers.at(1).protocol == "IPV6");
  REQUIRE(packet.layers.at(2).protocol == "UDP");
  require_bounded_ranges(packet);
  REQUIRE(capture.flows.size() == 1);
  REQUIRE(capture.flows.at(0).protocol == "UDP");
  REQUIRE(capture.packetSourceRanges.at(0).captureOffset == 76);
  REQUIRE(capture.packetSourceRanges.at(0).length == 62);
}

TEST_CASE("IPv6 extension fields remain bounded and first fragments decode UDP") {
  auto bytes = build_ipv6_udp_pcapng();
  constexpr std::size_t frame = 76;
  bytes.resize(bytes.size() + 8U, std::byte{0});
  std::copy_backward(bytes.begin() + frame + 54, bytes.begin() + frame + 62,
                     bytes.begin() + frame + 70);
  wirelens_test::put32le(bytes, 52, 104);
  wirelens_test::put32le(bytes, 148, 104);
  wirelens_test::put32le(bytes, 68, 70);
  wirelens_test::put32le(bytes, 72, 70);
  bytes[frame + 20] = std::byte{0};
  wirelens_test::put16be(bytes, frame + 18, 16);
  bytes[frame + 54] = std::byte{17};
  bytes[frame + 55] = std::byte{0};
  const auto result = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& packet = std::get<wirelens::CaptureDocument>(result).packets.at(0);
  REQUIRE(packet.layers.at(1).fields.at(6).value == "Hop-by-Hop Options");
  REQUIRE(packet.layers.at(2).protocol == "UDP");
}

TEST_CASE("IPv6 and UDP bounded protocol matrix") {
  SECTION("TCP, routing, and destination options expose layers and ranges") {
    const auto result = wirelens::parse_capture(build_ipv6_variant({0, 43, 60}, 6, 20));
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    const auto& packet = std::get<wirelens::CaptureDocument>(result).packets.at(0);
    REQUIRE(packet.layers.size() == 3);
    REQUIRE(packet.layers.at(2).protocol == "TCP");
    REQUIRE(packet.layers.at(1).fields.at(6).value == "Hop-by-Hop Options");
    REQUIRE(packet.layers.at(1).fields.at(9).value == "Routing");
    REQUIRE(packet.layers.at(1).fields.at(12).value == "Destination Options");
    REQUIRE(packet.layers.at(1).fields.at(6).byteRange->packetOffset == 54);
    REQUIRE(packet.layers.at(1).fields.at(9).byteRange->packetOffset == 62);
    REQUIRE(packet.layers.at(1).fields.at(12).byteRange->packetOffset == 70);
    require_bounded_ranges(packet);
  }
  SECTION("fragment fields are exposed and only the first fragment decodes transport") {
    const auto first = wirelens::parse_capture(build_ipv6_variant({44}, 17, 8, 8, 1));
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(first));
    const auto& firstPacket = std::get<wirelens::CaptureDocument>(first).packets.at(0);
    REQUIRE(firstPacket.layers.size() == 3);
    REQUIRE(firstPacket.layers.at(1).fields.at(6).value == "Fragment");
    REQUIRE(firstPacket.layers.at(1).fields.at(9).value == "0");
    REQUIRE(firstPacket.layers.at(1).fields.at(10).value == "true");
    require_bounded_ranges(firstPacket);

    const auto nonFirst = wirelens::parse_capture(build_ipv6_variant({44}, 17, 8, 8, 9));
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(nonFirst));
    const auto& nonFirstPacket = std::get<wirelens::CaptureDocument>(nonFirst).packets.at(0);
    REQUIRE(nonFirstPacket.layers.size() == 2);
    REQUIRE(nonFirstPacket.layers.at(1).protocol == "IPV6");
    require_bounded_ranges(nonFirstPacket);
  }
  SECTION("no-next-header and unknown next-header preserve IPv6") {
    for (const auto next : {59U, 250U}) {
      auto bytes = build_ipv6_variant({}, static_cast<std::uint8_t>(next), 0);
      const auto result = wirelens::parse_capture(bytes);
      REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
      const auto& packet = std::get<wirelens::CaptureDocument>(result).packets.at(0);
      REQUIRE(packet.layers.size() == 2);
      REQUIRE(packet.layers.at(1).protocol == "IPV6");
      require_bounded_ranges(packet);
    }
  }
  SECTION("eight extensions are accepted and nine stop at the boundary") {
    const std::vector<std::uint8_t> eight(8, 0);
    const auto accepted = wirelens::parse_capture(build_ipv6_variant(eight, 17, 8));
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(accepted));
    const auto& acceptedPacket = std::get<wirelens::CaptureDocument>(accepted).packets.at(0);
    REQUIRE(acceptedPacket.layers.size() == 3);
    REQUIRE(acceptedPacket.analysisFlags.empty());
    require_bounded_ranges(acceptedPacket);
    const std::vector<std::uint8_t> nine(9, 0);
    const auto stopped = wirelens::parse_capture(build_ipv6_variant(nine, 17, 8));
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(stopped));
    const auto& stoppedPacket = std::get<wirelens::CaptureDocument>(stopped).packets.at(0);
    REQUIRE(stoppedPacket.layers.size() == 2);
    REQUIRE(stoppedPacket.analysisFlags == std::vector<std::string>{"ipv6-extension-limit"});
    require_bounded_ranges(stoppedPacket);
  }
  SECTION("declared payload and captured bounds prevent transport over-read") {
    const auto shortDeclared = wirelens::parse_capture(build_ipv6_variant({}, 17, 8, 8, 0, 4));
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(shortDeclared));
    REQUIRE(std::get<wirelens::CaptureDocument>(shortDeclared).packets.at(0).layers.size() == 2);
    const auto longDeclared = wirelens::parse_capture(build_ipv6_variant({}, 17, 8, 8, 0, 80));
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(longDeclared));
    require_bounded_ranges(std::get<wirelens::CaptureDocument>(longDeclared).packets.at(0));
    auto truncatedExtension = build_ipv6_variant({0}, 17, 8);
    wirelens_test::put32le(truncatedExtension, 68, 58);
    wirelens_test::put32le(truncatedExtension, 72, 58);
    const auto truncatedResult = wirelens::parse_capture(truncatedExtension);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(truncatedResult));
    const auto& truncatedPacket =
        std::get<wirelens::CaptureDocument>(truncatedResult).packets.at(0);
    REQUIRE(truncatedPacket.layers.size() == 2);
    REQUIRE(truncatedPacket.layers.at(0).protocol == "ETHERNET");
    REQUIRE(truncatedPacket.layers.at(1).protocol == "IPV6");
    require_bounded_ranges(truncatedPacket);
  }
  SECTION("UDP length boundary is enforced for IPv4 and IPv6") {
    const auto ipv4Exact = wirelens::parse_capture(build_ipv4_udp_pcap());
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(ipv4Exact));
    REQUIRE(std::get<wirelens::CaptureDocument>(ipv4Exact).packets.at(0).layers.back().protocol ==
            "UDP");
    for (const auto udpLength : {0U, 7U, 9U, 65535U}) {
      auto bytes = build_ipv4_udp_pcap();
      wirelens_test::put16be(bytes, 40U + 38U, static_cast<std::uint16_t>(udpLength));
      const auto result = wirelens::parse_capture(bytes);
      REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
      const auto& packet = std::get<wirelens::CaptureDocument>(result).packets.at(0);
      REQUIRE(packet.layers.size() == 2);
      require_bounded_ranges(packet);
    }
    auto truncated = build_ipv4_udp_pcap();
    truncated.resize(24U + 16U + 38U);
    wirelens_test::put32le(truncated, 24U + 8U, 38);
    wirelens_test::put32le(truncated, 24U + 12U, 38);
    const auto truncatedResult = wirelens::parse_capture(truncated);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(truncatedResult));
    REQUIRE(std::get<wirelens::CaptureDocument>(truncatedResult).packets.at(0).layers.size() == 2);
    const auto ipv6Exact = wirelens::parse_capture(build_ipv6_variant({}, 17, 8, 8));
    REQUIRE(std::get<wirelens::CaptureDocument>(ipv6Exact).packets.at(0).layers.back().protocol ==
            "UDP");
    for (const auto udpLength : {0U, 7U, 9U, 65535U}) {
      const auto result = wirelens::parse_capture(
          build_ipv6_variant({}, 17, 8, static_cast<std::uint16_t>(udpLength)));
      REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
      const auto& packet = std::get<wirelens::CaptureDocument>(result).packets.at(0);
      REQUIRE(packet.layers.size() == 2);
      require_bounded_ranges(packet);
    }
  }
  SECTION("IPv6 address formatting handles zero forms") {
    auto zero = build_ipv6_variant({}, 59, 0);
    std::fill(zero.begin() + 76 + 22, zero.begin() + 76 + 54, std::byte{0});
    const auto zeroResult = wirelens::parse_capture(zero);
    REQUIRE(std::get<wirelens::CaptureDocument>(zeroResult).packets.at(0).sourceAddress == "::");
    auto trailing = build_ipv6_variant({}, 59, 0);
    std::fill(trailing.begin() + 76 + 22 + 4, trailing.begin() + 76 + 38, std::byte{0});
    const auto trailingResult = wirelens::parse_capture(trailing);
    REQUIRE(std::get<wirelens::CaptureDocument>(trailingResult).packets.at(0).sourceAddress ==
            "2001:db8::");
  }
}

TEST_CASE("UDP flow serialization omits TCP-only lifecycle fields") {
  const auto result = wirelens::parse_capture(build_ipv6_udp_pcapng());
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto json = wirelens::serialize_capture(std::get<wirelens::CaptureDocument>(result));
  REQUIRE(json.find("\"protocol\": \"UDP\"") != std::string::npos);
  REQUIRE(json.find("\"handshake\"") == std::string::npos);
}

TEST_CASE("parse_capture applies an explicit PCAPNG decimal timestamp resolution") {
  const auto result = wirelens::parse_capture(build_pcapng_with_nanosecond_option());
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.capture.timestampResolution == "nanoseconds");
  REQUIRE(capture.packets.at(0).timestampNs == "1");
}

TEST_CASE("parse_capture accepts a big-endian PCAPNG section") {
  const auto result = wirelens::parse_capture(build_big_endian_pcapng());
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  REQUIRE(std::get<wirelens::CaptureDocument>(result).packets.size() == 1);
}

TEST_CASE("parse_capture rejects malformed PCAPNG block structure") {
  auto bytes = build_ipv6_udp_pcapng();
  SECTION("truncated block") {
    bytes.resize(bytes.size() - 1);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::get<wirelens::ParseError>(result).code == "TRUNCATED_PCAPNG_BLOCK");
  }
  SECTION("mismatched trailing length") {
    bytes[bytes.size() - 4] = std::byte{0};
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::get<wirelens::ParseError>(result).code == "MISMATCHED_PCAPNG_BLOCK_LENGTH");
  }
  SECTION("unsupported section version") {
    bytes[14] = std::byte{1};
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::get<wirelens::ParseError>(result).code == "UNSUPPORTED_PCAPNG_VERSION");
  }
  SECTION("invalid alignment") {
    bytes[52] = std::byte{1};
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::get<wirelens::ParseError>(result).code == "INVALID_PCAPNG_BLOCK_LENGTH");
  }
  SECTION("captured length exceeds block data") {
    wirelens_test::put32le(bytes, 68, 65);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::get<wirelens::ParseError>(result).code == "INVALID_PCAPNG_PACKET_LENGTH");
  }
  SECTION("captured length exceeds original length") {
    wirelens_test::put32le(bytes, 72, 61);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::get<wirelens::ParseError>(result).code == "INVALID_PACKET_LENGTH");
  }
  SECTION("zero interface snap length means unlimited") {
    bytes[40] = std::byte{0};
    bytes[41] = std::byte{0};
    bytes[42] = std::byte{0};
    bytes[43] = std::byte{0};
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    REQUIRE(std::get<wirelens::CaptureDocument>(result).capture.interfaces.at(0).snapLength == 0);
  }
}

TEST_CASE("PCAPNG enforces the named block limit") {
  auto bytes = build_ipv6_udp_pcapng();
  const auto start = bytes.size();
  bytes.resize(start + 16U * 1024U * 1024U, std::byte{0});
  wirelens_test::put32le(bytes, start, 0x12345678);
  wirelens_test::put32le(bytes, start + 4, 16U * 1024U * 1024U);
  wirelens_test::put32le(bytes, bytes.size() - 4, 16U * 1024U * 1024U);
  const auto accepted = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(accepted));
  wirelens_test::put32le(bytes, start + 4, 16U * 1024U * 1024U + 4U);
  const auto rejected = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::ParseError>(rejected));
  REQUIRE(std::get<wirelens::ParseError>(rejected).code == "PCAPNG_BLOCK_LIMIT_EXCEEDED");
}

TEST_CASE("PCAPNG enforces the named interface limit") {
  const auto accepted =
      wirelens::parse_capture(build_pcapng_interfaces(wirelens::kMaxPcapngInterfaces));
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(accepted));
  REQUIRE(std::get<wirelens::CaptureDocument>(accepted).capture.interfaces.size() ==
          wirelens::kMaxPcapngInterfaces);

  const auto rejected =
      wirelens::parse_capture(build_pcapng_interfaces(wirelens::kMaxPcapngInterfaces + 1U));
  REQUIRE(std::holds_alternative<wirelens::ParseError>(rejected));
  const auto& error = std::get<wirelens::ParseError>(rejected);
  REQUIRE(error.code == "PCAPNG_INTERFACE_LIMIT_EXCEEDED");
  REQUIRE(error.captureOffset == 28U + wirelens::kMaxPcapngInterfaces * 20U);
}

TEST_CASE("PCAPNG sections reset local interface references") {
  auto bytes = build_ipv6_udp_pcapng();
  const auto section = bytes.size();
  bytes.resize(section + 48, std::byte{0});
  wirelens_test::put32le(bytes, section, 0x0a0d0d0a);
  wirelens_test::put32le(bytes, section + 4, 28);
  bytes[section + 8] = std::byte{0x4d};
  bytes[section + 9] = std::byte{0x3c};
  bytes[section + 10] = std::byte{0x2b};
  bytes[section + 11] = std::byte{0x1a};
  bytes[section + 12] = std::byte{1};
  wirelens_test::put32le(bytes, section + 24, 28);
  const auto idb = section + 28;
  wirelens_test::put32le(bytes, idb, 1);
  wirelens_test::put32le(bytes, idb + 4, 20);
  wirelens_test::put16(bytes, idb + 8, 1);
  wirelens_test::put32le(bytes, idb + 12, 0);
  wirelens_test::put32le(bytes, idb + 16, 20);
  const auto result = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.capture.interfaces.size() == 2);
  REQUIRE(capture.packets.at(0).interfaceId == 0);

  SECTION("a new section cannot use the prior section interface") {
    auto no_interface = build_ipv6_udp_pcapng();
    const auto section_start = no_interface.size();
    no_interface.resize(section_start + 28U + 32U, std::byte{0});
    wirelens_test::put32le(no_interface, section_start, 0x0a0d0d0a);
    wirelens_test::put32le(no_interface, section_start + 4, 28);
    no_interface[section_start + 8] = std::byte{0x4d};
    no_interface[section_start + 9] = std::byte{0x3c};
    no_interface[section_start + 10] = std::byte{0x2b};
    no_interface[section_start + 11] = std::byte{0x1a};
    no_interface[section_start + 12] = std::byte{1};
    wirelens_test::put32le(no_interface, section_start + 24, 28);
    const auto epb = section_start + 28U;
    wirelens_test::put32le(no_interface, epb, 6);
    wirelens_test::put32le(no_interface, epb + 4, 32);
    wirelens_test::put32le(no_interface, epb + 8, 0);
    wirelens_test::put32le(no_interface, epb + 28, 32);
    const auto failed = wirelens::parse_capture(no_interface);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(failed));
    REQUIRE(std::get<wirelens::ParseError>(failed).code == "INVALID_PCAPNG_INTERFACE");
  }

  SECTION("a big-endian section has local interfaces and byte order") {
    auto two_sections = build_ipv6_udp_pcapng();
    const auto section_start = two_sections.size();
    constexpr std::size_t section_length = 28U + 20U + 96U;
    two_sections.resize(section_start + section_length, std::byte{0});
    const auto put_be = [&](const std::size_t at, const std::uint32_t value) {
      wirelens_test::put32be(two_sections, at, value);
    };
    put_be(section_start, 0x0a0d0d0a);
    put_be(section_start + 4, 28);
    two_sections[section_start + 8] = std::byte{0x1a};
    two_sections[section_start + 9] = std::byte{0x2b};
    two_sections[section_start + 10] = std::byte{0x3c};
    two_sections[section_start + 11] = std::byte{0x4d};
    wirelens_test::put16be(two_sections, section_start + 12, 1);
    put_be(section_start + 24, 28);
    const auto idb = section_start + 28U;
    put_be(idb, 1);
    put_be(idb + 4, 20);
    wirelens_test::put16be(two_sections, idb + 8, 1);
    put_be(idb + 12, 65535);
    put_be(idb + 16, 20);
    const auto epb = idb + 20U;
    put_be(epb, 6);
    put_be(epb + 4, 96);
    put_be(epb + 8, 0);
    put_be(epb + 12, 0);
    put_be(epb + 16, 0);
    put_be(epb + 20, 62);
    put_be(epb + 24, 62);
    std::copy(two_sections.begin() + 76, two_sections.begin() + 76 + 62,
              two_sections.begin() + epb + 28);
    put_be(epb + 92, 96);
    const auto parsed = wirelens::parse_capture(two_sections);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(parsed));
    const auto& document = std::get<wirelens::CaptureDocument>(parsed);
    REQUIRE(document.packets.size() == 2);
    REQUIRE(document.capture.interfaces.size() == 2);
    REQUIRE(document.packets.at(1).interfaceId == 1);
    REQUIRE(document.packets.at(1).sourceAddress == "2001:db8::1");
  }
}

TEST_CASE("parse_capture aggregates unknown PCAPNG blocks") {
  auto bytes = build_ipv6_udp_pcapng();
  const auto oldSize = bytes.size();
  bytes.resize(oldSize + 24, std::byte{0});
  wirelens_test::put32le(bytes, oldSize, 0x12345678);
  wirelens_test::put32le(bytes, oldSize + 4, 12);
  wirelens_test::put32le(bytes, oldSize + 8, 12);
  wirelens_test::put32le(bytes, oldSize + 12, 0x12345678);
  wirelens_test::put32le(bytes, oldSize + 16, 12);
  wirelens_test::put32le(bytes, oldSize + 20, 12);
  const auto result = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.diagnostics.size() == 2);
  REQUIRE(capture.diagnostics.at(0).code == "DNS_TRUNCATED_HEADER");
  REQUIRE(capture.diagnostics.at(1).code == "UNKNOWN_PCAPNG_BLOCK");
  REQUIRE(capture.diagnostics.at(1).severity == "warning");
  REQUIRE(capture.diagnostics.at(1).count == 2);

  SECTION("diagnostics stop at the named limit") {
    auto many = build_ipv6_udp_pcapng();
    const auto first = many.size();
    constexpr std::size_t count = wirelens::kMaxDiagnostics + 1U;
    many.resize(first + count * 12U, std::byte{0});
    for (std::size_t i = 0; i < count; ++i) {
      const auto at = first + i * 12U;
      wirelens_test::put32le(many, at, 0x10000000U + static_cast<std::uint32_t>(i));
      wirelens_test::put32le(many, at + 4, 12);
      wirelens_test::put32le(many, at + 8, 12);
    }
    const auto limited = wirelens::parse_capture(many);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(limited));
    const auto& diagnostics = std::get<wirelens::CaptureDocument>(limited).diagnostics;
    REQUIRE(diagnostics.size() == wirelens::kMaxDiagnostics);
    REQUIRE(diagnostics.back().code == "DIAGNOSTIC_LIMIT_REACHED");
    REQUIRE(diagnostics.back().count.has_value());
  }
}

TEST_CASE("PCAPNG validates snap lengths and interface options") {
  SECTION("captured length at the snap length is accepted") {
    auto bytes = build_ipv6_udp_pcapng();
    wirelens_test::put32le(bytes, 40, 62);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(wirelens::parse_capture(bytes)));
  }
  SECTION("captured length above the snap length is rejected") {
    auto bytes = build_ipv6_udp_pcapng();
    wirelens_test::put32le(bytes, 40, 61);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "PCAPNG_PACKET_EXCEEDS_SNAPLEN");
  }
  SECTION("if_tsresol must have one byte") {
    auto bytes = build_pcapng_with_nanosecond_option();
    wirelens_test::put16(bytes, 46, 2);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "INVALID_PCAPNG_OPTION_LENGTH");
  }
  SECTION("non-empty options require an end marker") {
    auto bytes = build_pcapng_with_nanosecond_option();
    wirelens_test::put16(bytes, 52, 1);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "MISSING_PCAPNG_OPTION_END");
  }
  SECTION("option terminator length must be zero") {
    auto bytes = build_pcapng_with_nanosecond_option();
    wirelens_test::put16(bytes, 54, 1);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "INVALID_PCAPNG_OPTION_LENGTH");
  }
  SECTION("truncated option value and padding are typed") {
    auto bytes = build_pcapng_with_nanosecond_option();
    wirelens_test::put32le(bytes, 32, 28);
    wirelens_test::put16(bytes, 44, 1);
    wirelens_test::put16(bytes, 46, 5);
    wirelens_test::put32le(bytes, 52, 28);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "TRUNCATED_PCAPNG_OPTION");
  }
}

TEST_CASE("PCAPNG reports section and interface structural errors") {
  SECTION("enhanced packet before an interface") {
    std::vector<std::byte> bytes(28U + 32U, std::byte{0});
    wirelens_test::put32le(bytes, 0, 0x0a0d0d0a);
    wirelens_test::put32le(bytes, 4, 28);
    bytes[8] = std::byte{0x4d};
    bytes[9] = std::byte{0x3c};
    bytes[10] = std::byte{0x2b};
    bytes[11] = std::byte{0x1a};
    bytes[12] = std::byte{1};
    wirelens_test::put32le(bytes, 24, 28);
    wirelens_test::put32le(bytes, 28, 6);
    wirelens_test::put32le(bytes, 32, 32);
    wirelens_test::put32le(bytes, 36, 0);
    wirelens_test::put32le(bytes, 56, 32);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "INVALID_PCAPNG_INTERFACE");
  }
  SECTION("non-Ethernet interface") {
    auto bytes = build_ipv6_udp_pcapng();
    wirelens_test::put16(bytes, 36, 101);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "UNSUPPORTED_LINK_TYPE");
  }
  SECTION("a short section prefix is a section error") {
    const std::array<std::byte, 4> bytes{std::byte{0x0a}, std::byte{0x0d}, std::byte{0x0d},
                                         std::byte{0x0a}};
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "TRUNCATED_PCAPNG_SECTION");
  }
  SECTION("a truncated section header is a section error") {
    std::vector<std::byte> bytes(11U, std::byte{0});
    bytes[0] = std::byte{0x0a};
    bytes[1] = std::byte{0x0d};
    bytes[2] = std::byte{0x0d};
    bytes[3] = std::byte{0x0a};
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "TRUNCATED_PCAPNG_SECTION");
  }
}

TEST_CASE("PCAPNG timestamp resolutions are exact and labeled") {
  SECTION("decimal custom exponent floors to nanoseconds") {
    auto bytes = build_pcapng_with_nanosecond_option();
    bytes[48] = std::byte{10};
    wirelens_test::put32le(bytes, 76, 1000000);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    const auto& capture = std::get<wirelens::CaptureDocument>(result);
    REQUIRE(capture.capture.timestampResolution == "custom");
    REQUIRE(capture.packets.at(0).timestampNs == "100000");
  }
  SECTION("binary resolution is labeled") {
    auto bytes = build_pcapng_with_nanosecond_option();
    bytes[48] = std::byte{0x80};
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    REQUIRE(std::get<wirelens::CaptureDocument>(result).capture.timestampResolution == "binary");
  }
  SECTION("binary conversion is exact") {
    auto bytes = build_pcapng_with_nanosecond_option();
    bytes[48] = std::byte{0x80};
    wirelens_test::put32le(bytes, 76, 1000000);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    REQUIRE(std::get<wirelens::CaptureDocument>(result).packets.at(0).timestampNs ==
            "1000000000000000");
  }
  SECTION("a high decimal exponent floors fractional nanoseconds") {
    auto bytes = build_pcapng_with_nanosecond_option();
    bytes[48] = std::byte{12};
    wirelens_test::put32le(bytes, 72, 287);
    wirelens_test::put32le(bytes, 76, 1912276171U);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    REQUIRE(std::get<wirelens::CaptureDocument>(result).packets.at(0).timestampNs == "1234567890");
  }
  SECTION("timestamp overflow is typed") {
    auto bytes = build_pcapng_with_nanosecond_option();
    bytes[48] = std::byte{0};
    wirelens_test::put32le(bytes, 72, 0xffffffffU);
    wirelens_test::put32le(bytes, 76, 0xffffffffU);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
    REQUIRE(std::get<wirelens::ParseError>(result).code == "INVALID_TIMESTAMP");
  }
  SECTION("interfaces with different resolutions are mixed") {
    auto bytes = build_ipv6_udp_pcapng();
    const auto offset = bytes.size();
    bytes.resize(offset + 32, std::byte{0});
    wirelens_test::put32le(bytes, offset, 1);
    wirelens_test::put32le(bytes, offset + 4, 32);
    wirelens_test::put16(bytes, offset + 8, 1);
    wirelens_test::put32le(bytes, offset + 12, 0);
    wirelens_test::put16(bytes, offset + 16, 9);
    wirelens_test::put16(bytes, offset + 18, 1);
    bytes[offset + 20] = std::byte{9};
    wirelens_test::put32le(bytes, offset + 28, 32);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    REQUIRE(std::get<wirelens::CaptureDocument>(result).capture.timestampResolution == "mixed");
  }
}

TEST_CASE("protocol truncation keeps valid outer layers") {
  for (const auto frameLength : {10U, 34U, 50U}) {
    auto bytes = wirelens_test::build_handshake();
    bytes.resize(24 + 16 + frameLength);
    wirelens_test::put32le(bytes, 24 + 8, frameLength);
    wirelens_test::put32le(bytes, 24 + 12, frameLength);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
    const auto& packet = std::get<wirelens::CaptureDocument>(result).packets.at(0);
    REQUIRE(packet.layers.size() ==
            (frameLength < 14U ? 0U : (frameLength < 34U ? 1U : (frameLength < 54U ? 2U : 3U))));
  }
}

TEST_CASE("parse_capture rejects malformed record lengths") {
  auto bytes = wirelens_test::build_handshake();
  bytes[32] = std::byte{55};
  const auto result = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
  REQUIRE(std::get<wirelens::ParseError>(result).code == "INVALID_PACKET_LENGTH");
}

TEST_CASE("parse_capture reports each classic PCAP structural failure") {
  SECTION("unknown magic") {
    auto bytes = std::vector<std::byte>(24, std::byte{0});
    bytes[0] = std::byte{0};
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::get<wirelens::ParseError>(result).code == "UNSUPPORTED_MAGIC");
  }
  SECTION("unsupported link type") {
    auto bytes = wirelens_test::build_handshake();
    bytes[20] = std::byte{101};
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::get<wirelens::ParseError>(result).code == "UNSUPPORTED_LINK_TYPE");
  }
  SECTION("unsupported version") {
    auto bytes = wirelens_test::build_handshake();
    bytes[4] = std::byte{3};
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::get<wirelens::ParseError>(result).code == "UNSUPPORTED_VERSION");
  }
  SECTION("truncated record header") {
    auto bytes = wirelens_test::build_handshake();
    bytes.resize(24 + 8);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::get<wirelens::ParseError>(result).code == "TRUNCATED_PACKET_HEADER");
  }
  SECTION("truncated packet data") {
    auto bytes = wirelens_test::build_handshake();
    bytes.resize(bytes.size() - 1);
    const auto result = wirelens::parse_capture(bytes);
    REQUIRE(std::get<wirelens::ParseError>(result).code == "TRUNCATED_PACKET_DATA");
  }
}
