#include "fixture_builder.hpp"
#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"

#include <array>
#include <algorithm>
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
  bytes[8] = std::byte{0x1a}; bytes[9] = std::byte{0x2b}; bytes[10] = std::byte{0x3c}; bytes[11] = std::byte{0x4d};
  be16(12, 1); be16(14, 0);
  for (const auto start : {0U, 28U, 48U}) {
    be32(start, start == 0 ? 0x0a0d0d0aU : (start == 28 ? 1U : 6U));
    be32(start + 4, start == 0 ? 28U : (start == 28 ? 20U : 96U));
    be32(start + (start == 0 ? 24U : (start == 28 ? 16U : 92U)), start == 0 ? 28U : (start == 28 ? 20U : 96U));
  }
  be16(36, 1); be16(38, 0); be32(40, 65535);
  be32(56, 0); be32(60, 0); be32(64, 1000000); be32(68, 62); be32(72, 62);
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

TEST_CASE("PCAPNG sections reset local interface references") {
  auto bytes = build_ipv6_udp_pcapng();
  const auto section = bytes.size();
  bytes.resize(section + 48, std::byte{0});
  wirelens_test::put32le(bytes, section, 0x0a0d0d0a);
  wirelens_test::put32le(bytes, section + 4, 28);
  bytes[section + 8] = std::byte{0x4d}; bytes[section + 9] = std::byte{0x3c};
  bytes[section + 10] = std::byte{0x2b}; bytes[section + 11] = std::byte{0x1a};
  bytes[section + 12] = std::byte{1};
  wirelens_test::put32le(bytes, section + 24, 28);
  const auto idb = section + 28;
  wirelens_test::put32le(bytes, idb, 1); wirelens_test::put32le(bytes, idb + 4, 20);
  wirelens_test::put16(bytes, idb + 8, 1); wirelens_test::put32le(bytes, idb + 12, 0);
  wirelens_test::put32le(bytes, idb + 16, 20);
  const auto result = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.capture.interfaces.size() == 2);
  REQUIRE(capture.packets.at(0).interfaceId == 0);
}

TEST_CASE("parse_capture aggregates unknown PCAPNG blocks") {
  auto bytes = build_ipv6_udp_pcapng();
  const auto oldSize = bytes.size();
  bytes.resize(oldSize + 12, std::byte{0});
  wirelens_test::put32le(bytes, oldSize, 0x12345678);
  wirelens_test::put32le(bytes, oldSize + 4, 12);
  wirelens_test::put32le(bytes, oldSize + 8, 12);
  const auto result = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.diagnostics.size() == 1);
  REQUIRE(capture.diagnostics.at(0).code == "UNKNOWN_PCAPNG_BLOCK");
  REQUIRE(capture.diagnostics.at(0).severity == "warning");
  REQUIRE(capture.diagnostics.at(0).count == 1);

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
    REQUIRE(std::get<wirelens::CaptureDocument>(limited).diagnostics.size() == wirelens::kMaxDiagnostics);
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
