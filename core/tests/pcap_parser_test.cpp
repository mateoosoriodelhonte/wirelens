#include "fixture_builder.hpp"
#include "wirelens/parser.hpp"

#include <array>
#include <catch2/catch_test_macros.hpp>

namespace {

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
