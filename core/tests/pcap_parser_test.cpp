#include "wirelens/parser.hpp"
#include "fixture_builder.hpp"

#include <array>
#include <catch2/catch_test_macros.hpp>

TEST_CASE("parse_capture rejects a truncated global header") {
  const std::array<std::byte, 3> bytes{};
  const auto result = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::ParseError>(result));
  REQUIRE(std::get<wirelens::ParseError>(result).code == "TRUNCATED_GLOBAL_HEADER");
}

TEST_CASE("parse_capture accepts an empty valid capture") {
  std::vector<std::byte> bytes(24, std::byte{0});
  bytes[0] = std::byte{0xd4}; bytes[1] = std::byte{0xc3}; bytes[2] = std::byte{0xb2}; bytes[3] = std::byte{0xa1};
  bytes[4] = std::byte{2}; bytes[6] = std::byte{4}; bytes[20] = std::byte{1};
  const auto result = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  REQUIRE(std::get<wirelens::CaptureDocument>(result).packets.empty());
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
