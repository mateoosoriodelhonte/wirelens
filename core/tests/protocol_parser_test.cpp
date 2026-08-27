#include "fixture_builder.hpp"
#include "wirelens/parser.hpp"

#include <catch2/catch_test_macros.hpp>
#include <vector>

TEST_CASE("protocol layers expose handshake fields and byte ranges") {
  const auto result = wirelens::parse_capture(wirelens_test::build_handshake());
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& packet = std::get<wirelens::CaptureDocument>(result).packets.at(0);
  REQUIRE(packet.layers.size() == 3);
  const auto& ethernet = packet.layers.at(0);
  REQUIRE(ethernet.protocol == "ETHERNET");
  REQUIRE(ethernet.fields.at(0).value == "02:00:00:00:00:02");
  REQUIRE(ethernet.fields.at(1).value == "02:00:00:00:00:01");
  const auto& ipv4 = packet.layers.at(1);
  REQUIRE(ipv4.protocol == "IPV4");
  REQUIRE(ipv4.fields.at(3).value == "64");
  const auto& tcp = packet.layers.at(2);
  REQUIRE(tcp.protocol == "TCP");
  REQUIRE(tcp.explanationKey == "tcp");
  REQUIRE(tcp.fields.at(0).value == "51515");
  REQUIRE(tcp.fields.at(1).value == "443");
  REQUIRE(tcp.fields.at(2).value == "1000");
  REQUIRE(tcp.fields.at(5).value == "SYN");
  REQUIRE(tcp.fields.at(0).byteRange->packetOffset == 34);
  REQUIRE(tcp.fields.at(0).byteRange->captureOffset == 74);
  const auto& synAck = packet.layers.at(2);
  REQUIRE(synAck.fields.at(2).value == "1000");
  const auto result2 = wirelens::parse_capture(wirelens_test::build_handshake());
  const auto& packets = std::get<wirelens::CaptureDocument>(result2).packets;
  REQUIRE(packets.at(1).layers.at(2).fields.at(2).value == "5000");
  REQUIRE(packets.at(1).layers.at(2).fields.at(3).value == "1001");
  REQUIRE(packets.at(1).layers.at(2).fields.at(5).value == "SYN + ACK");
  REQUIRE(packets.at(1).layers.at(2).fields.at(5).explanationKey == "tcp.syn-ack");
  REQUIRE(packets.at(2).layers.at(2).fields.at(2).value == "1001");
  REQUIRE(packets.at(2).layers.at(2).fields.at(3).value == "5001");
  REQUIRE(packets.at(2).layers.at(2).fields.at(5).value == "ACK");
  REQUIRE(packets.at(2).layers.at(2).fields.at(5).explanationKey == "tcp.ack");
  REQUIRE(packets.at(0).layers.at(2).fields.at(5).explanationKey == "tcp.syn");
}

TEST_CASE("a non-first IPv4 fragment is not decoded as TCP") {
  auto bytes = wirelens_test::build_handshake();
  constexpr std::size_t firstFrameOffset = 24U + 16U;
  constexpr std::size_t ipv4FlagsAndOffset = firstFrameOffset + 14U + 6U;
  bytes[ipv4FlagsAndOffset] = std::byte{0x00};
  bytes[ipv4FlagsAndOffset + 1U] = std::byte{0x01};

  const auto result = wirelens::parse_capture(bytes);

  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.packets.at(0).layers.size() == 2);
  REQUIRE(capture.packets.at(0).layers.at(0).protocol == "ETHERNET");
  REQUIRE(capture.packets.at(0).layers.at(1).protocol == "IPV4");
  REQUIRE(capture.flows.size() == 1);
  REQUIRE(capture.flows.at(0).packetNumbers == std::vector<std::size_t>{2, 3});
}
