#include "wirelens/parser.hpp"
#include "fixture_builder.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("protocol layers expose handshake fields and byte ranges") {
  const auto result = wirelens::parse_capture(wirelens_test::build_handshake());
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& packet = std::get<wirelens::CaptureDocument>(result).packets.at(0);
  REQUIRE(packet.layers.size() == 1);
  const auto& ethernet = packet.layers.at(0);
  REQUIRE(ethernet.protocol == "ETHERNET");
  REQUIRE(ethernet.fields.at(0).value == "02:00:00:00:00:02");
  REQUIRE(ethernet.fields.at(1).value == "02:00:00:00:00:01");
  REQUIRE(ethernet.children.size() == 1);
  REQUIRE(ethernet.children.at(0).protocol == "IPV4");
  REQUIRE(ethernet.children.at(0).fields.at(3).value == "64");
  REQUIRE(ethernet.children.at(0).children.size() == 1);
  const auto& tcp = ethernet.children.at(0).children.at(0);
  REQUIRE(tcp.protocol == "TCP");
  REQUIRE(tcp.fields.at(0).value == "51515");
  REQUIRE(tcp.fields.at(1).value == "443");
  REQUIRE(tcp.fields.at(2).value == "1000");
  REQUIRE(tcp.fields.at(5).value == "SYN");
  REQUIRE(tcp.fields.at(0).byteRange->packetOffset == 34);
  REQUIRE(tcp.fields.at(0).byteRange->captureOffset == 74);
}
