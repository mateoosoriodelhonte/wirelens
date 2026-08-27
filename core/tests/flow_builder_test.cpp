#include "fixture_builder.hpp"
#include "wirelens/parser.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("flow reconstruction recognizes a complete three way handshake") {
  const auto result = wirelens::parse_capture(wirelens_test::build_handshake());
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.flows.size() == 1);
  const auto& flow = capture.flows.at(0);
  REQUIRE(flow.client.address == "192.0.2.10");
  REQUIRE(flow.server.address == "198.51.100.20");
  REQUIRE(flow.handshake == wirelens::HandshakeState::complete);
  REQUIRE(flow.events.size() == 3);
  REQUIRE(flow.events.at(0).label == "SYN");
  REQUIRE(flow.events.at(1).label == "SYN + ACK");
  REQUIRE(flow.events.at(2).label == "ACK");
}
