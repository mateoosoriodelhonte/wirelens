#include "fixture_builder.hpp"
#include "wirelens/parser.hpp"

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <string>
#include <vector>

namespace {
using wirelens_test::TcpPacketSpec;

wirelens::CaptureDocument parse(const std::vector<TcpPacketSpec>& packets) {
  const auto result = wirelens::parse_capture(wirelens_test::build_tcp_capture(packets));
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  return std::get<wirelens::CaptureDocument>(result);
}

std::vector<TcpPacketSpec> handshake() {
  return {{true, 1000, 0, 0x02, {}, {}, {}, 0},
          {false, 5000, 1001, 0x12, {}, {}, {}, 10'000},
          {true, 1001, 5001, 0x10, {}, {}, {}, 20'000}};
}

const wirelens::Observation* observation(const wirelens::CaptureDocument& capture,
                                         const std::string& type) {
  const auto found = std::find_if(capture.observations.begin(), capture.observations.end(),
                                  [&](const auto& value) { return value.type == type; });
  return found == capture.observations.end() ? nullptr : &*found;
}
} // namespace

TEST_CASE("TCP direction follows the first observed SYN without ACK") {
  const auto capture = parse({{false, 5000, 1001, 0x12}, {true, 1000, 0, 0x02}});
  REQUIRE(capture.flows.size() == 1);
  const auto& flow = capture.flows.front();
  REQUIRE(flow.client.address == "192.0.2.10");
  REQUIRE(flow.server.address == "198.51.100.20");
  REQUIRE_FALSE(flow.midStream);
  REQUIRE(flow.handshake == wirelens::HandshakeState::partial);
}

TEST_CASE("TCP direction uses the first packet when the capture begins mid stream") {
  const auto capture = parse({{false, 5001, 1001, 0x10, wirelens_test::byte_payload("data")}});
  REQUIRE(capture.flows.size() == 1);
  const auto& flow = capture.flows.front();
  REQUIRE(flow.client.address == "198.51.100.20");
  REQUIRE(flow.server.address == "192.0.2.10");
  REQUIRE(flow.midStream);
  REQUIRE(flow.handshake == wirelens::HandshakeState::unobserved);
}

TEST_CASE("TCP lifecycle records graceful and reset termination") {
  auto gracefulPackets = handshake();
  gracefulPackets.push_back({true, 1001, 5001, 0x11, {}, {}, {}, 30'000});
  gracefulPackets.push_back({false, 5001, 1002, 0x11, {}, {}, {}, 40'000});
  const auto graceful = parse(gracefulPackets);
  REQUIRE(graceful.flows.front().termination == "graceful");
  REQUIRE(graceful.flows.front().events.at(3).label == "FIN + ACK");
  REQUIRE(graceful.flows.front().events.at(4).label == "FIN + ACK");
  REQUIRE(observation(graceful, "tcp-connection-without-close") == nullptr);

  auto resetPackets = handshake();
  resetPackets.push_back({false, 5001, 1001, 0x14, {}, {}, {}, 30'000});
  const auto reset = parse(resetPackets);
  REQUIRE(reset.flows.front().termination == "reset");
  REQUIRE(reset.flows.front().events.back().label == "RST");
  const auto* resetObservation = observation(reset, "tcp-reset");
  REQUIRE(resetObservation != nullptr);
  REQUIRE(resetObservation->packetNumbers == std::vector<std::size_t>{4});
  REQUIRE(resetObservation->limitation == "Only packets in this capture were considered.");
}

TEST_CASE("TCP four tuple reuse after a terminal state starts a new flow") {
  const auto resetReuse = parse({{true, 1000, 0, 0x02},
                                 {false, 5000, 1001, 0x14},
                                 {true, 9000, 0, 0x02}});
  REQUIRE(resetReuse.flows.size() == 2);
  REQUIRE(resetReuse.flows.at(0).termination == "reset");
  REQUIRE(resetReuse.flows.at(1).id == "tcp-flow-2");
  REQUIRE(resetReuse.packets.at(2).flowId == "tcp-flow-2");

  auto closeReusePackets = handshake();
  closeReusePackets.push_back({true, 1001, 5001, 0x11});
  closeReusePackets.push_back({false, 5001, 1002, 0x11});
  closeReusePackets.push_back({true, 9000, 0, 0x02});
  const auto closeReuse = parse(closeReusePackets);
  REQUIRE(closeReuse.flows.size() == 2);
  REQUIRE(closeReuse.flows.at(0).termination == "graceful");
  REQUIRE(closeReuse.packets.back().flowId == "tcp-flow-2");
}

TEST_CASE("partial TCP handshake and open capture end produce neutral observations") {
  const auto capture = parse({{true, 1000, 0, 0x02}});
  REQUIRE(capture.flows.front().handshake == wirelens::HandshakeState::partial);
  REQUIRE(capture.flows.front().termination == "open-at-capture-end");
  const auto* handshakeObservation = observation(capture, "tcp-incomplete-handshake");
  REQUIRE(handshakeObservation != nullptr);
  REQUIRE(handshakeObservation->packetNumbers == std::vector<std::size_t>{1});
  const auto* openObservation = observation(capture, "tcp-connection-without-close");
  REQUIRE(openObservation != nullptr);
  REQUIRE(openObservation->packetNumbers == std::vector<std::size_t>{1});
}

TEST_CASE("exact same-range same-byte TCP data produces one retransmission candidate") {
  auto packets = handshake();
  packets.push_back({true, 1001, 5001, 0x10, wirelens_test::byte_payload("hello")});
  packets.push_back({true, 1001, 5001, 0x10, wirelens_test::byte_payload("hello")});
  packets.push_back({true, 1006, 5001, 0x11});
  packets.push_back({false, 5001, 1007, 0x11});
  const auto capture = parse(packets);
  const auto* retransmission = observation(capture, "tcp-retransmission-candidate");
  REQUIRE(retransmission != nullptr);
  REQUIRE(retransmission->packetNumbers == std::vector<std::size_t>{4, 5});
  REQUIRE(retransmission->message == "TCP segment appears to resend bytes already seen.");
}

TEST_CASE("TCP retransmission candidates handle an exact range across sequence wrap") {
  const auto payload = wirelens_test::byte_payload("wrap");
  const auto capture = parse({{true, 0xffff'fffeU, 0, 0x10, payload},
                              {true, 0xffff'fffeU, 0, 0x10, payload},
                              {true, 2, 0, 0x11},
                              {false, 10, 3, 0x11}});
  const auto* retransmission = observation(capture, "tcp-retransmission-candidate");
  REQUIRE(retransmission != nullptr);
  REQUIRE(retransmission->packetNumbers == std::vector<std::size_t>{1, 2});
}

TEST_CASE("TCP retransmission candidates reject overlap gaps bytes direction flags and truncation") {
  SECTION("overlap and gap") {
    const auto capture = parse({{true, 100, 0, 0x10, wirelens_test::byte_payload("abcd")},
                                {true, 100, 0, 0x10, wirelens_test::byte_payload("abc")},
                                {true, 110, 0, 0x10, wirelens_test::byte_payload("abcd")}});
    REQUIRE(observation(capture, "tcp-retransmission-candidate") == nullptr);
  }
  SECTION("changed bytes and direction") {
    const auto capture = parse({{true, 100, 0, 0x10, wirelens_test::byte_payload("abcd")},
                                {true, 100, 0, 0x10, wirelens_test::byte_payload("abce")},
                                {false, 100, 0, 0x10, wirelens_test::byte_payload("abcd")}});
    REQUIRE(observation(capture, "tcp-retransmission-candidate") == nullptr);
  }
  SECTION("same sequence span with changed FIN state") {
    const auto capture = parse({{true, 100, 0, 0x10, wirelens_test::byte_payload("ab")},
                                {true, 100, 0, 0x11, wirelens_test::byte_payload("a")}});
    REQUIRE(observation(capture, "tcp-retransmission-candidate") == nullptr);
  }
  SECTION("capture and IP truncation") {
    const auto payload = wirelens_test::byte_payload("ab");
    const auto capture = parse({{true, 100, 0, 0x10, payload, 4, 58},
                                {true, 100, 0, 0x10, payload, 4, 58}});
    REQUIRE(observation(capture, "tcp-retransmission-candidate") == nullptr);
  }
}

TEST_CASE("TCP observation count has an exact global boundary") {
  auto packets = handshake();
  const auto payload = wirelens_test::byte_payload("x");
  for (std::size_t index = 0; index < 1026; ++index)
    packets.push_back({true, 1001, 5001, 0x10, payload});
  packets.push_back({true, 1002, 5001, 0x11});
  packets.push_back({false, 5001, 1003, 0x11});
  const auto capture = parse(packets);
  REQUIRE(capture.observations.size() == wirelens::kMaxObservations);
  const auto diagnostic = std::find_if(capture.diagnostics.begin(), capture.diagnostics.end(),
                                       [](const auto& value) {
                                         return value.code == "OBSERVATION_LIMIT_REACHED";
                                       });
  REQUIRE(diagnostic != capture.diagnostics.end());
  REQUIRE(diagnostic->count == 1);
}
