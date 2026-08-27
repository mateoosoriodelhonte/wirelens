#include "fixture_builder.hpp"
#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("serialization emits a stable sanitized capture document") {
  const auto result = wirelens::parse_capture(wirelens_test::build_handshake());
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  auto capture = std::get<wirelens::CaptureDocument>(result);
  capture.diagnostics.push_back({"warning", "TEST", "message", "packet", 74, 1, std::nullopt});
  const auto json = wirelens::serialize_capture(capture);
  REQUIRE(json.find("\"schema\": \"wirelens.capture\"") != std::string::npos);
  REQUIRE(json.find("\"contractVersion\": \"2.0.0\"") != std::string::npos);
  REQUIRE(json.find("packet-1") != std::string::npos);
  REQUIRE(json.find("tcp-flow-1") != std::string::npos);
  REQUIRE(json.find("\"midStream\": false") != std::string::npos);
  REQUIRE(json.find("TCP connection had no observed close before the capture ended.") !=
          std::string::npos);
  REQUIRE(json.find("rawBytes") == std::string::npos);
  REQUIRE(json.find("payload") == std::string::npos);
  REQUIRE(json.find("\"context\": \"packet\"") != std::string::npos);
  REQUIRE(json.find("\"packetNumber\": 1") != std::string::npos);
  REQUIRE(json.find("\"count\": null") != std::string::npos);
}
