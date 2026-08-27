#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"
#include "fixture_builder.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("serialization emits a stable sanitized capture document") {
  const auto result = wirelens::parse_capture(wirelens_test::build_handshake());
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto json = wirelens::serialize_capture(std::get<wirelens::CaptureDocument>(result));
  REQUIRE(json.find("\"schema\": \"wirelens.capture\"") != std::string::npos);
  REQUIRE(json.find("\"contractVersion\": \"1.0.0\"") != std::string::npos);
  REQUIRE(json.find("packet-1") != std::string::npos);
  REQUIRE(json.find("tcp-flow-1") != std::string::npos);
  REQUIRE(json.find("rawBytes") == std::string::npos);
  REQUIRE(json.find("payload") == std::string::npos);
}
