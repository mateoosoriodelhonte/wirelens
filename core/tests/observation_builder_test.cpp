#include "protocol_internal.hpp"

#include "wirelens/parser.hpp"

#include <catch2/catch_test_macros.hpp>
#include <string>

namespace {
wirelens::Diagnostic diagnostic(const std::size_t index) {
  return {"warning",
          "TEST_DIAGNOSTIC_" + std::to_string(index),
          "Test diagnostic",
          "test",
          std::nullopt,
          std::nullopt,
          1U};
}
} // namespace

TEST_CASE("diagnostic and observation limits share a reserved summary in either order") {
  SECTION("observation limit is reached first") {
    wirelens::CaptureDocument capture;
    for (std::size_t index = 0; index <= wirelens::kMaxObservations; ++index) {
      wirelens::internal::add_observation(capture, "test", "Test observation", {index + 1U});
    }
    REQUIRE(capture.diagnostics.size() == 1U);
    REQUIRE(capture.diagnostics.back().code == "OBSERVATION_LIMIT_REACHED");
    for (std::size_t index = 0; index < wirelens::kMaxDiagnostics - 1U; ++index)
      wirelens::internal::add_diagnostic(capture, diagnostic(index));
    REQUIRE(capture.diagnostics.size() == wirelens::kMaxDiagnostics);
    REQUIRE(capture.diagnostics.front().code == "OBSERVATION_LIMIT_REACHED");
    REQUIRE(capture.diagnostics.back().code == "TEST_DIAGNOSTIC_1022");

    wirelens::internal::add_diagnostic(capture, diagnostic(wirelens::kMaxDiagnostics));

    REQUIRE(capture.diagnostics.size() == wirelens::kMaxDiagnostics);
    REQUIRE(capture.diagnostics.front().code == "DIAGNOSTIC_AND_OBSERVATION_LIMITS_REACHED");
    REQUIRE(capture.diagnostics.front().count == 2U);
    REQUIRE(capture.diagnostics.back().code == "TEST_DIAGNOSTIC_1022");
  }

  SECTION("diagnostic limit is reached first") {
    wirelens::CaptureDocument capture;
    for (std::size_t index = 0; index < wirelens::kMaxDiagnostics; ++index)
      wirelens::internal::add_diagnostic(capture, diagnostic(index));
    REQUIRE(capture.diagnostics.back().code == "DIAGNOSTIC_LIMIT_REACHED");
    for (std::size_t index = 0; index <= wirelens::kMaxObservations; ++index) {
      wirelens::internal::add_observation(capture, "test", "Test observation", {index + 1U});
    }
    REQUIRE(capture.diagnostics.back().code == "DIAGNOSTIC_AND_OBSERVATION_LIMITS_REACHED");
    REQUIRE(capture.diagnostics.back().count == 2U);
  }
}
