#include "protocol_internal.hpp"

#include "wirelens/parser.hpp"

#include <algorithm>
#include <utility>

namespace wirelens::internal {

void add_observation(CaptureDocument& capture, std::string type, std::string message,
                     std::vector<std::size_t> packetNumbers) {
  if (capture.observations.size() >= kMaxObservations) {
    const auto existing =
        std::find_if(capture.diagnostics.begin(), capture.diagnostics.end(),
                     [](const auto& value) { return value.code == "OBSERVATION_LIMIT_REACHED"; });
    if (existing != capture.diagnostics.end()) {
      existing->count = existing->count.value_or(0U) + 1U;
    } else if (capture.diagnostics.size() < kMaxDiagnostics) {
      capture.diagnostics.push_back(
          {"warning", "OBSERVATION_LIMIT_REACHED",
           "Additional observations were omitted after the 1,024 observation limit", "observations",
           std::nullopt, std::nullopt, 1U});
    } else {
      capture.diagnostics.back() = {
          "warning",
          "OBSERVATION_LIMIT_REACHED",
          "Additional observations were omitted after the 1,024 observation limit",
          "observations",
          std::nullopt,
          std::nullopt,
          1U};
    }
    return;
  }
  capture.observations.push_back({"observation-" + std::to_string(capture.observations.size() + 1),
                                  std::move(type), std::move(message), std::move(packetNumbers),
                                  "Only packets in this capture were considered."});
}

} // namespace wirelens::internal
