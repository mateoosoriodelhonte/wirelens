#include "protocol_internal.hpp"

#include "wirelens/parser.hpp"

#include <algorithm>
#include <utility>

namespace wirelens::internal {

void add_diagnostic(CaptureDocument& capture, Diagnostic diagnostic) {
  const auto diagnosticLimit =
      std::find_if(capture.diagnostics.begin(), capture.diagnostics.end(), [](const auto& value) {
        return value.code == "DIAGNOSTIC_LIMIT_REACHED" ||
               value.code == "DIAGNOSTIC_AND_OBSERVATION_LIMITS_REACHED";
      });
  if (diagnosticLimit != capture.diagnostics.end()) {
    diagnosticLimit->count = diagnosticLimit->count.value_or(0U) + diagnostic.count.value_or(1U);
    return;
  }
  const auto observationLimit =
      std::find_if(capture.diagnostics.begin(), capture.diagnostics.end(),
                   [](const auto& value) { return value.code == "OBSERVATION_LIMIT_REACHED"; });
  if (observationLimit != capture.diagnostics.end()) {
    if (capture.diagnostics.size() < kMaxDiagnostics) {
      capture.diagnostics.push_back(std::move(diagnostic));
      return;
    }
    observationLimit->code = "DIAGNOSTIC_AND_OBSERVATION_LIMITS_REACHED";
    observationLimit->message =
        "Additional diagnostics and observations were omitted after their 1,024 limits";
    observationLimit->context = "diagnostics,observations";
    observationLimit->count = observationLimit->count.value_or(0U) + diagnostic.count.value_or(1U);
    return;
  }
  if (capture.diagnostics.size() < kMaxDiagnostics - 1U) {
    capture.diagnostics.push_back(std::move(diagnostic));
    return;
  }
  if (capture.diagnostics.size() < kMaxDiagnostics) {
    capture.diagnostics.push_back(
        {"warning", "DIAGNOSTIC_LIMIT_REACHED",
         "Additional diagnostics were omitted after the 1,024 diagnostic limit", "diagnostics",
         std::nullopt, std::nullopt, diagnostic.count.value_or(1U)});
  }
}

void add_observation(CaptureDocument& capture, std::string type, std::string message,
                     std::vector<std::size_t> packetNumbers) {
  if (capture.observations.size() >= kMaxObservations) {
    const auto existing =
        std::find_if(capture.diagnostics.begin(), capture.diagnostics.end(), [](const auto& value) {
          return value.code == "OBSERVATION_LIMIT_REACHED" ||
                 value.code == "DIAGNOSTIC_AND_OBSERVATION_LIMITS_REACHED";
        });
    if (existing != capture.diagnostics.end()) {
      existing->count = existing->count.value_or(0U) + 1U;
    } else if (capture.diagnostics.size() < kMaxDiagnostics) {
      capture.diagnostics.push_back(
          {"warning", "OBSERVATION_LIMIT_REACHED",
           "Additional observations were omitted after the 1,024 observation limit", "observations",
           std::nullopt, std::nullopt, 1U});
    } else {
      const auto diagnosticLimit =
          std::find_if(capture.diagnostics.begin(), capture.diagnostics.end(),
                       [](const auto& value) { return value.code == "DIAGNOSTIC_LIMIT_REACHED"; });
      if (diagnosticLimit != capture.diagnostics.end()) {
        diagnosticLimit->code = "DIAGNOSTIC_AND_OBSERVATION_LIMITS_REACHED";
        diagnosticLimit->message =
            "Additional diagnostics and observations were omitted after their 1,024 limits";
        diagnosticLimit->context = "diagnostics,observations";
        diagnosticLimit->count = diagnosticLimit->count.value_or(0U) + 1U;
      }
    }
    return;
  }
  capture.observations.push_back({"observation-" + std::to_string(capture.observations.size() + 1),
                                  std::move(type), std::move(message), std::move(packetNumbers),
                                  "Only packets in this capture were considered."});
}

} // namespace wirelens::internal
