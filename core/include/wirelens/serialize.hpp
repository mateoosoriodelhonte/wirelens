#pragma once

#include "wirelens/model.hpp"

#include <string>

namespace wirelens {

[[nodiscard]] std::string serialize_capture(const CaptureDocument& capture);
[[nodiscard]] std::string format_summary(const CaptureDocument& capture);

} // namespace wirelens
