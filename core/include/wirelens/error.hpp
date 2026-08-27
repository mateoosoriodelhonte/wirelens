#pragma once

#include <cstddef>
#include <optional>
#include <string>

namespace wirelens {

struct ParseError {
  std::string code;
  std::string message;
  std::optional<std::size_t> captureOffset;
  std::optional<std::size_t> packetNumber;
};

} // namespace wirelens
