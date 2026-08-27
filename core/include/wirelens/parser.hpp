#pragma once

#include "wirelens/error.hpp"
#include "wirelens/model.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>

namespace wirelens {

constexpr std::size_t kMaxCaptureBytes = 64U * 1024U * 1024U;
constexpr std::size_t kMaxPacketCount = 65'536U;
constexpr std::size_t kMaxPcapngInterfaces = 65'536U;
constexpr std::size_t kMaxVlanTags = 8U;
constexpr std::size_t kMaxDiagnostics = 1'024U;
constexpr std::size_t kMaxDnsPointerHops = 16U;
constexpr std::size_t kMaxDnsLabels = 127U;
constexpr std::size_t kMaxDnsNameBytes = 255U;
constexpr std::size_t kMaxDnsQuestions = 256U;
constexpr std::size_t kMaxDnsRecords = 1'024U;
constexpr std::size_t kMaxObservations = 1'024U;
using ParseResult = std::variant<CaptureDocument, ParseError>;

[[nodiscard]] ParseResult parse_capture(std::span<const std::byte> bytes);

} // namespace wirelens
