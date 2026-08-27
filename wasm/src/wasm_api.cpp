#include "wirelens/wasm_api.h"

#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

struct MallocDeleter {
  void operator()(std::byte* pointer) const noexcept { std::free(pointer); }
};

using OwnedInput = std::unique_ptr<std::byte, MallocDeleter>;

struct PacketRange {
  std::size_t offset = 0;
  std::size_t size = 0;
};

struct Result {
  OwnedInput input;
  std::size_t inputSize = 0;
  wirelens::ParseResult parsed;
  std::string serialized;
  std::vector<PacketRange> packetRanges;

  Result(OwnedInput ownedInput, const std::size_t size, wirelens::ParseResult parsedResult)
      : input(std::move(ownedInput)), inputSize(size), parsed(std::move(parsedResult)) {}
};

bool is_little_endian_magic(const std::byte* bytes) noexcept {
  const auto first = std::to_integer<unsigned char>(bytes[0]);
  const auto second = std::to_integer<unsigned char>(bytes[1]);
  const auto third = std::to_integer<unsigned char>(bytes[2]);
  const auto fourth = std::to_integer<unsigned char>(bytes[3]);
  return (first == 0xd4U && second == 0xc3U && third == 0xb2U && fourth == 0xa1U) ||
         (first == 0x4dU && second == 0x3cU && third == 0xb2U && fourth == 0xa1U);
}

std::uint32_t read_u32(const std::byte* bytes, const bool little) noexcept {
  const auto b0 = std::to_integer<std::uint32_t>(bytes[0]);
  const auto b1 = std::to_integer<std::uint32_t>(bytes[1]);
  const auto b2 = std::to_integer<std::uint32_t>(bytes[2]);
  const auto b3 = std::to_integer<std::uint32_t>(bytes[3]);
  if (little)
    return b0 | (b1 << 8U) | (b2 << 16U) | (b3 << 24U);
  return (b0 << 24U) | (b1 << 16U) | (b2 << 8U) | b3;
}

std::vector<PacketRange> packet_ranges(const Result& result) {
  if (!std::holds_alternative<wirelens::CaptureDocument>(result.parsed) || result.inputSize < 24U)
    return {};
  const auto* bytes = result.input.get();
  const bool little = is_little_endian_magic(bytes);
  std::vector<PacketRange> ranges;
  const auto& packets = std::get<wirelens::CaptureDocument>(result.parsed).packets;
  ranges.reserve(packets.size());
  std::size_t offset = 24U;
  for (std::size_t index = 0; index < packets.size(); ++index) {
    if (result.inputSize - offset < 16U)
      return {};
    const auto captured = static_cast<std::size_t>(read_u32(bytes + offset + 8U, little));
    if (captured > result.inputSize - offset - 16U)
      return {};
    ranges.push_back({offset + 16U, captured});
    offset += 16U + captured;
  }
  return ranges;
}

struct Allocation {
  OwnedInput input;
  std::size_t size = 0;
};

class AllocationRegistry {
public:
  bool record(const uintptr_t pointer, const std::size_t size) noexcept {
    try {
      std::lock_guard lock(mutex_);
      return values_.emplace(pointer, size).second;
    } catch (...) {
      return false;
    }
  }

  std::optional<Allocation> consume(const uintptr_t pointer) noexcept {
    try {
      std::lock_guard lock(mutex_);
      const auto found = values_.find(pointer);
      if (found == values_.end())
        return std::nullopt;
      const auto size = found->second;
      values_.erase(found);
      return Allocation{OwnedInput(reinterpret_cast<std::byte*>(pointer)), size};
    } catch (...) {
      return std::nullopt;
    }
  }

  std::size_t size() const noexcept {
    try {
      std::lock_guard lock(mutex_);
      return values_.size();
    } catch (...) {
      return 0;
    }
  }

private:
  mutable std::mutex mutex_;
  std::unordered_map<uintptr_t, std::size_t> values_;
};

class Registry {
public:
  std::uint32_t insert(std::unique_ptr<Result> result) noexcept {
    if (!result)
      return 0;
    try {
      std::lock_guard lock(mutex_);
      constexpr std::uint64_t maxHandle = std::numeric_limits<std::uint32_t>::max();
      for (std::uint64_t attempts = 0; attempts < maxHandle; ++attempts) {
        const auto handle = nextHandle_++;
        if (nextHandle_ == 0)
          nextHandle_ = 1;
        if (handle == 0 || values_.contains(handle))
          continue;
        values_.emplace(handle, std::move(result));
        return handle;
      }
    } catch (...) {
      return 0;
    }
    return 0;
  }

  template <typename Function>
  auto with(const std::uint32_t handle, Function&& function) const noexcept
      -> decltype(function(static_cast<const Result*>(nullptr))) {
    try {
      std::lock_guard lock(mutex_);
      const auto found = values_.find(handle);
      return found == values_.end() ? function(nullptr) : function(found->second.get());
    } catch (...) {
      return function(nullptr);
    }
  }

  void erase(const std::uint32_t handle) noexcept {
    try {
      std::lock_guard lock(mutex_);
      values_.erase(handle);
    } catch (...) {
    }
  }

  std::size_t size() const noexcept {
    try {
      std::lock_guard lock(mutex_);
      return values_.size();
    } catch (...) {
      return 0;
    }
  }

private:
  mutable std::mutex mutex_;
  std::unordered_map<std::uint32_t, std::unique_ptr<Result>> values_;
  std::uint32_t nextHandle_ = 1;
};

Registry& registry() noexcept {
  static Registry instance;
  return instance;
}

AllocationRegistry& allocation_registry() noexcept {
  static AllocationRegistry instance;
  return instance;
}

} // namespace

namespace wirelens::wasm_testing {

std::size_t allocation_registry_size() noexcept { return allocation_registry().size(); }

std::size_t registry_size() noexcept { return registry().size(); }

} // namespace wirelens::wasm_testing

extern "C" {

uintptr_t wirelens_alloc(const size_t size) noexcept {
  if (size == 0)
    return 0;
  const auto pointer = std::malloc(size);
  if (pointer == nullptr)
    return 0;
  const auto address = reinterpret_cast<uintptr_t>(pointer);
  if (!allocation_registry().record(address, size)) {
    std::free(pointer);
    return 0;
  }
  return address;
}

uint32_t wirelens_parse_owned(const uintptr_t data, const size_t size) noexcept {
  if (data == 0)
    return 0;

  auto allocation = allocation_registry().consume(data);
  if (!allocation || allocation->size != size)
    return 0;
  OwnedInput input = std::move(allocation->input);
  try {
    wirelens::ParseResult parsed =
        wirelens::parse_capture(std::span<const std::byte>(input.get(), size));

    auto result = std::make_unique<Result>(std::move(input), size, std::move(parsed));
    if (std::holds_alternative<wirelens::CaptureDocument>(result->parsed)) {
      result->serialized =
          wirelens::serialize_capture(std::get<wirelens::CaptureDocument>(result->parsed));
      result->packetRanges = packet_ranges(*result);
    }
    return registry().insert(std::move(result));
  } catch (...) {
    return 0;
  }
}

int wirelens_result_ok(const uint32_t handle) noexcept {
  return registry().with(handle, [](const Result* result) -> int {
    return result != nullptr && std::holds_alternative<wirelens::CaptureDocument>(result->parsed)
               ? 1
               : 0;
  });
}

const char* wirelens_result_data(const uint32_t handle) noexcept {
  return registry().with(handle, [](const Result* result) -> const char* {
    if (result == nullptr || !std::holds_alternative<wirelens::CaptureDocument>(result->parsed) ||
        result->serialized.empty())
      return nullptr;
    return result->serialized.c_str();
  });
}

size_t wirelens_result_size(const uint32_t handle) noexcept {
  return registry().with(handle, [](const Result* result) -> size_t {
    if (result == nullptr || !std::holds_alternative<wirelens::CaptureDocument>(result->parsed))
      return 0;
    return result->serialized.size();
  });
}

const char* wirelens_result_error_code(const uint32_t handle) noexcept {
  return registry().with(handle, [](const Result* result) -> const char* {
    if (result == nullptr)
      return nullptr;
    const auto* error = std::get_if<wirelens::ParseError>(&result->parsed);
    return error == nullptr ? nullptr : error->code.c_str();
  });
}

uint64_t wirelens_result_error_offset(const uint32_t handle) noexcept {
  return registry().with(handle, [](const Result* result) -> uint64_t {
    if (result == nullptr)
      return std::numeric_limits<uint64_t>::max();
    const auto* error = std::get_if<wirelens::ParseError>(&result->parsed);
    if (error == nullptr || !error->captureOffset)
      return std::numeric_limits<uint64_t>::max();
    if constexpr (sizeof(std::size_t) > sizeof(uint64_t)) {
      if (*error->captureOffset > std::numeric_limits<uint64_t>::max())
        return std::numeric_limits<uint64_t>::max();
    }
    return static_cast<uint64_t>(*error->captureOffset);
  });
}

const uint8_t* wirelens_packet_data(const uint32_t handle, const size_t packet_index) noexcept {
  return registry().with(handle, [packet_index](const Result* result) -> const uint8_t* {
    if (result == nullptr || packet_index >= result->packetRanges.size())
      return nullptr;
    const auto range = result->packetRanges[packet_index];
    return reinterpret_cast<const uint8_t*>(result->input.get() + range.offset);
  });
}

size_t wirelens_packet_size(const uint32_t handle, const size_t packet_index) noexcept {
  return registry().with(handle, [packet_index](const Result* result) -> size_t {
    if (result == nullptr || packet_index >= result->packetRanges.size())
      return 0;
    return result->packetRanges[packet_index].size;
  });
}

void wirelens_release(const uint32_t handle) noexcept { registry().erase(handle); }

} // extern "C"
