#include "wirelens/wasm_api.h"

#include "fixture_builder.hpp"
#include "wirelens/parser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace wirelens::wasm_testing {
std::size_t allocation_registry_size() noexcept;
std::size_t registry_size() noexcept;
} // namespace wirelens::wasm_testing

namespace {

std::uint32_t parse(const std::vector<std::byte>& bytes) {
  const auto pointer = wirelens_alloc(bytes.size());
  REQUIRE(pointer != 0);
  std::memcpy(reinterpret_cast<void*>(pointer), bytes.data(), bytes.size());
  return wirelens_parse_owned(pointer, bytes.size());
}

std::string result_text(const std::uint32_t handle) {
  const auto* data = wirelens_result_data(handle);
  const auto size = wirelens_result_size(handle);
  REQUIRE(data != nullptr);
  return {data, size};
}

} // namespace

TEST_CASE("Wasm API owns a successful parse and exposes normalized JSON") {
  const auto bytes = wirelens_test::build_handshake();
  const auto handle = parse(bytes);

  REQUIRE(handle != 0);
  REQUIRE(wirelens_result_ok(handle) == 1);
  const auto text = result_text(handle);
  REQUIRE(text.find("\"packetCount\": 3") != std::string::npos);
  REQUIRE(text.find("rawBytes") == std::string::npos);
  REQUIRE(text.find("d4c3b2a1") == std::string::npos);
  REQUIRE(wirelens_result_error_code(handle) == nullptr);
  REQUIRE(wirelens_result_error_offset(handle) == std::numeric_limits<std::uint64_t>::max());

  wirelens_release(handle);
}

TEST_CASE("Wasm API retains typed malformed-input errors") {
  const std::vector<std::byte> bytes(3);
  const auto handle = parse(bytes);

  REQUIRE(handle != 0);
  REQUIRE(wirelens_result_ok(handle) == 0);
  REQUIRE(wirelens_result_data(handle) == nullptr);
  REQUIRE(wirelens_result_size(handle) == 0);
  REQUIRE(std::string(wirelens_result_error_code(handle)) == "TRUNCATED_GLOBAL_HEADER");
  REQUIRE(wirelens_result_error_offset(handle) == std::numeric_limits<std::uint64_t>::max());
  REQUIRE(wirelens_result_error_packet_number(handle) == std::numeric_limits<std::uint64_t>::max());

  wirelens_release(handle);
}

TEST_CASE("Wasm API rejects invalid handles and keeps release idempotent") {
  constexpr std::uint32_t invalid = 0xdeadbeefU;
  REQUIRE(wirelens_result_ok(invalid) == 0);
  REQUIRE(wirelens_result_data(invalid) == nullptr);
  REQUIRE(wirelens_result_size(invalid) == 0);
  REQUIRE(wirelens_result_error_code(invalid) == nullptr);
  REQUIRE(wirelens_result_error_offset(invalid) == std::numeric_limits<std::uint64_t>::max());
  REQUIRE(wirelens_result_error_packet_number(invalid) ==
          std::numeric_limits<std::uint64_t>::max());
  REQUIRE(wirelens_packet_data(invalid, 0) == nullptr);
  REQUIRE(wirelens_packet_size(invalid, 0) == 0);
  wirelens_release(invalid);
}

TEST_CASE("Wasm API retains a known parse-error packet number") {
  std::vector<std::byte> bytes(25, std::byte{0});
  bytes[0] = std::byte{0xd4};
  bytes[1] = std::byte{0xc3};
  bytes[2] = std::byte{0xb2};
  bytes[3] = std::byte{0xa1};
  bytes[4] = std::byte{2};
  bytes[6] = std::byte{4};
  bytes[20] = std::byte{1};
  const auto handle = parse(bytes);

  REQUIRE(handle != 0);
  REQUIRE(std::string(wirelens_result_error_code(handle)) == "TRUNCATED_PACKET_HEADER");
  REQUIRE(wirelens_result_error_offset(handle) == 24);
  REQUIRE(wirelens_result_error_packet_number(handle) == 1);

  wirelens_release(handle);
}

TEST_CASE("Wasm API returns bounded bytes for packet one") {
  const auto bytes = wirelens_test::build_handshake();
  const auto handle = parse(bytes);
  REQUIRE(handle != 0);

  const auto* packet = wirelens_packet_data(handle, 0);
  REQUIRE(packet != nullptr);
  REQUIRE(wirelens_packet_size(handle, 0) == 54);
  REQUIRE(std::memcmp(packet, bytes.data() + 40, 54) == 0);
  REQUIRE(wirelens_packet_data(handle, 3) == nullptr);
  REQUIRE(wirelens_packet_size(handle, 3) == 0);

  wirelens_release(handle);
  REQUIRE(wirelens_packet_data(handle, 0) == nullptr);
  REQUIRE(wirelens_packet_size(handle, 0) == 0);
  wirelens_release(handle);
}

TEST_CASE("Wasm API registry is cleaned after every result release") {
  const auto before = wirelens::wasm_testing::registry_size();
  const auto handle = parse(wirelens_test::build_handshake());
  REQUIRE(handle != 0);
  REQUIRE(wirelens::wasm_testing::registry_size() == before + 1);
  wirelens_release(handle);
  REQUIRE(wirelens::wasm_testing::registry_size() == before);
}

TEST_CASE("Wasm API consumes only registered allocations with exact sizes") {
  const auto before = wirelens::wasm_testing::allocation_registry_size();

  const auto exact = wirelens_alloc(1);
  REQUIRE(exact != 0);
  REQUIRE(wirelens::wasm_testing::allocation_registry_size() == before + 1);
  const auto mismatch = wirelens_parse_owned(exact, 24);
  REQUIRE(mismatch == 0);
  REQUIRE(wirelens::wasm_testing::allocation_registry_size() == before);

  std::array<std::byte, 24> arbitrary{};
  REQUIRE(wirelens_parse_owned(reinterpret_cast<uintptr_t>(arbitrary.data()), arbitrary.size()) ==
          0);
  REQUIRE(wirelens::wasm_testing::allocation_registry_size() == before);
}

TEST_CASE("Wasm API rejects a consumed allocation on a second parse") {
  const auto before = wirelens::wasm_testing::allocation_registry_size();
  const auto bytes = wirelens_test::build_handshake();
  const auto pointer = wirelens_alloc(bytes.size());
  REQUIRE(pointer != 0);
  std::memcpy(reinterpret_cast<void*>(pointer), bytes.data(), bytes.size());
  REQUIRE(wirelens::wasm_testing::allocation_registry_size() == before + 1);

  const auto handle = wirelens_parse_owned(pointer, bytes.size());
  REQUIRE(handle != 0);
  REQUIRE(wirelens::wasm_testing::allocation_registry_size() == before);
  REQUIRE(wirelens_parse_owned(pointer, bytes.size()) == 0);
  REQUIRE(wirelens::wasm_testing::allocation_registry_size() == before);
  wirelens_release(handle);
  REQUIRE(wirelens::wasm_testing::allocation_registry_size() == before);
}

TEST_CASE("Wasm API reports allocation and ownership boundary failures") {
  const auto before = wirelens::wasm_testing::allocation_registry_size();
  REQUIRE(wirelens_alloc(0) == 0);
  REQUIRE(wirelens_alloc(wirelens::kMaxCaptureBytes + 1U) == 0);
  REQUIRE(wirelens_alloc(std::numeric_limits<std::size_t>::max()) == 0);
  REQUIRE(wirelens_parse_owned(0, 0) == 0);

  const auto pointer = wirelens_alloc(1);
  REQUIRE(pointer != 0);
  const auto handle = wirelens_parse_owned(pointer, 64U * 1024U * 1024U + 1U);
  REQUIRE(handle == 0);
  REQUIRE(wirelens::wasm_testing::allocation_registry_size() == before);
}
