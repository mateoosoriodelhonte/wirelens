#include "wirelens/byte_reader.hpp"

#include <array>
#include <catch2/catch_test_macros.hpp>

TEST_CASE("ByteReader refuses reads beyond the remaining span") {
  const std::array<std::byte, 1> bytes{std::byte{0x42}};
  wirelens::ByteReader reader(bytes);
  REQUIRE(reader.read_u8() == 0x42);
  REQUIRE_FALSE(reader.read_u8().has_value());
  REQUIRE(reader.position() == 1);
}
