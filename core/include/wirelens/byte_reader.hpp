#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace wirelens {

class ByteReader {
public:
  explicit ByteReader(std::span<const std::byte> bytes) : bytes_(bytes) {}

  [[nodiscard]] std::optional<std::uint8_t> read_u8();
  [[nodiscard]] std::optional<std::uint16_t> read_u16_le();
  [[nodiscard]] std::optional<std::uint16_t> read_u16_be();
  [[nodiscard]] std::optional<std::uint32_t> read_u32_le();
  [[nodiscard]] std::optional<std::uint32_t> read_u32_be();
  [[nodiscard]] std::optional<std::span<const std::byte>> read_span(std::size_t length);
  [[nodiscard]] bool skip(std::size_t length);
  [[nodiscard]] std::size_t position() const { return position_; }
  [[nodiscard]] std::size_t remaining() const { return bytes_.size() - position_; }

private:
  [[nodiscard]] bool can_read(std::size_t length) const;
  std::span<const std::byte> bytes_;
  std::size_t position_ = 0;
};

} // namespace wirelens
