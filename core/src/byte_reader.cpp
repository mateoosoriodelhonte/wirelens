#include "wirelens/byte_reader.hpp"

namespace wirelens {

bool ByteReader::can_read(const std::size_t length) const { return length <= remaining(); }

std::optional<std::uint8_t> ByteReader::read_u8() {
  const auto value = read_span(1);
  if (!value)
    return std::nullopt;
  return std::to_integer<std::uint8_t>((*value)[0]);
}

std::optional<std::uint16_t> ByteReader::read_u16_le() {
  const auto value = read_span(2);
  if (!value)
    return std::nullopt;
  return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>((*value)[0]) |
                                    (std::to_integer<std::uint8_t>((*value)[1]) << 8U));
}

std::optional<std::uint16_t> ByteReader::read_u16_be() {
  const auto value = read_span(2);
  if (!value)
    return std::nullopt;
  return static_cast<std::uint16_t>((std::to_integer<std::uint8_t>((*value)[0]) << 8U) |
                                    std::to_integer<std::uint8_t>((*value)[1]));
}

std::optional<std::uint32_t> ByteReader::read_u32_le() {
  const auto value = read_span(4);
  if (!value)
    return std::nullopt;
  return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>((*value)[0]) |
                                    (std::to_integer<std::uint8_t>((*value)[1]) << 8U) |
                                    (std::to_integer<std::uint8_t>((*value)[2]) << 16U) |
                                    (std::to_integer<std::uint8_t>((*value)[3]) << 24U));
}

std::optional<std::uint32_t> ByteReader::read_u32_be() {
  const auto value = read_span(4);
  if (!value)
    return std::nullopt;
  return static_cast<std::uint32_t>((std::to_integer<std::uint8_t>((*value)[0]) << 24U) |
                                    (std::to_integer<std::uint8_t>((*value)[1]) << 16U) |
                                    (std::to_integer<std::uint8_t>((*value)[2]) << 8U) |
                                    std::to_integer<std::uint8_t>((*value)[3]));
}

std::optional<std::span<const std::byte>> ByteReader::read_span(const std::size_t length) {
  if (!can_read(length))
    return std::nullopt;
  const auto result = bytes_.subspan(position_, length);
  position_ += length;
  return result;
}

bool ByteReader::skip(const std::size_t length) {
  if (!can_read(length))
    return false;
  position_ += length;
  return true;
}

} // namespace wirelens
