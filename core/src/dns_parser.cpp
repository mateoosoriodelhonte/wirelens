#include "protocol_internal.hpp"

#include "wirelens/byte_reader.hpp"
#include "wirelens/parser.hpp"

#include <array>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace wirelens::internal {
namespace {

ByteRange range(const std::size_t captureOffset, const std::size_t packetOffset,
                const std::size_t length) {
  return {captureOffset + packetOffset, packetOffset, length};
}

void add_field(ProtocolLayer& layer, std::string name, std::string value,
               const std::size_t captureOffset, const std::size_t packetOffset,
               const std::size_t length) {
  layer.fields.push_back({std::move(name), std::move(value),
                          range(captureOffset, packetOffset, length), std::nullopt});
}

std::optional<std::uint8_t> byte_at(const std::span<const std::byte> bytes,
                                    const std::size_t offset) {
  if (offset >= bytes.size())
    return std::nullopt;
  return std::to_integer<std::uint8_t>(bytes[offset]);
}

std::optional<std::uint16_t> u16_at(const std::span<const std::byte> bytes,
                                    const std::size_t offset) {
  if (offset > bytes.size() || bytes.size() - offset < 2)
    return std::nullopt;
  ByteReader reader(bytes.subspan(offset, 2));
  return reader.read_u16_be();
}

void append_safe_octet(std::string& text, const std::uint8_t value) {
  if (value >= 0x21U && value <= 0x7eU && value != '.' && value != '\\') {
    text.push_back(static_cast<char>(value));
    return;
  }
  text.push_back('\\');
  text.push_back(static_cast<char>('0' + value / 100U));
  text.push_back(static_cast<char>('0' + (value / 10U) % 10U));
  text.push_back(static_cast<char>('0' + value % 10U));
}

struct NameResult {
  std::string value;
  std::size_t next = 0;
};

enum class NameError {
  truncated,
  pointerCycle,
  pointerHopLimit,
  labelLimit,
  nameLimit,
  invalid,
};

std::optional<NameResult> read_name(const std::span<const std::byte> bytes, const std::size_t start,
                                    NameError& error, std::vector<bool>& knownNameStarts) {
  std::vector<std::size_t> visited;
  std::vector<std::string> labels;
  std::size_t cursor = start;
  std::size_t next = start;
  std::size_t labelsCount = 0;
  std::size_t wireNameBytes = 0;
  bool jumped = false;
  for (;;) {
    const auto lengthByte = byte_at(bytes, cursor);
    if (!lengthByte) {
      error = NameError::truncated;
      return std::nullopt;
    }
    knownNameStarts[cursor] = true;
    if ((*lengthByte & 0xc0U) == 0xc0U) {
      if (cursor > bytes.size() || bytes.size() - cursor < 2) {
        error = NameError::truncated;
        return std::nullopt;
      }
      const auto low = byte_at(bytes, cursor + 1);
      if (!low) {
        error = NameError::truncated;
        return std::nullopt;
      }
      const auto target = static_cast<std::size_t>((*lengthByte & 0x3fU) << 8U) | *low;
      if (target >= bytes.size()) {
        error = NameError::invalid;
        return std::nullopt;
      }
      if (target == cursor) {
        error = NameError::pointerCycle;
        return std::nullopt;
      }
      if (target < 12U || target > cursor || !knownNameStarts[target]) {
        error = NameError::invalid;
        return std::nullopt;
      }
      if (!jumped)
        next = cursor + 2;
      jumped = true;
      if (visited.size() >= kMaxDnsPointerHops) {
        error = NameError::pointerHopLimit;
        return std::nullopt;
      }
      for (const auto prior : visited) {
        if (prior == target) {
          error = NameError::pointerCycle;
          return std::nullopt;
        }
      }
      visited.push_back(target);
      cursor = target;
      continue;
    }
    if ((*lengthByte & 0xc0U) != 0) {
      error = NameError::invalid;
      return std::nullopt;
    }
    ++cursor;
    if (*lengthByte == 0) {
      if (!jumped)
        next = cursor;
      if (wireNameBytes >= kMaxDnsNameBytes) {
        error = NameError::nameLimit;
        return std::nullopt;
      }
      std::string result;
      for (std::size_t index = 0; index < labels.size(); ++index) {
        if (index != 0)
          result.push_back('.');
        result += labels[index];
      }
      return NameResult{result.empty() ? "." : std::move(result), next};
    }
    if (*lengthByte > 63U || cursor > bytes.size() || bytes.size() - cursor < *lengthByte) {
      error = NameError::truncated;
      return std::nullopt;
    }
    ++labelsCount;
    if (labelsCount > kMaxDnsLabels) {
      error = NameError::labelLimit;
      return std::nullopt;
    }
    wireNameBytes += static_cast<std::size_t>(*lengthByte) + 1U;
    if (wireNameBytes >= kMaxDnsNameBytes) {
      error = NameError::nameLimit;
      return std::nullopt;
    }
    const auto label = bytes.subspan(cursor, *lengthByte);
    std::string text;
    text.reserve(label.size());
    for (const auto value : label)
      append_safe_octet(text, std::to_integer<std::uint8_t>(value));
    labels.push_back(std::move(text));
    cursor += *lengthByte;
  }
}

std::string ipv4(const std::span<const std::byte> bytes) {
  ByteReader reader(bytes);
  const auto first = reader.read_u8();
  const auto second = reader.read_u8();
  const auto third = reader.read_u8();
  const auto fourth = reader.read_u8();
  if (!first || !second || !third || !fourth)
    return {};
  return std::to_string(*first) + "." + std::to_string(*second) + "." + std::to_string(*third) +
         "." + std::to_string(*fourth);
}

std::optional<std::uint16_t> u16be_checked(const std::span<const std::byte> bytes,
                                           const std::size_t offset) {
  return u16_at(bytes, offset);
}

std::string ipv6(const std::span<const std::byte> bytes) {
  std::array<std::uint16_t, 8> words{};
  for (std::size_t index = 0; index < words.size(); ++index) {
    const auto word = u16be_checked(bytes, index * 2U);
    if (!word)
      return {};
    words[index] = *word;
  }
  std::size_t bestStart = 8;
  std::size_t bestLength = 0;
  for (std::size_t index = 0; index < 8;) {
    if (words[index] == 0) {
      const auto start = index;
      while (index < 8 && words[index] == 0)
        ++index;
      if (index - start > bestLength) {
        bestStart = start;
        bestLength = index - start;
      }
    } else {
      ++index;
    }
  }
  if (bestLength < 2) {
    bestStart = 8;
    bestLength = 0;
  }
  std::ostringstream result;
  for (std::size_t index = 0; index < 8; ++index) {
    if (index == bestStart) {
      result << "::";
      index += bestLength - 1U;
      continue;
    }
    if (index != 0 && index != bestStart + bestLength)
      result << ':';
    result << std::hex << std::nouppercase << words[index];
  }
  return result.str();
}

const char* name_error_code(const NameError value) {
  switch (value) {
  case NameError::pointerCycle:
    return "DNS_POINTER_CYCLE";
  case NameError::pointerHopLimit:
    return "DNS_POINTER_HOP_LIMIT";
  case NameError::labelLimit:
    return "DNS_LABEL_LIMIT_EXCEEDED";
  case NameError::nameLimit:
    return "DNS_NAME_LIMIT_EXCEEDED";
  case NameError::truncated:
    return "DNS_TRUNCATED_NAME";
  case NameError::invalid:
    return "DNS_INVALID_NAME";
  }
  return "DNS_INVALID_NAME";
}

std::optional<Diagnostic> dns_error(const char* code, const char* message,
                                    const std::size_t captureOffset,
                                    const std::size_t packetOffset) {
  return Diagnostic{"warning",    code,        message, "dns", captureOffset + packetOffset,
                    std::nullopt, std::nullopt};
}

} // namespace

std::optional<ProtocolLayer> decode_dns(const std::span<const std::byte> payload,
                                        const std::size_t captureOffset,
                                        const std::size_t packetOffset, const UdpFacts& udp,
                                        DnsFacts& facts) {
  facts = {};
  if (udp.sourcePort != 53 && udp.destinationPort != 53)
    return std::nullopt;
  if (payload.size() < 12) {
    facts.diagnostic =
        dns_error("DNS_TRUNCATED_HEADER", "DNS header is truncated", captureOffset, packetOffset);
    return std::nullopt;
  }
  ByteReader header(payload);
  const auto id = header.read_u16_be();
  const auto flags = header.read_u16_be();
  const auto questions = header.read_u16_be();
  const auto answers = header.read_u16_be();
  const auto authority = header.read_u16_be();
  const auto additional = header.read_u16_be();
  if (!id || !flags || !questions || !answers || !authority || !additional)
    return std::nullopt;
  if (*questions > kMaxDnsQuestions) {
    facts.diagnostic = dns_error("DNS_QUESTION_LIMIT_EXCEEDED", "DNS question count exceeds limit",
                                 captureOffset, packetOffset + 4);
    return std::nullopt;
  }
  const auto totalRecords = static_cast<std::size_t>(*answers) + *authority + *additional;
  if (totalRecords > kMaxDnsRecords) {
    facts.diagnostic = dns_error("DNS_RECORD_LIMIT_EXCEEDED", "DNS record count exceeds limit",
                                 captureOffset, packetOffset + 6);
    return std::nullopt;
  }
  if (*questions == 0) {
    facts.diagnostic = dns_error("DNS_INVALID_MESSAGE", "DNS message has no question",
                                 captureOffset, packetOffset + 4);
    return std::nullopt;
  }
  DnsFacts parsed;
  parsed.valid = true;
  parsed.response = (*flags & 0x8000U) != 0;
  parsed.transactionId = *id;
  parsed.opcode = static_cast<std::uint8_t>((*flags >> 11U) & 0x0fU);
  parsed.responseCode = static_cast<std::uint8_t>(*flags & 0x0fU);
  parsed.questionCount = *questions;
  parsed.source = udp.source;
  parsed.destination = udp.destination;
  parsed.sourcePort = udp.sourcePort;
  parsed.destinationPort = udp.destinationPort;
  std::size_t cursor = 12;
  std::size_t questionNameOffset = 12;
  std::size_t questionNameLength = 0;
  std::size_t questionTypeOffset = 12;
  std::vector<bool> knownNameStarts(payload.size(), false);
  for (std::size_t question = 0; question < *questions; ++question) {
    const auto nameOffset = cursor;
    NameError nameError = NameError::invalid;
    const auto name = read_name(payload, cursor, nameError, knownNameStarts);
    if (!name) {
      facts.diagnostic = dns_error(name_error_code(nameError), "DNS question name is invalid",
                                   captureOffset, packetOffset + cursor);
      return std::nullopt;
    }
    cursor = name->next;
    const auto type = u16_at(payload, cursor);
    const auto classCode = type ? u16_at(payload, cursor + 2U) : std::nullopt;
    if (!type || !classCode) {
      facts.diagnostic = dns_error("DNS_TRUNCATED_SECTION", "DNS question is truncated",
                                   captureOffset, packetOffset + cursor);
      return std::nullopt;
    }
    if (question == 0) {
      parsed.question = {name->value, *type, *classCode};
      questionNameOffset = nameOffset;
      questionNameLength = name->next - nameOffset;
      questionTypeOffset = cursor;
    }
    cursor += 4;
  }
  if (*questions != 1U) {
    parsed.diagnostic = dns_error("DNS_UNSUPPORTED_QUESTION_COUNT",
                                  "DNS exchange matching requires exactly one question",
                                  captureOffset, packetOffset + 4U);
  }
  for (std::size_t recordIndex = 0; recordIndex < totalRecords; ++recordIndex) {
    NameError nameError = NameError::invalid;
    const auto name = read_name(payload, cursor, nameError, knownNameStarts);
    if (!name) {
      facts.diagnostic = dns_error(name_error_code(nameError), "DNS record name is invalid",
                                   captureOffset, packetOffset + cursor);
      return std::nullopt;
    }
    cursor = name->next;
    const auto type = u16_at(payload, cursor);
    const auto classCode = type ? u16_at(payload, cursor + 2U) : std::nullopt;
    const auto length = classCode ? u16_at(payload, cursor + 8U) : std::nullopt;
    if (!type || !classCode || !length || cursor > payload.size() ||
        payload.size() - cursor < 10U) {
      facts.diagnostic = dns_error("DNS_TRUNCATED_SECTION", "DNS record header is truncated",
                                   captureOffset, packetOffset + cursor);
      return std::nullopt;
    }
    cursor += 10;
    if (static_cast<std::size_t>(*length) > payload.size() - cursor) {
      facts.diagnostic = dns_error("DNS_TRUNCATED_SECTION", "DNS record data is truncated",
                                   captureOffset, packetOffset + cursor);
      return std::nullopt;
    }
    const auto recordData = payload.subspan(cursor, *length);
    if (*type == 1U && *length != 4U) {
      facts.diagnostic = dns_error("DNS_INVALID_RECORD_LENGTH", "DNS A record length is invalid",
                                   captureOffset, packetOffset + cursor);
      return std::nullopt;
    }
    if (*type == 28U && *length != 16U) {
      facts.diagnostic = dns_error("DNS_INVALID_RECORD_LENGTH", "DNS AAAA record length is invalid",
                                   captureOffset, packetOffset + cursor);
      return std::nullopt;
    }
    if (recordIndex < *answers && *classCode == 1U && (*type == 1U || *type == 28U)) {
      parsed.answers.push_back(
          {name->value, *type, *classCode, *type == 1U ? ipv4(recordData) : ipv6(recordData)});
    }
    cursor += *length;
  }
  if (cursor != payload.size()) {
    facts.diagnostic = dns_error("DNS_TRAILING_DATA", "DNS message has trailing data",
                                 captureOffset, packetOffset + cursor);
    return std::nullopt;
  }
  ProtocolLayer layer{"DNS", "DNS", {}, std::nullopt, std::nullopt};
  layer.explanationKey = "dns";
  layer.byteRange = range(captureOffset, packetOffset, payload.size());
  add_field(layer, "transactionId", std::to_string(parsed.transactionId), captureOffset,
            packetOffset, 2);
  add_field(layer, "messageType", parsed.response ? "response" : "query", captureOffset,
            packetOffset + 2, 2);
  add_field(layer, "responseCode", std::to_string(parsed.responseCode), captureOffset,
            packetOffset + 2, 2);
  add_field(layer, "questionCount", std::to_string(*questions), captureOffset, packetOffset + 4, 2);
  add_field(layer, "answerCount", std::to_string(*answers), captureOffset, packetOffset + 6, 2);
  add_field(layer, "questionName", parsed.question.name, captureOffset,
            packetOffset + questionNameOffset, questionNameLength);
  add_field(layer, "questionType", std::to_string(parsed.question.type), captureOffset,
            packetOffset + questionTypeOffset, 2);
  facts = std::move(parsed);
  return layer;
}

} // namespace wirelens::internal
