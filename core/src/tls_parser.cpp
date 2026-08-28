#include "protocol_internal.hpp"

#include "wirelens/parser.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace wirelens::internal {
namespace {

struct Hello {
  bool client = false;
  std::size_t packet = 0;
  std::size_t completionPacket = 0;
  std::vector<std::size_t> packetNumbers;
  std::string recordVersion;
  std::string legacyVersion;
  std::vector<std::string> offeredVersions;
  std::optional<std::string> negotiatedVersion;
  std::optional<std::string> serverName;
};

std::uint16_t u16(const std::vector<std::byte>& bytes, const std::size_t offset) {
  return static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(bytes[offset]) << 8U) |
                                    std::to_integer<std::uint8_t>(bytes[offset + 1U]));
}

std::uint32_t u24(const std::vector<std::byte>& bytes, const std::size_t offset) {
  return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset])) << 16U) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 1U])) << 8U) |
         std::to_integer<std::uint8_t>(bytes[offset + 2U]);
}

std::optional<std::string> version(const std::uint16_t value) {
  switch (value) {
  case 0x0301:
    return "TLS 1.0";
  case 0x0302:
    return "TLS 1.1";
  case 0x0303:
    return "TLS 1.2";
  case 0x0304:
    return "TLS 1.3";
  default:
    return std::nullopt;
  }
}

std::optional<std::string> ascii_name(const std::vector<std::byte>& bytes, const std::size_t begin,
                                      const std::size_t length) {
  if (length == 0U || length > kMaxTlsServerNameBytes || begin > bytes.size() ||
      length > bytes.size() - begin)
    return std::nullopt;
  std::string result;
  result.reserve(length);
  for (std::size_t index = 0; index < length; ++index) {
    const auto value = std::to_integer<std::uint8_t>(bytes[begin + index]);
    if (!((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
          (value >= '0' && value <= '9') || value == '-' || value == '.'))
      return std::nullopt;
    result.push_back(static_cast<char>(value));
  }
  return result;
}

std::vector<std::size_t> evidence_packets(const ApplicationStream& stream, const std::size_t end) {
  std::vector<std::size_t> result;
  const auto limit = std::min(end, stream.bytePacketNumbers.size());
  for (std::size_t index = 0; index < limit; ++index)
    result.push_back(stream.bytePacketNumbers[index]);
  if (result.empty())
    result = stream.packetNumbers;
  std::sort(result.begin(), result.end());
  result.erase(std::unique(result.begin(), result.end()), result.end());
  return result;
}

bool parse_extensions(const std::vector<std::byte>& bytes, const std::size_t begin,
                      const std::size_t length, Hello& hello, bool& serverNameLimit) {
  if (length > kMaxTlsExtensionBytes || begin > bytes.size() || length > bytes.size() - begin)
    return false;
  const auto end = begin + length;
  std::size_t cursor = begin;
  while (cursor + 4U <= end) {
    const auto type = u16(bytes, cursor);
    const auto size = u16(bytes, cursor + 2U);
    cursor += 4U;
    if (size > end - cursor)
      return false;
    if (type == 0U) {
      if (size < 2U)
        return false;
      const auto listLength = u16(bytes, cursor);
      if (listLength != size - 2U)
        return false;
      std::size_t item = cursor + 2U;
      const auto listEnd = item + listLength;
      while (item < listEnd) {
        if (listEnd - item < 3U)
          return false;
        const auto nameType = std::to_integer<std::uint8_t>(bytes[item]);
        const auto nameLength = u16(bytes, item + 1U);
        item += 3U;
        if (nameLength > listEnd - item)
          return false;
        if (nameType == 0U && !hello.serverName) {
          if (nameLength == 0U || nameLength > kMaxTlsServerNameBytes) {
            serverNameLimit = true;
            return false;
          }
          if (const auto name = ascii_name(bytes, item, nameLength))
            hello.serverName = *name;
          else
            return false;
        }
        item += nameLength;
      }
      if (item != listEnd)
        return false;
    } else if (type == 43U) {
      if (hello.client) {
        if (size < 1U)
          return false;
        const auto listLength = std::to_integer<std::uint8_t>(bytes[cursor]);
        if (listLength != size - 1U || listLength < 2U || (listLength % 2U) != 0U)
          return false;
        const auto offeredCount = listLength / 2U;
        if (offeredCount > kMaxTlsOfferedVersions)
          return false;
        for (std::size_t item = cursor + 1U; item + 1U < cursor + 1U + listLength; item += 2U) {
          if (const auto offered = version(u16(bytes, item)))
            hello.offeredVersions.push_back(*offered);
        }
      } else if (!hello.client && size == 2U) {
        hello.negotiatedVersion = version(u16(bytes, cursor));
      } else {
        return false;
      }
    }
    cursor += size;
  }
  return cursor == end;
}

std::optional<Hello> parse_hello(const ApplicationStream& stream, CaptureDocument& capture) {
  const auto& bytes = stream.bytes;
  std::size_t cursor = 0;
  while (cursor + 5U <= bytes.size()) {
    const auto contentType = std::to_integer<std::uint8_t>(bytes[cursor]);
    const auto recordVersionValue = u16(bytes, cursor + 1U);
    const auto recordLength = u16(bytes, cursor + 3U);
    const auto recordVersionValueName = version(recordVersionValue);
    if (contentType != 22U || !recordVersionValueName)
      return std::nullopt;
    if (recordLength > kMaxTlsRecordBytes) {
      add_diagnostic(capture, {"warning", "TLS_RECORD_LIMIT", "TLS record exceeds the 18 KiB limit",
                               stream.flowId, std::nullopt,
                               stream.packetNumbers.empty()
                                   ? std::nullopt
                                   : std::optional<std::size_t>{stream.packetNumbers.front()},
                               1U});
      return std::nullopt;
    }
    if (recordLength < 4U || recordLength > bytes.size() - cursor - 5U)
      return std::nullopt;
    const auto body = cursor + 5U;
    const auto handshakeType = std::to_integer<std::uint8_t>(bytes[body]);
    const auto handshakeLength = u24(bytes, body + 1U);
    if ((handshakeType != 1U && handshakeType != 2U) || handshakeLength > kMaxTlsHandshakeBytes) {
      if (handshakeType == 1U || handshakeType == 2U)
        add_diagnostic(capture,
                       {"warning", "TLS_HANDSHAKE_LIMIT", "TLS handshake exceeds the 16 KiB limit",
                        stream.flowId, std::nullopt,
                        stream.packetNumbers.empty()
                            ? std::nullopt
                            : std::optional<std::size_t>{stream.packetNumbers.front()},
                        1U});
      return std::nullopt;
    }
    if (handshakeLength + 4U > recordLength || handshakeLength + 4U > bytes.size() - body)
      return std::nullopt;
    const auto helloBegin = body + 4U;
    const auto helloEnd = helloBegin + handshakeLength;
    bool serverNameLimit = false;
    if (handshakeType == 1U) {
      if (handshakeLength < 34U)
        return std::nullopt;
      const auto legacy = version(u16(bytes, helloBegin));
      if (!legacy)
        return std::nullopt;
      std::size_t position = helloBegin + 34U;
      if (position >= helloEnd)
        return std::nullopt;
      const auto sessionLength = std::to_integer<std::uint8_t>(bytes[position++]);
      if (sessionLength > 32U || sessionLength > helloEnd - position)
        return std::nullopt;
      position += sessionLength;
      if (position + 2U > helloEnd)
        return std::nullopt;
      const auto cipherLength = u16(bytes, position);
      position += 2U;
      if (cipherLength == 0U || (cipherLength % 2U) != 0U || cipherLength > helloEnd - position)
        return std::nullopt;
      position += cipherLength;
      if (position >= helloEnd)
        return std::nullopt;
      const auto compressionLength = std::to_integer<std::uint8_t>(bytes[position++]);
      if (compressionLength == 0U || compressionLength > helloEnd - position)
        return std::nullopt;
      for (std::size_t index = 0; index < compressionLength; ++index)
        if (bytes[position + index] != std::byte{0})
          return std::nullopt;
      position += compressionLength;
      const auto helloPackets = evidence_packets(stream, helloEnd);
      Hello result{true,
                   helloPackets.empty() ? 0U : helloPackets.front(),
                   helloEnd <= stream.bytePacketNumbers.size()
                       ? stream.bytePacketNumbers[helloEnd - 1U]
                       : (helloPackets.empty() ? 0U : helloPackets.back()),
                   helloPackets,
                   *recordVersionValueName,
                   *legacy,
                   {},
                   std::nullopt,
                   std::nullopt};
      if (position + 2U <= helloEnd) {
        const auto extensionLength = u16(bytes, position);
        position += 2U;
        if (extensionLength != helloEnd - position || extensionLength > kMaxTlsExtensionBytes)
          return std::nullopt;
        if (!parse_extensions(bytes, position, extensionLength, result, serverNameLimit)) {
          if (serverNameLimit)
            add_diagnostic(capture, {"warning", "TLS_SERVER_NAME_LIMIT",
                                     "TLS server name exceeds the 253 byte limit", stream.flowId,
                                     std::nullopt,
                                     stream.packetNumbers.empty()
                                         ? std::nullopt
                                         : std::optional<std::size_t>{stream.packetNumbers.front()},
                                     1U});
          return std::nullopt;
        }
      } else if (position != helloEnd) {
        return std::nullopt;
      }
      if (result.offeredVersions.empty())
        result.offeredVersions.push_back(*legacy);
      return result;
    }
    if (handshakeLength < 34U)
      return std::nullopt;
    const auto legacy = version(u16(bytes, helloBegin));
    if (!legacy)
      return std::nullopt;
    std::size_t position = helloBegin + 34U;
    if (position >= helloEnd)
      return std::nullopt;
    const auto sessionLength = std::to_integer<std::uint8_t>(bytes[position++]);
    if (sessionLength > 32U || sessionLength > helloEnd - position)
      return std::nullopt;
    position += sessionLength;
    if (position + 3U > helloEnd)
      return std::nullopt;
    const auto cipherLength = 2U;
    position += cipherLength;
    const auto compressionMethod = std::to_integer<std::uint8_t>(bytes[position++]);
    if (compressionMethod != 0U)
      return std::nullopt;
    const auto helloPackets = evidence_packets(stream, helloEnd);
    Hello result{false,
                 helloPackets.empty() ? 0U : helloPackets.front(),
                 helloEnd <= stream.bytePacketNumbers.size()
                     ? stream.bytePacketNumbers[helloEnd - 1U]
                     : (helloPackets.empty() ? 0U : helloPackets.back()),
                 helloPackets,
                 *recordVersionValueName,
                 *legacy,
                 {},
                 std::nullopt,
                 std::nullopt};
    if (position + 2U <= helloEnd) {
      const auto extensionLength = u16(bytes, position);
      position += 2U;
      if (extensionLength != helloEnd - position || extensionLength > kMaxTlsExtensionBytes)
        return std::nullopt;
      if (!parse_extensions(bytes, position, extensionLength, result, serverNameLimit)) {
        if (serverNameLimit)
          add_diagnostic(capture,
                         {"warning", "TLS_SERVER_NAME_LIMIT",
                          "TLS server name exceeds the 253 byte limit", stream.flowId, std::nullopt,
                          stream.packetNumbers.empty()
                              ? std::nullopt
                              : std::optional<std::size_t>{stream.packetNumbers.front()},
                          1U});
        return std::nullopt;
      }
    } else if (position != helloEnd) {
      return std::nullopt;
    }
    if (!result.negotiatedVersion)
      result.negotiatedVersion = legacy;
    return result;
  }
  return std::nullopt;
}

bool recognized_tls_prefix(const ApplicationStream& stream) {
  return stream.bytes.size() >= 5U && std::to_integer<std::uint8_t>(stream.bytes[0]) == 22U;
}

void tls_layer(ParsedPacket& packet, const Hello& hello) {
  ProtocolLayer layer{"TLS",
                      hello.client ? "TLS ClientHello" : "TLS ServerHello",
                      {},
                      std::nullopt,
                      std::string{"tls"}};
  layer.fields.push_back({"recordVersion", hello.recordVersion, std::nullopt, std::nullopt});
  layer.fields.push_back({"legacyVersion", hello.legacyVersion, std::nullopt, std::nullopt});
  if (hello.client)
    layer.fields.push_back({"offeredVersions",
                            [&] {
                              std::string value;
                              for (std::size_t index = 0; index < hello.offeredVersions.size();
                                   ++index) {
                                if (index != 0U)
                                  value += ", ";
                                value += hello.offeredVersions[index];
                              }
                              return value;
                            }(),
                            std::nullopt, std::nullopt});
  else if (hello.negotiatedVersion)
    layer.fields.push_back(
        {"negotiatedVersion", *hello.negotiatedVersion, std::nullopt, std::nullopt});
  if (hello.serverName)
    layer.fields.push_back({"serverName", *hello.serverName, std::nullopt, std::nullopt});
  packet.packet.layers.push_back(std::move(layer));
}

} // namespace

void build_tls(CaptureDocument& capture, std::vector<ParsedPacket>& packets,
               const std::vector<ApplicationStream>& streams) {
  std::map<std::string, std::pair<std::optional<Hello>, std::optional<Hello>>> handshakes;
  std::map<std::size_t, ParsedPacket*> packetMap;
  for (auto& packet : packets)
    packetMap.emplace(packet.packet.number, &packet);
  for (const auto& stream : streams) {
    if (stream.bytes.empty() || stream.ambiguous || stream.truncated)
      continue;
    auto hello = parse_hello(stream, capture);
    if (!hello) {
      const auto specificLimit = std::any_of(capture.diagnostics.begin(), capture.diagnostics.end(),
                                             [&](const auto& diagnostic) {
                                               return diagnostic.context == stream.flowId &&
                                                      (diagnostic.code == "TLS_RECORD_LIMIT" ||
                                                       diagnostic.code == "TLS_HANDSHAKE_LIMIT" ||
                                                       diagnostic.code == "TLS_SERVER_NAME_LIMIT");
                                             });
      if (recognized_tls_prefix(stream) && !specificLimit)
        add_diagnostic(capture, {"warning", "TLS_MALFORMED",
                                 "Recognized TLS prefix failed strict record or handshake parsing",
                                 stream.flowId, std::nullopt,
                                 stream.packetNumbers.empty()
                                     ? std::nullopt
                                     : std::optional<std::size_t>{stream.packetNumbers.front()},
                                 1U});
      continue;
    }
    if (hello->client != stream.fromClient)
      continue;
    auto& pair = handshakes[stream.flowId];
    if (hello->client) {
      if (!pair.first)
        pair.first = *hello;
    } else if (!pair.second) {
      pair.second = *hello;
    }
    for (const auto number : hello->packetNumbers) {
      const auto found = packetMap.find(number);
      if (found != packetMap.end() && number == hello->completionPacket)
        tls_layer(*found->second, *hello);
    }
  }
  for (const auto& [flowId, pair] : handshakes) {
    TlsHandshake handshake{"tls-handshake-0",
                           flowId,
                           std::nullopt,
                           std::nullopt,
                           pair.first.has_value() && pair.second.has_value() &&
                               pair.first->packet < pair.second->packet,
                           "WireLens does not decrypt TLS application data."};
    if (pair.first) {
      handshake.clientHello = TlsClientHello{pair.first->recordVersion, pair.first->legacyVersion,
                                             pair.first->offeredVersions, pair.first->serverName,
                                             pair.first->packetNumbers};
    }
    if (pair.second) {
      handshake.serverHello =
          TlsServerHello{pair.second->recordVersion, pair.second->legacyVersion,
                         pair.second->negotiatedVersion, pair.second->packetNumbers};
    }
    capture.tlsHandshakes.push_back(std::move(handshake));
  }
  for (std::size_t index = 0; index < capture.tlsHandshakes.size(); ++index)
    capture.tlsHandshakes[index].id = "tls-handshake-" + std::to_string(index + 1U);
}

} // namespace wirelens::internal
