#include "protocol_internal.hpp"

#include "wirelens/parser.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace wirelens::internal {
namespace {

struct Message {
  std::string flowId;
  bool fromClient = false;
  bool request = false;
  std::size_t end = 0;
  std::size_t firstPacket = 0;
  std::size_t completionPacket = 0;
  std::vector<std::size_t> packetNumbers;
  std::optional<HttpRequest> requestValue;
  std::optional<HttpResponse> responseValue;
};

bool token_char(const unsigned char value) {
  if (std::isalnum(value) != 0)
    return true;
  constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
  return punctuation.find(static_cast<char>(value)) != std::string_view::npos;
}

bool visible_header_value(const std::string_view value) {
  for (const auto character : value) {
    const auto byte = static_cast<unsigned char>(character);
    if (byte < 0x20U && byte != '\t')
      return false;
    if (byte == 0x7fU)
      return false;
  }
  return true;
}

bool recognized_prefix(const std::vector<std::byte>& bytes) {
  if (bytes.size() >= 5U && std::to_integer<unsigned char>(bytes[0]) == 'H' &&
      std::to_integer<unsigned char>(bytes[1]) == 'T' && std::to_integer<unsigned char>(bytes[2]) == 'T' &&
      std::to_integer<unsigned char>(bytes[3]) == 'P' && bytes[4] == std::byte{'/'})
    return true;
  if (bytes.empty())
    return false;
  const auto first = std::to_integer<unsigned char>(bytes.front());
  if (first < 'A' || first > 'Z')
    return false;
  const auto limit = std::min(bytes.size(), kMaxHttpLineBytes);
  std::string prefix;
  prefix.reserve(limit);
  for (std::size_t index = 0; index < limit; ++index)
    prefix.push_back(static_cast<char>(std::to_integer<unsigned char>(bytes[index])));
  return prefix.find(" HTTP/1.") != std::string::npos;
}

std::string lower(std::string value) {
  for (auto& character : value)
    character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  return value;
}

std::string trim(std::string_view value) {
  std::size_t begin = 0;
  while (begin < value.size() && (value[begin] == ' ' || value[begin] == '\t'))
    ++begin;
  std::size_t end = value.size();
  while (end > begin && (value[end - 1] == ' ' || value[end - 1] == '\t'))
    --end;
  return std::string(value.substr(begin, end - begin));
}

bool secret_name(const std::string_view name) {
  constexpr std::string_view words[] = {"authorization", "cookie", "token", "secret", "credential",
                                        "password", "session", "jwt", "api-key", "apikey", "proxy-authorization"};
  return std::any_of(std::begin(words), std::end(words), [&](const auto word) {
    return name.find(word) != std::string_view::npos;
  });
}

HttpHeader sanitized_header(const std::string& name, const std::string& rawValue) {
  const auto normalized = lower(name);
  constexpr std::string_view allowed[] = {"host", "content-type", "content-length", "accept",
                                          "user-agent", "server", "date"};
  const auto isAllowed = std::find(std::begin(allowed), std::end(allowed), normalized) != std::end(allowed);
  if (!isAllowed || secret_name(normalized) || rawValue.size() > 8192U || !visible_header_value(rawValue))
    return {normalized, std::nullopt, true};
  return {normalized, rawValue, false};
}

std::string redact_target(const std::string_view target) {
  const auto question = target.find('?');
  if (question == std::string_view::npos)
    return std::string(target);
  const auto fragment = target.find('#', question + 1U);
  const auto queryEnd = fragment == std::string_view::npos ? target.size() : fragment;
  std::string result(target.substr(0, question + 1U));
  const auto query = target.substr(question + 1U, queryEnd - question - 1U);
  std::size_t begin = 0;
  while (begin <= query.size()) {
    const auto separator = query.find_first_of("&;", begin);
    const auto end = separator == std::string_view::npos ? query.size() : separator;
    const auto part = query.substr(begin, end - begin);
    const auto equals = part.find('=');
    result.append(part.substr(0, equals == std::string_view::npos ? part.size() : equals));
    result += "=[redacted]";
    if (separator == std::string_view::npos)
      break;
    result.push_back(query[separator]);
    begin = separator + 1U;
  }
  if (fragment != std::string_view::npos)
    result.append(target.substr(fragment));
  return result;
}

std::optional<std::size_t> crlf(const std::vector<std::byte>& bytes, const std::size_t begin) {
  if (begin >= bytes.size())
    return std::nullopt;
  for (std::size_t position = begin; position + 1U < bytes.size(); ++position) {
    if (bytes[position] == std::byte{'\r'} && bytes[position + 1U] == std::byte{'\n'})
      return position;
  }
  return std::nullopt;
}

std::string ascii(const std::vector<std::byte>& bytes, const std::size_t begin,
                  const std::size_t end) {
  std::string result;
  result.reserve(end - begin);
  for (std::size_t position = begin; position < end; ++position)
    result.push_back(static_cast<char>(std::to_integer<unsigned char>(bytes[position])));
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

std::optional<Message> parse_message(const ApplicationStream& stream, CaptureDocument& capture) {
  (void)capture;
  if (stream.bytes.empty() || stream.ambiguous || stream.truncated)
    return std::nullopt;
  const auto lineEnd = crlf(stream.bytes, 0);
  if (!lineEnd)
    return std::nullopt;
  if (*lineEnd + 2U > kMaxHttpLineBytes)
    return std::nullopt;
  const auto line = ascii(stream.bytes, 0, *lineEnd);
  const bool isResponse = line.starts_with("HTTP/1.0 ") || line.starts_with("HTTP/1.1 ");
  const auto firstSpace = line.find(' ');
  const auto secondSpace = firstSpace == std::string::npos ? std::string::npos : line.find(' ', firstSpace + 1U);
  const bool isRequest = !isResponse && firstSpace != std::string::npos && secondSpace != std::string::npos &&
                         secondSpace > firstSpace + 1U && line.size() > secondSpace + 1U &&
                         (line.substr(secondSpace + 1U) == "HTTP/1.0" || line.substr(secondSpace + 1U) == "HTTP/1.1");
  if (!isRequest && !isResponse)
    return std::nullopt;

  const auto headerStart = *lineEnd + 2U;
  std::size_t cursor = headerStart;
  std::size_t count = 0;
  std::vector<HttpHeader> headers;
  while (true) {
    const auto next = crlf(stream.bytes, cursor);
    if (!next)
      return std::nullopt;
    if (*next - cursor + 2U > kMaxHttpLineBytes)
      return std::nullopt;
    if (*next + 2U > kMaxHttpHeaderBytes)
      return std::nullopt;
    if (*next == cursor) {
      const auto headerEnd = cursor + 2U;
      if (headerEnd > kMaxHttpHeaderBytes)
        return std::nullopt;
      Message result;
      result.flowId = stream.flowId;
      result.fromClient = stream.fromClient;
      result.request = isRequest;
      result.end = headerEnd;
      result.packetNumbers = evidence_packets(stream, headerEnd);
      result.firstPacket = result.packetNumbers.empty() ? 0U : result.packetNumbers.front();
      result.completionPacket = headerEnd <= stream.bytePacketNumbers.size()
                                    ? stream.bytePacketNumbers[headerEnd - 1U]
                                    : (result.packetNumbers.empty() ? 0U : result.packetNumbers.back());
      if (isRequest) {
        const auto method = line.substr(0, firstSpace);
        const auto targetRaw = line.substr(firstSpace + 1U, secondSpace - firstSpace - 1U);
        if (!std::all_of(method.begin(), method.end(), [](const auto c) { return token_char(static_cast<unsigned char>(c)); }) ||
            targetRaw.empty() || targetRaw.find('#') != std::string::npos ||
            targetRaw.find_first_of(" \t\r\n") != std::string::npos ||
            !std::all_of(targetRaw.begin(), targetRaw.end(), [](const auto c) {
              const auto byte = static_cast<unsigned char>(c);
              return byte >= 0x21U && byte <= 0x7eU;
            }))
          return std::nullopt;
        const auto target = redact_target(targetRaw);
        const auto version = line.substr(secondSpace + 1U);
        result.requestValue = HttpRequest{method + " " + target + " " + version, method, target, version,
                                          std::move(headers), result.packetNumbers};
      } else {
        const auto version = line.substr(0, 8U);
        if (line.size() < 12U)
          return std::nullopt;
        const auto status = line.substr(9U, 3U);
        if ((version != "HTTP/1.0" && version != "HTTP/1.1") ||
            !std::all_of(status.begin(), status.end(), [](const auto c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; }))
          return std::nullopt;
        const auto statusCode = static_cast<std::uint16_t>(std::stoul(status));
        if (statusCode < 100U || statusCode > 599U || line[8] != ' ')
          return std::nullopt;
        auto reason = line.size() > 12U ? line.substr(12U) : std::string{};
        if (!visible_header_value(reason))
          return std::nullopt;
        result.responseValue = HttpResponse{line, version, statusCode, std::move(reason), std::move(headers),
                                            result.packetNumbers};
      }
      return result;
    }
    if (++count > kMaxHttpHeaderCount)
      return std::nullopt;
    if (*next + 2U > kMaxHttpHeaderBytes)
      return std::nullopt;
    const auto raw = ascii(stream.bytes, cursor, *next);
    const auto colon = raw.find(':');
    if (colon == std::string::npos || colon == 0U || colon > 128U ||
        !std::all_of(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(colon),
                     [](const auto c) { return token_char(static_cast<unsigned char>(c)); }))
      return std::nullopt;
    headers.push_back(sanitized_header(raw.substr(0, colon), trim(raw.substr(colon + 1U))));
    cursor = *next + 2U;
    if (cursor > kMaxHttpHeaderBytes)
      return std::nullopt;
  }
}

void http_layer(ParsedPacket& packet, const Message& message) {
  ProtocolLayer layer{"HTTP", message.request ? "HTTP request" : "HTTP response", {}, std::nullopt,
                      std::string{"http"}};
  if (message.requestValue) {
    layer.fields.push_back({"method", message.requestValue->method, std::nullopt, std::nullopt});
    layer.fields.push_back({"target", message.requestValue->target, std::nullopt, std::nullopt});
    layer.fields.push_back({"version", message.requestValue->version, std::nullopt, std::nullopt});
  } else if (message.responseValue) {
    layer.fields.push_back({"version", message.responseValue->version, std::nullopt, std::nullopt});
    layer.fields.push_back({"statusCode", std::to_string(message.responseValue->statusCode), std::nullopt, std::nullopt});
  }
  packet.packet.layers.push_back(std::move(layer));
}

} // namespace

void build_http(CaptureDocument& capture, std::vector<ParsedPacket>& packets,
                const std::vector<ApplicationStream>& streams) {
  struct Pending {
    HttpExchange exchange;
  };
  std::vector<Message> messages;
  std::map<std::size_t, ParsedPacket*> packetMap;
  for (auto& packet : packets)
    packetMap.emplace(packet.packet.number, &packet);
  for (const auto& stream : streams) {
    if (!stream.fromClient && stream.bytes.empty())
      continue;
    auto message = parse_message(stream, capture);
    if (!message) {
      if (!stream.ambiguous && !stream.truncated && recognized_prefix(stream.bytes))
        add_diagnostic(capture, {"warning", "HTTP_MALFORMED", "Recognized HTTP prefix failed strict HTTP/1.x parsing",
                                 stream.flowId, std::nullopt,
                                 stream.packetNumbers.empty() ? std::nullopt
                                                               : std::optional<std::size_t>{stream.packetNumbers.front()}, 1U});
      continue;
    }
    for (const auto number : message->packetNumbers) {
      const auto found = packetMap.find(number);
      if (found != packetMap.end())
      if (number == message->completionPacket)
        http_layer(*found->second, *message);
    }
    messages.push_back(std::move(*message));
  }
  std::stable_sort(messages.begin(), messages.end(), [](const auto& left, const auto& right) {
    return left.firstPacket < right.firstPacket;
  });

  std::map<std::string, HttpExchange> pending;
  std::map<std::string, bool> ambiguousFlows;
  for (const auto& message : messages) {
    if (message.requestValue && message.fromClient) {
      const auto existing = pending.find(message.flowId);
      if (existing != pending.end()) {
        capture.httpExchanges.push_back(std::move(existing->second));
        pending.erase(existing);
        ambiguousFlows[message.flowId] = true;
      }
      if (ambiguousFlows[message.flowId]) {
        capture.httpExchanges.push_back({"http-exchange-0", message.flowId, message.requestValue,
                                         std::nullopt, std::nullopt, false});
      } else {
        pending.emplace(message.flowId,
                        HttpExchange{"http-exchange-0", message.flowId, message.requestValue, std::nullopt,
                                     std::nullopt, false});
      }
      continue;
    }
    if (!message.responseValue || message.fromClient)
      continue;
    const auto pendingIt = pending.find(message.flowId);
    if (pendingIt != pending.end() && !ambiguousFlows[message.flowId]) {
      auto& request = pendingIt->second;
      request.response = message.responseValue;
      request.matched = true;
      const auto requestPacket = request.request->packetNumbers.empty() ? 0U : request.request->packetNumbers.back();
      const auto responsePacket = message.packetNumbers.empty() ? 0U : message.packetNumbers.front();
      const auto requestIt = std::find_if(packets.begin(), packets.end(), [&](const auto& packet) {
        return packet.packet.number == requestPacket;
      });
      const auto responseIt = std::find_if(packets.begin(), packets.end(), [&](const auto& packet) {
        return packet.packet.number == responsePacket;
      });
      if (requestIt != packets.end() && responseIt != packets.end()) {
        const auto start = std::stoull(requestIt->packet.timestampNs);
        const auto end = std::stoull(responseIt->packet.timestampNs);
        request.latencyNs = std::to_string(end >= start ? end - start : 0U);
      }
      capture.httpExchanges.push_back(std::move(request));
      pending.erase(pendingIt);
    } else {
      capture.httpExchanges.push_back({"http-exchange-0", message.flowId, std::nullopt,
                                       message.responseValue, std::nullopt, false});
    }
  }
  for (auto& [flowId, request] : pending)
    capture.httpExchanges.push_back(std::move(request));
  for (std::size_t index = 0; index < capture.httpExchanges.size(); ++index)
    capture.httpExchanges[index].id = "http-exchange-" + std::to_string(index + 1U);
}

} // namespace wirelens::internal
