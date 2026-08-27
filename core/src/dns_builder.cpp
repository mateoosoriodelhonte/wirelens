#include "protocol_internal.hpp"

#include "wirelens/parser.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace wirelens::internal {
namespace {

bool equal_name(const std::string& left, const std::string& right) {
  if (left.size() != right.size())
    return false;
  for (std::size_t index = 0; index < left.size(); ++index) {
    const auto a =
        left[index] >= 'A' && left[index] <= 'Z' ? left[index] + ('a' - 'A') : left[index];
    const auto b =
        right[index] >= 'A' && right[index] <= 'Z' ? right[index] + ('a' - 'A') : right[index];
    if (a != b)
      return false;
  }
  return true;
}

bool same_query(const DnsFacts& left, const DnsFacts& right) {
  return left.transactionId == right.transactionId && left.opcode == right.opcode &&
         left.question.type == right.question.type &&
         left.question.classCode == right.question.classCode &&
         equal_name(left.question.name, right.question.name);
}

bool reverse_tuple(const DnsFacts& query, const DnsFacts& response) {
  return query.source == response.destination && query.destination == response.source &&
         query.sourcePort == response.destinationPort &&
         query.destinationPort == response.sourcePort;
}

std::optional<std::uint64_t> timestamp_value(const std::string& value) {
  std::uint64_t result = 0;
  for (const auto character : value) {
    if (character < '0' || character > '9')
      return std::nullopt;
    const auto digit = static_cast<std::uint64_t>(character - '0');
    if (result > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U)
      return std::nullopt;
    result = result * 10U + digit;
  }
  return result;
}

std::string response_code(const std::uint8_t code) {
  switch (code) {
  case 0:
    return "NOERROR";
  case 1:
    return "FORMERR";
  case 2:
    return "SERVFAIL";
  case 3:
    return "NXDOMAIN";
  case 4:
    return "NOTIMP";
  case 5:
    return "REFUSED";
  default:
    return "RCODE_" + std::to_string(code);
  }
}

void add_observation(CaptureDocument& capture, std::string type, std::string message,
                     std::vector<std::size_t> packetNumbers) {
  if (capture.observations.size() >= kMaxObservations) {
    const auto existing =
        std::find_if(capture.diagnostics.begin(), capture.diagnostics.end(),
                     [](const auto& value) { return value.code == "OBSERVATION_LIMIT_REACHED"; });
    if (existing != capture.diagnostics.end()) {
      existing->count = existing->count.value_or(0U) + 1U;
    } else if (capture.diagnostics.size() < kMaxDiagnostics) {
      capture.diagnostics.push_back(
          {"warning", "OBSERVATION_LIMIT_REACHED",
           "Additional observations were omitted after the 1,024 observation limit", "observations",
           std::nullopt, std::nullopt, 1U});
    }
    return;
  }
  capture.observations.push_back({"observation-" + std::to_string(capture.observations.size() + 1),
                                  std::move(type), std::move(message), std::move(packetNumbers),
                                  "Only packets in this capture were considered."});
}

bool at_least_three_times(const std::uint64_t candidate, const std::uint64_t medianLow,
                          const std::uint64_t medianHigh) {
  // Compare 2*candidate >= 3*(low+high), which is the exact comparison to
  // three times the mathematical median for an even-sized sample.
  const auto left = static_cast<unsigned __int128>(candidate) * 2U;
  const auto right =
      (static_cast<unsigned __int128>(medianLow) + static_cast<unsigned __int128>(medianHigh)) * 3U;
  return left >= right;
}

} // namespace

void build_dns(CaptureDocument& capture, const std::vector<ParsedPacket>& packets) {
  struct ExchangeState {
    DnsExchange exchange;
    const ParsedPacket* query = nullptr;
    const ParsedPacket* response = nullptr;
  };
  std::vector<ExchangeState> states;
  for (const auto& packet : packets) {
    const auto& dns = packet.dns;
    if (!dns.valid || dns.opcode != 0 || dns.questionCount != 1U)
      continue;
    if (!dns.response) {
      DnsExchange exchange;
      exchange.id = "dns-exchange-" + std::to_string(states.size() + 1);
      exchange.question = dns.question;
      exchange.queryPacketNumber = packet.packet.number;
      states.push_back({std::move(exchange), &packet, nullptr});
      continue;
    }
    std::vector<std::size_t> candidates;
    for (std::size_t index = 0; index < states.size(); ++index) {
      const auto& state = states[index];
      if (!state.response && state.query && same_query(state.query->dns, dns) &&
          reverse_tuple(state.query->dns, dns))
        candidates.push_back(index);
    }
    if (candidates.size() != 1U) {
      DnsExchange exchange;
      exchange.id = "dns-exchange-" + std::to_string(states.size() + 1);
      exchange.question = dns.question;
      exchange.responsePacketNumber = packet.packet.number;
      exchange.responseCode = response_code(dns.responseCode);
      exchange.answers = dns.answers;
      states.push_back({std::move(exchange), nullptr, &packet});
      continue;
    }
    auto& state = states[candidates.front()];
    const auto queryTime = timestamp_value(state.query->packet.timestampNs);
    const auto responseTime = timestamp_value(packet.packet.timestampNs);
    if (!queryTime || !responseTime || *responseTime < *queryTime) {
      // A response before its query is not a safe latency match.
      DnsExchange exchange;
      exchange.id = "dns-exchange-" + std::to_string(states.size() + 1);
      exchange.question = dns.question;
      exchange.responsePacketNumber = packet.packet.number;
      exchange.responseCode = response_code(dns.responseCode);
      exchange.answers = dns.answers;
      states.push_back({std::move(exchange), nullptr, &packet});
      continue;
    }
    state.exchange.responsePacketNumber = packet.packet.number;
    state.exchange.responseCode = response_code(dns.responseCode);
    state.exchange.answers = dns.answers;
    state.exchange.latencyNs = std::to_string(*responseTime - *queryTime);
    state.exchange.matched = true;
    state.response = &packet;
  }

  for (auto& state : states) {
    if (state.exchange.responsePacketNumber && state.exchange.responseCode &&
        (*state.exchange.responseCode == "NXDOMAIN" ||
         *state.exchange.responseCode == "SERVFAIL")) {
      std::vector<std::size_t> evidence;
      if (state.exchange.queryPacketNumber)
        evidence.push_back(*state.exchange.queryPacketNumber);
      evidence.push_back(*state.exchange.responsePacketNumber);
      add_observation(capture, "dns-error", "DNS response returned " + *state.exchange.responseCode,
                      std::move(evidence));
    }
    capture.dnsExchanges.push_back(std::move(state.exchange));
  }

  std::vector<std::uint64_t> latencies;
  for (std::size_t exchangeIndex = 0; exchangeIndex < capture.dnsExchanges.size();
       ++exchangeIndex) {
    const auto& exchange = capture.dnsExchanges[exchangeIndex];
    if (exchange.matched && exchange.latencyNs) {
      if (const auto value = timestamp_value(*exchange.latencyNs))
        latencies.push_back(*value);
    }
  }
  if (latencies.size() < 5U)
    return;
  for (const auto& exchange : capture.dnsExchanges) {
    if (!exchange.matched || !exchange.latencyNs || !exchange.queryPacketNumber ||
        !exchange.responsePacketNumber)
      continue;
    const auto candidate = timestamp_value(*exchange.latencyNs);
    if (!candidate || *candidate < 500'000'000ULL)
      continue;
    std::vector<std::uint64_t> others;
    others.reserve(latencies.size() - 1U);
    std::size_t matchedIndex = 0;
    for (std::size_t index = 0; index < capture.dnsExchanges.size(); ++index) {
      if (&capture.dnsExchanges[index] == &exchange)
        matchedIndex = index;
    }
    for (std::size_t index = 0; index < capture.dnsExchanges.size(); ++index) {
      const auto& other = capture.dnsExchanges[index];
      if (!other.matched || !other.latencyNs)
        continue;
      if (index == matchedIndex) {
        continue;
      }
      if (const auto value = timestamp_value(*other.latencyNs))
        others.push_back(*value);
    }
    if (others.size() != latencies.size() - 1U)
      continue;
    std::sort(others.begin(), others.end());
    const auto middleHigh = others[others.size() / 2U];
    const auto middleLow = others[(others.size() - 1U) / 2U];
    if (at_least_three_times(*candidate, middleLow, middleHigh))
      add_observation(capture, "slow-dns", "DNS response latency met the slow-response rule",
                      {*exchange.queryPacketNumber, *exchange.responsePacketNumber});
  }
}

} // namespace wirelens::internal
