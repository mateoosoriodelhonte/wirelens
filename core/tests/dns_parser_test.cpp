#include "fixture_builder.hpp"
#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

void put32leAt(std::vector<std::byte>& bytes, const std::size_t offset, const std::uint32_t value) {
  wirelens_test::put32le(bytes, offset, value);
}

std::vector<std::byte> dnsMessage(const bool response, const std::uint16_t id,
                                  const std::uint8_t responseCode = 0) {
  const std::vector<std::byte> name{std::byte{7},   std::byte{'e'}, std::byte{'x'}, std::byte{'a'},
                                    std::byte{'m'}, std::byte{'p'}, std::byte{'l'}, std::byte{'e'},
                                    std::byte{3},   std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
                                    std::byte{0}};
  const auto size = response ? 12U + name.size() + 4U + 2U + 10U + 4U : 12U + name.size() + 4U;
  std::vector<std::byte> result(size, std::byte{0});
  wirelens_test::put16be(result, 0, id);
  wirelens_test::put16be(result, 2,
                         static_cast<std::uint16_t>((response ? 0x8000U : 0U) | responseCode));
  wirelens_test::put16be(result, 4, 1);
  wirelens_test::put16be(result, 6, response ? 1 : 0);
  std::copy(name.begin(), name.end(), result.begin() + 12);
  wirelens_test::put16be(result, 12 + name.size(), 1);
  wirelens_test::put16be(result, 12 + name.size() + 2, 1);
  if (response) {
    const auto answer = 12U + name.size() + 4U;
    result[answer] = std::byte{0xc0};
    result[answer + 1] = std::byte{0x0c};
    wirelens_test::put16be(result, answer + 2, 1);
    wirelens_test::put16be(result, answer + 4, 1);
    put32leAt(result, answer + 6, 0x3cU);
    // TTL is network order. Rewrite the four bytes explicitly.
    wirelens_test::put32be(result, answer + 6, 60);
    wirelens_test::put16be(result, answer + 10, 4);
    result[answer + 12] = std::byte{192};
    result[answer + 13] = std::byte{0};
    result[answer + 14] = std::byte{2};
    result[answer + 15] = std::byte{53};
  }
  return result;
}

std::vector<std::byte> buildDnsCapture(const std::vector<std::pair<bool, std::uint32_t>>& packets) {
  std::vector<std::vector<std::byte>> messages;
  for (std::size_t index = 0; index < packets.size(); ++index)
    messages.push_back(
        dnsMessage(packets[index].first, static_cast<std::uint16_t>(0x4000 + index / 2U)));
  const auto frameSize = [&](const std::vector<std::byte>& message) {
    return 14U + 20U + 8U + message.size();
  };
  std::size_t total = 24;
  for (const auto& message : messages)
    total += 16U + frameSize(message);
  std::vector<std::byte> bytes(total, std::byte{0});
  bytes[0] = std::byte{0xd4};
  bytes[1] = std::byte{0xc3};
  bytes[2] = std::byte{0xb2};
  bytes[3] = std::byte{0xa1};
  wirelens_test::put16(bytes, 4, 2);
  wirelens_test::put16(bytes, 6, 4);
  wirelens_test::put32le(bytes, 16, 65535);
  wirelens_test::put32le(bytes, 20, 1);
  std::size_t record = 24;
  for (std::size_t index = 0; index < messages.size(); ++index) {
    const auto& message = messages[index];
    const auto frameLength = frameSize(message);
    wirelens_test::put32le(bytes, record, 1);
    wirelens_test::put32le(bytes, record + 4, packets[index].second);
    wirelens_test::put32le(bytes, record + 8, static_cast<std::uint32_t>(frameLength));
    wirelens_test::put32le(bytes, record + 12, static_cast<std::uint32_t>(frameLength));
    const auto frame = record + 16;
    const std::array<std::uint8_t, 6> clientMac{2, 0, 0, 0, 0, 1};
    const std::array<std::uint8_t, 6> serverMac{2, 0, 0, 0, 0, 2};
    const auto& sourceMac = packets[index].first ? serverMac : clientMac;
    const auto& destinationMac = packets[index].first ? clientMac : serverMac;
    for (std::size_t byte = 0; byte < 6; ++byte) {
      bytes[frame + byte] = static_cast<std::byte>(destinationMac[byte]);
      bytes[frame + 6 + byte] = static_cast<std::byte>(sourceMac[byte]);
    }
    bytes[frame + 12] = std::byte{0x08};
    bytes[frame + 13] = std::byte{0x00};
    const auto ip = frame + 14;
    bytes[ip] = std::byte{0x45};
    wirelens_test::put16be(bytes, ip + 2, static_cast<std::uint16_t>(20U + 8U + message.size()));
    bytes[ip + 8] = std::byte{64};
    bytes[ip + 9] = std::byte{17};
    const std::array<std::uint8_t, 4> clientIp{192, 0, 2, 10};
    const std::array<std::uint8_t, 4> serverIp{198, 51, 100, 53};
    const auto& sourceIp = packets[index].first ? serverIp : clientIp;
    const auto& destinationIp = packets[index].first ? clientIp : serverIp;
    for (std::size_t byte = 0; byte < 4; ++byte) {
      bytes[ip + 12 + byte] = static_cast<std::byte>(sourceIp[byte]);
      bytes[ip + 16 + byte] = static_cast<std::byte>(destinationIp[byte]);
    }
    const auto udp = ip + 20;
    wirelens_test::put16be(bytes, udp, packets[index].first ? 53 : 53000);
    wirelens_test::put16be(bytes, udp + 2, packets[index].first ? 53000 : 53);
    wirelens_test::put16be(bytes, udp + 4, static_cast<std::uint16_t>(8U + message.size()));
    std::copy(message.begin(), message.end(), bytes.begin() + static_cast<std::ptrdiff_t>(udp + 8));
    record += 16U + frameLength;
  }
  return bytes;
}

} // namespace

TEST_CASE("DNS over UDP parses a query, response, A answer, and exact latency") {
  const auto result = wirelens::parse_capture(buildDnsCapture({{false, 0}, {true, 500'000}}));
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.dnsExchanges.size() == 1);
  const auto& exchange = capture.dnsExchanges.front();
  REQUIRE(exchange.matched);
  REQUIRE(exchange.question.name == "example.com");
  REQUIRE(exchange.responsePacketNumber == 2);
  REQUIRE(exchange.latencyNs == "500000000");
  REQUIRE(exchange.answers.size() == 1);
  REQUIRE(exchange.answers.front().value == "192.0.2.53");
  REQUIRE(capture.packets.at(0).layers.back().protocol == "DNS");
  REQUIRE(wirelens::serialize_capture(capture).find("raw") == std::string::npos);
}

TEST_CASE("non-DNS UDP and malformed port 53 payloads do not create DNS exchanges") {
  auto bytes = buildDnsCapture({{false, 1}});
  const auto result = wirelens::parse_capture(bytes);
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.dnsExchanges.size() == 1);
  REQUIRE(capture.packets.at(0).layers.back().protocol == "DNS");

  SECTION("a non-standard destination port is not a DNS claim") {
    bytes[76] = std::byte{0x67};
    bytes[77] = std::byte{0x69};
    const auto nonDns = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(nonDns));
    const auto& document = std::get<wirelens::CaptureDocument>(nonDns);
    REQUIRE(document.dnsExchanges.empty());
    REQUIRE(document.diagnostics.empty());
  }

  SECTION("a truncated port 53 message is diagnostic-only") {
    wirelens_test::put16be(bytes, 78, 12);
    const auto malformed = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(malformed));
    const auto& document = std::get<wirelens::CaptureDocument>(malformed);
    REQUIRE(document.dnsExchanges.empty());
    REQUIRE(document.diagnostics.size() == 1);
    REQUIRE(document.diagnostics.front().code == "DNS_TRUNCATED_HEADER");
  }

  SECTION("a compression self-cycle is bounded") {
    bytes[94] = std::byte{0xc0};
    bytes[95] = std::byte{0x0c};
    const auto malformed = wirelens::parse_capture(bytes);
    REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(malformed));
    const auto& document = std::get<wirelens::CaptureDocument>(malformed);
    REQUIRE(document.dnsExchanges.empty());
    REQUIRE(document.diagnostics.front().code == "DNS_POINTER_CYCLE");
  }
}

TEST_CASE("slow DNS uses the exact five-match and 500 millisecond boundaries") {
  const auto result = wirelens::parse_capture(buildDnsCapture({{false, 0},
                                                               {true, 10'000},
                                                               {false, 100'000},
                                                               {true, 120'000},
                                                               {false, 200'000},
                                                               {true, 230'000},
                                                               {false, 300'000},
                                                               {true, 340'000},
                                                               {false, 400'000},
                                                               {true, 900'000}}));
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.dnsExchanges.size() == 5);
  REQUIRE(capture.observations.size() == 1);
  REQUIRE(capture.observations.front().type == "slow-dns");
  REQUIRE(capture.observations.front().packetNumbers == std::vector<std::size_t>{9, 10});
}
