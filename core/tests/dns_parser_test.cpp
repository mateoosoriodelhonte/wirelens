#include "fixture_builder.hpp"
#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"

#include "../src/protocol_internal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

std::vector<std::byte> readFixture(const std::string& name) {
  auto project = std::filesystem::current_path();
  for (std::size_t level = 0;
       level < 8U && !std::filesystem::exists(project / "fixtures/generated" / name); ++level)
    project = project.parent_path();
  std::ifstream input(project / "fixtures/generated" / name, std::ios::binary);
  const std::vector<char> characters{std::istreambuf_iterator<char>(input),
                                     std::istreambuf_iterator<char>()};
  std::vector<std::byte> bytes;
  bytes.reserve(characters.size());
  for (const auto character : characters)
    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  return bytes;
}

struct DecodedDns {
  std::optional<wirelens::ProtocolLayer> layer;
  wirelens::internal::DnsFacts facts;
};

DecodedDns decodeDns(const std::vector<std::byte>& message) {
  const auto response =
      message.size() >= 4U && (std::to_integer<std::uint8_t>(message[2]) & 0x80U) != 0;
  wirelens::internal::UdpFacts udp{true,
                                   response ? "198.51.100.53" : "192.0.2.10",
                                   response ? "192.0.2.10" : "198.51.100.53",
                                   static_cast<std::uint16_t>(response ? 53 : 53000),
                                   static_cast<std::uint16_t>(response ? 53000 : 53),
                                   message.size()};
  DecodedDns result;
  result.layer = wirelens::internal::decode_dns(message, 0, 0, udp, result.facts);
  return result;
}

std::vector<std::byte> questionListMessage(const std::vector<std::vector<std::byte>>& names,
                                           const bool response) {
  std::size_t size = 12U;
  for (const auto& name : names)
    size += name.size() + 4U;
  std::vector<std::byte> message(size, std::byte{0});
  wirelens_test::put16be(message, 0, 0x4567U);
  wirelens_test::put16be(message, 2, response ? 0x8000U : 0U);
  wirelens_test::put16be(message, 4, static_cast<std::uint16_t>(names.size()));
  std::size_t cursor = 12U;
  for (const auto& name : names) {
    std::copy(name.begin(), name.end(), message.begin() + static_cast<std::ptrdiff_t>(cursor));
    cursor += name.size();
    wirelens_test::put16be(message, cursor, 1);
    wirelens_test::put16be(message, cursor + 2U, 1);
    cursor += 4U;
  }
  return message;
}

std::vector<std::byte> responseWithRecord(const std::uint16_t answerCount,
                                          const std::uint16_t authorityCount,
                                          const std::uint16_t type,
                                          const std::vector<std::byte>& data) {
  std::vector<std::byte> message(29U + data.size(), std::byte{0});
  wirelens_test::put16be(message, 0, 0x4567U);
  wirelens_test::put16be(message, 2, 0x8000U);
  wirelens_test::put16be(message, 4, 1);
  wirelens_test::put16be(message, 6, answerCount);
  wirelens_test::put16be(message, 8, authorityCount);
  wirelens_test::put16be(message, 13, 1);
  wirelens_test::put16be(message, 15, 1);
  message[17] = std::byte{0xc0};
  message[18] = std::byte{0x0c};
  wirelens_test::put16be(message, 19, type);
  wirelens_test::put16be(message, 21, 1);
  wirelens_test::put16be(message, 27, static_cast<std::uint16_t>(data.size()));
  std::copy(data.begin(), data.end(), message.begin() + 29);
  return message;
}

std::vector<std::byte> questionsMessage(const std::size_t count,
                                        const std::vector<std::byte>& name = {std::byte{0}}) {
  std::vector<std::byte> message(12U + count * (name.size() + 4U), std::byte{0});
  wirelens_test::put16be(message, 4, static_cast<std::uint16_t>(count));
  std::size_t cursor = 12U;
  for (std::size_t question = 0; question < count; ++question) {
    std::copy(name.begin(), name.end(), message.begin() + static_cast<std::ptrdiff_t>(cursor));
    cursor += name.size();
    wirelens_test::put16be(message, cursor, 1);
    wirelens_test::put16be(message, cursor + 2U, 1);
    cursor += 4U;
  }
  return message;
}

std::vector<std::byte> pointerChainMessage(const std::size_t records) {
  std::vector<std::byte> message(17U + records * 12U, std::byte{0});
  wirelens_test::put16be(message, 2, 0x8000U);
  wirelens_test::put16be(message, 4, 1);
  wirelens_test::put16be(message, 6, static_cast<std::uint16_t>(records));
  wirelens_test::put16be(message, 13, 1);
  wirelens_test::put16be(message, 15, 1);
  for (std::size_t record = 0; record < records; ++record) {
    const auto offset = 17U + record * 12U;
    const auto target = record == 0 ? 12U : offset - 12U;
    message[offset] = static_cast<std::byte>(0xc0U | ((target >> 8U) & 0x3fU));
    message[offset + 1U] = static_cast<std::byte>(target & 0xffU);
    wirelens_test::put16be(message, offset + 2U, 16);
    wirelens_test::put16be(message, offset + 4U, 1);
  }
  return message;
}

std::vector<std::byte> recordsMessage(const std::size_t records) {
  std::vector<std::byte> message(17U + records * 12U, std::byte{0});
  wirelens_test::put16be(message, 2, 0x8000U);
  wirelens_test::put16be(message, 4, 1);
  wirelens_test::put16be(message, 6, static_cast<std::uint16_t>(records));
  wirelens_test::put16be(message, 13, 1);
  wirelens_test::put16be(message, 15, 1);
  for (std::size_t record = 0; record < records; ++record) {
    const auto offset = 17U + record * 12U;
    message[offset] = std::byte{0xc0};
    message[offset + 1U] = std::byte{0x0c};
    wirelens_test::put16be(message, offset + 2U, 16);
    wirelens_test::put16be(message, offset + 4U, 1);
  }
  return message;
}

wirelens::internal::ParsedPacket dnsPacket(const std::size_t number, const bool response,
                                           const std::uint16_t id,
                                           const std::uint8_t responseCode = 0) {
  wirelens::internal::ParsedPacket packet;
  packet.packet.number = number;
  packet.packet.timestampNs = std::to_string(number * 1'000'000ULL);
  packet.dns.valid = true;
  packet.dns.response = response;
  packet.dns.transactionId = id;
  packet.dns.opcode = 0;
  packet.dns.responseCode = responseCode;
  packet.dns.questionCount = 1;
  packet.dns.question = {"example.com", 1, 1};
  packet.dns.source = response ? "198.51.100.53" : "192.0.2.10";
  packet.dns.destination = response ? "192.0.2.10" : "198.51.100.53";
  packet.dns.sourcePort = response ? 53 : 53000;
  packet.dns.destinationPort = response ? 53000 : 53;
  return packet;
}

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

TEST_CASE("DNS integration preserves protocol order and canonical answer text") {
  const auto result = wirelens::parse_capture(readFixture("dns-exchanges.pcap"));
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  REQUIRE(capture.packets.at(0).layers.at(0).protocol == "ETHERNET");
  REQUIRE(capture.packets.at(0).layers.at(1).protocol == "IPV4");
  REQUIRE(capture.packets.at(0).layers.at(2).protocol == "UDP");
  REQUIRE(capture.packets.at(0).layers.at(3).protocol == "DNS");
  REQUIRE(capture.dnsExchanges.at(1).answers.at(0).value == "2001:db8::35");
  const auto& fields = capture.packets.at(0).layers.at(3).fields;
  const auto questionName = std::find_if(
      fields.begin(), fields.end(), [](const auto& field) { return field.name == "questionName"; });
  const auto questionType = std::find_if(
      fields.begin(), fields.end(), [](const auto& field) { return field.name == "questionType"; });
  REQUIRE(questionName != fields.end());
  REQUIRE(questionName->byteRange->packetOffset == 54U);
  REQUIRE(questionName->byteRange->length == 13U);
  REQUIRE(questionType != fields.end());
  REQUIRE(questionType->byteRange->packetOffset == 67U);
}

TEST_CASE("DNS names enforce root, label, expanded-size, and pointer boundaries") {
  SECTION("the root name has a schema-safe representation") {
    const auto decoded = decodeDns(questionsMessage(1));
    REQUIRE(decoded.layer);
    REQUIRE(decoded.facts.question.name == ".");
  }

  SECTION("a 63-byte label is accepted and a reserved 64-byte form is rejected") {
    std::vector<std::byte> acceptedName(65U, std::byte{'a'});
    acceptedName.front() = std::byte{63};
    acceptedName.back() = std::byte{0};
    REQUIRE(decodeDns(questionsMessage(1, acceptedName)).layer);
    acceptedName.front() = std::byte{64};
    const auto rejected = decodeDns(questionsMessage(1, acceptedName));
    REQUIRE_FALSE(rejected.layer);
    REQUIRE(rejected.facts.diagnostic);
    REQUIRE(rejected.facts.diagnostic->code == "DNS_INVALID_NAME");
  }

  SECTION("wire names accept 255 bytes and reject 256 bytes") {
    auto makeName = [](const std::array<std::size_t, 4>& lengths) {
      std::vector<std::byte> name;
      for (const auto length : lengths) {
        name.push_back(static_cast<std::byte>(length));
        name.insert(name.end(), length, std::byte{'a'});
      }
      name.push_back(std::byte{0});
      return name;
    };
    REQUIRE(decodeDns(questionsMessage(1, makeName({63, 63, 63, 61}))).layer);
    const auto rejected = decodeDns(questionsMessage(1, makeName({63, 63, 63, 62})));
    REQUIRE_FALSE(rejected.layer);
    REQUIRE(rejected.facts.diagnostic->code == "DNS_NAME_LIMIT_EXCEEDED");
  }

  SECTION("127 labels are accepted and 128 are rejected") {
    auto labels = [](const std::size_t count) {
      std::vector<std::byte> name;
      for (std::size_t label = 0; label < count; ++label) {
        name.push_back(std::byte{1});
        name.push_back(std::byte{'a'});
      }
      name.push_back(std::byte{0});
      return name;
    };
    REQUIRE(decodeDns(questionsMessage(1, labels(127))).layer);
    const auto rejected = decodeDns(questionsMessage(1, labels(128)));
    REQUIRE_FALSE(rejected.layer);
    REQUIRE(rejected.facts.diagnostic->code == "DNS_LABEL_LIMIT_EXCEEDED");
  }

  SECTION("binary and separator bytes have an unambiguous safe representation") {
    const std::vector<std::byte> name{std::byte{3}, std::byte{'a'}, std::byte{0}, std::byte{'.'},
                                      std::byte{0}};
    const auto decoded = decodeDns(questionsMessage(1, name));
    REQUIRE(decoded.layer);
    REQUIRE(decoded.facts.question.name == "a\\000\\046");
  }

  SECTION("header and forward pointers are rejected") {
    auto headerPointer = questionsMessage(1);
    headerPointer[12] = std::byte{0xc0};
    headerPointer.insert(headerPointer.begin() + 13, std::byte{0});
    REQUIRE_FALSE(decodeDns(headerPointer).layer);

    std::vector<std::byte> forward(21U, std::byte{0});
    wirelens_test::put16be(forward, 4, 1);
    forward[12] = std::byte{0xc0};
    forward[13] = std::byte{20};
    wirelens_test::put16be(forward, 14, 1);
    wirelens_test::put16be(forward, 16, 1);
    REQUIRE_FALSE(decodeDns(forward).layer);
  }

  SECTION("a pointer into an earlier label is rejected") {
    const std::vector<std::byte> earlier{std::byte{2}, std::byte{1}, std::byte{0}, std::byte{0}};
    const std::vector<std::byte> interiorPointer{std::byte{0xc0}, std::byte{13}};
    const auto rejected = decodeDns(questionListMessage({earlier, interiorPointer}, false));
    REQUIRE_FALSE(rejected.layer);
    REQUIRE(rejected.facts.diagnostic);
    REQUIRE(rejected.facts.diagnostic->code == "DNS_INVALID_NAME");
  }

  SECTION("sixteen compression hops are accepted and the seventeenth is rejected") {
    REQUIRE(decodeDns(pointerChainMessage(16)).layer);
    const auto rejected = decodeDns(pointerChainMessage(17));
    REQUIRE_FALSE(rejected.layer);
    REQUIRE(rejected.facts.diagnostic->code == "DNS_POINTER_HOP_LIMIT");
  }
}

TEST_CASE("DNS rejects bytes after all declared sections") {
  auto message = questionsMessage(1);
  message.push_back(std::byte{'W'});
  message.push_back(std::byte{'L'});
  const auto rejected = decodeDns(message);
  REQUIRE_FALSE(rejected.layer);
  REQUIRE(rejected.facts.diagnostic);
  REQUIRE(rejected.facts.diagnostic->code == "DNS_TRAILING_DATA");
}

TEST_CASE("DNS section counts stop at their exact named limits") {
  REQUIRE(decodeDns(questionsMessage(wirelens::kMaxDnsQuestions)).layer);
  const auto tooManyQuestions = decodeDns(questionsMessage(wirelens::kMaxDnsQuestions + 1U));
  REQUIRE_FALSE(tooManyQuestions.layer);
  REQUIRE(tooManyQuestions.facts.diagnostic->code == "DNS_QUESTION_LIMIT_EXCEEDED");
  REQUIRE(decodeDns(recordsMessage(wirelens::kMaxDnsRecords)).layer);
  const auto tooManyRecords = decodeDns(recordsMessage(wirelens::kMaxDnsRecords + 1U));
  REQUIRE_FALSE(tooManyRecords.layer);
  REQUIRE(tooManyRecords.facts.diagnostic->code == "DNS_RECORD_LIMIT_EXCEEDED");
}

TEST_CASE("DNS exchanges never guess from incomplete or ambiguous question evidence") {
  SECTION("multiple questions that differ after the first are not paired") {
    const std::vector<std::byte> root{std::byte{0}};
    const std::vector<std::byte> first{std::byte{1}, std::byte{'a'}, std::byte{0}};
    const std::vector<std::byte> second{std::byte{1}, std::byte{'b'}, std::byte{0}};
    const auto query = decodeDns(questionListMessage({root, first}, false));
    const auto response = decodeDns(questionListMessage({root, second}, true));
    REQUIRE(query.layer);
    REQUIRE(response.layer);
    auto queryPacket = dnsPacket(1, false, 0x4567U);
    auto responsePacket = dnsPacket(2, true, 0x4567U);
    queryPacket.dns = query.facts;
    responsePacket.dns = response.facts;
    queryPacket.packet.timestampNs = "1000000000";
    responsePacket.packet.timestampNs = "1000000001";
    wirelens::CaptureDocument capture;
    wirelens::internal::build_dns(capture, {queryPacket, responsePacket});
    REQUIRE(std::none_of(capture.dnsExchanges.begin(), capture.dnsExchanges.end(),
                         [](const auto& exchange) { return exchange.matched; }));
  }

  SECTION("duplicate exact queries make the response ambiguous") {
    const auto first = dnsPacket(1, false, 7);
    const auto second = dnsPacket(2, false, 7);
    const auto response = dnsPacket(3, true, 7);
    wirelens::CaptureDocument capture;
    wirelens::internal::build_dns(capture, {first, second, response});
    REQUIRE(capture.dnsExchanges.size() == 3U);
    REQUIRE(std::none_of(capture.dnsExchanges.begin(), capture.dnsExchanges.end(),
                         [](const auto& exchange) { return exchange.matched; }));
  }

  SECTION("a same-ID query on another tuple cannot steal the response") {
    const auto matching = dnsPacket(1, false, 9);
    auto other = dnsPacket(2, false, 9);
    other.dns.source = "203.0.113.10";
    other.dns.destination = "203.0.113.53";
    const auto response = dnsPacket(3, true, 9);
    wirelens::CaptureDocument capture;
    wirelens::internal::build_dns(capture, {matching, other, response});
    REQUIRE(capture.dnsExchanges.at(0).matched);
    REQUIRE_FALSE(capture.dnsExchanges.at(1).matched);
  }

  SECTION("a response before its query remains unmatched") {
    const auto response = dnsPacket(1, true, 11);
    const auto query = dnsPacket(2, false, 11);
    wirelens::CaptureDocument capture;
    wirelens::internal::build_dns(capture, {response, query});
    REQUIRE(capture.dnsExchanges.size() == 2U);
    REQUIRE_FALSE(capture.dnsExchanges.at(0).matched);
    REQUIRE_FALSE(capture.dnsExchanges.at(1).matched);
  }
}

TEST_CASE("DNS exchanges preserve unknown response codes") {
  const auto query = dnsPacket(1, false, 13);
  const auto response = dnsPacket(2, true, 13, 9);
  wirelens::CaptureDocument capture;
  wirelens::internal::build_dns(capture, {query, response});
  REQUIRE(capture.dnsExchanges.size() == 1U);
  REQUIRE(capture.dnsExchanges.front().matched);
  REQUIRE(capture.dnsExchanges.front().responseCode == "RCODE_9");
}

TEST_CASE("DNS exposes only selected answer data") {
  SECTION("an A record in the authority section is not labeled as an answer") {
    const auto decoded = decodeDns(
        responseWithRecord(0, 1, 1, {std::byte{192}, std::byte{0}, std::byte{2}, std::byte{99}}));
    REQUIRE(decoded.layer);
    REQUIRE(decoded.facts.answers.empty());
  }

  SECTION("unknown record data never enters fields or normalized facts") {
    const std::vector<std::byte> sentinel{
        std::byte{'W'}, std::byte{'I'}, std::byte{'R'}, std::byte{'E'}, std::byte{'L'},
        std::byte{'E'}, std::byte{'N'}, std::byte{'S'}, std::byte{'_'}, std::byte{'S'},
        std::byte{'E'}, std::byte{'N'}, std::byte{'T'}, std::byte{'I'}, std::byte{'N'},
        std::byte{'E'}, std::byte{'L'}};
    const auto decoded = decodeDns(responseWithRecord(1, 0, 16, sentinel));
    REQUIRE(decoded.layer);
    REQUIRE(decoded.facts.answers.empty());
    for (const auto& field : decoded.layer->fields)
      REQUIRE(field.value.find("WIRELENS_SENTINEL") == std::string::npos);
  }
}

TEST_CASE("slow DNS uses the mathematical median at the exact ratio boundary") {
  const auto exact = wirelens::parse_capture(buildDnsCapture({{false, 0},
                                                              {true, 100'000},
                                                              {false, 0},
                                                              {true, 200'000},
                                                              {false, 0},
                                                              {true, 300'000},
                                                              {false, 0},
                                                              {true, 400'000},
                                                              {false, 0},
                                                              {true, 750'000}}));
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(exact));
  const auto& exactObservations = std::get<wirelens::CaptureDocument>(exact).observations;
  REQUIRE(std::count_if(exactObservations.begin(), exactObservations.end(),
                        [](const auto& value) { return value.type == "slow-dns"; }) == 1U);

  const auto below = wirelens::parse_capture(buildDnsCapture({{false, 0},
                                                              {true, 100'000},
                                                              {false, 0},
                                                              {true, 200'000},
                                                              {false, 0},
                                                              {true, 300'000},
                                                              {false, 0},
                                                              {true, 400'000},
                                                              {false, 0},
                                                              {true, 749'999}}));
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(below));
  const auto& belowObservations = std::get<wirelens::CaptureDocument>(below).observations;
  REQUIRE(std::none_of(belowObservations.begin(), belowObservations.end(),
                       [](const auto& value) { return value.type == "slow-dns"; }));
}

TEST_CASE("DNS observations report evidence omitted at the named cap") {
  std::vector<wirelens::internal::ParsedPacket> packets;
  packets.reserve((wirelens::kMaxObservations + 1U) * 2U);
  for (std::size_t exchange = 0; exchange <= wirelens::kMaxObservations; ++exchange) {
    const auto id = static_cast<std::uint16_t>(exchange + 1U);
    packets.push_back(dnsPacket(exchange * 2U + 1U, false, id));
    packets.push_back(dnsPacket(exchange * 2U + 2U, true, id, 3));
  }
  wirelens::CaptureDocument capture;
  wirelens::internal::build_dns(capture, packets);
  REQUIRE(capture.observations.size() == wirelens::kMaxObservations);
  REQUIRE(capture.diagnostics.size() == 1);
  REQUIRE(capture.diagnostics.front().code == "OBSERVATION_LIMIT_REACHED");
  REQUIRE(capture.diagnostics.front().count == 1U);
}
