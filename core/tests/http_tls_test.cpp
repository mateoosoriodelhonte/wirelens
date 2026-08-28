#include "fixture_builder.hpp"
#include "protocol_internal.hpp"
#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace {
using wirelens_test::TcpPacketSpec;

void append16(std::vector<std::byte>& bytes, const std::uint16_t value) {
  bytes.push_back(static_cast<std::byte>(value >> 8U));
  bytes.push_back(static_cast<std::byte>(value));
}

std::vector<std::byte> client_hello() {
  std::vector<std::byte> body;
  append16(body, 0x0303U);
  body.resize(body.size() + 32U, std::byte{0x11});
  body.push_back(std::byte{0});
  append16(body, 2U);
  append16(body, 0x1301U);
  body.push_back(std::byte{1});
  body.push_back(std::byte{0});
  std::vector<std::byte> extensions;
  append16(extensions, 0U);
  append16(extensions, 17U);
  append16(extensions, 15U);
  extensions.push_back(std::byte{0});
  append16(extensions, 12U);
  const auto name = wirelens_test::byte_payload("example.test");
  extensions.insert(extensions.end(), name.begin(), name.end());
  append16(extensions, 43U);
  append16(extensions, 5U);
  extensions.push_back(std::byte{4});
  append16(extensions, 0x0304U);
  append16(extensions, 0x0303U);
  append16(body, static_cast<std::uint16_t>(extensions.size()));
  body.insert(body.end(), extensions.begin(), extensions.end());
  std::vector<std::byte> result{std::byte{22}, std::byte{3}, std::byte{3}};
  append16(result, static_cast<std::uint16_t>(body.size() + 4U));
  result.push_back(std::byte{1});
  result.push_back(static_cast<std::byte>(body.size() >> 16U));
  result.push_back(static_cast<std::byte>(body.size() >> 8U));
  result.push_back(static_cast<std::byte>(body.size()));
  result.insert(result.end(), body.begin(), body.end());
  return result;
}

std::vector<std::byte> server_hello() {
  std::vector<std::byte> body;
  append16(body, 0x0303U);
  body.resize(body.size() + 32U, std::byte{0x22});
  body.push_back(std::byte{0});
  append16(body, 0x1301U);
  body.push_back(std::byte{0});
  append16(body, 6U);
  append16(body, 43U);
  append16(body, 2U);
  append16(body, 0x0304U);
  std::vector<std::byte> result{std::byte{22}, std::byte{3}, std::byte{3}};
  append16(result, static_cast<std::uint16_t>(body.size() + 4U));
  result.push_back(std::byte{2});
  result.push_back(static_cast<std::byte>(body.size() >> 16U));
  result.push_back(static_cast<std::byte>(body.size() >> 8U));
  result.push_back(static_cast<std::byte>(body.size()));
  result.insert(result.end(), body.begin(), body.end());
  return result;
}

std::vector<std::byte> slice(const std::vector<std::byte>& bytes, const std::size_t begin,
                             const std::size_t end) {
  return {bytes.begin() + static_cast<std::ptrdiff_t>(begin),
          bytes.begin() + static_cast<std::ptrdiff_t>(end)};
}

wirelens::CaptureDocument parse(const std::vector<TcpPacketSpec>& packets) {
  const auto result = wirelens::parse_capture(wirelens_test::build_tcp_capture(packets));
  REQUIRE(std::holds_alternative<wirelens::CaptureDocument>(result));
  return std::get<wirelens::CaptureDocument>(result);
}
} // namespace

TEST_CASE("HTTP reconstructs split headers and redacts sensitive values") {
  const auto request = wirelens_test::byte_payload(
      "GET /search?q=private&next=two HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer SECRET_SENTINEL\r\nX-Secret: body\r\n\r\nBODY_SENTINEL");
  const auto response = wirelens_test::byte_payload("HTTP/1.1 204 No Content\r\nServer: example.test\r\n\r\n");
  const auto split = request.size() / 2U;
  const auto capture = parse({{true, 1000, 0, 0x10, slice(request, 0, split), {}, {}, 0, false,
                               51515, 8443},
                              {true, static_cast<std::uint32_t>(1000U + split), 0, 0x10,
                               slice(request, split, request.size()), {}, {}, 1, false, 51515, 8443},
                              {false, 2000, 0, 0x10, response, {}, {}, 30, false, 51515, 8443}});
  REQUIRE(capture.httpExchanges.size() == 1U);
  const auto& exchange = capture.httpExchanges.front();
  REQUIRE(exchange.matched);
  REQUIRE(exchange.request->target == "/search?q=[redacted]&next=[redacted]");
  REQUIRE(exchange.request->headers.at(0).value == "example.test");
  REQUIRE(exchange.request->headers.at(1).value == std::nullopt);
  REQUIRE(exchange.request->headers.at(1).redacted);
  REQUIRE(exchange.request->packetNumbers == std::vector<std::size_t>{1U, 2U});
  REQUIRE(exchange.response->packetNumbers == std::vector<std::size_t>{3U});
  REQUIRE(std::count_if(capture.packets.at(0).layers.begin(), capture.packets.at(0).layers.end(),
                        [](const auto& layer) { return layer.protocol == "HTTP"; }) == 0U);
  REQUIRE(std::count_if(capture.packets.at(1).layers.begin(), capture.packets.at(1).layers.end(),
                        [](const auto& layer) { return layer.protocol == "HTTP"; }) == 1U);
  const auto serialized = wirelens::serialize_capture(capture);
  REQUIRE(serialized.find("SECRET_SENTINEL") == std::string::npos);
  REQUIRE(serialized.find("BODY_SENTINEL") == std::string::npos);
}

TEST_CASE("HTTP gap and strict syntax do not create claims") {
  const auto request = wirelens_test::byte_payload("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
  const auto completePrefix = parse({{true, 1000, 0, 0x10, request}});
  REQUIRE(completePrefix.httpExchanges.size() == 1U);
  const auto split = request.size() / 2U;
  const auto gap = parse({{true, 1000, 0, 0x10, slice(request, 0, split)},
                          {true, static_cast<std::uint32_t>(1000U + split + 1U), 0, 0x10,
                           slice(request, split, request.size())}});
  REQUIRE(gap.httpExchanges.empty());
  REQUIRE(std::any_of(gap.diagnostics.begin(), gap.diagnostics.end(), [](const auto& diagnostic) {
    return diagnostic.code == "APPLICATION_GAP_UNFILLED";
  }));
}

TEST_CASE("TCP prefix reconstruction fills an out of order gap") {
  const auto request = wirelens_test::byte_payload("GET /filled HTTP/1.1\r\nHost: example.test\r\n\r\n");
  const auto split = request.size() / 2U;
  const auto capture = parse({{true, static_cast<std::uint32_t>(1000U + split), 0, 0x10,
                               slice(request, split, request.size())},
                              {true, 1000, 0, 0x10, slice(request, 0, split)}});
  REQUIRE(capture.httpExchanges.size() == 1U);
  REQUIRE(capture.httpExchanges.front().request->target == "/filled");
}

TEST_CASE("TLS parses ClientHello and ServerHello on a nonstandard port") {
  const auto client = client_hello();
  const auto server = server_hello();
  const auto capture = parse({{true, 1000, 0, 0x10, client, {}, {}, 0, false, 40000, 8443},
                              {false, 2000, 0, 0x10, server, {}, {}, 30, false, 40000, 8443}});
  REQUIRE(capture.tlsHandshakes.size() == 1U);
  const auto& handshake = capture.tlsHandshakes.front();
  REQUIRE(handshake.matched);
  REQUIRE(handshake.clientHello->serverName == "example.test");
  REQUIRE(handshake.clientHello->offeredVersions == std::vector<std::string>{"TLS 1.3", "TLS 1.2"});
  REQUIRE(handshake.serverHello->negotiatedVersion == "TLS 1.3");
  REQUIRE(std::count_if(capture.packets.at(0).layers.begin(), capture.packets.at(0).layers.end(),
                        [](const auto& layer) { return layer.protocol == "TLS"; }) == 1U);
}

TEST_CASE("Malformed TLS on port 443 produces no TLS claim") {
  const auto capture = parse({{true, 1000, 0, 0x10, wirelens_test::byte_payload("not TLS"), {}, {}, 0, false,
                               40000, 443}});
  REQUIRE(capture.tlsHandshakes.empty());
}

TEST_CASE("Malformed HTTP status line produces no exchange and no exception") {
  const auto capture = parse({{false, 2000, 0, 0x10,
                               wirelens_test::byte_payload("HTTP/1.1 \r\nServer: x\r\n\r\n"), {}, {}, 0,
                               false, 51515, 8443}});
  REQUIRE(capture.httpExchanges.empty());
  REQUIRE(std::any_of(capture.diagnostics.begin(), capture.diagnostics.end(), [](const auto& diagnostic) {
    return diagnostic.code == "HTTP_MALFORMED";
  }));
}

TEST_CASE("HTTP header count and byte boundaries are bounded") {
  wirelens::CaptureDocument capture;
  wirelens::internal::ApplicationStream stream;
  stream.flowId = "tcp-flow-1";
  stream.fromClient = true;
  stream.complete = true;
  stream.bytes = wirelens_test::byte_payload("GET / HTTP/1.1\r\n");
  for (std::size_t index = 0; index < wirelens::kMaxHttpHeaderCount; ++index) {
    const auto line = "X-" + std::to_string(index) + ": value\r\n";
    const auto bytes = wirelens_test::byte_payload(line);
    stream.bytes.insert(stream.bytes.end(), bytes.begin(), bytes.end());
  }
  const auto terminator = wirelens_test::byte_payload("\r\n");
  stream.bytes.insert(stream.bytes.end(), terminator.begin(), terminator.end());
  std::vector<wirelens::internal::ParsedPacket> packets;
  wirelens::internal::build_http(capture, packets, {stream});
  REQUIRE(capture.httpExchanges.size() == 1U);

  stream.bytes.insert(stream.bytes.end() - 2, std::byte{'X'});
  capture.httpExchanges.clear();
  wirelens::internal::build_http(capture, packets, {stream});
  REQUIRE(capture.httpExchanges.empty());
}

TEST_CASE("HTTP header byte budget rejects a terminator beyond the exact limit") {
  wirelens::CaptureDocument capture;
  wirelens::internal::ApplicationStream stream;
  stream.flowId = "tcp-flow-1";
  stream.fromClient = true;
  stream.complete = true;
  const auto prefix = wirelens_test::byte_payload("GET / HTTP/1.1\r\n");
  stream.bytes = prefix;
  const auto lineSize = (wirelens::kMaxHttpHeaderBytes - prefix.size() - 4U) / 2U;
  for (int line = 0; line < 2; ++line) {
    stream.bytes.push_back(std::byte{'X'});
    stream.bytes.push_back(std::byte{':'});
    stream.bytes.resize(stream.bytes.size() + lineSize - 4U, std::byte{'a'});
    stream.bytes.push_back(std::byte{'\r'});
    stream.bytes.push_back(std::byte{'\n'});
  }
  const auto terminator = wirelens_test::byte_payload("\r\n\r\n");
  stream.bytes.insert(stream.bytes.end(), terminator.begin(), terminator.end());
  std::vector<wirelens::internal::ParsedPacket> packets;
  wirelens::internal::build_http(capture, packets, {stream});
  REQUIRE(capture.httpExchanges.size() == 1U);
  stream.bytes.insert(stream.bytes.end() - 4, std::byte{'a'});
  capture.httpExchanges.clear();
  wirelens::internal::build_http(capture, packets, {stream});
  REQUIRE(capture.httpExchanges.empty());
}
