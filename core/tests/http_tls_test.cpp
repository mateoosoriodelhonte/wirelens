#include "fixture_builder.hpp"
#include "protocol_internal.hpp"
#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"

#include <algorithm>
#include <array>
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

std::vector<std::byte>
client_hello(const std::string& serverName = "example.test",
             const std::vector<std::uint16_t>& offeredVersions = {0x0304U, 0x0303U},
             const std::vector<std::byte>& sessionId = {},
             const std::vector<std::uint16_t>& ciphers = {0x1301U},
             const std::vector<std::byte>& compressionMethods = {std::byte{0}}) {
  std::vector<std::byte> body;
  append16(body, 0x0303U);
  body.resize(body.size() + 32U, std::byte{0x11});
  body.push_back(static_cast<std::byte>(sessionId.size()));
  body.insert(body.end(), sessionId.begin(), sessionId.end());
  append16(body, static_cast<std::uint16_t>(ciphers.size() * 2U));
  for (const auto cipher : ciphers)
    append16(body, cipher);
  body.push_back(static_cast<std::byte>(compressionMethods.size()));
  body.insert(body.end(), compressionMethods.begin(), compressionMethods.end());
  std::vector<std::byte> extensions;
  append16(extensions, 0U);
  append16(extensions, static_cast<std::uint16_t>(serverName.size() + 5U));
  append16(extensions, static_cast<std::uint16_t>(serverName.size() + 3U));
  extensions.push_back(std::byte{0});
  append16(extensions, static_cast<std::uint16_t>(serverName.size()));
  const auto name = wirelens_test::byte_payload(serverName);
  extensions.insert(extensions.end(), name.begin(), name.end());
  append16(extensions, 43U);
  append16(extensions, static_cast<std::uint16_t>(offeredVersions.size() * 2U + 1U));
  extensions.push_back(static_cast<std::byte>(offeredVersions.size() * 2U));
  for (const auto offered : offeredVersions)
    append16(extensions, offered);
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

std::vector<std::byte> server_hello(const std::uint8_t compressionMethod = 0U) {
  std::vector<std::byte> body;
  append16(body, 0x0303U);
  body.resize(body.size() + 32U, std::byte{0x22});
  body.push_back(std::byte{0});
  append16(body, 0x1301U);
  body.push_back(static_cast<std::byte>(compressionMethod));
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

wirelens::CaptureDocument parse_tls_stream(const std::vector<std::byte>& bytes,
                                           const bool fromClient) {
  wirelens::CaptureDocument capture;
  wirelens::internal::ApplicationStream stream;
  stream.flowId = "tcp-flow-1";
  stream.fromClient = fromClient;
  stream.complete = true;
  stream.packetNumbers = {1U};
  stream.bytePacketNumbers.assign(bytes.size(), 1U);
  stream.bytes = bytes;
  wirelens::internal::ParsedPacket packet;
  packet.packet.number = 1U;
  std::vector<wirelens::internal::ParsedPacket> packets{packet};
  wirelens::internal::build_tls(capture, packets, {stream});
  for (const auto& parsed : packets)
    capture.packets.push_back(parsed.packet);
  return capture;
}

wirelens::CaptureDocument parse_http_stream(const std::vector<std::byte>& bytes,
                                            const bool fromClient) {
  wirelens::CaptureDocument capture;
  wirelens::internal::ApplicationStream stream;
  stream.flowId = "tcp-flow-1";
  stream.fromClient = fromClient;
  stream.complete = true;
  stream.packetNumbers = {1U};
  stream.bytePacketNumbers.assign(bytes.size(), 1U);
  stream.bytes = bytes;
  std::vector<wirelens::internal::ParsedPacket> packets(1U);
  packets.front().packet.number = 1U;
  wirelens::internal::build_http(capture, packets, {stream});
  for (const auto& parsed : packets)
    capture.packets.push_back(parsed.packet);
  return capture;
}
} // namespace

TEST_CASE("HTTP reconstructs split headers and redacts sensitive values") {
  const auto request = wirelens_test::byte_payload(
      "GET /search?q=private&next=two HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer "
      "SECRET_SENTINEL\r\nX-Secret: body\r\n\r\nBODY_SENTINEL");
  const auto response =
      wirelens_test::byte_payload("HTTP/1.1 204 No Content\r\nServer: example.test\r\n\r\n");
  const auto split = request.size() / 2U;
  const auto capture =
      parse({{true, 1000, 0, 0x10, slice(request, 0, split), {}, {}, 0, false, 51515, 8443},
             {true,
              static_cast<std::uint32_t>(1000U + split),
              0,
              0x10,
              slice(request, split, request.size()),
              {},
              {},
              1,
              false,
              51515,
              8443},
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
  const auto request =
      wirelens_test::byte_payload("GET /filled HTTP/1.1\r\nHost: example.test\r\n\r\n");
  const auto split = request.size() / 2U;
  const auto capture = parse({{true, static_cast<std::uint32_t>(1000U + split), 0, 0x10,
                               slice(request, split, request.size())},
                              {true, 1000, 0, 0x10, slice(request, 0, split)}});
  REQUIRE(capture.httpExchanges.size() == 1U);
  REQUIRE(capture.httpExchanges.front().request->target == "/filled");
}

TEST_CASE("TCP prefix reconstruction advances payload sequence after SYN") {
  const auto request =
      wirelens_test::byte_payload("GET /syn HTTP/1.1\r\nHost: example.test\r\n\r\n");
  const auto split = request.size() / 2U;
  const auto capture =
      parse({{true, 1000, 0, 0x02, slice(request, 0, split), {}, {}, 0, false, 40000, 8443},
             {true,
              static_cast<std::uint32_t>(1001U + split),
              0,
              0x10,
              slice(request, split, request.size()),
              {},
              {},
              1,
              false,
              40000,
              8443}});
  REQUIRE(capture.httpExchanges.size() == 1U);
  REQUIRE(capture.httpExchanges.front().request->target == "/syn");
}

TEST_CASE("TCP prefix reconstruction keeps serial bases independent per direction") {
  const auto request = wirelens_test::byte_payload("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
  const auto response = wirelens_test::byte_payload("HTTP/1.1 200 OK\r\n\r\n");
  const auto split = response.size() / 2U;
  const std::vector<TcpPacketSpec> packets{
      {true, 1000, 0, 0x10, request, {}, {}, 0, false, 40000, 8443},
      {false,
       0x80000004U,
       0,
       0x10,
       slice(response, split, response.size()),
       {},
       {},
       10,
       false,
       40000,
       8443},
      {false, 0x7ffffffbU, 0, 0x10, slice(response, 0, split), {}, {}, 20, false, 40000, 8443}};
  const auto capture = parse(packets);
  REQUIRE(capture.httpExchanges.size() == 1U);
  REQUIRE(capture.httpExchanges.front().matched);
}

TEST_CASE("HTTP pairing keeps independent outstanding requests per flow") {
  const auto requestA = wirelens_test::byte_payload("GET /a HTTP/1.1\r\nHost: a.test\r\n\r\n");
  const auto requestB = wirelens_test::byte_payload("GET /b HTTP/1.1\r\nHost: b.test\r\n\r\n");
  const auto responseA = wirelens_test::byte_payload("HTTP/1.1 200 OK\r\n\r\n");
  const auto responseB = wirelens_test::byte_payload("HTTP/1.1 201 Created\r\n\r\n");
  const std::vector<TcpPacketSpec> packets{
      {true, 1000, 0, 0x10, requestA, {}, {}, 0, false, 40000, 8443},
      {true, 3000, 0, 0x10, requestB, {}, {}, 1, false, 40001, 8444},
      {false, 2000, 0, 0x10, responseA, {}, {}, 10, false, 40000, 8443},
      {false, 4000, 0, 0x10, responseB, {}, {}, 11, false, 40001, 8444}};
  const auto capture = parse(packets);
  REQUIRE(capture.httpExchanges.size() == 2U);
  REQUIRE(capture.httpExchanges.at(0).matched);
  REQUIRE(capture.httpExchanges.at(1).matched);
}

TEST_CASE("HTTP matched latency stays null when timestamps are reversed") {
  const auto request = wirelens_test::byte_payload("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
  const auto response = wirelens_test::byte_payload("HTTP/1.1 200 OK\r\n\r\n");
  const auto capture = parse({{true, 1000, 0, 0x10, request, {}, {}, 20, false, 40000, 8443},
                              {false, 2000, 0, 0x10, response, {}, {}, 10, false, 40000, 8443}});
  REQUIRE(capture.httpExchanges.size() == 1U);
  REQUIRE(capture.httpExchanges.front().matched);
  REQUIRE(capture.httpExchanges.front().latencyNs == std::nullopt);
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

TEST_CASE("TLS accepts hellos only on their transport directions") {
  const auto wrongClient = parse_tls_stream(client_hello(), false);
  REQUIRE(wrongClient.tlsHandshakes.empty());
  REQUIRE(wrongClient.packets.front().layers.empty());

  const auto wrongServer = parse_tls_stream(server_hello(), true);
  REQUIRE(wrongServer.tlsHandshakes.empty());
  REQUIRE(wrongServer.packets.front().layers.empty());
}

TEST_CASE("TLS supported versions counts unknown values toward the raw limit") {
  std::vector<std::uint16_t> offered(64U, 0x7f00U);
  offered[0] = 0x0304U;
  const auto accepted = parse_tls_stream(client_hello("example.test", offered), true);
  REQUIRE(accepted.tlsHandshakes.size() == 1U);
  REQUIRE(accepted.tlsHandshakes.front().clientHello->offeredVersions ==
          std::vector<std::string>{"TLS 1.3"});

  offered.push_back(0x0303U);
  const auto rejected = parse_tls_stream(client_hello("example.test", offered), true);
  REQUIRE(rejected.tlsHandshakes.empty());
}

TEST_CASE("TLS enforces hello session, cipher, and compression syntax") {
  REQUIRE(
      parse_tls_stream(
          client_hello("example.test", {0x0304U}, std::vector<std::byte>(32U, std::byte{0})), true)
          .tlsHandshakes.size() == 1U);
  REQUIRE(
      parse_tls_stream(
          client_hello("example.test", {0x0304U}, std::vector<std::byte>(33U, std::byte{0})), true)
          .tlsHandshakes.empty());
  REQUIRE(parse_tls_stream(server_hello(), false).tlsHandshakes.size() == 1U);
  REQUIRE(parse_tls_stream(server_hello(1U), false).tlsHandshakes.empty());

  REQUIRE(parse_tls_stream(client_hello("example.test", {0x0304U}, {}, {}, {}), true)
              .tlsHandshakes.empty());
  REQUIRE(parse_tls_stream(client_hello("example.test", {0x0304U}, {}, {}, {std::byte{1}}), true)
              .tlsHandshakes.empty());
  REQUIRE(
      parse_tls_stream(client_hello("example.test", {0x0304U}, {}, {0x1301U}, {std::byte{0}}), true)
          .tlsHandshakes.size() == 1U);
}

TEST_CASE("TLS rejects trailing bytes after the declared extensions") {
  auto trailing = client_hello();
  const auto recordLength =
      static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(trailing[3]) << 8U) |
      std::to_integer<std::uint8_t>(trailing[4]);
  trailing[3] = static_cast<std::byte>((recordLength + 1U) >> 8U);
  trailing[4] = static_cast<std::byte>(recordLength + 1U);
  const auto handshakeLength =
      (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(trailing[6])) << 16U) |
      (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(trailing[7])) << 8U) |
      std::to_integer<std::uint8_t>(trailing[8]);
  trailing[6] = static_cast<std::byte>((handshakeLength + 1U) >> 16U);
  trailing[7] = static_cast<std::byte>((handshakeLength + 1U) >> 8U);
  trailing[8] = static_cast<std::byte>(handshakeLength + 1U);
  trailing.push_back(std::byte{0});
  REQUIRE(parse_tls_stream(trailing, true).tlsHandshakes.empty());
}

TEST_CASE("TLS metadata remains unmatched when ServerHello precedes ClientHello") {
  const auto client = client_hello();
  const auto server = server_hello();
  const auto capture = parse({{true, 1000, 0, 0x02, {}, {}, {}, 0, false, 40000, 8443},
                              {false, 2000, 1000, 0x10, server, {}, {}, 0, false, 40000, 8443},
                              {true, 1001, 0, 0x10, client, {}, {}, 30, false, 40000, 8443}});
  REQUIRE(capture.tlsHandshakes.size() == 1U);
  REQUIRE_FALSE(capture.tlsHandshakes.front().matched);
  REQUIRE(capture.tlsHandshakes.front().clientHello.has_value());
  REQUIRE(capture.tlsHandshakes.front().serverHello.has_value());
}

TEST_CASE("HTTP request fragments are rejected before query redaction") {
  const auto capture =
      parse({{true,
              1000,
              0,
              0x10,
              wirelens_test::byte_payload("GET /safe#SECRET_SENTINEL HTTP/1.1\r\n\r\n"),
              {},
              {},
              0,
              false,
              40000,
              8443}});
  REQUIRE(capture.httpExchanges.empty());
  REQUIRE(std::none_of(capture.diagnostics.begin(), capture.diagnostics.end(),
                       [](const auto& diagnostic) {
                         return diagnostic.code == "HTTP_MALFORMED" &&
                                diagnostic.message.find("SECRET_SENTINEL") != std::string::npos;
                       }));
}

TEST_CASE("HTTP redacts query components without keys") {
  const auto capture =
      parse({{true,
              1000,
              0,
              0x10,
              wirelens_test::byte_payload("GET /?SECRET_SENTINEL HTTP/1.1\r\n\r\n"),
              {},
              {},
              0,
              false,
              40000,
              8443}});
  REQUIRE(capture.httpExchanges.size() == 1U);
  REQUIRE(capture.httpExchanges.front().request->target == "/?[redacted]");
  const auto serialized = wirelens::serialize_capture(capture);
  REQUIRE(serialized.find("SECRET_SENTINEL") == std::string::npos);
}

TEST_CASE("HTTP rejects absolute-form request userinfo and preserves origin-form at signs") {
  const auto credential =
      parse({{true,
              1000,
              0,
              0x10,
              wirelens_test::byte_payload(
                  "GET http://user:SECRET_SENTINEL@example.test/path HTTP/1.1\r\n\r\n"),
              {},
              {},
              0,
              false,
              40000,
              8443}});
  REQUIRE(credential.httpExchanges.empty());
  const auto credentialSerialized = wirelens::serialize_capture(credential);
  REQUIRE(credentialSerialized.find("SECRET_SENTINEL") == std::string::npos);
  for (const auto& diagnostic : credential.diagnostics)
    REQUIRE(diagnostic.message.find("SECRET_SENTINEL") == std::string::npos);

  const auto origin = parse({{true,
                              1000,
                              0,
                              0x10,
                              wirelens_test::byte_payload("GET /user@foo HTTP/1.1\r\n\r\n"),
                              {},
                              {},
                              0,
                              false,
                              40000,
                              8443}});
  REQUIRE(origin.httpExchanges.size() == 1U);
  REQUIRE(origin.httpExchanges.front().request->target == "/user@foo");
}

TEST_CASE("HTTP line length accepts 8 KiB and rejects the next byte") {
  const auto prefix = wirelens_test::byte_payload("GET /");
  const auto suffix = wirelens_test::byte_payload(" HTTP/1.1\r\n\r\n");
  wirelens::internal::ApplicationStream stream;
  stream.flowId = "tcp-flow-1";
  stream.fromClient = true;
  stream.complete = true;
  stream.bytes = prefix;
  stream.bytes.resize(wirelens::kMaxHttpLineBytes - suffix.size() + 2U, std::byte{'a'});
  stream.bytes.insert(stream.bytes.end(), suffix.begin(), suffix.end());
  wirelens::CaptureDocument capture;
  std::vector<wirelens::internal::ParsedPacket> packets;
  wirelens::internal::build_http(capture, packets, {stream});
  REQUIRE(capture.httpExchanges.size() == 1U);
  stream.bytes.insert(stream.bytes.end() - suffix.size(), std::byte{'a'});
  capture.httpExchanges.clear();
  wirelens::internal::build_http(capture, packets, {stream});
  REQUIRE(capture.httpExchanges.empty());
}

TEST_CASE("TLS SNI accepts 253 bytes and rejects 254 bytes") {
  const auto accepted = parse(
      {{true, 1000, 0, 0x10, client_hello(std::string(253U, 'a')), {}, {}, 0, false, 40000, 8443}});
  REQUIRE(accepted.tlsHandshakes.size() == 1U);
  REQUIRE(accepted.tlsHandshakes.front().clientHello->serverName->size() == 253U);
  const auto rejected = parse(
      {{true, 1000, 0, 0x10, client_hello(std::string(254U, 'a')), {}, {}, 0, false, 40000, 8443}});
  REQUIRE(rejected.tlsHandshakes.empty());
  REQUIRE(std::any_of(
      rejected.diagnostics.begin(), rejected.diagnostics.end(),
      [](const auto& diagnostic) { return diagnostic.code == "TLS_SERVER_NAME_LIMIT"; }));
}

TEST_CASE("TLS limits and malformed extension lengths fail closed") {
  auto run = [](std::vector<std::byte> bytes) {
    wirelens::CaptureDocument capture;
    wirelens::internal::ApplicationStream stream;
    stream.flowId = "tcp-flow-1";
    stream.fromClient = true;
    stream.complete = true;
    stream.packetNumbers = {1U};
    stream.bytes = std::move(bytes);
    std::vector<wirelens::internal::ParsedPacket> packets;
    wirelens::internal::build_tls(capture, packets, {stream});
    return capture;
  };
  const auto record =
      run({std::byte{22}, std::byte{3}, std::byte{3}, std::byte{0x48}, std::byte{1}});
  REQUIRE(record.tlsHandshakes.empty());
  REQUIRE(record.diagnostics.front().code == "TLS_RECORD_LIMIT");
  const auto handshake = run({std::byte{22}, std::byte{3}, std::byte{3}, std::byte{0}, std::byte{4},
                              std::byte{1}, std::byte{0}, std::byte{0x40}, std::byte{1}});
  REQUIRE(handshake.tlsHandshakes.empty());
  REQUIRE(handshake.diagnostics.front().code == "TLS_HANDSHAKE_LIMIT");
  auto malformedBytes = client_hello();
  const std::array<std::byte, 2> extensionType{std::byte{0}, std::byte{43}};
  const auto extensionMarker = std::search(malformedBytes.begin(), malformedBytes.end(),
                                           extensionType.begin(), extensionType.end());
  REQUIRE(extensionMarker != malformedBytes.end());
  malformedBytes[static_cast<std::size_t>(extensionMarker - malformedBytes.begin()) + 2U] =
      std::byte{0xff};
  malformedBytes[static_cast<std::size_t>(extensionMarker - malformedBytes.begin()) + 3U] =
      std::byte{0xff};
  const auto malformed = run(std::move(malformedBytes));
  REQUIRE(malformed.tlsHandshakes.empty());
  REQUIRE(malformed.diagnostics.front().code == "TLS_MALFORMED");
}

TEST_CASE("TCP application retention enforces direction and capture budgets") {
  wirelens::CaptureDocument capture;
  std::vector<std::vector<std::byte>> payloads(
      65U,
      std::vector<std::byte>(wirelens::kMaxRetainedApplicationBytesPerDirection, std::byte{'x'}));
  std::vector<wirelens::internal::ParsedPacket> packets;
  for (std::size_t index = 0; index < payloads.size(); ++index) {
    const auto flowId = "tcp-flow-" + std::to_string(index + 1U);
    const auto endpoint = "endpoint-" + std::to_string(index + 1U);
    capture.flows.push_back({flowId,
                             "TCP",
                             {"192.0.2.10", 40000U, "ipv4"},
                             {"198.51.100.20", static_cast<std::uint16_t>(8443U + index), "ipv4"},
                             endpoint,
                             endpoint,
                             "0",
                             "0",
                             1U,
                             0U,
                             0U,
                             wirelens::HandshakeState::unobserved,
                             false,
                             "open-at-capture-end",
                             {},
                             {}});
    wirelens::internal::ParsedPacket packet;
    packet.packet.flowId = flowId;
    packet.packet.sourceEndpointId = endpoint;
    packet.tcp.valid = true;
    packet.tcp.sequence = 1000U;
    packet.tcp.payload = payloads[index];
    packet.packet.number = index + 1U;
    packets.push_back(packet);
  }
  packets.front().tcp.payload = payloads.front();
  payloads.push_back(std::vector<std::byte>(1U, std::byte{'y'}));
  wirelens::internal::ParsedPacket extra;
  extra.packet.flowId = "tcp-flow-1";
  extra.packet.sourceEndpointId = "endpoint-1";
  extra.packet.number = 66U;
  extra.tcp.valid = true;
  extra.tcp.sequence = 1000U + wirelens::kMaxRetainedApplicationBytesPerDirection;
  extra.tcp.payload = payloads.back();
  packets.push_back(extra);
  const auto streams = wirelens::internal::reconstruct_tcp_prefixes(capture, packets);
  REQUIRE(streams.size() == 65U);
  REQUIRE(streams.at(0).bytes.size() == wirelens::kMaxRetainedApplicationBytesPerDirection);
  REQUIRE(streams.at(0).limited);
  REQUIRE(streams.back().limited);
  REQUIRE(streams.back().bytes.empty());
}

TEST_CASE("Malformed TLS on port 443 produces no TLS claim") {
  const auto capture = parse({{true,
                               1000,
                               0,
                               0x10,
                               wirelens_test::byte_payload("not TLS"),
                               {},
                               {},
                               0,
                               false,
                               40000,
                               443}});
  REQUIRE(capture.tlsHandshakes.empty());
}

TEST_CASE("Malformed HTTP status line produces no exchange and no exception") {
  const auto capture = parse({{false,
                               2000,
                               0,
                               0x10,
                               wirelens_test::byte_payload("HTTP/1.1 \r\nServer: x\r\n\r\n"),
                               {},
                               {},
                               0,
                               false,
                               51515,
                               8443}});
  REQUIRE(capture.httpExchanges.empty());
  REQUIRE(std::any_of(capture.diagnostics.begin(), capture.diagnostics.end(),
                      [](const auto& diagnostic) { return diagnostic.code == "HTTP_MALFORMED"; }));
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

  const auto extra = wirelens_test::byte_payload("X-extra: value\r\n");
  stream.bytes.insert(stream.bytes.end() - 2, extra.begin(), extra.end());
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
  const auto lineSize = (wirelens::kMaxHttpHeaderBytes - prefix.size() - 4U) / 4U;
  REQUIRE(lineSize <= wirelens::kMaxHttpLineBytes);
  for (int line = 0; line < 4; ++line) {
    stream.bytes.push_back(std::byte{'X'});
    stream.bytes.push_back(std::byte{':'});
    stream.bytes.resize(stream.bytes.size() + lineSize - 4U, std::byte{'a'});
    stream.bytes.push_back(std::byte{'\r'});
    stream.bytes.push_back(std::byte{'\n'});
  }
  const auto terminator = wirelens_test::byte_payload("\r\n\r\n");
  stream.bytes.insert(stream.bytes.end(), terminator.begin(), terminator.end());
  REQUIRE(stream.bytes.size() == wirelens::kMaxHttpHeaderBytes);
  std::vector<wirelens::internal::ParsedPacket> packets;
  wirelens::internal::build_http(capture, packets, {stream});
  REQUIRE(capture.httpExchanges.size() == 1U);
  stream.bytes.insert(stream.bytes.end() - 4, std::byte{'a'});
  capture.httpExchanges.clear();
  wirelens::internal::build_http(capture, packets, {stream});
  REQUIRE(capture.httpExchanges.empty());
}

TEST_CASE("HTTP method and reason lengths stay within schema caps") {
  const auto method = std::string(wirelens::kMaxHttpMethodBytes, 'A');
  const auto acceptedMethod = parse({{true,
                                      1000,
                                      0,
                                      0x10,
                                      wirelens_test::byte_payload(method + " / HTTP/1.1\r\n\r\n"),
                                      {},
                                      {},
                                      0,
                                      false,
                                      40000,
                                      8443}});
  REQUIRE(acceptedMethod.httpExchanges.size() == 1U);
  const auto rejectedMethod = parse({{true,
                                      1000,
                                      0,
                                      0x10,
                                      wirelens_test::byte_payload(method + "A / HTTP/1.1\r\n\r\n"),
                                      {},
                                      {},
                                      0,
                                      false,
                                      40000,
                                      8443}});
  REQUIRE(rejectedMethod.httpExchanges.empty());

  const auto reason = std::string(wirelens::kMaxHttpReasonBytes, 'a');
  const auto acceptedReason =
      parse_http_stream(wirelens_test::byte_payload("HTTP/1.1 200 " + reason + "\r\n\r\n"), false);
  REQUIRE(acceptedReason.httpExchanges.size() == 1U);
  const auto rejectedReason =
      parse_http_stream(wirelens_test::byte_payload("HTTP/1.1 200 " + reason + "a\r\n\r\n"), false);
  REQUIRE(rejectedReason.httpExchanges.empty());
}

TEST_CASE("HTTP rejects non-ASCII allowlisted values before serialization") {
  auto request =
      wirelens_test::byte_payload("GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: ");
  request.push_back(std::byte{0xff});
  const auto suffix = wirelens_test::byte_payload("\r\n\r\n");
  request.insert(request.end(), suffix.begin(), suffix.end());
  const auto capture = parse({{true, 1000, 0, 0x10, request, {}, {}, 0, false, 40000, 8443}});
  REQUIRE(capture.httpExchanges.size() == 1U);
  REQUIRE(capture.httpExchanges.front().request->headers.at(1).value == std::nullopt);
  REQUIRE(capture.httpExchanges.front().request->headers.at(1).redacted);
  REQUIRE_NOTHROW(wirelens::serialize_capture(capture));
  const auto serialized = wirelens::serialize_capture(capture);
  REQUIRE(serialized.find("\"value\": null") != std::string::npos);

  auto response = wirelens_test::byte_payload("HTTP/1.1 200 ");
  response.push_back(std::byte{0xff});
  response.insert(response.end(), suffix.begin(), suffix.end());
  const auto invalidResponse = parse_http_stream(response, false);
  REQUIRE(invalidResponse.httpExchanges.empty());
  REQUIRE_NOTHROW(wirelens::serialize_capture(invalidResponse));
  for (const auto& diagnostic : invalidResponse.diagnostics)
    REQUIRE(diagnostic.message.find("\xff") == std::string::npos);
}
