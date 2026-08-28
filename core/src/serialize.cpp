#include "wirelens/serialize.hpp"

#include <nlohmann/json.hpp>

namespace wirelens {
namespace {
using json = nlohmann::json;

json range_json(const ByteRange& value) {
  return {{"captureOffset", value.captureOffset},
          {"packetOffset", value.packetOffset},
          {"length", value.length}};
}

json field_json(const ProtocolField& value) {
  json field{{"name", value.name},
             {"value", value.value},
             {"byteRange", nullptr},
             {"explanationKey", nullptr}};
  if (value.byteRange)
    field["byteRange"] = range_json(*value.byteRange);
  if (value.explanationKey)
    field["explanationKey"] = *value.explanationKey;
  return field;
}

json layer_json(const ProtocolLayer& value) {
  json layer{{"protocol", value.protocol},
             {"label", value.label},
             {"fields", json::array()},
             {"byteRange", nullptr},
             {"explanationKey", nullptr}};
  if (value.byteRange)
    layer["byteRange"] = range_json(*value.byteRange);
  if (value.explanationKey)
    layer["explanationKey"] = *value.explanationKey;
  for (const auto& field : value.fields)
    layer["fields"].push_back(field_json(field));
  return layer;
}

json question_json(const DnsQuestion& value) {
  return {{"name", value.name}, {"type", value.type}, {"class", value.classCode}};
}

json record_json(const DnsRecord& value) {
  return {{"name", value.name},
          {"type", value.type},
          {"class", value.classCode},
          {"value", value.value}};
}

json http_header_json(const HttpHeader& value) {
  return {{"name", value.name}, {"value", value.value}, {"redacted", value.redacted}};
}

json http_request_json(const HttpRequest& value) {
  json result{{"line", value.line},       {"method", value.method},
              {"target", value.target},   {"version", value.version},
              {"headers", json::array()}, {"packetNumbers", value.packetNumbers}};
  for (const auto& header : value.headers)
    result["headers"].push_back(http_header_json(header));
  return result;
}

json http_response_json(const HttpResponse& value) {
  json result{
      {"line", value.line},     {"version", value.version}, {"statusCode", value.statusCode},
      {"reason", value.reason}, {"headers", json::array()}, {"packetNumbers", value.packetNumbers}};
  for (const auto& header : value.headers)
    result["headers"].push_back(http_header_json(header));
  return result;
}

json tls_client_hello_json(const TlsClientHello& value) {
  return {{"recordVersion", value.recordVersion},
          {"legacyVersion", value.legacyVersion},
          {"offeredVersions", value.offeredVersions},
          {"serverName", value.serverName},
          {"packetNumbers", value.packetNumbers}};
}

json tls_server_hello_json(const TlsServerHello& value) {
  return {{"recordVersion", value.recordVersion},
          {"legacyVersion", value.legacyVersion},
          {"negotiatedVersion", value.negotiatedVersion},
          {"packetNumbers", value.packetNumbers}};
}

const char* handshake_text(const HandshakeState state) {
  switch (state) {
  case HandshakeState::complete:
    return "complete";
  case HandshakeState::partial:
    return "partial";
  case HandshakeState::unobserved:
    return "unobserved";
  }
  return "unobserved";
}

} // namespace

std::string serialize_capture(const CaptureDocument& capture) {
  json result{{"schema", capture.schema}, {"contractVersion", capture.contractVersion}};
  result["capture"] = {{"format", capture.capture.format},
                       {"timestampResolution", capture.capture.timestampResolution},
                       {"packetCount", capture.capture.packetCount},
                       {"capturedBytes", capture.capture.capturedBytes},
                       {"originalBytes", capture.capture.originalBytes},
                       {"startTimestampNs", capture.capture.startTimestampNs},
                       {"endTimestampNs", capture.capture.endTimestampNs},
                       {"durationNs", capture.capture.durationNs}};
  result["capture"]["interfaces"] = json::array();
  for (const auto& interface : capture.capture.interfaces)
    result["capture"]["interfaces"].push_back(
        {{"id", interface.id},
         {"linkType", interface.linkType},
         {"snapLength", interface.snapLength},
         {"timestampResolution", interface.timestampResolution}});
  result["endpoints"] = json::array();
  for (const auto& endpoint : capture.endpoints) {
    result["endpoints"].push_back({{"id", endpoint.id},
                                   {"address", endpoint.address},
                                   {"port", endpoint.port},
                                   {"addressFamily", endpoint.addressFamily}});
  }
  result["packets"] = json::array();
  for (const auto& packet : capture.packets) {
    json item{{"id", packet.id},
              {"number", packet.number},
              {"timestampNs", packet.timestampNs},
              {"capturedLength", packet.capturedLength},
              {"originalLength", packet.originalLength},
              {"interfaceId", packet.interfaceId},
              {"sourceEndpointId", packet.sourceEndpointId},
              {"destinationEndpointId", packet.destinationEndpointId},
              {"summary", packet.summary},
              {"layers", json::array()},
              {"flowId", packet.flowId},
              {"analysisFlags", packet.analysisFlags}};
    for (const auto& layer : packet.layers)
      item["layers"].push_back(layer_json(layer));
    result["packets"].push_back(std::move(item));
  }
  result["flows"] = json::array();
  for (const auto& flow : capture.flows) {
    json item{{"id", flow.id},
              {"protocol", flow.protocol},
              {"clientEndpointId", flow.clientEndpointId},
              {"serverEndpointId", flow.serverEndpointId},
              {"startTimestampNs", flow.startTimestampNs},
              {"endTimestampNs", flow.endTimestampNs},
              {"packetNumbers", flow.packetNumbers},
              {"capturedBytes", flow.capturedBytes},
              {"originalBytes", flow.originalBytes}};
    if (flow.protocol == "TCP") {
      item["handshake"] = handshake_text(flow.handshake);
      item["midStream"] = flow.midStream;
      item["termination"] = flow.termination;
      item["events"] = json::array();
      for (const auto& event : flow.events)
        item["events"].push_back({{"packetNumber", event.packetNumber}, {"label", event.label}});
    }
    result["flows"].push_back(std::move(item));
  }
  result["dnsExchanges"] = json::array();
  for (const auto& exchange : capture.dnsExchanges) {
    json item{{"id", exchange.id},
              {"question", question_json(exchange.question)},
              {"queryPacketNumber", exchange.queryPacketNumber},
              {"responsePacketNumber", exchange.responsePacketNumber},
              {"responseCode", exchange.responseCode},
              {"answers", json::array()},
              {"latencyNs", exchange.latencyNs},
              {"matched", exchange.matched}};
    for (const auto& answer : exchange.answers)
      item["answers"].push_back(record_json(answer));
    result["dnsExchanges"].push_back(std::move(item));
  }
  result["httpExchanges"] = json::array();
  for (const auto& exchange : capture.httpExchanges) {
    json item{
        {"id", exchange.id},   {"flowId", exchange.flowId},       {"request", nullptr},
        {"response", nullptr}, {"latencyNs", exchange.latencyNs}, {"matched", exchange.matched}};
    if (exchange.request)
      item["request"] = http_request_json(*exchange.request);
    if (exchange.response)
      item["response"] = http_response_json(*exchange.response);
    result["httpExchanges"].push_back(std::move(item));
  }
  result["tlsHandshakes"] = json::array();
  for (const auto& handshake : capture.tlsHandshakes) {
    json item{{"id", handshake.id},           {"flowId", handshake.flowId},
              {"clientHello", nullptr},       {"serverHello", nullptr},
              {"matched", handshake.matched}, {"limitation", handshake.limitation}};
    if (handshake.clientHello)
      item["clientHello"] = tls_client_hello_json(*handshake.clientHello);
    if (handshake.serverHello)
      item["serverHello"] = tls_server_hello_json(*handshake.serverHello);
    result["tlsHandshakes"].push_back(std::move(item));
  }
  result["observations"] = json::array();
  for (const auto& observation : capture.observations)
    result["observations"].push_back({{"id", observation.id},
                                      {"type", observation.type},
                                      {"message", observation.message},
                                      {"packetNumbers", observation.packetNumbers},
                                      {"limitation", observation.limitation}});
  result["diagnostics"] = json::array();
  for (const auto& diagnostic : capture.diagnostics) {
    result["diagnostics"].push_back({{"severity", diagnostic.severity},
                                     {"code", diagnostic.code},
                                     {"message", diagnostic.message},
                                     {"context", diagnostic.context},
                                     {"captureOffset", diagnostic.captureOffset},
                                     {"packetNumber", diagnostic.packetNumber},
                                     {"count", diagnostic.count}});
  }
  return result.dump(2);
}

std::string format_summary(const CaptureDocument& capture) {
  std::size_t complete = 0;
  std::size_t tcpFlows = 0;
  for (const auto& flow : capture.flows) {
    if (flow.protocol != "TCP")
      continue;
    ++tcpFlows;
    if (flow.handshake == HandshakeState::complete)
      ++complete;
  }
  const auto duration = std::stoull(capture.capture.durationNs);
  return "Packets: " + std::to_string(capture.packets.size()) + "\n" + "Duration: " +
         (duration % 1000000ULL == 0 ? std::to_string(duration / 1000000ULL) + " ms"
                                     : capture.capture.durationNs + " ns") +
         "\n" + "TCP connections: " + std::to_string(tcpFlows) + "\n" +
         "Handshake: " + (complete > 0 ? "complete" : "incomplete") + "\n";
}

} // namespace wirelens
