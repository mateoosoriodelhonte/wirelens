#include "wirelens/serialize.hpp"

#include <nlohmann/json.hpp>

namespace wirelens {
namespace {
using json = nlohmann::json;

json range_json(const ByteRange& value) {
  return {{"captureOffset", value.captureOffset}, {"packetOffset", value.packetOffset}, {"length", value.length}};
}

json field_json(const ProtocolField& value) {
  json field{{"name", value.name}, {"value", value.value}, {"byteRange", nullptr}, {"explanationKey", nullptr}};
  if (value.byteRange) field["byteRange"] = range_json(*value.byteRange);
  if (value.explanationKey) field["explanationKey"] = *value.explanationKey;
  return field;
}

json layer_json(const ProtocolLayer& value) {
  json layer{{"protocol", value.protocol}, {"label", value.label}, {"fields", json::array()},
             {"byteRange", nullptr}, {"explanationKey", nullptr}};
  if (value.byteRange) layer["byteRange"] = range_json(*value.byteRange);
  if (value.explanationKey) layer["explanationKey"] = *value.explanationKey;
  for (const auto& field : value.fields) layer["fields"].push_back(field_json(field));
  return layer;
}

const char* handshake_text(const HandshakeState state) {
  switch (state) {
    case HandshakeState::complete: return "complete";
    case HandshakeState::partial: return "partial";
    case HandshakeState::unobserved: return "unobserved";
  }
  return "unobserved";
}

}  // namespace

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
  result["endpoints"] = json::array();
  for (const auto& endpoint : capture.endpoints) {
    result["endpoints"].push_back({{"id", endpoint.id}, {"address", endpoint.address},
                                   {"port", endpoint.port}, {"addressFamily", endpoint.addressFamily}});
  }
  result["packets"] = json::array();
  for (const auto& packet : capture.packets) {
    json item{{"id", packet.id}, {"number", packet.number}, {"timestampNs", packet.timestampNs},
              {"capturedLength", packet.capturedLength}, {"originalLength", packet.originalLength},
              {"sourceEndpointId", packet.sourceEndpointId}, {"destinationEndpointId", packet.destinationEndpointId},
              {"summary", packet.summary}, {"layers", json::array()}, {"flowId", packet.flowId},
              {"analysisFlags", packet.analysisFlags}};
    for (const auto& layer : packet.layers) item["layers"].push_back(layer_json(layer));
    result["packets"].push_back(std::move(item));
  }
  result["flows"] = json::array();
  for (const auto& flow : capture.flows) {
    json item{{"id", flow.id}, {"protocol", flow.protocol},
              {"clientEndpointId", flow.clientEndpointId}, {"serverEndpointId", flow.serverEndpointId},
              {"startTimestampNs", flow.startTimestampNs}, {"endTimestampNs", flow.endTimestampNs},
              {"packetNumbers", flow.packetNumbers}, {"capturedBytes", flow.capturedBytes},
              {"originalBytes", flow.originalBytes}, {"handshake", handshake_text(flow.handshake)},
              {"termination", flow.termination},
              {"events", json::array()}};
    for (const auto& event : flow.events) item["events"].push_back({{"packetNumber", event.packetNumber}, {"label", event.label}});
    result["flows"].push_back(std::move(item));
  }
  result["diagnostics"] = json::array();
  for (const auto& diagnostic : capture.diagnostics) {
    result["diagnostics"].push_back({{"severity", diagnostic.severity}, {"code", diagnostic.code},
                                     {"message", diagnostic.message}, {"context", diagnostic.context},
                                     {"captureOffset", diagnostic.captureOffset}, {"packetNumber", diagnostic.packetNumber}});
  }
  return result.dump(2);
}

std::string format_summary(const CaptureDocument& capture) {
  std::size_t complete = 0;
  for (const auto& flow : capture.flows) if (flow.handshake == HandshakeState::complete) ++complete;
  const auto duration = std::stoull(capture.capture.durationNs);
  return "Packets: " + std::to_string(capture.packets.size()) + "\n" +
         "Duration: " + (duration % 1000000ULL == 0 ? std::to_string(duration / 1000000ULL) + " ms" : capture.capture.durationNs + " ns") + "\n" +
         "TCP connections: " + std::to_string(capture.flows.size()) + "\n" +
         "Handshake: " + (complete > 0 ? "complete" : "incomplete") + "\n";
}

}  // namespace wirelens
