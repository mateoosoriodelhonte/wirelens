#include "protocol_internal.hpp"

#include <algorithm>

namespace wirelens::internal {

void build_flows(CaptureDocument& capture, std::vector<ParsedPacket>& packets) {
  struct FlowState {
    TcpFlow flow;
    TcpFacts first;
    std::uint32_t serverSequence = 0;
    bool sawSyn = false;
    bool sawSynAck = false;
    bool sawFinalAck = false;
  };
  std::vector<FlowState> states;
  for (auto& parsed : packets) {
    if (!parsed.tcp.valid) continue;
    auto& tcp = parsed.tcp;
    auto stateIt = std::find_if(states.begin(), states.end(), [&](const FlowState& state) {
      const auto same = state.first.source == tcp.source && state.first.destination == tcp.destination &&
                        state.first.sourcePort == tcp.sourcePort && state.first.destinationPort == tcp.destinationPort;
      const auto reverse = state.first.source == tcp.destination && state.first.destination == tcp.source &&
                           state.first.sourcePort == tcp.destinationPort && state.first.destinationPort == tcp.sourcePort;
      return same || reverse;
    });
    if (stateIt == states.end()) {
      FlowState state;
      state.first = tcp;
      state.flow.id = "tcp-flow-" + std::to_string(states.size() + 1);
      state.flow.client = {tcp.source, tcp.sourcePort};
      state.flow.server = {tcp.destination, tcp.destinationPort};
      const auto find_endpoint = [&](const std::string& address, const std::uint16_t port) {
        const auto it = std::find_if(capture.endpoints.begin(), capture.endpoints.end(), [&](const Endpoint& endpoint) {
          return endpoint.address == address && endpoint.port == port;
        });
        if (it != capture.endpoints.end()) return it->id;
        const auto id = "endpoint-" + std::to_string(capture.endpoints.size() + 1);
        capture.endpoints.push_back({id, address, port, "TCP", "ipv4"});
        return id;
      };
      state.flow.clientEndpointId = find_endpoint(tcp.source, tcp.sourcePort);
      state.flow.serverEndpointId = find_endpoint(tcp.destination, tcp.destinationPort);
      state.flow.startTimestampNs = parsed.packet.timestampNs;
      stateIt = states.emplace(states.end(), std::move(state));
    }
    auto& state = *stateIt;
    const bool fromClient = tcp.source == state.flow.client.address && tcp.sourcePort == state.flow.client.port;
    parsed.packet.flowId = state.flow.id;
    parsed.packet.sourceEndpointId = fromClient ? state.flow.clientEndpointId : state.flow.serverEndpointId;
    parsed.packet.destinationEndpointId = fromClient ? state.flow.serverEndpointId : state.flow.clientEndpointId;
    state.flow.packetNumbers.push_back(parsed.packet.number);
    state.flow.capturedBytes += parsed.packet.capturedLength;
    state.flow.originalBytes += parsed.packet.originalLength;
    state.flow.endTimestampNs = parsed.packet.timestampNs;
    std::string label;
    if ((tcp.flags & 0x12U) == 0x02U && fromClient) {
      state.sawSyn = true; label = "SYN";
    } else if ((tcp.flags & 0x12U) == 0x12U && !fromClient && state.sawSyn &&
               tcp.acknowledgment == state.first.sequence + 1U) {
      state.sawSynAck = true; state.serverSequence = tcp.sequence; label = "SYN + ACK";
    } else if ((tcp.flags & 0x12U) == 0x10U && fromClient && state.sawSynAck &&
               tcp.acknowledgment == state.serverSequence + 1U) {
      state.sawFinalAck = true; label = "ACK";
    }
    if (!label.empty()) state.flow.events.push_back({parsed.packet.id, parsed.packet.number, label});
  }
  for (auto& state : states) {
    state.flow.packetCount = state.flow.packetNumbers.size();
    state.flow.handshake = state.sawSyn && state.sawSynAck && state.sawFinalAck
                               ? HandshakeState::complete
                               : (state.sawSyn || state.sawSynAck ? HandshakeState::partial : HandshakeState::unobserved);
    capture.flows.push_back(std::move(state.flow));
  }
}
}  // namespace wirelens::internal
