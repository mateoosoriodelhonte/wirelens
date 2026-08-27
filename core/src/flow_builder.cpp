#include "protocol_internal.hpp"

#include <algorithm>

namespace wirelens::internal {

void build_flows(CaptureDocument& capture, std::vector<ParsedPacket>& packets) {
  struct FlowState {
    Flow flow;
    TcpFacts first;
    UdpFacts firstUdp;
    bool isUdp = false;
    std::uint32_t serverSequence = 0;
    bool sawSyn = false;
    bool sawSynAck = false;
    bool sawFinalAck = false;
  };
  std::vector<FlowState> states;
  for (auto& parsed : packets) {
    if (!parsed.tcp.valid && !parsed.udp.valid)
      continue;
    const auto isUdp = parsed.udp.valid;
    const auto& tcp = parsed.tcp;
    const auto& udp = parsed.udp;
    const auto& source = isUdp ? udp.source : tcp.source;
    const auto& destination = isUdp ? udp.destination : tcp.destination;
    const auto sourcePort = isUdp ? udp.sourcePort : tcp.sourcePort;
    const auto destinationPort = isUdp ? udp.destinationPort : tcp.destinationPort;
    auto stateIt = std::find_if(states.begin(), states.end(), [&](const FlowState& state) {
      const auto& firstSource = state.isUdp ? state.firstUdp.source : state.first.source;
      const auto& firstDestination = state.isUdp ? state.firstUdp.destination : state.first.destination;
      const auto firstSourcePort = state.isUdp ? state.firstUdp.sourcePort : state.first.sourcePort;
      const auto firstDestinationPort = state.isUdp ? state.firstUdp.destinationPort : state.first.destinationPort;
      const auto same = state.isUdp == isUdp && firstSource == source &&
                        firstDestination == destination && firstSourcePort == sourcePort &&
                        firstDestinationPort == destinationPort;
      const auto reverse = state.isUdp == isUdp && firstSource == destination &&
                           firstDestination == source && firstSourcePort == destinationPort &&
                           firstDestinationPort == sourcePort;
      return same || reverse;
    });
    if (stateIt == states.end()) {
      FlowState state;
      state.isUdp = isUdp;
      state.first = tcp;
      state.firstUdp = udp;
      state.flow.id = std::string(isUdp ? "udp-flow-" : "tcp-flow-") +
                      std::to_string(states.size() + 1);
      state.flow.protocol = isUdp ? "UDP" : "TCP";
      state.flow.client = {source, sourcePort,
                           source.find(':') != std::string::npos ? "ipv6" : "ipv4"};
      state.flow.server = {destination, destinationPort,
                           destination.find(':') != std::string::npos ? "ipv6" : "ipv4"};
      const auto find_endpoint = [&](const std::string& address, const std::uint16_t port) {
        const auto it = std::find_if(capture.endpoints.begin(), capture.endpoints.end(),
                                     [&](const Endpoint& endpoint) {
                                       return endpoint.address == address && endpoint.port == port &&
                                              endpoint.protocol == (isUdp ? "UDP" : "TCP");
                                     });
        if (it != capture.endpoints.end())
          return it->id;
        const auto id = "endpoint-" + std::to_string(capture.endpoints.size() + 1);
        capture.endpoints.push_back({id, address, port, isUdp ? "UDP" : "TCP",
                                     address.find(':') != std::string::npos ? "ipv6" : "ipv4"});
        return id;
      };
      state.flow.clientEndpointId = find_endpoint(source, sourcePort);
      state.flow.serverEndpointId = find_endpoint(destination, destinationPort);
      state.flow.startTimestampNs = parsed.packet.timestampNs;
      stateIt = states.emplace(states.end(), std::move(state));
    }
    auto& state = *stateIt;
    const bool fromClient = source == state.flow.client.address && sourcePort == state.flow.client.port;
    parsed.packet.flowId = state.flow.id;
    parsed.packet.sourceEndpointId =
        fromClient ? state.flow.clientEndpointId : state.flow.serverEndpointId;
    parsed.packet.destinationEndpointId =
        fromClient ? state.flow.serverEndpointId : state.flow.clientEndpointId;
    state.flow.packetNumbers.push_back(parsed.packet.number);
    state.flow.capturedBytes += parsed.packet.capturedLength;
    state.flow.originalBytes += parsed.packet.originalLength;
    state.flow.endTimestampNs = parsed.packet.timestampNs;
    std::string label;
    if (!state.isUdp && (tcp.flags & 0x12U) == 0x02U && fromClient) {
      state.sawSyn = true;
      label = "SYN";
    } else if (!state.isUdp && (tcp.flags & 0x12U) == 0x12U && !fromClient && state.sawSyn &&
               tcp.acknowledgment == state.first.sequence + 1U) {
      state.sawSynAck = true;
      state.serverSequence = tcp.sequence;
      label = "SYN + ACK";
    } else if (!state.isUdp && (tcp.flags & 0x12U) == 0x10U && fromClient && state.sawSynAck &&
               tcp.acknowledgment == state.serverSequence + 1U) {
      state.sawFinalAck = true;
      label = "ACK";
    }
    if (!label.empty())
      state.flow.events.push_back({parsed.packet.id, parsed.packet.number, label});
  }
  for (auto& state : states) {
    state.flow.packetCount = state.flow.packetNumbers.size();
    state.flow.handshake = state.isUdp ? HandshakeState::unobserved : (state.sawSyn && state.sawSynAck && state.sawFinalAck
                               ? HandshakeState::complete
                               : (state.sawSyn || state.sawSynAck ? HandshakeState::partial
                                                                  : HandshakeState::unobserved));
    capture.flows.push_back(std::move(state.flow));
  }
}
} // namespace wirelens::internal
