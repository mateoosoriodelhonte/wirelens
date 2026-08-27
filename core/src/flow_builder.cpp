#include "protocol_internal.hpp"

#include "wirelens/parser.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace wirelens::internal {
namespace {

constexpr std::uint8_t kFin = 0x01U;
constexpr std::uint8_t kSyn = 0x02U;
constexpr std::uint8_t kRst = 0x04U;
constexpr std::uint8_t kAck = 0x10U;
constexpr std::uint64_t kSerialHalfSpace = std::uint64_t{1} << 31U;
constexpr std::size_t kMaxPayloadHashCollisions = 8;

bool has_flag(const std::uint8_t flags, const std::uint8_t flag) { return (flags & flag) != 0U; }

std::string address_family(const std::string& address) {
  return address.find(':') == std::string::npos ? "ipv4" : "ipv6";
}

struct SegmentEvidence {
  std::span<const std::byte> payload;
  std::size_t packetNumber = 0;
};

using SegmentKey = std::tuple<bool, std::uint32_t, std::size_t, bool, bool, std::uint64_t>;

struct FlowState {
  Flow flow;
  TcpFacts firstTcp;
  UdpFacts firstUdp;
  bool isUdp = false;
  bool roleSetBySyn = false;
  bool sawReset = false;
  bool sawForwardFin = false;
  bool sawReverseFin = false;
  std::vector<ParsedPacket*> packets;
};

bool tuple_matches(const FlowState& state, const bool isUdp, const std::string& source,
                   const std::string& destination, const std::uint16_t sourcePort,
                   const std::uint16_t destinationPort) {
  if (state.isUdp != isUdp)
    return false;
  const auto& firstSource = state.isUdp ? state.firstUdp.source : state.firstTcp.source;
  const auto& firstDestination =
      state.isUdp ? state.firstUdp.destination : state.firstTcp.destination;
  const auto firstSourcePort = state.isUdp ? state.firstUdp.sourcePort : state.firstTcp.sourcePort;
  const auto firstDestinationPort =
      state.isUdp ? state.firstUdp.destinationPort : state.firstTcp.destinationPort;
  if (address_family(firstSource) != address_family(source))
    return false;
  const auto same = firstSource == source && firstDestination == destination &&
                    firstSourcePort == sourcePort && firstDestinationPort == destinationPort;
  const auto reverse = firstSource == destination && firstDestination == source &&
                       firstSourcePort == destinationPort && firstDestinationPort == sourcePort;
  return same || reverse;
}

bool forward_from_first(const FlowState& state, const std::string& source,
                        const std::uint16_t sourcePort) {
  const auto& firstSource = state.isUdp ? state.firstUdp.source : state.firstTcp.source;
  const auto firstSourcePort = state.isUdp ? state.firstUdp.sourcePort : state.firstTcp.sourcePort;
  return source == firstSource && sourcePort == firstSourcePort;
}

bool terminal(const FlowState& state) {
  return state.sawReset || (state.sawForwardFin && state.sawReverseFin);
}

std::uint32_t serial_advance(const std::uint32_t value, const std::uint32_t amount) {
  return value + amount;
}

bool same_payload(const std::span<const std::byte> left, const std::span<const std::byte> right) {
  return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin());
}

std::uint64_t payload_fingerprint(const std::span<const std::byte> payload) {
  std::uint64_t value = 14695981039346656037ULL;
  for (const auto byte : payload) {
    value ^= std::to_integer<std::uint8_t>(byte);
    value *= 1099511628211ULL;
  }
  return value;
}

void report_collision_limit(CaptureDocument& capture, const FlowState& state,
                            const std::size_t packetNumber) {
  const auto existing =
      std::find_if(capture.diagnostics.begin(), capture.diagnostics.end(), [](const auto& value) {
        return value.code == "TCP_RETRANSMISSION_EVIDENCE_LIMIT";
      });
  if (existing != capture.diagnostics.end()) {
    existing->count = existing->count.value_or(0U) + 1U;
    return;
  }
  if (capture.diagnostics.size() < kMaxDiagnostics) {
    capture.diagnostics.push_back(
        {"warning", "TCP_RETRANSMISSION_EVIDENCE_LIMIT",
         "TCP retransmission comparison stopped for an ambiguous payload group after 8 candidates",
         state.flow.id, std::nullopt, packetNumber, 1U});
  }
}

std::vector<std::size_t> boundary_evidence(const FlowState& state) {
  if (state.packets.empty())
    return {};
  const auto first = state.packets.front()->packet.number;
  const auto last = state.packets.back()->packet.number;
  if (first == last)
    return {first};
  return {first, last};
}

void finalize_tcp_flow(CaptureDocument& capture, FlowState& state) {
  bool sawSyn = false;
  bool sawSynAck = false;
  bool sawFinalAck = false;
  bool sawClientFin = false;
  bool sawServerFin = false;
  bool sawReset = false;
  std::uint32_t clientSequence = 0;
  std::uint32_t serverSequence = 0;
  std::optional<std::size_t> firstHandshakePacket;
  std::optional<std::size_t> firstResetPacket;
  std::map<SegmentKey, std::vector<SegmentEvidence>> segments;

  state.flow.events.clear();
  state.flow.midStream = !state.roleSetBySyn;
  for (const auto* parsed : state.packets) {
    const auto& tcp = parsed->tcp;
    const auto syn = has_flag(tcp.flags, kSyn);
    const auto ack = has_flag(tcp.flags, kAck);
    const auto fin = has_flag(tcp.flags, kFin);
    const auto rst = has_flag(tcp.flags, kRst);
    const auto fromClient =
        tcp.source == state.flow.client.address && tcp.sourcePort == state.flow.client.port;
    if (syn && !firstHandshakePacket)
      firstHandshakePacket = parsed->packet.number;

    bool completingAck = false;
    if (syn && !ack && fromClient && !sawSyn) {
      sawSyn = true;
      clientSequence = tcp.sequence;
    } else if (syn && ack && !fromClient && sawSyn &&
               tcp.acknowledgment == serial_advance(clientSequence, 1U) && !sawSynAck) {
      sawSynAck = true;
      serverSequence = tcp.sequence;
    } else if (!syn && ack && fromClient && sawSynAck &&
               tcp.sequence == serial_advance(clientSequence, 1U) &&
               tcp.acknowledgment == serial_advance(serverSequence, 1U) && !sawFinalAck) {
      sawFinalAck = true;
      completingAck = true;
    }

    if (fin) {
      if (fromClient)
        sawClientFin = true;
      else
        sawServerFin = true;
    }
    if (rst) {
      sawReset = true;
      if (!firstResetPacket)
        firstResetPacket = parsed->packet.number;
    }

    std::string event;
    if (rst)
      event = "RST";
    else if (syn && ack)
      event = "SYN + ACK";
    else if (syn)
      event = "SYN";
    else if (fin)
      event = ack ? "FIN + ACK" : "FIN";
    else if (!tcp.payload.empty())
      event = "DATA";
    else if (completingAck)
      event = "ACK";
    if (!event.empty())
      state.flow.events.push_back({parsed->packet.id, parsed->packet.number, std::move(event)});

    const auto sequenceSpan = static_cast<std::uint64_t>(tcp.payload.size()) +
                              static_cast<std::uint64_t>(syn) + static_cast<std::uint64_t>(fin);
    if (tcp.payloadComplete && !tcp.payload.empty() && sequenceSpan < kSerialHalfSpace) {
      const SegmentKey key{fromClient, tcp.sequence, static_cast<std::size_t>(sequenceSpan),
                           syn,        fin,          payload_fingerprint(tcp.payload)};
      auto& candidates = segments[key];
      const auto prior = std::find_if(candidates.begin(), candidates.end(), [&](const auto& value) {
        return same_payload(value.payload, tcp.payload);
      });
      if (prior != candidates.end()) {
        add_observation(capture, "tcp-retransmission-candidate",
                        "TCP segment appears to resend bytes already seen.",
                        {prior->packetNumber, parsed->packet.number});
      } else if (candidates.size() < kMaxPayloadHashCollisions) {
        candidates.push_back({tcp.payload, parsed->packet.number});
      } else {
        report_collision_limit(capture, state, parsed->packet.number);
      }
    }
  }

  state.flow.packetCount = state.flow.packetNumbers.size();
  state.flow.handshake =
      sawSyn && sawSynAck && sawFinalAck
          ? HandshakeState::complete
          : (firstHandshakePacket ? HandshakeState::partial : HandshakeState::unobserved);
  state.flow.termination =
      sawReset ? "reset" : (sawClientFin && sawServerFin ? "graceful" : "open-at-capture-end");

  if (firstResetPacket)
    add_observation(capture, "tcp-reset", "TCP reset was observed.", {*firstResetPacket});
  if (state.flow.handshake == HandshakeState::partial && firstHandshakePacket) {
    add_observation(capture, "tcp-incomplete-handshake", "TCP handshake evidence was incomplete.",
                    {*firstHandshakePacket});
  }
  if (state.flow.termination == "open-at-capture-end") {
    add_observation(capture, "tcp-connection-without-close",
                    "TCP connection had no observed close before the capture ended.",
                    boundary_evidence(state));
  }
}

} // namespace

void build_flows(CaptureDocument& capture, std::vector<ParsedPacket>& packets) {
  std::vector<FlowState> states;
  std::size_t tcpFlowCount = 0;
  std::size_t udpFlowCount = 0;

  const auto find_endpoint = [&](const std::string& address, const std::uint16_t port,
                                 const bool isUdp) {
    const auto protocol = isUdp ? "UDP" : "TCP";
    const auto found = std::find_if(capture.endpoints.begin(), capture.endpoints.end(),
                                    [&](const Endpoint& endpoint) {
                                      return endpoint.address == address && endpoint.port == port &&
                                             endpoint.protocol == protocol;
                                    });
    if (found != capture.endpoints.end())
      return found->id;
    const auto id = "endpoint-" + std::to_string(capture.endpoints.size() + 1);
    capture.endpoints.push_back({id, address, port, protocol, address_family(address)});
    return id;
  };

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
    const auto startsTcp = !isUdp && has_flag(tcp.flags, kSyn) && !has_flag(tcp.flags, kAck);

    auto stateIndex = states.size();
    for (auto index = states.size(); index > 0; --index) {
      if (tuple_matches(states[index - 1], isUdp, source, destination, sourcePort,
                        destinationPort)) {
        stateIndex = index - 1;
        break;
      }
    }
    if (stateIndex != states.size() && startsTcp && terminal(states[stateIndex]))
      stateIndex = states.size();

    if (stateIndex == states.size()) {
      FlowState state;
      state.isUdp = isUdp;
      state.firstTcp = tcp;
      state.firstUdp = udp;
      state.roleSetBySyn = startsTcp;
      state.flow.id = isUdp ? "udp-flow-" + std::to_string(++udpFlowCount)
                            : "tcp-flow-" + std::to_string(++tcpFlowCount);
      state.flow.protocol = isUdp ? "UDP" : "TCP";
      state.flow.client = {source, sourcePort, address_family(source)};
      state.flow.server = {destination, destinationPort, address_family(destination)};
      state.flow.clientEndpointId = find_endpoint(source, sourcePort, isUdp);
      state.flow.serverEndpointId = find_endpoint(destination, destinationPort, isUdp);
      state.flow.startTimestampNs = parsed.packet.timestampNs;
      states.push_back(std::move(state));
      stateIndex = states.size() - 1;
    }

    auto& state = states[stateIndex];
    if (startsTcp && !state.roleSetBySyn) {
      if (source != state.flow.client.address || sourcePort != state.flow.client.port) {
        std::swap(state.flow.client, state.flow.server);
        std::swap(state.flow.clientEndpointId, state.flow.serverEndpointId);
      }
      state.roleSetBySyn = true;
    }

    const auto fromClient =
        source == state.flow.client.address && sourcePort == state.flow.client.port;
    parsed.packet.flowId = state.flow.id;
    parsed.packet.sourceEndpointId =
        fromClient ? state.flow.clientEndpointId : state.flow.serverEndpointId;
    parsed.packet.destinationEndpointId =
        fromClient ? state.flow.serverEndpointId : state.flow.clientEndpointId;
    state.flow.packetNumbers.push_back(parsed.packet.number);
    state.flow.capturedBytes += parsed.packet.capturedLength;
    state.flow.originalBytes += parsed.packet.originalLength;
    state.flow.endTimestampNs = parsed.packet.timestampNs;
    state.packets.push_back(&parsed);

    if (!isUdp) {
      if (has_flag(tcp.flags, kRst))
        state.sawReset = true;
      if (has_flag(tcp.flags, kFin)) {
        if (forward_from_first(state, source, sourcePort))
          state.sawForwardFin = true;
        else
          state.sawReverseFin = true;
      }
    }
  }

  for (auto& state : states) {
    if (!state.isUdp)
      finalize_tcp_flow(capture, state);
    else
      state.flow.packetCount = state.flow.packetNumbers.size();
    capture.flows.push_back(std::move(state.flow));
  }
}

} // namespace wirelens::internal
