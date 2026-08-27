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
  std::uint64_t sequenceEpoch = 0;
};

using SegmentKey = std::tuple<bool, std::uint32_t, std::size_t, bool, bool, std::uint64_t>;
using EndpointKey = std::pair<std::string, std::uint16_t>;
using TupleKey =
    std::tuple<bool, std::string, std::string, std::uint16_t, std::string, std::uint16_t>;

struct DirectionSequenceState {
  std::optional<std::uint32_t> highWater;
  std::uint64_t epoch = 0;
};

struct RangeState {
  std::map<std::uint64_t, std::uint64_t> intervals;
  bool ambiguous = false;
};

struct PendingRetransmission {
  bool fromClient = false;
  std::size_t priorPacketNumber = 0;
  std::size_t packetNumber = 0;
};

struct FlowState {
  Flow flow;
  TcpFacts firstTcp;
  UdpFacts firstUdp;
  bool isUdp = false;
  bool roleSetBySyn = false;
  bool sawReset = false;
  bool sawForwardFin = false;
  bool sawReverseFin = false;
  bool ambiguousReuse = false;
  std::optional<std::uint32_t> initialSynSequence;
  std::vector<ParsedPacket*> packets;
};

TupleKey tuple_key(const bool isUdp, const std::string& source, const std::string& destination,
                   const std::uint16_t sourcePort, const std::uint16_t destinationPort) {
  EndpointKey first{source, sourcePort};
  EndpointKey second{destination, destinationPort};
  if (second < first)
    std::swap(first, second);
  return {isUdp, address_family(source), first.first, first.second, second.first, second.second};
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

bool serial_before(const std::uint32_t left, const std::uint32_t right) {
  const auto distance = right - left;
  return distance != 0U && distance < kSerialHalfSpace;
}

std::uint32_t sequence_span(const TcpFacts& tcp) {
  return static_cast<std::uint32_t>(tcp.payload.size()) +
         static_cast<std::uint32_t>(has_flag(tcp.flags, kSyn)) +
         static_cast<std::uint32_t>(has_flag(tcp.flags, kFin));
}

std::uint64_t sequence_epoch(DirectionSequenceState& direction, const std::uint32_t sequence,
                             const std::uint32_t span) {
  const auto end = serial_advance(sequence, span);
  if (!direction.highWater) {
    direction.highWater = end;
    return direction.epoch;
  }
  if (serial_before(*direction.highWater, end)) {
    if (end < *direction.highWater)
      ++direction.epoch;
    direction.highWater = end;
  }
  return direction.epoch;
}

bool interval_overlaps(const std::map<std::uint64_t, std::uint64_t>& intervals,
                       const std::uint64_t start, const std::uint64_t end) {
  const auto next = intervals.lower_bound(start);
  if (next != intervals.end() && next->first < end)
    return true;
  if (next != intervals.begin()) {
    const auto previous = std::prev(next);
    return previous->second > start;
  }
  return false;
}

void add_distinct_range(RangeState& state, const std::uint32_t sequence, const std::uint32_t span) {
  if (state.ambiguous)
    return;
  constexpr std::uint64_t serialSpace = std::uint64_t{1} << 32U;
  const auto start = static_cast<std::uint64_t>(sequence);
  const auto unboundedEnd = start + span;
  const auto firstEnd = std::min(unboundedEnd, serialSpace);
  const auto wrappedEnd = unboundedEnd > serialSpace ? unboundedEnd - serialSpace : 0U;
  if (interval_overlaps(state.intervals, start, firstEnd) ||
      (wrappedEnd > 0U && interval_overlaps(state.intervals, 0U, wrappedEnd))) {
    state.ambiguous = true;
    state.intervals.clear();
    return;
  }
  state.intervals.emplace(start, firstEnd);
  if (wrappedEnd > 0U)
    state.intervals.emplace(0U, wrappedEnd);
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
  add_diagnostic(
      capture,
      {"warning", "TCP_RETRANSMISSION_EVIDENCE_LIMIT",
       "TCP retransmission comparison stopped for an ambiguous payload group after 8 candidates",
       state.flow.id, std::nullopt, packetNumber, 1U});
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
  std::uint32_t clientSynSpan = 0;
  std::uint32_t serverSynSpan = 0;
  std::optional<std::size_t> firstHandshakePacket;
  std::optional<std::size_t> firstResetPacket;
  std::map<SegmentKey, std::vector<SegmentEvidence>> segments;
  std::map<bool, RangeState> ranges;
  std::vector<PendingRetransmission> pendingRetransmissions;
  DirectionSequenceState clientSequenceState;
  DirectionSequenceState serverSequenceState;

  state.flow.events.clear();
  state.flow.midStream = !state.roleSetBySyn || state.ambiguousReuse;
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
      clientSynSpan = sequence_span(tcp);
    } else if (syn && ack && !fromClient && sawSyn &&
               tcp.acknowledgment == serial_advance(clientSequence, clientSynSpan) && !sawSynAck) {
      sawSynAck = true;
      serverSequence = tcp.sequence;
      serverSynSpan = sequence_span(tcp);
    } else if (!syn && ack && fromClient && sawSynAck &&
               tcp.sequence == serial_advance(clientSequence, clientSynSpan) &&
               tcp.acknowledgment == serial_advance(serverSequence, serverSynSpan) &&
               !sawFinalAck) {
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

    const auto sequenceSpan = sequence_span(tcp);
    if (tcp.payloadComplete && sequenceSpan > 0U && sequenceSpan < kSerialHalfSpace) {
      auto& direction = fromClient ? clientSequenceState : serverSequenceState;
      const auto epoch = sequence_epoch(direction, tcp.sequence, sequenceSpan);
      const SegmentKey key{fromClient, tcp.sequence, static_cast<std::size_t>(sequenceSpan),
                           syn,        fin,          payload_fingerprint(tcp.payload)};
      auto& candidates = segments[key];
      const auto prior = std::find_if(candidates.begin(), candidates.end(), [&](const auto& value) {
        return value.sequenceEpoch == epoch && same_payload(value.payload, tcp.payload);
      });
      if (prior != candidates.end()) {
        pendingRetransmissions.push_back({fromClient, prior->packetNumber, parsed->packet.number});
      } else if (candidates.size() < kMaxPayloadHashCollisions) {
        add_distinct_range(ranges[fromClient], tcp.sequence, sequenceSpan);
        candidates.push_back({tcp.payload, parsed->packet.number, epoch});
      } else {
        report_collision_limit(capture, state, parsed->packet.number);
      }
    }
  }

  if (!state.ambiguousReuse) {
    for (const auto& pending : pendingRetransmissions) {
      const auto range = ranges.find(pending.fromClient);
      if (range != ranges.end() && !range->second.ambiguous) {
        add_observation(capture, "tcp-retransmission-candidate",
                        "TCP segment appears to resend bytes already seen.",
                        {pending.priorPacketNumber, pending.packetNumber});
      }
    }
  }

  state.flow.packetCount = state.flow.packetNumbers.size();
  state.flow.handshake =
      sawSyn && sawSynAck && sawFinalAck
          ? HandshakeState::complete
          : (firstHandshakePacket ? HandshakeState::partial : HandshakeState::unobserved);
  state.flow.termination = sawReset                       ? "reset"
                           : sawClientFin && sawServerFin ? "graceful"
                           : state.ambiguousReuse         ? "unknown"
                                                          : "open-at-capture-end";

  if (firstResetPacket)
    add_observation(capture, "tcp-reset", "TCP reset was observed.", {*firstResetPacket});
  if (state.flow.handshake == HandshakeState::partial && firstHandshakePacket) {
    add_observation(capture, "tcp-incomplete-handshake", "TCP handshake evidence was incomplete.",
                    {*firstHandshakePacket});
  }
  if (state.flow.termination == "open-at-capture-end" || state.flow.termination == "unknown") {
    add_observation(capture, "tcp-connection-without-close",
                    "TCP connection had no observed close before the capture ended.",
                    boundary_evidence(state));
  }
}

} // namespace

void build_flows(CaptureDocument& capture, std::vector<ParsedPacket>& packets) {
  std::vector<FlowState> states;
  std::map<TupleKey, std::size_t> latestFlowByTuple;
  std::map<std::tuple<std::string, std::string, std::uint16_t>, std::string> endpointIds;
  std::size_t tcpFlowCount = 0;
  std::size_t udpFlowCount = 0;

  const auto find_endpoint = [&](const std::string& address, const std::uint16_t port,
                                 const bool isUdp) {
    const auto protocol = isUdp ? "UDP" : "TCP";
    const auto key = std::tuple{std::string(protocol), address, port};
    const auto found = endpointIds.find(key);
    if (found != endpointIds.end())
      return found->second;
    const auto id = "endpoint-" + std::to_string(capture.endpoints.size() + 1);
    capture.endpoints.push_back({id, address, port, protocol, address_family(address)});
    endpointIds.emplace(key, id);
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
    const auto key = tuple_key(isUdp, source, destination, sourcePort, destinationPort);

    const auto latest = latestFlowByTuple.find(key);
    auto stateIndex = latest == latestFlowByTuple.end() ? states.size() : latest->second;
    if (stateIndex != states.size() && startsTcp && terminal(states[stateIndex]))
      stateIndex = states.size();

    if (stateIndex == states.size()) {
      FlowState state;
      state.isUdp = isUdp;
      state.firstTcp = tcp;
      state.firstUdp = udp;
      state.roleSetBySyn = startsTcp;
      if (startsTcp)
        state.initialSynSequence = tcp.sequence;
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
      latestFlowByTuple[key] = stateIndex;
    }

    auto& state = states[stateIndex];
    if (startsTcp && state.roleSetBySyn && state.initialSynSequence &&
        tcp.sequence != *state.initialSynSequence && !state.ambiguousReuse) {
      state.ambiguousReuse = true;
      add_diagnostic(capture,
                     {"warning", "TCP_CONNECTION_REUSE_AMBIGUOUS",
                      "A new SYN used a different initial sequence before an observed close; "
                      "packets remain in one mid-stream flow",
                      state.flow.id, std::nullopt, parsed.packet.number, 1U});
    } else if (startsTcp && !state.roleSetBySyn) {
      if (source != state.flow.client.address || sourcePort != state.flow.client.port) {
        std::swap(state.flow.client, state.flow.server);
        std::swap(state.flow.clientEndpointId, state.flow.serverEndpointId);
      }
      state.roleSetBySyn = true;
      state.initialSynSequence = tcp.sequence;
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
