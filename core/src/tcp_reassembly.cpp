#include "protocol_internal.hpp"

#include "wirelens/parser.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace wirelens::internal {
namespace {

struct Segment {
  std::int64_t start = 0;
  std::span<const std::byte> bytes;
  std::size_t packetNumber = 0;
  bool complete = true;
};

struct Direction {
  std::vector<Segment> segments;
};

struct Cell {
  std::byte value{};
  std::size_t packetNumber = 0;
};

void diagnostic(CaptureDocument& capture, const std::string& code, const std::string& message,
                const std::string& context, const std::optional<std::size_t> packet = {}) {
  add_diagnostic(capture, {"warning", code, message, context, std::nullopt, packet, 1U});
}

std::int64_t sequence_offset(const std::uint32_t base, const std::uint32_t sequence) {
  return static_cast<std::int64_t>(static_cast<std::int32_t>(sequence - base));
}

std::vector<std::size_t> unique_packets(const std::vector<std::size_t>& values) {
  auto result = values;
  std::sort(result.begin(), result.end());
  result.erase(std::unique(result.begin(), result.end()), result.end());
  return result;
}

ApplicationStream reconstruct(CaptureDocument& capture, const std::string& flowId,
                              const bool fromClient, const Direction& direction,
                              std::size_t& retainedCaptureBytes) {
  ApplicationStream result;
  result.flowId = flowId;
  result.fromClient = fromClient;
  if (direction.segments.empty())
    return result;

  std::int64_t minimum = 0;
  bool minimumSet = false;
  std::size_t observedBytes = 0;
  for (const auto& segment : direction.segments) {
    if (!minimumSet || segment.start < minimum) {
      minimum = segment.start;
      minimumSet = true;
    }
    observedBytes += segment.bytes.size();
    result.truncated = result.truncated || !segment.complete;
    result.packetNumbers.push_back(segment.packetNumber);
  }
  result.packetNumbers = unique_packets(result.packetNumbers);

  const auto perDirectionLimit = kMaxRetainedApplicationBytesPerDirection;
  const auto end = minimum + static_cast<std::int64_t>(perDirectionLimit);
  std::map<std::int64_t, Cell> cells;
  for (const auto& original : direction.segments) {
    const auto start = original.start;
    const auto stop = std::min<std::int64_t>(start + static_cast<std::int64_t>(original.bytes.size()), end);
    for (std::int64_t position = std::max(start, minimum); position < stop; ++position) {
      const auto index = static_cast<std::size_t>(position - start);
      const auto found = cells.find(position);
      if (found != cells.end()) {
        if (found->second.value != original.bytes[index])
          result.ambiguous = true;
      } else {
        cells.emplace(position, Cell{original.bytes[index], original.packetNumber});
      }
    }
    if (start + static_cast<std::int64_t>(original.bytes.size()) > end)
      result.limited = true;
  }
  if (observedBytes > perDirectionLimit)
    result.limited = true;
  if (result.limited)
    diagnostic(capture, "APPLICATION_DIRECTION_LIMIT", "TCP application prefix exceeded the 64 KiB direction limit",
               flowId, direction.segments.back().packetNumber);

  const auto available = std::min(cells.size(), kMaxRetainedApplicationBytesPerDirection);
  if (available > kMaxRetainedApplicationBytesPerCapture - retainedCaptureBytes) {
    result.limited = true;
    diagnostic(capture, "APPLICATION_CAPTURE_LIMIT", "TCP application prefixes exceeded the 4 MiB capture limit",
               flowId, direction.segments.back().packetNumber);
  }
  const auto allowed = std::min(available, kMaxRetainedApplicationBytesPerCapture - retainedCaptureBytes);
  std::int64_t cursor = minimum;
  for (std::size_t copied = 0; copied < allowed; ++copied, ++cursor) {
    const auto found = cells.find(cursor);
    if (found == cells.end())
      break;
    result.bytes.push_back(found->second.value);
    result.bytePacketNumbers.push_back(found->second.packetNumber);
  }
  retainedCaptureBytes += result.bytes.size();

  for (const auto& cell : cells) {
    if (cell.first >= minimum && cell.first < cursor &&
        std::find(result.packetNumbers.begin(), result.packetNumbers.end(), cell.second.packetNumber) ==
            result.packetNumbers.end())
      result.packetNumbers.push_back(cell.second.packetNumber);
  }
  result.packetNumbers = unique_packets(result.packetNumbers);
  if (!cells.empty()) {
    if (cells.find(minimum) == cells.end()) {
      result.gap = true;
    } else {
      // A missing byte is a gap only when a later segment proves that the
      // stream continued. A prefix that ends at the last observed byte is
      // merely incomplete, not a false gap claim.
      const auto following = cells.upper_bound(cursor);
      result.gap = following != cells.end() && following->first < end;
      for (std::int64_t expected = minimum; !result.gap && expected < cursor; ++expected) {
        if (cells.find(expected) == cells.end())
          result.gap = cells.upper_bound(expected) != cells.end();
      }
    }
  }
  if (result.gap)
    diagnostic(capture, "APPLICATION_GAP_UNFILLED", "TCP application prefix contains an unfilled sequence gap",
               flowId, direction.segments.back().packetNumber);
  if (result.ambiguous)
    diagnostic(capture, "APPLICATION_OVERLAP_AMBIGUOUS", "TCP application prefix contains conflicting overlapping bytes",
               flowId, direction.segments.back().packetNumber);
  if (result.truncated)
    diagnostic(capture, "APPLICATION_TRUNCATED", "TCP application prefix includes a truncated packet",
               flowId, direction.segments.back().packetNumber);
  result.complete = !result.bytes.empty() && !result.gap && !result.ambiguous && !result.truncated;
  return result;
}

} // namespace

std::vector<ApplicationStream> reconstruct_tcp_prefixes(
    CaptureDocument& capture, const std::vector<ParsedPacket>& packets) {
  struct FlowDirections {
    Direction client;
    Direction server;
  };
  std::map<std::string, FlowDirections> directions;
  std::map<std::string, std::array<std::optional<std::uint32_t>, 2>> bases;
  for (const auto& packet : packets) {
    if (!packet.tcp.valid || !packet.packet.flowId || packet.tcp.payload.empty())
      continue;
    const auto& flow = *packet.packet.flowId;
    const auto flowIt = std::find_if(capture.flows.begin(), capture.flows.end(),
                                     [&](const auto& value) { return value.id == flow; });
    if (flowIt == capture.flows.end() || flowIt->protocol != "TCP")
      continue;
    // TCP facts do not duplicate the address on parsed packets. Endpoint IDs are authoritative
    // after flow construction and avoid treating a reused port as a direction change.
    const bool clientDirection = packet.packet.sourceEndpointId == flowIt->clientEndpointId;
    auto& direction = clientDirection ? directions[flow].client : directions[flow].server;
    const auto directionIndex = clientDirection ? 0U : 1U;
    auto& base = bases[flow][directionIndex];
    if (!base)
      base = packet.tcp.sequence;
    const auto start = sequence_offset(*base, packet.tcp.sequence);
    direction.segments.push_back({start, packet.tcp.payload, packet.packet.number,
                                  packet.tcp.payloadComplete});
  }

  std::vector<ApplicationStream> streams;
  std::size_t retainedCaptureBytes = 0;
  for (const auto& flow : capture.flows) {
    if (flow.protocol != "TCP")
      continue;
    auto found = directions.find(flow.id);
    if (found == directions.end())
      continue;
    auto sortSegments = [](Direction& direction) {
      std::sort(direction.segments.begin(), direction.segments.end(),
                [](const auto& left, const auto& right) { return left.start < right.start; });
    };
    sortSegments(found->second.client);
    sortSegments(found->second.server);
    if (!found->second.client.segments.empty())
      streams.push_back(reconstruct(capture, flow.id, true, found->second.client, retainedCaptureBytes));
    if (!found->second.server.segments.empty())
      streams.push_back(reconstruct(capture, flow.id, false, found->second.server, retainedCaptureBytes));
  }
  return streams;
}

void build_applications(CaptureDocument& capture, std::vector<ParsedPacket>& packets) {
  const auto streams = reconstruct_tcp_prefixes(capture, packets);
  build_http(capture, packets, streams);
  build_tls(capture, packets, streams);
}

} // namespace wirelens::internal
