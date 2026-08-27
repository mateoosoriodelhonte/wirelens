#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wirelens {

struct ByteRange {
  std::size_t captureOffset = 0;
  std::size_t packetOffset = 0;
  std::size_t length = 0;
};

struct ProtocolField {
  std::string name;
  std::string value;
  std::optional<ByteRange> byteRange;
  std::optional<std::string> explanationKey;
};

struct ProtocolLayer {
  std::string protocol;
  std::string label;
  std::vector<ProtocolField> fields;
  std::optional<ByteRange> byteRange;
  std::optional<std::string> explanationKey;
};

struct Endpoint {
  std::string id;
  std::string address;
  std::uint16_t port = 0;
  std::string protocol;
  std::string addressFamily = "unknown";
};

struct CaptureInterface {
  std::size_t id = 0;
  std::uint16_t linkType = 1;
  std::uint32_t snapLength = 0;
  std::string timestampResolution = "microseconds";
};

struct Packet {
  std::string id;
  std::size_t number = 0;
  std::string timestampNs;
  std::size_t capturedLength = 0;
  std::size_t originalLength = 0;
  std::string sourceAddress;
  std::string destinationAddress;
  std::uint16_t sourcePort = 0;
  std::uint16_t destinationPort = 0;
  std::string summary;
  std::optional<std::string> flowId;
  std::optional<std::string> sourceEndpointId;
  std::optional<std::string> destinationEndpointId;
  std::vector<std::string> analysisFlags;
  std::vector<ProtocolLayer> layers;
  std::optional<std::size_t> interfaceId;
};

enum class HandshakeState { unobserved, partial, complete };

struct FlowEndpoint {
  std::string address;
  std::uint16_t port = 0;
  std::string addressFamily = "unknown";
};

struct FlowEvent {
  std::string packetId;
  std::size_t packetNumber = 0;
  std::string label;
};

struct Flow {
  std::string id;
  std::string protocol = "TCP";
  FlowEndpoint client;
  FlowEndpoint server;
  std::string clientEndpointId;
  std::string serverEndpointId;
  std::string startTimestampNs;
  std::string endTimestampNs;
  std::size_t packetCount = 0;
  std::uint64_t capturedBytes = 0;
  std::uint64_t originalBytes = 0;
  HandshakeState handshake = HandshakeState::unobserved;
  bool midStream = false;
  std::string termination = "open-at-capture-end";
  std::vector<std::size_t> packetNumbers;
  std::vector<FlowEvent> events;
};

using TcpFlow = Flow;

struct DnsQuestion {
  std::string name;
  std::uint16_t type = 0;
  std::uint16_t classCode = 0;
};

struct DnsRecord {
  std::string name;
  std::uint16_t type = 0;
  std::uint16_t classCode = 0;
  std::string value;
};

struct DnsExchange {
  std::string id;
  DnsQuestion question;
  std::optional<std::size_t> queryPacketNumber;
  std::optional<std::size_t> responsePacketNumber;
  std::optional<std::string> responseCode;
  std::vector<DnsRecord> answers;
  std::optional<std::string> latencyNs;
  bool matched = false;
};

struct Observation {
  std::string id;
  std::string type;
  std::string message;
  std::vector<std::size_t> packetNumbers;
  std::string limitation;
};

struct CaptureInfo {
  std::string format = "pcap";
  std::string timestampResolution = "microseconds";
  std::size_t packetCount = 0;
  std::uint64_t capturedBytes = 0;
  std::uint64_t originalBytes = 0;
  std::optional<std::string> startTimestampNs;
  std::optional<std::string> endTimestampNs;
  std::string durationNs = "0";
  std::vector<CaptureInterface> interfaces;
};

struct Diagnostic {
  std::string severity;
  std::string code;
  std::string message;
  std::string context;
  std::optional<std::size_t> captureOffset;
  std::optional<std::size_t> packetNumber;
  std::optional<std::size_t> count;
};

struct CaptureDocument {
  std::string schema = "wirelens.capture";
  std::string contractVersion = "2.0.0";
  CaptureInfo capture;
  std::vector<Endpoint> endpoints;
  std::vector<Packet> packets;
  std::vector<Flow> flows;
  std::vector<DnsExchange> dnsExchanges;
  std::vector<Observation> observations;
  std::vector<Diagnostic> diagnostics;
  // Private packet byte locations used by the native/WASM byte bridge. This
  // member is deliberately omitted by serialize_capture().
  std::vector<ByteRange> packetSourceRanges;
};

} // namespace wirelens
