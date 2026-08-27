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
};

enum class HandshakeState { unobserved, partial, complete };

struct FlowEndpoint {
  std::string address;
  std::uint16_t port = 0;
};

struct FlowEvent {
  std::string packetId;
  std::size_t packetNumber = 0;
  std::string label;
};

struct TcpFlow {
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
  std::string termination = "open-at-capture-end";
  std::vector<std::size_t> packetNumbers;
  std::vector<FlowEvent> events;
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
};

struct Diagnostic {
  std::string severity;
  std::string code;
  std::string message;
  std::string context;
  std::optional<std::size_t> captureOffset;
  std::optional<std::size_t> packetNumber;
};

struct CaptureDocument {
  std::string schema = "wirelens.capture";
  std::string contractVersion = "1.0.0";
  CaptureInfo capture;
  std::vector<Endpoint> endpoints;
  std::vector<Packet> packets;
  std::vector<TcpFlow> flows;
  std::vector<Diagnostic> diagnostics;
};

} // namespace wirelens
