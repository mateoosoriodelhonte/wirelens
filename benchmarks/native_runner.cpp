#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(__APPLE__) || defined(__linux__)
#include <sys/resource.h>
#define WIRELENS_HAS_RUSAGE 1
#endif

namespace {
using Clock = std::chrono::steady_clock;
using Json = nlohmann::json;

struct Options {
  std::string capture;
  std::size_t runs = 10;
  std::size_t warmup = 2;
};

void usage() {
  std::cerr << "Usage: wirelens_benchmark_native --capture PATH [--runs N] [--warmup N]\n";
}

bool parse_count(const char* value, std::size_t& result, const bool allowZero = false) {
  try {
    const auto parsed = std::stoull(value);
    if ((!allowZero && parsed == 0) || parsed > 100000)
      return false;
    result = static_cast<std::size_t>(parsed);
    return true;
  } catch (...) {
    return false;
  }
}

bool parse_options(const int argc, char** argv, Options& options) {
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--capture" && index + 1 < argc) {
      options.capture = argv[++index];
    } else if (argument == "--runs" && index + 1 < argc) {
      if (!parse_count(argv[++index], options.runs))
        return false;
    } else if (argument == "--warmup" && index + 1 < argc) {
      if (!parse_count(argv[++index], options.warmup, true))
        return false;
    } else {
      return false;
    }
  }
  return !options.capture.empty();
}

std::vector<std::byte> read_capture(const std::string& path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input)
    throw std::runtime_error("unable to open capture: " + path);
  const auto end = input.tellg();
  if (end < 0 || static_cast<std::uintmax_t>(end) > wirelens::kMaxCaptureBytes)
    throw std::runtime_error("capture exceeds the 64 MiB limit");
  std::vector<std::byte> bytes(static_cast<std::size_t>(end));
  input.seekg(0, std::ios::beg);
  if (!bytes.empty())
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (input.gcount() != static_cast<std::streamsize>(bytes.size()))
    throw std::runtime_error("unable to read capture: " + path);
  return bytes;
}

double elapsed_ms(const Clock::time_point start, const Clock::time_point end) {
  return std::chrono::duration<double, std::milli>(end - start).count();
}

std::uint64_t peak_memory_bytes() {
#if defined(WIRELENS_HAS_RUSAGE)
  struct rusage usage{};
  if (getrusage(RUSAGE_SELF, &usage) != 0)
    return 0;
#if defined(__APPLE__)
  return static_cast<std::uint64_t>(usage.ru_maxrss);
#else
  return static_cast<std::uint64_t>(usage.ru_maxrss) * 1024U;
#endif
#else
  return 0;
#endif
}

int run(const Options& options) {
  const auto bytes = read_capture(options.capture);
  for (std::size_t index = 0; index < options.warmup; ++index) {
    const auto parsed = wirelens::parse_capture(bytes);
    if (!std::holds_alternative<wirelens::CaptureDocument>(parsed))
      throw std::runtime_error("warmup parse failed");
    if (wirelens::serialize_capture(std::get<wirelens::CaptureDocument>(parsed)).empty())
      throw std::runtime_error("warmup serialization failed");
  }

  std::vector<double> parse_ms;
  std::vector<double> serialization_ms;
  std::vector<std::uint64_t> memory;
  parse_ms.reserve(options.runs);
  serialization_ms.reserve(options.runs);
  memory.reserve(options.runs);
  std::size_t packet_count = 0;
  std::size_t json_bytes = 0;
  for (std::size_t index = 0; index < options.runs; ++index) {
    const auto parse_start = Clock::now();
    const auto parsed = wirelens::parse_capture(bytes);
    const auto parse_end = Clock::now();
    if (!std::holds_alternative<wirelens::CaptureDocument>(parsed))
      throw std::runtime_error("parse failed");
    const auto& document = std::get<wirelens::CaptureDocument>(parsed);
    packet_count = document.packets.size();

    const auto serialize_start = Clock::now();
    const auto serialized = wirelens::serialize_capture(document);
    const auto serialize_end = Clock::now();
    if (serialized.empty())
      throw std::runtime_error("serialization returned empty JSON");
    json_bytes = serialized.size();
    parse_ms.push_back(elapsed_ms(parse_start, parse_end));
    serialization_ms.push_back(elapsed_ms(serialize_start, serialize_end));
#if defined(WIRELENS_HAS_RUSAGE)
    memory.push_back(peak_memory_bytes());
#endif
  }

  Json output{{"runner", "native"},          {"bytes", bytes.size()},
              {"packetCount", packet_count}, {"jsonBytes", json_bytes},
              {"parseMs", parse_ms},         {"jsonSerializationMs", serialization_ms},
              {"peakMemoryBytes", memory},   {"peakMemorySupported", !memory.empty()}};
  std::cout << output.dump() << '\n';
  return 0;
}
} // namespace

int main(const int argc, char** argv) {
  Options options;
  if (!parse_options(argc, argv, options)) {
    usage();
    return 2;
  }
  try {
    return run(options);
  } catch (const std::exception& error) {
    std::cerr << "benchmark error: " << error.what() << '\n';
    return 1;
  }
}
