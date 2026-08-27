#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"

#include <exception>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {
int run(const int argc, char** argv) {
  if (argc < 2 || argc > 3) {
    std::cerr << "Usage: wirelens <capture.pcap> [--json]\n";
    return 2;
  }
  const std::string path = argv[1];
  const bool json = argc == 3 && std::string(argv[2]) == "--json";
  if (argc == 3 && !json) {
    std::cerr << "Unknown option: " << argv[2] << "\n";
    return 2;
  }
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    std::cerr << "Unable to open capture: " << path << "\n";
    return 2;
  }
  input.seekg(0, std::ios::end);
  const auto end = input.tellg();
  if (end < 0 || static_cast<std::uintmax_t>(end) > wirelens::kMaxCaptureBytes) {
    std::cerr << "FILE_TOO_LARGE: Capture exceeds the 64 MiB limit\n";
    return 2;
  }
  input.seekg(0, std::ios::beg);
  std::vector<std::byte> bytes(static_cast<std::size_t>(end));
  const auto expected = static_cast<std::streamsize>(bytes.size());
  if (expected != 0)
    input.read(reinterpret_cast<char*>(bytes.data()), expected);
  if (input.gcount() != expected) {
    std::cerr << "Unable to read capture: " << path << "\n";
    return 2;
  }
  const auto result = wirelens::parse_capture(bytes);
  if (std::holds_alternative<wirelens::ParseError>(result)) {
    const auto& parseError = std::get<wirelens::ParseError>(result);
    std::cerr << parseError.code << ": " << parseError.message << "\n";
    return 2;
  }
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  std::cout << (json ? wirelens::serialize_capture(capture) : wirelens::format_summary(capture));
  if (json)
    std::cout << '\n';
  return 0;
}
} // namespace

int main(const int argc, char** argv) {
  try {
    return run(argc, argv);
  } catch (const std::exception& error) {
    std::cerr << "INTERNAL_ERROR: " << error.what() << '\n';
  } catch (...) {
    std::cerr << "INTERNAL_ERROR: Unexpected native failure\n";
  }
  return 2;
}
