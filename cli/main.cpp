#include "wirelens/parser.hpp"
#include "wirelens/serialize.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

int main(int argc, char** argv) {
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
  const std::vector<char> data((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  std::vector<std::byte> bytes;
  bytes.reserve(data.size());
  for (const auto value : data) bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
  const auto result = wirelens::parse_capture(bytes);
  if (std::holds_alternative<wirelens::ParseError>(result)) {
    const auto& parseError = std::get<wirelens::ParseError>(result);
    std::cerr << parseError.code << ": " << parseError.message << "\n";
    return 2;
  }
  const auto& capture = std::get<wirelens::CaptureDocument>(result);
  std::cout << (json ? wirelens::serialize_capture(capture) : wirelens::format_summary(capture));
  if (json) std::cout << '\n';
  return 0;
}
