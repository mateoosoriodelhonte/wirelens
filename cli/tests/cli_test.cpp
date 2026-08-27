#include "fixture_builder.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/wait.h>

namespace {
std::string read_file(const std::filesystem::path& path) {
  std::ifstream input(path);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
std::string quote(const std::filesystem::path& path) { return "\"" + path.string() + "\""; }
int exit_status(const int status) { return WIFEXITED(status) ? WEXITSTATUS(status) : -1; }
} // namespace

int main(int argc, char** argv) {
  if (argc != 2)
    return 1;
  const auto root = std::filesystem::temp_directory_path() / "wirelens-cli-behavior";
  std::filesystem::create_directories(root);
  const auto capture = root / "handshake.pcap";
  const auto malformed = root / "malformed.pcap";
  const auto summary = root / "summary.txt";
  const auto json = root / "capture.json";
  {
    std::ofstream output(capture, std::ios::binary);
    const auto bytes = wirelens_test::build_handshake();
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
  }
  {
    std::ofstream output(malformed, std::ios::binary);
    output << "bad";
  }
  if (exit_status(std::system(
          (quote(argv[1]) + " " + quote(root / "missing.pcap") + " >/dev/null 2>/dev/null")
              .c_str())) != 2)
    return 2;
  if (exit_status(std::system(
          (quote(argv[1]) + " " + quote(malformed) + " >/dev/null 2>/dev/null").c_str())) != 2)
    return 3;
  if (std::system((quote(argv[1]) + " " + quote(capture) + " >" + quote(summary)).c_str()) != 0)
    return 4;
  if (read_file(summary) !=
      "Packets: 3\nDuration: 20 ms\nTCP connections: 1\nHandshake: complete\n")
    return 5;
  if (std::system((quote(argv[1]) + " " + quote(capture) + " --json >" + quote(json)).c_str()) != 0)
    return 6;
  const auto output = read_file(json);
  if (output.empty() || output.back() != '\n' ||
      output.find("\"schema\": \"wirelens.capture\"") == std::string::npos ||
      output.find("\"packet-1\"") == std::string::npos ||
      output.find("\"rawBytes\"") != std::string::npos)
    return 7;
  return 0;
}
