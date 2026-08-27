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
  const auto pcapng = root / "ipv6-udp.pcapng";
  {
    std::ofstream output(capture, std::ios::binary);
    const auto bytes = wirelens_test::build_handshake();
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
  }
  {
    auto project = std::filesystem::current_path();
    for (std::size_t levels = 0; levels < 8 && !std::filesystem::exists(project / "fixtures/generated/ipv6-udp.pcapng"); ++levels)
      project = project.parent_path();
    if (!std::filesystem::exists(project / "fixtures/generated/ipv6-udp.pcapng"))
      return 8;
    std::filesystem::copy_file(project / "fixtures/generated/ipv6-udp.pcapng", pcapng,
                                std::filesystem::copy_options::overwrite_existing);
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
  const auto udpSummary = root / "udp-summary.txt";
  if (std::system((quote(argv[1]) + " " + quote(pcapng) + " >" + quote(udpSummary)).c_str()) != 0)
    return 9;
  if (read_file(udpSummary).find("TCP connections: 0\n") == std::string::npos)
    return 10;
  return 0;
}
