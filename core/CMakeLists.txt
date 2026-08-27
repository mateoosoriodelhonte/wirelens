add_library(wirelens_core
  src/byte_reader.cpp
  src/pcap_parser.cpp
  src/ethernet_parser.cpp
  src/ipv4_parser.cpp
  src/tcp_parser.cpp
  src/flow_builder.cpp
  src/serialize.cpp)
wirelens_require_json()
target_include_directories(wirelens_core PUBLIC include)
target_link_libraries(wirelens_core PUBLIC nlohmann_json::nlohmann_json)
target_compile_features(wirelens_core PUBLIC cxx_std_20)
if(WIRELENS_WARNINGS_AS_ERRORS)
  target_compile_options(wirelens_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

if(WIRELENS_BUILD_TESTS)
  add_subdirectory(tests)
endif()
