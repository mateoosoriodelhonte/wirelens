wirelens_require_catch2()
add_executable(wirelens_tests
  byte_reader_test.cpp
  pcap_parser_test.cpp
  protocol_parser_test.cpp
  dns_parser_test.cpp
  flow_builder_test.cpp
  observation_builder_test.cpp
  tcp_lifecycle_test.cpp
  http_tls_test.cpp
  serialization_test.cpp)
target_link_libraries(wirelens_tests PRIVATE wirelens_core Catch2::Catch2WithMain)
target_include_directories(wirelens_tests PRIVATE ${PROJECT_SOURCE_DIR}/core/src)
target_compile_features(wirelens_tests PRIVATE cxx_std_20)
if(WIRELENS_WARNINGS_AS_ERRORS)
  target_compile_options(wirelens_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
include(Catch)
catch_discover_tests(wirelens_tests)
