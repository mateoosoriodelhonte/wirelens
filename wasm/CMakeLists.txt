add_library(wirelens_wasm_api STATIC src/wasm_api.cpp)
target_include_directories(wirelens_wasm_api PUBLIC include)
target_link_libraries(wirelens_wasm_api PUBLIC wirelens_core)
target_compile_features(wirelens_wasm_api PUBLIC cxx_std_20)

if(WIRELENS_WARNINGS_AS_ERRORS)
  target_compile_options(wirelens_wasm_api PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

if(WIRELENS_BUILD_TESTS AND NOT EMSCRIPTEN)
  wirelens_require_catch2()
  add_executable(wirelens_wasm_api_tests tests/wasm_api_test.cpp)
  target_include_directories(wirelens_wasm_api_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../core/tests)
  target_link_libraries(wirelens_wasm_api_tests PRIVATE wirelens_wasm_api Catch2::Catch2WithMain)
  target_compile_features(wirelens_wasm_api_tests PRIVATE cxx_std_20)
  if(WIRELENS_WARNINGS_AS_ERRORS)
    target_compile_options(wirelens_wasm_api_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME WasmApi COMMAND wirelens_wasm_api_tests)
endif()

if(EMSCRIPTEN)
  add_executable(wirelens_wasm src/wasm_api.cpp)
  target_link_libraries(wirelens_wasm PRIVATE wirelens_core)
  target_include_directories(wirelens_wasm PRIVATE include)
  target_compile_features(wirelens_wasm PRIVATE cxx_std_20)
  target_link_options(
    wirelens_wasm
    PRIVATE
      "-sMODULARIZE=1"
      "-sEXPORT_ES6=1"
      "-sENVIRONMENT=worker,node"
      "-sALLOW_MEMORY_GROWTH=1"
      "-sFILESYSTEM=0"
      "-sNO_EXIT_RUNTIME=1"
      "-sEXPORTED_FUNCTIONS=_wirelens_alloc,_wirelens_parse_owned,_wirelens_result_ok,_wirelens_result_data,_wirelens_result_size,_wirelens_result_error_code,_wirelens_result_error_offset,_wirelens_result_error_packet_number,_wirelens_packet_data,_wirelens_packet_size,_wirelens_release"
      "-sEXPORTED_RUNTIME_METHODS=HEAPU8")
  set_target_properties(
    wirelens_wasm
    PROPERTIES
      OUTPUT_NAME wirelens
      SUFFIX .js
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/web/static/wasm")
endif()
