include(FetchContent)

# Source: https://cmake.org/cmake/help/latest/module/FetchContent.html

function(wirelens_require_json)
  if(NOT TARGET nlohmann_json::nlohmann_json)
    FetchContent_Declare(
      nlohmann_json
      GIT_REPOSITORY https://github.com/nlohmann/json.git
      GIT_TAG v3.12.0
      GIT_SHALLOW TRUE
      SYSTEM
      EXCLUDE_FROM_ALL)
    FetchContent_MakeAvailable(nlohmann_json)
  endif()
endfunction()

function(wirelens_require_catch2)
  if(NOT TARGET Catch2::Catch2WithMain)
    FetchContent_Declare(
      Catch2
      GIT_REPOSITORY https://github.com/catchorg/Catch2.git
      GIT_TAG v3.16.0
      GIT_SHALLOW TRUE
      SYSTEM
      EXCLUDE_FROM_ALL)
    FetchContent_MakeAvailable(Catch2)
    list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
    set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" PARENT_SCOPE)
  endif()
endfunction()
