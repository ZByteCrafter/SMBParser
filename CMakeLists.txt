cmake_minimum_required(VERSION 3.14)
project(SMBParser VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

# nlohmann::json
FetchContent_Declare(json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3)
FetchContent_MakeAvailable(json)

# Static library
add_library(smbparser STATIC
    src/smb1_packet.cpp
    src/smb2_packet.cpp
    src/smb_parser.cpp
    src/file_assembler.cpp)
target_include_directories(smbparser PUBLIC include)
target_link_libraries(smbparser PUBLIC nlohmann_json::nlohmann_json)

# Tests
option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING)
    if(MSVC)
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    endif()
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0)
    FetchContent_MakeAvailable(googletest)
    enable_testing()
    add_subdirectory(tests)
endif()
