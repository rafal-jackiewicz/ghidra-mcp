# Copyright 2026 Rafał Jackiewicz
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.16)
project(ghidra-mcp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(Threads REQUIRED)
find_package(nlohmann_json 3.9 REQUIRED)  # Debian: apt install nlohmann-json3-dev

# The Ghidra bridge script is embedded in the binary so that the server is a single file.
set(BRIDGE_JAVA ${CMAKE_CURRENT_SOURCE_DIR}/bridge/GhidraMcpBridge.java)
set(GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
add_custom_command(
  OUTPUT ${GENERATED_DIR}/bridge_script.hpp
  COMMAND ${CMAKE_COMMAND} -DINPUT=${BRIDGE_JAVA} -DOUTPUT=${GENERATED_DIR}/bridge_script.hpp
          -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed.cmake
  DEPENDS ${BRIDGE_JAVA} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed.cmake
  COMMENT "Embedding GhidraMcpBridge.java"
  VERBATIM)
file(WRITE ${GENERATED_DIR}/version.hpp
     "#pragma once\n#define GHIDRA_MCP_VERSION \"${PROJECT_VERSION}\"\n")

add_executable(ghidra-mcp
  src/main.cpp
  src/audit.cpp
  src/bridge.cpp
  src/http.cpp
  src/mcp.cpp
  src/registrar.cpp
  src/util.cpp
  ${GENERATED_DIR}/bridge_script.hpp)
target_include_directories(ghidra-mcp PRIVATE ${GENERATED_DIR})
target_compile_options(ghidra-mcp PRIVATE -Wall -Wextra)
target_link_libraries(ghidra-mcp PRIVATE Threads::Threads nlohmann_json::nlohmann_json)

install(TARGETS ghidra-mcp RUNTIME DESTINATION bin)
