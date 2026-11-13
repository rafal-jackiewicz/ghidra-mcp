# Turns a text file into a C++ header holding it as a raw string literal.
# Usage: cmake -DINPUT=<file> -DOUTPUT=<header> -P embed.cmake
file(READ "${INPUT}" CONTENT)
string(FIND "${CONTENT}" ")GHIDRAMCP\"" CLASH)
if(NOT CLASH EQUAL -1)
  message(FATAL_ERROR "${INPUT} contains the raw string delimiter")
endif()
file(WRITE "${OUTPUT}"
     "#pragma once\nstatic const char kBridgeScript[] = R\"GHIDRAMCP(${CONTENT})GHIDRAMCP\";\n")
