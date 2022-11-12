cmake_minimum_required(VERSION 3.14.0)
project(SecurityTest VERSION 0.1 DESCRIPTION "")


set(StreamTest ${CMAKE_CURRENT_SOURCE_DIR}/../../Stream/test)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Cipher ${CMAKE_CURRENT_BINARY_DIR}/Cipher)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Digest ${CMAKE_CURRENT_BINARY_DIR}/Digest)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Signature ${CMAKE_CURRENT_BINARY_DIR}/Signature)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/TLS ${CMAKE_CURRENT_BINARY_DIR}/TLS)