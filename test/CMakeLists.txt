cmake_minimum_required(VERSION 3.14.0)
project(StreamSecurityTest VERSION 0.1 DESCRIPTION "")


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_INSTALL_PREFIX}/bin/${CMAKE_SYSTEM_PROCESSOR}/${CMAKE_BUILD_TYPE})


set(UTIL_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../Stream/test/include)
set(INC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(SRC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(${PROJECT_NAME}_Cipher_00)
target_include_directories(${PROJECT_NAME}_Cipher_00 PRIVATE ${INC_ROOT} ${UTIL_PATH})
target_link_libraries(${PROJECT_NAME}_Cipher_00 PRIVATE StreamOBJ StreamSecurityOBJ)
target_sources(${PROJECT_NAME}_Cipher_00 PRIVATE ${SRC_ROOT}/Cipher_00.cpp)
add_test(NAME ${PROJECT_NAME}_Cipher_00 COMMAND ${PROJECT_NAME}_Cipher_00)

add_executable(${PROJECT_NAME}_Digest_00)
target_include_directories(${PROJECT_NAME}_Digest_00 PRIVATE ${INC_ROOT} ${UTIL_PATH})
target_link_libraries(${PROJECT_NAME}_Digest_00 PRIVATE StreamOBJ StreamSecurityOBJ)
target_sources(${PROJECT_NAME}_Digest_00 PRIVATE ${SRC_ROOT}/Digest_00.cpp)
add_test(NAME ${PROJECT_NAME}_Digest_00 COMMAND ${PROJECT_NAME}_Digest_00)

add_executable(${PROJECT_NAME}_Signature_00)
target_include_directories(${PROJECT_NAME}_Signature_00 PRIVATE ${INC_ROOT} ${UTIL_PATH})
target_link_libraries(${PROJECT_NAME}_Signature_00 PRIVATE StreamOBJ StreamSecurityOBJ)
target_sources(${PROJECT_NAME}_Signature_00 PRIVATE ${SRC_ROOT}/Signature_00.cpp)
add_test(NAME ${PROJECT_NAME}_Signature_00 COMMAND ${PROJECT_NAME}_Signature_00)

add_executable(${PROJECT_NAME}_TLS_00)
target_include_directories(${PROJECT_NAME}_TLS_00 PRIVATE ${INC_ROOT} ${UTIL_PATH})
target_link_libraries(${PROJECT_NAME}_TLS_00 PRIVATE StreamOBJ StreamSecurityOBJ -lpthread)
target_sources(${PROJECT_NAME}_TLS_00 PRIVATE ${SRC_ROOT}/TLS_00.cpp)
add_test(NAME ${PROJECT_NAME}_TLS_00 COMMAND ${PROJECT_NAME}_TLS_00)