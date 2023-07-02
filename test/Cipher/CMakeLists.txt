cmake_minimum_required(VERSION 3.20.0)
cmake_path(GET CMAKE_CURRENT_SOURCE_DIR FILENAME Class)
project(${PROJECT_NAME}_${Class} VERSION 0.1 DESCRIPTION "")

set(INC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/inc)
set(SRC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(${PROJECT_NAME}_Cipher_00)
target_include_directories(${PROJECT_NAME}_Cipher_00 PRIVATE ${StreamTest}/inc)
target_link_libraries(${PROJECT_NAME}_Cipher_00 PRIVATE Stream Security)
target_sources(${PROJECT_NAME}_Cipher_00 PRIVATE ${SRC_ROOT}/Cipher_00.cpp)
add_test(NAME ${PROJECT_NAME}_Cipher_00 COMMAND ${PROJECT_NAME}_Cipher_00)