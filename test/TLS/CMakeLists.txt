cmake_minimum_required(VERSION 3.20.0)
project(${PROJECT_NAME}_${Class} VERSION 0.1 DESCRIPTION "")

set(INC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/inc)
set(SRC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(${PROJECT_NAME}_Client)
target_link_libraries(${PROJECT_NAME}_Client PRIVATE Stream Security)
target_sources(${PROJECT_NAME}_Client PRIVATE ${SRC_ROOT}/Client.cpp)
add_test(NAME ${PROJECT_NAME}_Client COMMAND ${PROJECT_NAME}_Client)

add_executable(${PROJECT_NAME}_Server)
target_link_libraries(${PROJECT_NAME}_Server PRIVATE Stream Security)
target_sources(${PROJECT_NAME}_Server PRIVATE ${SRC_ROOT}/Server.cpp)
add_test(NAME ${PROJECT_NAME}_Server COMMAND ${PROJECT_NAME}_Server)