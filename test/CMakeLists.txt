cmake_minimum_required(VERSION 3.20.0)
project(${PROJECT_NAME}Test VERSION 0.1 DESCRIPTION "")


file(GLOB Classes RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/[A-Z]*)
foreach(Class ${Classes})
	if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${Class})
		add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/${Class} ${CMAKE_CURRENT_BINARY_DIR}/${Class})
	endif()
endforeach()
