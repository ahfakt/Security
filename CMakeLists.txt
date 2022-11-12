cmake_minimum_required(VERSION 3.14.0)
project(Security VERSION 0.7 DESCRIPTION "Security related operations on streams")


set(DEPENDENCIES Stream)
set(INC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/inc)
set(SRC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(INC_LIST
		${INC_ROOT}/${PROJECT_NAME}/Certificate.hpp
		${INC_ROOT}/${PROJECT_NAME}/Cipher.hpp
		${INC_ROOT}/${PROJECT_NAME}/Digest.hpp
		${INC_ROOT}/${PROJECT_NAME}/Key.hpp
		${INC_ROOT}/${PROJECT_NAME}/Signature.hpp
		${INC_ROOT}/${PROJECT_NAME}/TLS.hpp)
set(SRC_LIST
		${SRC_ROOT}/Certificate.cpp
		${SRC_ROOT}/Cipher.cpp
		${SRC_ROOT}/Digest.cpp
		${SRC_ROOT}/Key.cpp
		${SRC_ROOT}/Signature.cpp
		${SRC_ROOT}/TLS.cpp)


add_library(${PROJECT_NAME} OBJECT)
target_include_directories(${PROJECT_NAME} PUBLIC inc)
target_sources(${PROJECT_NAME} PUBLIC ${INC_LIST} PRIVATE ${SRC_LIST})

foreach(T IN LISTS DEPENDENCIES)
	if (NOT TARGET ${T})
		add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../${T} ${CMAKE_CURRENT_BINARY_DIR}/../${T})
	endif ()
endforeach()
target_link_libraries(${PROJECT_NAME} PUBLIC ${DEPENDENCIES} -lssl -lcrypto)


if (CMAKE_BUILD_TYPE MATCHES Debug)
	enable_testing()
	add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/test ${CMAKE_CURRENT_BINARY_DIR}/Testing)
elseif (CMAKE_BUILD_TYPE MATCHES Release)
	find_package(Doxygen)
	if (DOXYGEN_FOUND)
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/doxygen.cfg ${CMAKE_CURRENT_BINARY_DIR}/doxygen.cfg @ONLY)
		add_custom_target(${PROJECT_NAME}Doc
			COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/doxygen.cfg
			COMMENT "Generating ${PROJECT_NAME} documentation with Doxygen"
			VERBATIM)
	endif (DOXYGEN_FOUND)
endif()
