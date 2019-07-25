cmake_minimum_required(VERSION 2.6)

# list of all the fuzz tests in each directory
set(fuzz_targets rpcsendfuzz)

foreach(target_name IN LISTS fuzz_targets)
	add_executable(${target_name} ${target_name}.c)
	target_link_libraries(${target_name} netconf2)
endforeach(target_name)

include_directories(${CMAKE_SOURCE_DIR}/src ${PROJECT_BINARY_DIR})
configure_file("${PROJECT_SOURCE_DIR}/fuzz/config.h.in" "${PROJECT_BINARY_DIR}/fuzz/config.h" ESCAPE_QUOTES @ONLY)
