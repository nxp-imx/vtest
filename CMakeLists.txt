
cmake_minimum_required (VERSION 3.4)

project (testprog)

find_package(v2xhsm REQUIRED)
find_package(hsmstub REQUIRED)

add_executable (testprog
	src/testprog.c
	)

target_include_directories (testprog
	PRIVATE ../include
	)

target_link_libraries (testprog
	v2xhsm
	hsmstub)

install (TARGETS testprog RUNTIME DESTINATION bin)
