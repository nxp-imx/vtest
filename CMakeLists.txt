
cmake_minimum_required (VERSION 3.4)

project (vtest)

find_package(v2xsehsm REQUIRED)
find_package(hsmstub REQUIRED)

add_executable (vtest
	src/vtest.c
	)

target_include_directories (vtest
	PRIVATE ../include
	)

target_link_libraries (vtest
	v2xsehsm
	hsmstub)

install (TARGETS vtest RUNTIME DESTINATION bin)
