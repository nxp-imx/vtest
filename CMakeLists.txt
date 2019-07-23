
cmake_minimum_required (VERSION 3.4)

project (testprog)

add_executable (testprog
	src/testprog.c
	)

target_include_directories (testprog
	PRIVATE ../include
	)

add_library(v2xhsm STATIC IMPORTED)
set_target_properties(v2xhsm PROPERTIES
	IMPORTED_LOCATION "${INSTALLED_LIBRARIES}/v2xhsm/libv2xhsm.a"
	INTERFACE_INCLUDE_DIRECTORIES "${INSTALLED_INCLUDES}/v2xhsm"
	)

add_library(hsmstub STATIC IMPORTED)
set_target_properties(hsmstub PROPERTIES
	IMPORTED_LOCATION "${INSTALLED_LIBRARIES}/hsmstub/libhsmstub.a"
	INTERFACE_INCLUDE_DIRECTORIES "${INSTALLED_INCLUDES}/hsmstub"
	)

target_link_libraries (testprog
	v2xhsm
	hsmstub)

install (TARGETS testprog RUNTIME DESTINATION bin)
