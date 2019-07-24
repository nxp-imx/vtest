
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
	IMPORTED_LOCATION "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/v2xhsm/libv2xhsm.a"
	INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/v2xhsm"
	)

add_library(hsmstub STATIC IMPORTED)
set_target_properties(hsmstub PROPERTIES
	IMPORTED_LOCATION "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/hsmstub/libhsmstub.a"
	INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/hsmstub"
	)

target_link_libraries (testprog
	v2xhsm
	hsmstub)

install (TARGETS testprog RUNTIME DESTINATION bin)
