
cmake_minimum_required (VERSION 3.4)

project (vtest)

set (vtest_VERSION 0.1)

find_package(v2xsehsm REQUIRED)
find_package(hsmstub REQUIRED)

configure_file (
	${PROJECT_SOURCE_DIR}/version.h.in
	${CMAKE_CURRENT_SOURCE_DIR}/include/version.h
	)

configure_file(
	${PROJECT_SOURCE_DIR}/Doxyfile.in
	${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
	@ONLY
	)

add_custom_target(doc
	COMMAND doxygen ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	VERBATIM)

add_executable (vtest
	src/vtest.c
	src/testlist.c
	src/se/SEdevicemanagement.c
	src/se/SEkeymanagement.c
	src/se/SEsignature.c
	src/se/SEecies.c
	src/se/SEdatastorage.c
	src/se/SEutility.c
	src/se/SEkeyinjection.c
	src/se/SEmisc.c
	src/ecdsa/ECDSAplaceholder.c
	)

target_include_directories (vtest
	PRIVATE include
	PRIVATE include/se
	PRIVATE include/ecdsa
	PRIVATE ../include
	)

target_link_libraries (vtest
	v2xsehsm
	hsmstub)

target_compile_options(vtest PRIVATE -Werror -Wall)

install (TARGETS vtest RUNTIME DESTINATION bin)
