
cmake_minimum_required (VERSION 3.4)

project (vtest)

set (vtest_VERSION 0.2)

find_package(v2xsehsm REQUIRED)

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
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	COMMAND doxygen Doxyfile
	COMMAND make -C doxygen/latex pdf
	COMMAND mv doxygen/latex/refman.pdf vtest_api_manual.pdf
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
	src/se/SEperformance.c
	src/se/SEmisc.c
	src/ecc/ECCcrypto.c
	src/ecc/ECCdevicemgmt.c
	)

target_include_directories (vtest
	PRIVATE include
	PRIVATE include/se
	PRIVATE include/ecc
	PRIVATE ../include
	PRIVATE ${ECC_SRC}/../../include
	PRIVATE ${SECO_LIBS_DIR}/include
	)

target_link_libraries (vtest
	v2xCrypto
	${SECO_LIBS_DIR}/hsm_lib.a
	${ZLIB_DIR}/libz.a
	${ECC_SRC}/libECDSA.so
	pthread
	rt
	${LTTNG_LIB}
	dl
	)

target_compile_options(vtest PRIVATE -Werror -Wall)

target_link_options(vtest PRIVATE
	-Wl,--unresolved-symbols=ignore-in-shared-libs)

install (TARGETS vtest RUNTIME DESTINATION bin)

# Following should be temporary, until seco nvm handler is properly integrated in system
add_executable (seco_nvm_daemon
	src/se/seco_nvm_daemon.c
	)

target_compile_options(seco_nvm_daemon PRIVATE -Werror -Wall)
target_link_libraries(seco_nvm_daemon
	${SECO_LIBS_DIR}/seco_nvm_manager.a
	${SECO_LIBS_DIR}/hsm_lib.a
	${ZLIB_DIR}/libz.a
	)

target_include_directories(seco_nvm_daemon PRIVATE ${SECO_LIBS_DIR}/include)
install (TARGETS seco_nvm_daemon RUNTIME DESTINATION bin)
