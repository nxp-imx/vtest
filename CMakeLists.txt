
cmake_minimum_required (VERSION 3.4)

project (vtest)

set (vtest_VERSION 0.5)
set (UNIFIED_LIBS TRUE)
set (LEGACY_SECO_LIBS FALSE)

find_package(v2xsehsm CONFIG REQUIRED)

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
	src/se/SEsm2_eces.c
	src/se/SEdatastorage.c
	src/se/SEutility.c
	src/se/SEkeyinjection.c
	src/se/SEperformance.c
	src/se/SEcipher.c
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
	PRIVATE ${ECC_SRC}/lib/include
	PRIVATE ${HSM_LIBS_DIR}/include
	PRIVATE ${HSM_LIBS_DIR}/include/hsm
	)

if(UNIFIED_LIBS)
target_link_libraries (vtest
	v2xCrypto
	${HSM_LIBS_DIR}/lib_hsm.so
	${HSM_LIBS_DIR}/lib_hsm.so.0
	${HSM_LIBS_DIR}/lib_hsm.so.0.1
	${ZLIB_DIR}/libz.a
	${ECC_SRC}/libECDSA.so
	pthread
	rt
	${LTTNG_LIB}
	dl
	crypto
	)
endif(UNIFIED_LIBS)

if(LEGACY_SECO_LIBS)
target_link_libraries(vtest
	v2xCrypto
	${HSM_LIBS_DIR}/hsm_lib.a
	${ZLIB_DIR}/libz.a
	${ECC_SRC}/libECDSA.so
	pthread
	rt
	${LTTNG_LIB}
	dl
	crypto
	)
add_definitions(-D LEGACY_SECO_LIBS)
endif(LEGACY_SECO_LIBS)

target_compile_options(vtest PRIVATE -Werror -Wall)

target_link_options(vtest PRIVATE
	-Wl,--unresolved-symbols=ignore-in-shared-libs)

install (TARGETS vtest RUNTIME DESTINATION bin)

if(LEGACY_SECO_LIBS)
# Following should be temporary, until seco nvm handler is properly integrated in system
add_executable (seco_nvm_daemon
	src/se/seco_nvm_daemon.c
	)

target_compile_options(seco_nvm_daemon PRIVATE -Werror -Wall)
target_link_libraries(seco_nvm_daemon
	${HSM_LIBS_DIR}/seco_nvm_manager.a
	${HSM_LIBS_DIR}/hsm_lib.a
#	${ZLIB_DIR}/libz.a
	)

target_include_directories(seco_nvm_daemon PRIVATE ${SECO_LIBS_DIR}/include)
install (TARGETS seco_nvm_daemon RUNTIME DESTINATION bin)
endif(LEGACY_SECO_LIBS)
