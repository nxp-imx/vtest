/*
 * Copyright 2019 NXP
 */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON  ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS  SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 *
 * @file ECCdevicemgmt.h
 *
 * @brief Header file for tests for ECC device management (requirements R1.*)
 *
 */

#ifndef ECCDEVICEMGMT_H
#define ECCDEVICEMGMT_H

/** Dispatcher version - major */
#define DISP_MAJOR_VERSION 0
/** Dispatcher version - minor */
#define DISP_MINOR_VERSION 1
/** Dispatcher version - patch */
#define DISP_PATCH_VERSION 0

/** Library version - major */
#define LIB_MAJOR_VERSION 0
/** Library version - minor */
#define LIB_MINOR_VERSION 1
/** Library version - patch */
#define LIB_PATCH_VERSION 0

/** LLC driver version - major : must be 0 since it is not used */
#define LLC_MAJOR_VERSION 0
/** LLC driver version - minor : must be 0 since it is not used */
#define LLC_MINOR_VERSION 0
/** LLC driver version - ptach : must be 0 since it is not used */
#define LLC_PATCH_VERSION 0

/**
 * List of tests from to be run from ECCdevicemgmt.c
 * Tests should be listed in order of incrementing test number
 */
#define ECC_DEVICEMGMT_TESTS \
	VTEST_DEFINE_TEST(10101, &ecc_test_activate,                    \
		"Test initialization of ECC dispatcher")                \
	VTEST_DEFINE_TEST(10102, &ecc_test_deactivate_negative,         \
		"Test deactivation of ECC dispatcher when not active")  \
	VTEST_DEFINE_TEST(10103, &ecc_test_get_versions,                \
		"Test to retrieve versions")                            \
	VTEST_DEFINE_TEST(10104, &ecc_test_get_versions_negative,       \
		"Test to retrieve versions when not active")            \
	VTEST_DEFINE_TEST(10105, &ecc_test_activate_negative,           \
		"Test initialization of dispatcher twice")              \
	VTEST_DEFINE_TEST(10106, &ecc_test_cputime,                     \
		"Test setting load of executing units")                 \
	VTEST_DEFINE_TEST(10107, &ecc_test_cputime_async,               \
		"Test asynchronous setting load of executing units")    \

void ecc_test_activate(void);
void ecc_test_deactivate_negative(void);
void ecc_test_get_versions(void);
void ecc_test_get_versions_negative(void);
void ecc_test_activate_negative(void);
void ecc_test_cputime(void);
void ecc_test_cputime_async(void);

#endif /* ECCDEVICEMGMT_H */

