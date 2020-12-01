
/*
 * Copyright 2019-2020 NXP
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
 * @file SEkeyinjection.h
 *
 * @brief Header file for tests for SE Key Injection (requirements R11.*)
 *
 */

#ifndef SEKEYINJECTION_H
#define SEKEYINJECTION_H

/**
 * List of tests from to be run from SEkeyinjection.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_KEY_INJECTION_TESTS \
	VTEST_DEFINE_TEST(110101, &test_endKeyInjection, \
		"Test v2xSe_endKeyInjection for expected behaviour")\
	VTEST_DEFINE_TEST(110601, &test_createKek, \
		"Test v2xSe_createKek for expected behaviour")\
	VTEST_DEFINE_TEST(110301, &test_injectMaEccPrivateKey, \
		"Test v2xSe_injectMaEccPrivateKey for expected behaviour")\
	VTEST_DEFINE_TEST(110303, &test_injectMaEccPrivateKey_sm2, \
		"Test v2xSe_injectMaEccPrivateKey with SM2 for expected behaviour")\
	VTEST_DEFINE_TEST(110401, &test_injectRtEccPrivateKey_empty, \
		"Test v2xSe_injectRtEccPrivateKey for keys in empty slots")\
	VTEST_DEFINE_TEST(110402, &test_injectRtEccPrivateKey_overwrite, \
		"Test v2xSe_injectRtEccPrivateKey for keys in full slots")\
	VTEST_DEFINE_TEST(110404, &test_injectRtEccPrivateKey_empty_sm2, \
		"Test v2xSe_injectRtEccPrivateKey with SM2 for expected behaviour")\
	VTEST_DEFINE_TEST(110501, &test_injectBaEccPrivateKey_empty, \
		"Test v2xSe_injectBaEccPrivateKey for keys in empty slots")\
	VTEST_DEFINE_TEST(110502, &test_injectBaEccPrivateKey_overwrite, \
		"Test v2xSe_injectBaEccPrivateKey for keys in full slots")\
	VTEST_DEFINE_TEST(110504, &test_injectBaEccPrivateKey_empty_sm2, \
		"Test v2xSe_injectBaEccPrivateKey with SM2 for expected behaviour")\

void test_endKeyInjection(void);
void test_createKek(void);
void test_injectMaEccPrivateKey(void);
void test_injectMaEccPrivateKey_sm2(void);
void test_injectRtEccPrivateKey_empty(void);
void test_injectRtEccPrivateKey_overwrite(void);
void test_injectRtEccPrivateKey_empty_sm2(void);
void test_injectBaEccPrivateKey_empty(void);
void test_injectBaEccPrivateKey_overwrite(void);
void test_injectBaEccPrivateKey_empty_sm2(void);

#endif
