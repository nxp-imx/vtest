
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
 * @file SEsignature.h
 *
 * @brief Header files for tests for SE Signature (requirements R7.*)
 *
 */

#ifndef SESIGNATURE_H
#define SESIGNATURE_H

/**
 * List of tests from to be run from SEsignature.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_SIGNATURE_TESTS \
	VTEST_DEFINE_TEST(70101, &test_createBaSign, \
		"Test v2xSe_createBaSign for expected behaviour")\
	VTEST_DEFINE_TEST(70104, &test_createBaSign_sm2, \
		"Test v2xSe_createBaSign with SM2 key for expected behaviour")\
	VTEST_DEFINE_TEST(70201, &test_createMaSign, \
		"Test v2xSe_createMaSign for expected behaviour")\
	VTEST_DEFINE_TEST(70204, &test_createMaSign_sm2, \
		"Test v2xSe_createMaSign with SM2 key for expected behaviour")\
	VTEST_DEFINE_TEST(70301, &test_createRtSignLowLatency, \
		"Test v2xSe_createRtSignLowLatency for expected behaviour")\
	VTEST_DEFINE_TEST(70401, &test_createRtSign, \
		"Test v2xSe_createRtSign for expected behaviour")\
	VTEST_DEFINE_TEST(70404, &test_createRtSign_sm2, \
		"Test v2xSe_createRtSign with SM2 key for expected behaviour")\
	VTEST_DEFINE_TEST(70501, &test_v2xSe_sm2_get_z, \
		"Test v2xSe_sm2_get_z for expected behaviour")

void test_createBaSign(void);
void test_createMaSign(void);
void test_createRtSign(void);
void test_createRtSignLowLatency(void);
void test_createBaSign_sm2(void);
void test_createMaSign_sm2(void);
void test_createRtSign_sm2(void);
void test_v2xSe_sm2_get_z(void);

#endif
