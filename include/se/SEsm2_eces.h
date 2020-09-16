/*
 * Copyright 2020 NXP
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
 * @file SEsm2_eces.h
 *
 * @brief Header files for tests for SE ECIES (requirements R18.*)
 *
 */

#ifndef SE_SM2_ECES_H
#define SE_SM2_ECES_H

/**
 * List of tests from to be run from SEecies.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_SM2_ECES_TESTS \
	VTEST_DEFINE_TEST(180101, &test_encryptUsingSm2Eces, \
		"Test v2xSe_encryptUsingSm2Eces for expected behaviour")\
	VTEST_DEFINE_TEST(180201, &test_decryptUsingRtSm2Eces, \
		"Test v2xSe_decryptUsingRtSm2Eces for expected behaviour")\
	VTEST_DEFINE_TEST(180301, &test_decryptUsingMaSm2Eces, \
		"Test v2xSe_decryptUsingMaSm2Eces for expected behaviour")\
	VTEST_DEFINE_TEST(180401, &test_decryptUsingBaSm2Eces, \
		"Test v2xSe_decryptUsingBaSm2Eces for expected behaviour")

void test_encryptUsingSm2Eces(void);
void test_decryptUsingRtSm2Eces(void);
void test_decryptUsingMaSm2Eces(void);
void test_decryptUsingBaSm2Eces(void);

#endif
