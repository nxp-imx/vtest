
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
 * @file SEkeymanagement.h
 *
 * @brief Header file for tests for SE Key Management (requirements R6.*)
 *
 */

#ifndef SEKEYMANAGEMENT_H
#define SEKEYMANAGEMENT_H

/**
 * List of tests from to be run from SEkeymanagement.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_KEY_MANAGEMENT_TESTS \
	VTEST_DEFINE_TEST(60101, &test_generateMaEccKeyPair, \
		"Test v2xSe_generateMaEccKeyPair for expected behaviour")\
	VTEST_DEFINE_TEST(60104, &test_generateMaEccKeyPair_sm2, \
		"Test SMx v2xSe_generateMaEccKeyPair for expected behaviour")\
	VTEST_DEFINE_TEST(60201, &test_getMaEccPublicKey, \
		"Test v2xSe_getMaEccPublicKey for expected behaviour")\
	VTEST_DEFINE_TEST(60204, &test_getMaEccPublicKey_sm2, \
		"Test v2xSe_getMaEccPublicKey for expected behaviour with SM2 key")\
	VTEST_DEFINE_TEST(60301, &test_generateRtEccKeyPair_empty, \
		"Test v2xSe_generateRtEccKeyPair for keys in empty slots")\
	VTEST_DEFINE_TEST(60302, &test_generateRtEccKeyPair_overwrite, \
		"Test v2xSe_generateRtEccKeyPair for keys in full slots")\
	VTEST_DEFINE_TEST(60304, &test_rtKeyCreationSpeed, \
		"Test speed of run time key creation")\
	VTEST_DEFINE_TEST(60305, &test_generateRtEccKeyPair_empty_sm2, \
		"Test v2xSe_generateRtEccKeyPair for SM2 keys in empty slots")\
	VTEST_DEFINE_TEST(60401, &test_deleteRtEccPrivateKey, \
		"Test v2xSe_deleteRtEccPrivateKey for existing keys")\
	VTEST_DEFINE_TEST(60501, &test_getRtEccPublicKey, \
		"Test v2xSe_getRtEccPublicKey for expected behaviour")\
	VTEST_DEFINE_TEST(60504, &test_getRtEccPublicKey_sm2, \
		"Test v2xSe_getRtEccPublicKey for expected behaviour with SM2 key")\
	VTEST_DEFINE_TEST(60601, &test_generateBaEccKeyPair_empty, \
		"Test v2xSe_generateBaEccKeyPair for keys in empty slots")\
	VTEST_DEFINE_TEST(60602, &test_generateBaEccKeyPair_overwrite, \
		"Test v2xSe_generateBaEccKeyPair for keys in full slots")\
	VTEST_DEFINE_TEST(60604, &test_baKeyCreationSpeed, \
		"Test speed of base key creation")\
	VTEST_DEFINE_TEST(60605, &test_generateBaEccKeyPair_empty_sm2, \
		"Test v2xSe_generateBaEccKeyPair for SM2 keys in empty slots")\
	VTEST_DEFINE_TEST(60701, &test_deleteBaEccPrivateKey, \
		"Test v2xSe_deleteBaEccPrivateKey for existing keys")\
	VTEST_DEFINE_TEST(60801, &test_getBaEccPublicKey, \
		"Test v2xSe_getBaEccPublicKey for expected behaviour")\
	VTEST_DEFINE_TEST(60804, &test_getBaEccPublicKey_sm2, \
		"Test v2xSe_getBaEccPublicKey for expected behaviour with SM2 key")\
	VTEST_DEFINE_TEST(60901, &test_deriveRtEccKeyPair_empty, \
		"Test v2xSe_deriveRtEccKeyPair for keys in empty slots")\
	VTEST_DEFINE_TEST(60902, &test_deriveRtEccKeyPair_overwrite, \
		"Test v2xSe_deriveRtEccKeyPair for keys in full slots")\
	VTEST_DEFINE_TEST(61001, &test_activateRtKeyForSigning, \
		"Test v2xSe_activateRtKeyForSigning for normal operation")\

void test_generateMaEccKeyPair(void);
void test_generateMaEccKeyPair_sm2(void);
void test_getMaEccPublicKey(void);
void test_getMaEccPublicKey_sm2(void);
void test_generateRtEccKeyPair_empty(void);
void test_generateRtEccKeyPair_empty_sm2(void);
void test_generateRtEccKeyPair_overwrite(void);
void test_deleteRtEccPrivateKey(void);
void test_getRtEccPublicKey(void);
void test_getRtEccPublicKey_sm2(void);
void test_generateBaEccKeyPair_empty(void);
void test_generateBaEccKeyPair_empty_sm2(void);
void test_generateBaEccKeyPair_overwrite(void);
void test_deleteBaEccPrivateKey(void);
void test_getBaEccPublicKey(void);
void test_getBaEccPublicKey_sm2(void);
void test_deriveRtEccKeyPair_empty(void);
void test_deriveRtEccKeyPair_overwrite(void);
void test_activateRtKeyForSigning(void);
void test_rtKeyCreationSpeed(void);
void test_baKeyCreationSpeed(void);

/** Number of keys created during key creation test */
#define KEY_SPEED_CREATE_NUM 2000

#endif
