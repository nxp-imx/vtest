
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
 * @file SEutility.c
 *
 * @brief Tests for SE Utility (requirements R10.*)
 *
 */

#include <string.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEutility.h"

/**
 *
 * @brief Test v2xSe_getRandomNumber for expected behaviour
 *
 * This function tests v2xSe_getRandomNumber for expected behaviour
 * The following behaviours are tested:
 *  - generated random number does not exceed requested size
 *  - two successive random numbers are different
 *  - random number request for maximum size does not fail
 *
 */
void test_getRandomNumber(void)
{
	TypeSW_t statusCode;
	int i;
	int modified;
	TypeRandomNumber_t rand1;
	TypeRandomNumber_t rand2;

	/* Move to ACTIVATED state with EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

/* Test generated random number does not exceed requested size */
	/* Preload random number with fixed pattern */
	memset(rand1.data, TEST_BYTE, V2XSE_MAX_RND_NUM_SIZE);
	/* Generate limited size random number */
	VTEST_CHECK_RESULT(v2xSe_getRandomNumber(sizeof(long), &statusCode,
						&rand1), V2XSE_SUCCESS);
	/* Verify data after requested size is unchanged */
	modified = 0;
	for (i = sizeof(long); i < V2XSE_MAX_RND_NUM_SIZE; i++)
		if (rand1.data[i] != TEST_BYTE)
			modified = 1;
	VTEST_CHECK_RESULT(modified, 0);

/* Test two successive random numbers are different */
	/* Get another random number */
	VTEST_CHECK_RESULT(v2xSe_getRandomNumber(sizeof(long), &statusCode,
						&rand2), V2XSE_SUCCESS);
	/* Make sure they are different */
	VTEST_CHECK_RESULT(!memcmp(rand1.data, rand2.data, sizeof(long)), 0);

/* Test random number request for maximum size does not fail */
	/* Get max size random number */
	VTEST_CHECK_RESULT(v2xSe_getRandomNumber(V2XSE_MAX_RND_NUM_SIZE,
					&statusCode, &rand2), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_getKeyLenfromCurveID for expected behaviour
 *
 * This function tests v2xSe_getKeyLenfromCurveID for expected behaviour
 * The following behaviours are tested:
 *  - size V2XSE_256_EC_PUB_KEY returned for all 256 bit curves
 *  - size V2XSE_384_EC_PUB_KEY returned for all 384 bit curves
 *
 */
void test_getKeyLenFromCurveID(void)
{

/* Test size V2XSE_256_EC_PUB_KEY returned for all 256 bit curves */
	/* Verify key length for V2XSE_CURVE_NISTP256 */
	VTEST_CHECK_RESULT(v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_NISTP256),
							V2XSE_256_EC_PUB_KEY);
	/* Verify key length for V2XSE_CURVE_BP256R1 */
	VTEST_CHECK_RESULT(v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_BP256R1),
							V2XSE_256_EC_PUB_KEY);
	/* Verify key length for V2XSE_CURVE_BP256T1 */
	VTEST_CHECK_RESULT(v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_BP256T1),
							V2XSE_256_EC_PUB_KEY);

/* Test size V2XSE_384_EC_PUB_KEY returned for all 384 bit curves */
	/* Verify key length for V2XSE_CURVE_NISTP256 */
	VTEST_CHECK_RESULT(v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_NISTP384),
							V2XSE_384_EC_PUB_KEY);
	/* Verify key length for V2XSE_CURVE_BP384R1 */
	VTEST_CHECK_RESULT(v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_BP384R1),
							V2XSE_384_EC_PUB_KEY);
	/* Verify key length for V2XSE_CURVE_BP384T1 */
	VTEST_CHECK_RESULT(v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_BP384T1),
							V2XSE_384_EC_PUB_KEY);
}


/**
 *
 * @brief Test v2xSe_getSigLenFromHashLen for expected behaviour
 *
 * This function tests v2xSe_getSigLenFromHashLen for expected behaviour
 * The following behaviours are tested:
 *  - size 64 returned for V2XSE_256_EC_HASH_SIZE
 *  - size 96 returned for V2XSE_384_EC_HASH_SIZE
 *
 */
void test_getSigLenFromHashLen(void)
{

/* Test size 64 returned for V2XSE_256_EC_HASH_SIZE */
	VTEST_CHECK_RESULT(v2xSe_getSigLenFromHashLen(V2XSE_256_EC_HASH_SIZE),
									65);

/* Test size 96 returned for V2XSE_384_EC_HASH_SIZE */
	VTEST_CHECK_RESULT(v2xSe_getSigLenFromHashLen(V2XSE_384_EC_HASH_SIZE),
									97);
}
