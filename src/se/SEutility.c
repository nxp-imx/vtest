
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEutility.c
 *
 * @brief Tests for SE Utility (requirements R10.*)
 *
 */

#include <string.h>
#include <v2xseapi.h>
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
									64);

/* Test size 96 returned for V2XSE_384_EC_HASH_SIZE */
	VTEST_CHECK_RESULT(v2xSe_getSigLenFromHashLen(V2XSE_384_EC_HASH_SIZE),
									96);
}
