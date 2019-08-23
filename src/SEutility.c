
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

#include <stdio.h>
#include <string.h>
#include <v2xseapi.h>
#include "vtest.h"
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getRandomNumber(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	int i;
	TypeRandomNumber_t rand1;
	TypeRandomNumber_t rand2;

	/* Move to ACTIVATED state with EU applet */
	if (setupActivatedState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;

/* Test generated random number does not exceed requested size */
	/* Preload random number with fixed pattern */
	memset(rand1.data, TEST_BYTE, V2XSE_MAX_RND_NUM_SIZE);
	/* Generate limited size random number */
	retVal = v2xSe_getRandomNumber(sizeof(long), &statusCode, &rand1);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRandomNumber returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify data after requested size is unchanged */
	for (i = sizeof(long); i < V2XSE_MAX_RND_NUM_SIZE; i++) {
		if (rand1.data[i] != TEST_BYTE) {
			printf("ERROR: v2xSe_getRandomNumber overflowed\n");
			return VTEST_FAIL;
		}
	}

/* Test two successive random numbers are different */
	/* Get another random number */
	retVal = v2xSe_getRandomNumber(sizeof(long), &statusCode, &rand2);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRandomNumber returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Make sure they are different */
	if (!memcmp(rand1.data, rand2.data, sizeof(long))) {
		printf("ERROR: Identical random numbers generated\n");
		printf(" rand1: 0x%lx, rand2: 0x%lx\n", *(long*)(rand1.data),
							*(long*)(rand2.data));
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getKeyLenFromCurveID(void)
{
	int32_t keyLen;

/* Test size V2XSE_256_EC_PUB_KEY returned for all 256 bit curves */
	/* Verify key length for V2XSE_CURVE_NISTP256 */
	keyLen = v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_NISTP256);
	if (keyLen != V2XSE_256_EC_PUB_KEY) {
		printf("ERROR: v2xSe_getKeyLenFromCurveID for %d gave %d\n",
						V2XSE_CURVE_NISTP256, keyLen);
		return VTEST_FAIL;
	}
	/* Verify key length for V2XSE_CURVE_BP256R1 */
	keyLen = v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_BP256R1);
	if (keyLen != V2XSE_256_EC_PUB_KEY) {
		printf("ERROR: v2xSe_getKeyLenFromCurveID for %d gave %d\n",
						V2XSE_CURVE_BP256R1, keyLen);
		return VTEST_FAIL;
	}
	/* Verify key length for V2XSE_CURVE_BP256T1 */
	keyLen = v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_BP256T1);
	if (keyLen != V2XSE_256_EC_PUB_KEY) {
		printf("ERROR: v2xSe_getKeyLenFromCurveID for %d gave %d\n",
						V2XSE_CURVE_BP256T1, keyLen);
		return VTEST_FAIL;
	}

/* Test size V2XSE_384_EC_PUB_KEY returned for all 384 bit curves */
	/* Verify key length for V2XSE_CURVE_NISTP256 */
	keyLen = v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_NISTP384);
	if (keyLen != V2XSE_384_EC_PUB_KEY) {
		printf("ERROR: v2xSe_getKeyLenFromCurveID for %d gave %d\n",
						V2XSE_CURVE_NISTP384, keyLen);
		return VTEST_FAIL;
	}
	/* Verify key length for V2XSE_CURVE_BP384R1 */
	keyLen = v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_BP384R1);
	if (keyLen != V2XSE_384_EC_PUB_KEY) {
		printf("ERROR: v2xSe_getKeyLenFromCurveID for %d gave %d\n",
						V2XSE_CURVE_BP384R1, keyLen);
		return VTEST_FAIL;
	}
	/* Verify key length for V2XSE_CURVE_BP384T1 */
	keyLen = v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_BP384T1);
	if (keyLen != V2XSE_384_EC_PUB_KEY) {
		printf("ERROR: v2xSe_getKeyLenFromCurveID for %d gave %d\n",
						V2XSE_CURVE_BP384T1, keyLen);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getSigLenFromHashLen(void)
{
	int32_t sigLen;

/* Test size 64 returned for V2XSE_256_EC_HASH_SIZE */
	sigLen = v2xSe_getSigLenFromHashLen(V2XSE_256_EC_HASH_SIZE);
	if (sigLen != 64) {
		printf("ERROR: v2xSe_getSigLenFromHashLen for %d gave %d\n",
					V2XSE_256_EC_HASH_SIZE, sigLen);
		return VTEST_FAIL;
	}

/* Test size 96 returned for V2XSE_384_EC_HASH_SIZE */
	sigLen = v2xSe_getSigLenFromHashLen(V2XSE_384_EC_HASH_SIZE);
	if (sigLen != 96) {
		printf("ERROR: v2xSe_getSigLenFromHashLen for %d gave %d\n",
					V2XSE_384_EC_HASH_SIZE, sigLen);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
}
