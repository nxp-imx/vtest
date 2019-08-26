
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEsignature.c
 *
 * @brief Tests for SE Signature (requirements R7.*)
 *
 */

#include <stdio.h>
#include <v2xseapi.h>
#include "vtest.h"
#include "SEsignature.h"

/**
 *
 * @brief Test v2xSe_createBaSign for expected behaviour
 *
 * This function tests v2xSe_createBaSign for expected behaviour
 * The following behaviours are tested:
 *  - signature generated with valid inputs
 * TODO: try different algs, verify signature, different slots...
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_createBaSign(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeHash_t hash;
	TypeSignature_t signature;

	/* Create dummy hash data */
	hash.data[0] = 14;
	/* Move to ACTIVATED state, normal operating mode */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Make sure BA key exists */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_NISTP256,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create signature */
	retVal = v2xSe_createBaSign(SLOT_ZERO, 32, &hash, &statusCode,
								&signature);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_createBaSign returned %d\n",
								retVal);
		return VTEST_FAIL;
	}

	/* TODO: verify signature - test should return CONF until then */
	return VTEST_CONF;
}

/**
 *
 * @brief Test v2xSe_createMaSign for expected behaviour
 *
 * This function tests v2xSe_createMaSign for expected behaviour
 * The following behaviours are tested:
 *  - signature generated with valid inputs
 * TODO: try different algs, verify signature, different applet...
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_createMaSign(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeHash_t hash;
	TypeSignature_t signature;

	/* Create dummy hash data */
	hash.data[0] = 15;
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force reset of all keys */
	if (removeNvmVariable(EU_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete EU phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state, normal operating mode */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Generate MA key of known curveId */
	retVal = v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP256, &statusCode,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateMaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create signature */
	retVal = v2xSe_createMaSign(32, &hash, &statusCode, &signature);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_createMaSign returned %d\n", retVal);
		return VTEST_FAIL;
	}

	/* TODO: verify signature - test should return CONF until then */
	return VTEST_CONF;
}

/**
 *
 * @brief Test v2xSe_createRtSignLowLatency for expected behaviour
 *
 * This function tests v2xSe_createRtSignLowLatency for expected behaviour
 * The following behaviours are tested:
 *  - signature generated with valid inputs
 * TODO: try different algs, verify signature, different slots...
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_createRtSignLowLatency(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeHash_t hash;
	TypeSignature_t signature;
	TypeLowlatencyIndicator_t fastIndicator;

	/* Create dummy hash data */
	hash.data[0] = 17;
	/* Move to ACTIVATED state, normal operating mode */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Make sure RT key exists */
	retVal = v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT, V2XSE_CURVE_BP256R1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Activate key for low latency signature */
	retVal = v2xSe_activateRtKeyForSigning(NON_ZERO_SLOT, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_activateRtKeyForSigning returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create signature */
	retVal = v2xSe_createRtSignLowLatency(&hash, &statusCode, &signature,
							&fastIndicator);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_createRtSignLowLatency returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	if (fastIndicator != 1) {
		printf("ERROR: Slow signature indicated\n");
		return VTEST_FAIL;

	}

	/* TODO: verify signature - test should return CONF until then */
	return VTEST_CONF;
}

/**
 *
 * @brief Test v2xSe_createRtSign for expected behaviour
 *
 * This function tests v2xSe_createRtSign for expected behaviour
 * The following behaviours are tested:
 *  - signature generated with valid inputs
 * TODO: try different algs, verify signature, different slots...
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_createRtSign(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeHash_t hash;
	TypeSignature_t signature;

	/* Create dummy hash data */
	hash.data[0] = 16;
	/* Move to ACTIVATED state, normal operating mode */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Make sure RT key exists */
	retVal = v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT, V2XSE_CURVE_BP256R1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create signature */
	retVal = v2xSe_createRtSign(NON_ZERO_SLOT, &hash, &statusCode,
								&signature);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_createRtSign returned %d\n",
								retVal);
		return VTEST_FAIL;
	}

	/* TODO: verify signature - test should return CONF until then */
	return VTEST_CONF;
}
