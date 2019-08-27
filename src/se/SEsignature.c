
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

#include <v2xseapi.h>
#include "vtest.h"
#include "SEmisc.h"
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
 */
void test_createBaSign(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeHash_t hash;
	TypeSignature_t signature;

	/* Create dummy hash data */
	hash.data[0] = 14;
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Make sure BA key exists */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createBaSign(SLOT_ZERO, 32, &hash,
		&statusCode, &signature), V2XSE_SUCCESS);
	/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
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
  */
void test_createMaSign(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeHash_t hash;
	TypeSignature_t signature;

	/* Create dummy hash data */
	hash.data[0] = 15;
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(),VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate MA key of known curveId */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP256,
					&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT( v2xSe_createMaSign(32, &hash, &statusCode,
						&signature), V2XSE_SUCCESS);

	/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
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
 */
void test_createRtSignLowLatency(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeHash_t hash;
	TypeSignature_t signature;
	TypeLowlatencyIndicator_t fastIndicator;

	/* Create dummy hash data */
	hash.data[0] = 17;
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Make sure RT key exists */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Activate key for low latency signature */
	VTEST_CHECK_RESULT(v2xSe_activateRtKeyForSigning(NON_ZERO_SLOT,
						&statusCode), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createRtSignLowLatency(&hash, &statusCode,
				&signature, &fastIndicator), V2XSE_SUCCESS);
	VTEST_CHECK_RESULT(fastIndicator, 1);

	/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
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
 */
void test_createRtSign(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeHash_t hash;
	TypeSignature_t signature;

	/* Create dummy hash data */
	hash.data[0] = 16;
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Make sure RT key exists */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createRtSign(NON_ZERO_SLOT, &hash,
				&statusCode, &signature), V2XSE_SUCCESS);

	/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}
