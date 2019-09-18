
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
 * @file SEsignature.c
 *
 * @brief Tests for SE Signature (requirements R7.*)
 *
 */

#include <v2xSe.h>
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

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

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

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

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
	VTEST_CHECK_RESULT(fastIndicator, 0);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

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

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}
