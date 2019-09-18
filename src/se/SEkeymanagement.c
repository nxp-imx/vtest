
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
 * @file SEkeymanagement.c
 *
 * @brief Tests for SE Key Management (requirements R6.*)
 *
 */

#include <time.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEkeymanagement.h"

/**
 *
 * @brief Test v2xSe_generateMaEccKeyPair for expected behaviour
 *
 * This function tests v2xSe_generateMaEccKeyPair for expected behaviour
 * The following behaviours are tested:
 *  - MA key can be generated and retrieved for EU applet
 *  - MA key can be generated and retrieved for US applet
 *  - MA key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved
 *  - MA key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved
 *  - MA key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved
 *  - MA key for curve V2XSE_CURVE_NISTP384 can be generated and retrieved
 *  - MA key for curve V2XSE_CURVE_BP384R1 can be generated and retrieved
 *  - MA key for curve V2XSE_CURVE_BP384T1 can be generated and retrieved
 *
 */
void test_generateMaEccKeyPair(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;

/* Test MA key can be generated and retrieved for EU applet */
/* Test MA key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Create MA key */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP256,
		&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve MA public key */
	VTEST_CHECK_RESULT(v2xSe_getMaEccPublicKey(&statusCode, &curveId,
						&pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP256);

/* Test MA key can be generated and retrieved for US applet */
/* Test MA key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(US_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode, US applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Create MA key */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP256R1,
		&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve MA public key */
	VTEST_CHECK_RESULT(v2xSe_getMaEccPublicKey(&statusCode, &curveId,
						&pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256R1);

/* Test MA key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Create MA key */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP256T1,
		&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve MA public key */
	VTEST_CHECK_RESULT(v2xSe_getMaEccPublicKey(&statusCode, &curveId,
						&pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256T1);

/* Test MA key for curve V2XSE_CURVE_NISTP384 can be generated and retrieved */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Create MA key */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP384,
		&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve MA public key */
	VTEST_CHECK_RESULT(v2xSe_getMaEccPublicKey(&statusCode, &curveId,
						&pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP384);

/* Test MA key for curve V2XSE_CURVE_BP384R1 can be generated and retrieved */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Create MA key */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP384R1,
		&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve MA public key */
	VTEST_CHECK_RESULT(v2xSe_getMaEccPublicKey(&statusCode, &curveId,
						&pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP384R1);

/* Test MA key for curve V2XSE_CURVE_BP384T1 can be generated and retrieved */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Create MA key */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP384T1,
		&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve MA public key */
	VTEST_CHECK_RESULT(v2xSe_getMaEccPublicKey(&statusCode, &curveId,
						&pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP384T1);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_generateRtEccKeyPair for keys in empty slots
 *
 * This function tests v2xSe_generateRtEccKeyPair for keys in empty slots
 * The following behaviours are tested:
 *  - Rt key can be generated and retrieved for EU applet
 *  - Rt key can be generated and retrieved for US applet
 *  - Rt key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved
 *  - Rt key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved
 *  - Rt key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved
 *  - Rt key can be generated and retrieved in slot 0
 *  - Rt key can be generated and retrieved in non-zero slot
 *  - Rt key can be generated and retrieved in max slot
 *
 */
void test_generateRtEccKeyPair_empty(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Rt key can be generated and retrieved for EU applet */
/* Test Rt key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxDataSlots <= NON_ZERO_SLOT, 0);
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Create Rt key */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP256);

/* Test Rt key can be generated and retrieved for US applet */
/* Test Rt key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(NON_ZERO_SLOT, &statusCode);
	/* Create Rt key */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode,
		&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256R1);

/* Test Rt key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in max slot */
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(MAX_SLOT, &statusCode);
	/* Create Rt key */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(MAX_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(MAX_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256T1);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_generateRtEccKeyPair for keys in full slots
 *
 * This function tests v2xSe_generateRtEccKeyPair for keys in full slots
 * The following behaviours are tested:
 *  - Rt key can be generated and retrieved for EU applet
 *  - Rt key can be generated and retrieved for US applet
 *  - Rt key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved
 *  - Rt key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved
 *  - Rt key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved
 *  - Rt key can be generated and retrieved in slot 0
 *  - Rt key can be generated and retrieved in non-zero slot
 *  - Rt key can be generated and retrieved in max slot
 *
 */
void test_generateRtEccKeyPair_overwrite(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Rt key can be generated and retrieved for EU applet */
/* Test Rt key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxDataSlots <= NON_ZERO_SLOT, 0);
	/* Create Rt key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create Rt key */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP256);

/* Test Rt key can be generated and retrieved for US applet */
/* Test Rt key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Create Rt key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create Rt key */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode,
		&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256R1);

/* Test Rt key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in max slot */
	/* Create Rt key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(MAX_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create Rt key */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(MAX_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(MAX_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256T1);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_deleteRtEccPrivateKey for existing keys
 *
 * This function tests v2xSe_deleteRtEccPrivateKey for existing keys
 * The following behaviours are tested:
 *  - Rt key can be deleted for EU applet
 *  - Rt key can be deleted for US applet
 *  - Rt key can be generated and retrieved in slot 0
 *  - Rt key can be generated and retrieved in non-zero slot
 *  - Rt key can be generated and retrieved in max slot
 *  - deleting rt key in slot 0 does not affect rt key in non-zero slot
 *
 */
void test_deleteRtEccPrivateKey(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Rt key can be deleted for EU applet */
/* Test Rt key can be deleted in slot 0 */
/* Rt key can be generated and retrieved in non-zero slot */
/* Test deleting rt key in slot 0 does not affect rt key in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxDataSlots <= NON_ZERO_SLOT, 0);
	/* Create Rt key in slot 0 - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Rt public key - verify key present */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Create Rt key in non-zero slot - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Rt public key - verify key present */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode,
		&curveId, &pubKey), V2XSE_SUCCESS);
	/* Delete key in slot 0 */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);
	/* Verify can no longer retrieve key in slot 0 */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_FAILURE);
	/* Retrieve Rt public key on non-zero slot - verify key still present */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode,
		&curveId, &pubKey), V2XSE_SUCCESS);
	/* Delete key in non-zero slot */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(NON_ZERO_SLOT,
		&statusCode), V2XSE_SUCCESS);
	/* Verify can no longer retrieve key in non-zero slot */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode,
		&curveId, &pubKey), V2XSE_FAILURE);

/* Test Rt key can be deleted for US applet */
/* Test Rt key can be deleted in max slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Create Rt key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(MAX_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(MAX_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Delete key in max slot */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(MAX_SLOT, &statusCode),
								V2XSE_SUCCESS);
	/* Verify can no longer retrieve key in max slot */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(MAX_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_FAILURE);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_generateBaEccKeyPair for keys in empty slots
 *
 * This function tests v2xSe_generateBaEccKeyPair for keys in empty slots
 * The following behaviours are tested:
 *  - Ba key can be generated and retrieved for EU applet
 *  - Ba key can be generated and retrieved for US applet
 *  - Ba key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved
 *  - Ba key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved
 *  - Ba key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved
 *  - Ba key for curve V2XSE_CURVE_NISTP384 can be generated and retrieved
 *  - Ba key for curve V2XSE_CURVE_BP384R1 can be generated and retrieved
 *  - Ba key for curve V2XSE_CURVE_BP384T1 can be generated and retrieved
 *  - Ba key can be generated and retrieved in slot 0
 *  - Ba key can be generated and retrieved in non-zero slot
 *  - Ba key can be generated and retrieved in max slot
 *
 */
void test_generateBaEccKeyPair_empty(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Ba key can be generated and retrieved for EU applet */
/* Test Ba key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxDataSlots <= NON_ZERO_SLOT, 0);
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP256);

/* Test Ba key can be generated and retrieved for US applet */
/* Test Ba key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(NON_ZERO_SLOT, &statusCode);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256R1);

/* Test Ba key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in max slot */
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(MAX_SLOT, &statusCode);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(MAX_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(MAX_SLOT, &statusCode,
		&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256T1);

/* Test Ba key for curve V2XSE_CURVE_NISTP384 can be generated and retrieved */
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP384, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP384);

/* Test Ba key for curve V2XSE_CURVE_BP384R1 can be generated and retrieved */
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP384R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP384R1);

/* Test Ba key for curve V2XSE_CURVE_BP384T1 can be generated and retrieved */
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP384T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP384T1);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_generateBaEccKeyPair for keys in full slots
 *
 * This function tests v2xSe_generateBaEccKeyPair for keys in full slots
 * The following behaviours are tested:
 *  - Ba key can be generated and retrieved for EU applet
 *  - Ba key can be generated and retrieved for US applet
 *  - Ba key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved
 *  - Ba key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved
 *  - Ba key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved
 *  - Ba key for curve V2XSE_CURVE_NISTP384 can be generated and retrieved
 *  - Ba key for curve V2XSE_CURVE_BP384R1 can be generated and retrieved
 *  - Ba key for curve V2XSE_CURVE_BP384T1 can be generated and retrieved
 *  - Ba key can be generated and retrieved in slot 0
 *  - Ba key can be generated and retrieved in non-zero slot
 *  - Ba key can be generated and retrieved in max slot
 *
  */
void test_generateBaEccKeyPair_overwrite(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Ba key can be generated and retrieved for EU applet */
/* Test Ba key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxDataSlots <= NON_ZERO_SLOT, 0);
	/* Create Ba key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP256);

/* Test Ba key can be generated and retrieved for US applet */
/* Test Ba key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Create Ba key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256R1);

/* Test Ba key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in max slot */
	/* Create Ba key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(MAX_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(MAX_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(MAX_SLOT, &statusCode,
		&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256T1);

/* Test Ba key for curve V2XSE_CURVE_NISTP384 can be generated and retrieved */
	/* Create Ba key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP384, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP384);

/* Test Ba key for curve V2XSE_CURVE_BP384R1 can be generated and retrieved */
	/* Create Ba key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP384R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP384R1);

/* Test Ba key for curve V2XSE_CURVE_BP384T1 can be generated and retrieved */
	/* Create Ba key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create Ba key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP384T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP384T1);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_deleteBaEccPrivateKey for existing keys
 *
 * This function tests v2xSe_deleteBaEccPrivateKey for existing keys
 * The following behaviours are tested:
 *  - Ba key can be deleted for EU applet
 *  - Ba key can be deleted for US applet
 *  - Ba key can be generated and retrieved in slot 0
 *  - Ba key can be generated and retrieved in non-zero slot
 *  - Ba key can be generated and retrieved in max slot
 *  - deleting Ba key in slot 0 does not affect Ba key in non-zero slot
 *
 */
void test_deleteBaEccPrivateKey(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Ba key can be deleted for EU applet */
/* Test Ba key can be deleted in slot 0 */
/* Test Ba key can be generated and retrieved in non-zero slot */
/* Test deleting Ba key in slot 0 does not affect Ba key in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxDataSlots <= NON_ZERO_SLOT, 0);
	/* Create Ba key in slot 0 - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key - verify key present */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Create Ba key in non-zero slot - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key - verify key present */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Delete key in slot 0 */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);
	/* Verify can no longer retrieve key in slot 0 */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_FAILURE);
	/* Retrieve Ba public key on non-zero slot - verify key still present */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Delete key in non-zero slot */
	VTEST_CHECK_RESULT( v2xSe_deleteBaEccPrivateKey(NON_ZERO_SLOT,
						&statusCode), V2XSE_SUCCESS);
	/* Verify can no longer retrieve key in non-zero slot */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode,
		&curveId, &pubKey), V2XSE_FAILURE);

/* Test Ba key can be deleted for US applet */
/* Test Ba key can be deleted in max slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Create Ba key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(MAX_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Retrieve Ba public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(MAX_SLOT, &statusCode,
		&curveId, &pubKey), V2XSE_SUCCESS);
	/* Delete key in max slot */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(MAX_SLOT, &statusCode),
								V2XSE_SUCCESS);
	/* Verify can no longer retrieve key in max slot */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(MAX_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_FAILURE);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_deriveRtEccKeyPair for keys in empty slots
 *
 * This function tests v2xSe_deriveRtEccKeyPair for keys in empty slots
 * The following behaviours are tested:
 *  - Rt key for curve V2XSE_CURVE_NISTP256 can be derived and retrieved
 *  - Rt key for curve V2XSE_CURVE_BP256R1 can be derived and retrieved
 *  - Rt key for curve V2XSE_CURVE_BP256T1 can be derived and retrieved
 *  - Rt key can be derived and retrieved in slot 0
 *  - Rt key can be derived and retrieved in non-zero slot
 *  - Rt key can be derived and retrieved in max slot
 *
 */
void test_deriveRtEccKeyPair_empty(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;
	TypeInt256_t data1;
	TypeInt256_t data2;
	TypeInt256_t data3;

	/* Move to ACTIVATED state, normal operating mode, US applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxDataSlots <= NON_ZERO_SLOT, 0);
	/* Set up key derivation parameters */
	data1.data[0] = 1;
	data2.data[0] = 2;
	data3.data[0] = 3;

/* Test Rt key for curve V2XSE_CURVE_NISTP256 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in slot 0 */
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Generate Ba key to use in derivation - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(MAX_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Derive Rt key */
	VTEST_CHECK_RESULT( v2xSe_deriveRtEccKeyPair(MAX_SLOT, &data1, &data2,
		&data3, SLOT_ZERO, V2XSE_RSP_WITH_PUBKEY, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP256);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode,
		&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP256);

/* Test Rt key for curve V2XSE_CURVE_BP256R1 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in non-zero slot */
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(NON_ZERO_SLOT, &statusCode);
	/* Generate Ba key to use in derivation - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Derive Rt key */
	VTEST_CHECK_RESULT(v2xSe_deriveRtEccKeyPair(SLOT_ZERO, &data1, &data2,
		&data3,	NON_ZERO_SLOT, V2XSE_RSP_WITH_PUBKEY, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256R1);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256R1);

/* Test Rt key for curve V2XSE_CURVE_BP256T1 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in max slot */
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(MAX_SLOT, &statusCode);
	/* Generate Ba key to use in derivation - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Derive Rt key */
	VTEST_CHECK_RESULT(v2xSe_deriveRtEccKeyPair(SLOT_ZERO, &data1, &data2,
		&data3,	MAX_SLOT, V2XSE_RSP_WITH_PUBKEY, &statusCode, &curveId,
						&pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256T1);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(MAX_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256T1);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_deriveRtEccKeyPair for keys in full slots
 *
 * This function tests v2xSe_deriveRtEccKeyPair for keys in full slots
 * The following behaviours are tested:
 *  - Rt key for curve V2XSE_CURVE_NISTP256 can be derived and retrieved
 *  - Rt key for curve V2XSE_CURVE_BP256R1 can be derived and retrieved
 *  - Rt key for curve V2XSE_CURVE_BP256T1 can be derived and retrieved
 *  - Rt key can be derived and retrieved in slot 0
 *  - Rt key can be derived and retrieved in non-zero slot
 *  - Rt key can be derived and retrieved in max slot
 *
 */
void test_deriveRtEccKeyPair_overwrite(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;
	TypeInt256_t data1;
	TypeInt256_t data2;
	TypeInt256_t data3;

	/* Move to ACTIVATED state, normal operating mode, US applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxDataSlots <= NON_ZERO_SLOT, 0);
	/* Set up key derivation parameters */
	data1.data[0] = 1;
	data2.data[0] = 2;
	data3.data[0] = 3;

/* Test Rt key for curve V2XSE_CURVE_NISTP256 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in slot 0 */
	/* Create Rt key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Generate Ba key to use in derivation - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(MAX_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Derive Rt key */
	VTEST_CHECK_RESULT( v2xSe_deriveRtEccKeyPair(MAX_SLOT, &data1, &data2,
		&data3, SLOT_ZERO, V2XSE_RSP_WITH_PUBKEY, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP256);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode,
		&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_NISTP256);

/* Test Rt key for curve V2XSE_CURVE_BP256R1 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in non-zero slot */
	/* Create Rt key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Generate Ba key to use in derivation - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Derive Rt key */
	VTEST_CHECK_RESULT(v2xSe_deriveRtEccKeyPair(SLOT_ZERO, &data1, &data2,
		&data3,	NON_ZERO_SLOT, V2XSE_RSP_WITH_PUBKEY, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256R1);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256R1);

/* Test Rt key for curve V2XSE_CURVE_BP256T1 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in max slot */
	/* Create Rt key - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(MAX_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Generate Ba key to use in derivation - may overwrite */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Derive Rt key */
	VTEST_CHECK_RESULT(v2xSe_deriveRtEccKeyPair(SLOT_ZERO, &data1, &data2,
		&data3,	MAX_SLOT, V2XSE_RSP_WITH_PUBKEY, &statusCode, &curveId,
						&pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256T1);
	/* Retrieve Rt public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(MAX_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify curveId is correct */
	VTEST_CHECK_RESULT(curveId, V2XSE_CURVE_BP256T1);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_activateRtKeyForSigning for expected behaviour
 *
 * This function tests v2xSe_activateRtKeyForSigning for expected behaviour
 * The following behaviours are tested:
 *  - signature generated with valid inputs
 * TODO: try different algs, different slots...
 *
 */
void test_activateRtKeyForSigning(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeHash_t hash;
	TypeSignature_t signature;
	TypeLowlatencyIndicator_t fastIndicator;

	/* Create dummy hash data */
	hash.data[0] = 20;
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
 * @brief Test speed of run time key creation
 *
 * This function tests the speed of run time key creation
 * The following behaviours are tested:
 *  - key generated in empty slot
 * TODO: try different key types, update, more keys for better accuracy
 *
 */
void test_rtKeyCreationSpeed(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	int i;
	struct timespec startTime, endTime;
	long nsTimeDiff;
	float keySpeedMs;

/* Measure speed of creating NIST P256 key in empty slot */
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);

	/* Delete any existing keys, ignore errors if no key present in slot */
	for (i = 0; i < KEY_SPEED_CREATE_NUM; i++)
		v2xSe_deleteRtEccPrivateKey(i, &statusCode);

	/* Log start time */
	if (clock_gettime(CLOCK_BOOTTIME, &startTime) == -1) {
		VTEST_FLAG_CONF();
		return;
	}

	/* Create the keys */
	for (i = 0; i < KEY_SPEED_CREATE_NUM; i++)
		VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(i,
			V2XSE_CURVE_NISTP256, &statusCode, &pubKey),
								V2XSE_SUCCESS);
	/* Log end time */
	if (clock_gettime(CLOCK_BOOTTIME, &endTime) == -1) {
		VTEST_FLAG_CONF();
		return;
	}

	/* Calculate elapsed time and key create time */
	nsTimeDiff = (endTime.tv_sec - startTime.tv_sec) * 1000000000;
	nsTimeDiff += endTime.tv_nsec;
	nsTimeDiff -= startTime.tv_nsec;
	VTEST_LOG("Elapsed time for %d keys: %ld ns\n", KEY_SPEED_CREATE_NUM,
								nsTimeDiff);
	keySpeedMs = nsTimeDiff / (float)KEY_SPEED_CREATE_NUM / (float)1000000;
	VTEST_LOG("Key creation time: %.2f ms\n", keySpeedMs);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

	/* Need to define pass/fail criteria */
	VTEST_FLAG_CONF();
}

/**
 *
 * @brief Test speed of base key creation
 *
 * This function tests the speed of base key creation
 * The following behaviours are tested:
 *  - key generated in empty slot
 * TODO: try different key types, update, more keys for better accuracy
 *
 */
void test_baKeyCreationSpeed(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	int i;
	struct timespec startTime, endTime;
	long nsTimeDiff;
	float keySpeedMs;

/* Measure speed of creating NIST P256 key in empty slot */
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);

	/* Delete any existing keys, ignore errors if no key present in slot */
	for (i = 0; i < KEY_SPEED_CREATE_NUM; i++)
		v2xSe_deleteBaEccPrivateKey(i, &statusCode);

	/* Log start time */
	if (clock_gettime(CLOCK_BOOTTIME, &startTime) == -1) {
		VTEST_FLAG_CONF();
		return;
	}

	/* Create the keys */
	for (i = 0; i < KEY_SPEED_CREATE_NUM; i++)
		VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(i,
			V2XSE_CURVE_NISTP256, &statusCode, &pubKey),
								V2XSE_SUCCESS);
	/* Log end time */
	if (clock_gettime(CLOCK_BOOTTIME, &endTime) == -1) {
		VTEST_FLAG_CONF();
		return;
	}

	/* Calculate elapsed time and key create time */
	nsTimeDiff = (endTime.tv_sec - startTime.tv_sec) * 1000000000;
	nsTimeDiff += endTime.tv_nsec;
	nsTimeDiff -= startTime.tv_nsec;
	VTEST_LOG("Elapsed time for %d keys: %ld ns\n", KEY_SPEED_CREATE_NUM,
								nsTimeDiff);
	keySpeedMs = nsTimeDiff / (float)KEY_SPEED_CREATE_NUM / (float)1000000;
	VTEST_LOG("Key creation time: %.2f ms\n", keySpeedMs);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

	/* Need to define pass/fail criteria */
	VTEST_FLAG_CONF();
}
