
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEkeymanagement.c
 *
 * @brief Tests for SE Key Management (requirements R6.*)
 *
 */

#include <stdio.h>
#include <v2xseapi.h>
#include "vtest.h"
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_generateMaEccKeyPair(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;

/* Test MA key can be generated and retrieved for EU applet */
/* Test MA key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force reset of all keys */
	if (removeNvmVariable(EU_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete EU phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Create MA key */
	retVal = v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP256, &statusCode,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateMaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive MA public key */
	retVal = v2xSe_getMaEccPublicKey(&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getMaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP256) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP256, curveId);
		return VTEST_FAIL;
	}

/* Test MA key can be generated and retrieved for US applet */
/* Test MA key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force reset of all keys */
	if (removeNvmVariable(US_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete US phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state, normal operating mode, US applet */
	if (setupActivatedNormalState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Create MA key */
	retVal = v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP256R1, &statusCode,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateMaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive MA public key */
	retVal = v2xSe_getMaEccPublicKey(&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getMaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256R1, curveId);
		return VTEST_FAIL;
	}

/* Test MA key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force reset of all keys */
	if (removeNvmVariable(EU_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete EU phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Create MA key */
	retVal = v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP256T1, &statusCode,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateMaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive MA public key */
	retVal = v2xSe_getMaEccPublicKey(&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getMaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256T1, curveId);
		return VTEST_FAIL;
	}

/* Test MA key for curve V2XSE_CURVE_NISTP384 can be generated and retrieved */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force reset of all keys */
	if (removeNvmVariable(EU_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete EU phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Create MA key */
	retVal = v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP384, &statusCode,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateMaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive MA public key */
	retVal = v2xSe_getMaEccPublicKey(&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getMaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP384) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP384, curveId);
		return VTEST_FAIL;
	}

/* Test MA key for curve V2XSE_CURVE_BP384R1 can be generated and retrieved */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force reset of all keys */
	if (removeNvmVariable(EU_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete EU phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Create MA key */
	retVal = v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP384R1, &statusCode,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateMaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive MA public key */
	retVal = v2xSe_getMaEccPublicKey(&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getMaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP384R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP384R1, curveId);
		return VTEST_FAIL;
	}

/* Test MA key for curve V2XSE_CURVE_BP384T1 can be generated and retrieved */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force reset of all keys */
	if (removeNvmVariable(EU_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete EU phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Create MA key */
	retVal = v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP384T1, &statusCode,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateMaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive MA public key */
	retVal = v2xSe_getMaEccPublicKey(&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getMaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP384T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP384T1, curveId);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_generateRtEccKeyPair_empty(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Rt key can be generated and retrieved for EU applet */
/* Test Rt key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Get SE info, to know max data slot available */
	retVal = v2xSe_getSeInfo(&statusCode, &seInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSeInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	if (seInfo.maxDataSlots <= NON_ZERO_SLOT) {
		printf("ERROR: Only %d slots, test needs modification\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Create Rt key */
	retVal = v2xSe_generateRtEccKeyPair(SLOT_ZERO, V2XSE_CURVE_NISTP256,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP256) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP256, curveId);
		return VTEST_FAIL;
	}

/* Test Rt key can be generated and retrieved for US applet */
/* Test Rt key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	if (setupActivatedNormalState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(NON_ZERO_SLOT, &statusCode);
	/* Create Rt key */
	retVal = v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
				V2XSE_CURVE_BP256R1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256R1, curveId);
		return VTEST_FAIL;
	}

/* Test Rt key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in max slot */
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(MAX_SLOT, &statusCode);
	/* Create Rt key */
	retVal = v2xSe_generateRtEccKeyPair(MAX_SLOT,
				V2XSE_CURVE_BP256T1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(MAX_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256T1, curveId);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_generateRtEccKeyPair_overwrite(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Rt key can be generated and retrieved for EU applet */
/* Test Rt key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Get SE info, to know max data slot available */
	retVal = v2xSe_getSeInfo(&statusCode, &seInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSeInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	if (seInfo.maxDataSlots <= NON_ZERO_SLOT) {
		printf("ERROR: Only %d slots, test needs modification\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Rt key - may overwrite */
	retVal = v2xSe_generateRtEccKeyPair(SLOT_ZERO,
				V2XSE_CURVE_BP256R1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Rt key */
	retVal = v2xSe_generateRtEccKeyPair(SLOT_ZERO, V2XSE_CURVE_NISTP256,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP256) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP256, curveId);
		return VTEST_FAIL;
	}

/* Test Rt key can be generated and retrieved for US applet */
/* Test Rt key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	if (setupActivatedNormalState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Create Rt key - may overwrite */
	retVal = v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
				V2XSE_CURVE_BP256R1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Rt key */
	retVal = v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
				V2XSE_CURVE_BP256R1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256R1, curveId);
		return VTEST_FAIL;
	}

/* Test Rt key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved */
/* Test Rt key can be generated and retrieved in max slot */
	/* Create Rt key - may overwrite */
	retVal = v2xSe_generateRtEccKeyPair(MAX_SLOT,
				V2XSE_CURVE_BP256T1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Rt key */
	retVal = v2xSe_generateRtEccKeyPair(MAX_SLOT,
				V2XSE_CURVE_BP256T1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(MAX_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256T1, curveId);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_deleteRtEccPrivateKey(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Rt key can be deleted for EU applet */
/* Test Rt key can be deleted in slot 0 */
/* Rt key can be generated and retrieved in non-zero slot */
/* Test deleting rt key in slot 0 does not affect rt key in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Get SE info, to know max data slot available */
	retVal = v2xSe_getSeInfo(&statusCode, &seInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSeInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	if (seInfo.maxDataSlots <= NON_ZERO_SLOT) {
		printf("ERROR: Only %d slots, test needs modification\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Rt key in slot 0 - may overwrite */
	retVal = v2xSe_generateRtEccKeyPair(SLOT_ZERO, V2XSE_CURVE_NISTP256,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key - verify key present */
	retVal = v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Create Rt key in non-zero slot - may overwrite */
	retVal = v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT, V2XSE_CURVE_BP256R1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key - verify key present */
	retVal = v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Delete key in slot 0 */
	retVal = v2xSe_deleteRtEccPrivateKey(SLOT_ZERO, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deleteRtEccPrivateKey returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify can no longer retrive key in slot 0 */
	retVal = v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal == V2XSE_SUCCESS) {
		printf("ERROR: Key not deleted\n");
		return VTEST_FAIL;
	}
	/* Retrive Rt public key on non-zero slot - verify key still present */
	retVal = v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Delete key in non-zero slot */
	retVal = v2xSe_deleteRtEccPrivateKey(NON_ZERO_SLOT, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deleteRtEccPrivateKey returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify can no longer retrive key in non-zero slot */
	retVal = v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal == V2XSE_SUCCESS) {
		printf("ERROR: Key not deleted\n");
		return VTEST_FAIL;
	}


/* Test Rt key can be deleted for US applet */
/* Test Rt key can be deleted in max slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	if (setupActivatedNormalState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Create Rt key - may overwrite */
	retVal = v2xSe_generateRtEccKeyPair(MAX_SLOT,
				V2XSE_CURVE_BP256T1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Delete key in max slot */
	retVal = v2xSe_deleteRtEccPrivateKey(MAX_SLOT, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deleteRtEccPrivateKey returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify can no longer retrive key in max slot */
	retVal = v2xSe_getRtEccPublicKey(MAX_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal == V2XSE_SUCCESS) {
		printf("ERROR: Key not deleted\n");
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_generateBaEccKeyPair_empty(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Ba key can be generated and retrieved for EU applet */
/* Test Ba key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Get SE info, to know max data slot available */
	retVal = v2xSe_getSeInfo(&statusCode, &seInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSeInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	if (seInfo.maxDataSlots <= NON_ZERO_SLOT) {
		printf("ERROR: Only %d slots, test needs modification\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_NISTP256,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP256) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP256, curveId);
		return VTEST_FAIL;
	}

/* Test Ba key can be generated and retrieved for US applet */
/* Test Ba key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	if (setupActivatedNormalState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(NON_ZERO_SLOT, &statusCode);
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(NON_ZERO_SLOT,
				V2XSE_CURVE_BP256R1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256R1, curveId);
		return VTEST_FAIL;
	}

/* Test Ba key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in max slot */
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(MAX_SLOT, &statusCode);
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(MAX_SLOT,
				V2XSE_CURVE_BP256T1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(MAX_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256T1, curveId);
		return VTEST_FAIL;
	}

/* Test Ba key for curve V2XSE_CURVE_NISTP384 can be generated and retrieved */
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_NISTP384,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP384) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP384, curveId);
		return VTEST_FAIL;
	}

/* Test Ba key for curve V2XSE_CURVE_BP384R1 can be generated and retrieved */
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_BP384R1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP384R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP384R1, curveId);
		return VTEST_FAIL;
	}

/* Test Ba key for curve V2XSE_CURVE_BP384T1 can be generated and retrieved */
	/* Delete existing Ba key (ignore error if key does not exist) */
	v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_BP384T1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP384T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP384T1, curveId);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_generateBaEccKeyPair_overwrite(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Ba key can be generated and retrieved for EU applet */
/* Test Ba key for curve V2XSE_CURVE_NISTP256 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Get SE info, to know max data slot available */
	retVal = v2xSe_getSeInfo(&statusCode, &seInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSeInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	if (seInfo.maxDataSlots <= NON_ZERO_SLOT) {
		printf("ERROR: Only %d slots, test needs modification\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Ba key - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO,
				V2XSE_CURVE_NISTP256, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_NISTP256,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP256) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP256, curveId);
		return VTEST_FAIL;
	}

/* Test Ba key can be generated and retrieved for US applet */
/* Test Ba key for curve V2XSE_CURVE_BP256R1 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	if (setupActivatedNormalState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Create Ba key - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(NON_ZERO_SLOT,
				V2XSE_CURVE_BP256R1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(NON_ZERO_SLOT,
				V2XSE_CURVE_BP256R1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256R1, curveId);
		return VTEST_FAIL;
	}

/* Test Ba key for curve V2XSE_CURVE_BP256T1 can be generated and retrieved */
/* Test Ba key can be generated and retrieved in max slot */
	/* Create Ba key - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(MAX_SLOT,
				V2XSE_CURVE_BP256T1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(MAX_SLOT,
				V2XSE_CURVE_BP256T1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(MAX_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256T1, curveId);
		return VTEST_FAIL;
	}

/* Test Ba key for curve V2XSE_CURVE_NISTP384 can be generated and retrieved */
	/* Create Ba key - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO,
				V2XSE_CURVE_BP256R1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_NISTP384,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP384) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP384, curveId);
		return VTEST_FAIL;
	}

/* Test Ba key for curve V2XSE_CURVE_BP384R1 can be generated and retrieved */
	/* Create Ba key - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO,
				V2XSE_CURVE_BP256R1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_BP384R1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP384R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP384R1, curveId);
		return VTEST_FAIL;
	}

/* Test Ba key for curve V2XSE_CURVE_BP384T1 can be generated and retrieved */
	/* Create Ba key - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO,
				V2XSE_CURVE_BP256R1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Ba key */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_BP384T1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP384T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP384T1, curveId);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_deleteBaEccPrivateKey(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;

/* Test Ba key can be deleted for EU applet */
/* Test Ba key can be deleted in slot 0 */
/* Test Ba key can be generated and retrieved in non-zero slot */
/* Test deleting Ba key in slot 0 does not affect Ba key in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Get SE info, to know max data slot available */
	retVal = v2xSe_getSeInfo(&statusCode, &seInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSeInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	if (seInfo.maxDataSlots <= NON_ZERO_SLOT) {
		printf("ERROR: Only %d slots, test needs modification\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Create Ba key in slot 0 - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_NISTP256,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key - verify key present */
	retVal = v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Create Ba key in non-zero slot - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(NON_ZERO_SLOT, V2XSE_CURVE_BP256R1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key - verify key present */
	retVal = v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Delete key in slot 0 */
	retVal = v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deleteBaEccPrivateKey returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify can no longer retrive key in slot 0 */
	retVal = v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal == V2XSE_SUCCESS) {
		printf("ERROR: Key not deleted\n");
		return VTEST_FAIL;
	}
	/* Retrive Ba public key on non-zero slot - verify key still present */
	retVal = v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Delete key in non-zero slot */
	retVal = v2xSe_deleteBaEccPrivateKey(NON_ZERO_SLOT, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deleteBaEccPrivateKey returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify can no longer retrive key in non-zero slot */
	retVal = v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal == V2XSE_SUCCESS) {
		printf("ERROR: Key not deleted\n");
		return VTEST_FAIL;
	}


/* Test Ba key can be deleted for US applet */
/* Test Ba key can be deleted in max slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	if (setupActivatedNormalState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Create Ba key - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(MAX_SLOT,
				V2XSE_CURVE_BP256T1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Retrive Ba public key */
	retVal = v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getBaEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Delete key in max slot */
	retVal = v2xSe_deleteBaEccPrivateKey(MAX_SLOT, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deleteBaEccPrivateKey returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify can no longer retrive key in max slot */
	retVal = v2xSe_getBaEccPublicKey(MAX_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal == V2XSE_SUCCESS) {
		printf("ERROR: Key not deleted\n");
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_deriveRtEccKeyPair_empty(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;
	TypeInt256_t data1;
	TypeInt256_t data2;
	TypeInt256_t data3;

	/* Move to ACTIVATED state, normal operating mode, US applet */
	if (setupActivatedNormalState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Get SE info, to know max data slot available */
	retVal = v2xSe_getSeInfo(&statusCode, &seInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSeInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	if (seInfo.maxDataSlots <= NON_ZERO_SLOT) {
		printf("ERROR: Only %d slots, test needs modification\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Set up key derivation parameters */
	data1.data[0] = 1;
	data2.data[0] = 2;
	data3.data[0] = 3;

/* Test Rt key for curve V2XSE_CURVE_NISTP256 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in slot 0 */
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(SLOT_ZERO, &statusCode);
	/* Generate Ba key to use in derivation - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(MAX_SLOT, V2XSE_CURVE_NISTP256,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Derive Rt key */
	retVal = v2xSe_deriveRtEccKeyPair(MAX_SLOT, &data1, &data2, &data3,
					SLOT_ZERO, V2XSE_RSP_WITH_PUBKEY,
					&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deriveRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP256) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP256, curveId);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP256) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP256, curveId);
		return VTEST_FAIL;
	}

/* Test Rt key for curve V2XSE_CURVE_BP256R1 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in non-zero slot */
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(NON_ZERO_SLOT, &statusCode);
	/* Generate Ba key to use in derivation - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_BP256R1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Derive Rt key */
	retVal = v2xSe_deriveRtEccKeyPair(SLOT_ZERO, &data1, &data2, &data3,
					NON_ZERO_SLOT, V2XSE_RSP_WITH_PUBKEY,
					&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deriveRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256R1, curveId);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256R1, curveId);
		return VTEST_FAIL;
	}

/* Test Rt key for curve V2XSE_CURVE_BP256T1 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in max slot */
	/* Delete existing Rt key (ignore error if key does not exist) */
	v2xSe_deleteRtEccPrivateKey(MAX_SLOT, &statusCode);
	/* Generate Ba key to use in derivation - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_BP256T1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Derive Rt key */
	retVal = v2xSe_deriveRtEccKeyPair(SLOT_ZERO, &data1, &data2, &data3,
					MAX_SLOT, V2XSE_RSP_WITH_PUBKEY,
					&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deriveRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256T1, curveId);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(MAX_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256T1, curveId);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_deriveRtEccKeyPair_overwrite(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;
	TypeInt256_t data1;
	TypeInt256_t data2;
	TypeInt256_t data3;

	/* Move to ACTIVATED state, normal operating mode, US applet */
	if (setupActivatedNormalState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Get SE info, to know max data slot available */
	retVal = v2xSe_getSeInfo(&statusCode, &seInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSeInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	if (seInfo.maxDataSlots <= NON_ZERO_SLOT) {
		printf("ERROR: Only %d slots, test needs modification\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Set up key derivation parameters */
	data1.data[0] = 1;
	data2.data[0] = 2;
	data3.data[0] = 3;

/* Test Rt key for curve V2XSE_CURVE_NISTP256 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in slot 0 */
	/* Create Rt key - may overwrite */
	retVal = v2xSe_generateRtEccKeyPair(SLOT_ZERO,
				V2XSE_CURVE_NISTP256, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Generate Ba key to use in derivation - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(MAX_SLOT, V2XSE_CURVE_NISTP256,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Derive Rt key */
	retVal = v2xSe_deriveRtEccKeyPair(MAX_SLOT, &data1, &data2, &data3,
					SLOT_ZERO, V2XSE_RSP_WITH_PUBKEY,
					&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deriveRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP256) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP256, curveId);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_NISTP256) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_NISTP256, curveId);
		return VTEST_FAIL;
	}

/* Test Rt key for curve V2XSE_CURVE_BP256R1 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in non-zero slot */
	/* Create Rt key - may overwrite */
	retVal = v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
				V2XSE_CURVE_BP256R1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Generate Ba key to use in derivation - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_BP256R1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Derive Rt key */
	retVal = v2xSe_deriveRtEccKeyPair(SLOT_ZERO, &data1, &data2, &data3,
					NON_ZERO_SLOT, V2XSE_RSP_WITH_PUBKEY,
					&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deriveRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256R1, curveId);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256R1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256R1, curveId);
		return VTEST_FAIL;
	}

/* Test Rt key for curve V2XSE_CURVE_BP256T1 can be derived and retrieved */
/* Test Rt key can be derived and retrieved in max slot */
	/* Create Rt key - may overwrite */
	retVal = v2xSe_generateRtEccKeyPair(MAX_SLOT,
				V2XSE_CURVE_BP256T1, &statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Generate Ba key to use in derivation - may overwrite */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_BP256T1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Derive Rt key */
	retVal = v2xSe_deriveRtEccKeyPair(SLOT_ZERO, &data1, &data2, &data3,
					MAX_SLOT, V2XSE_RSP_WITH_PUBKEY,
					&statusCode, &curveId, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deriveRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256T1, curveId);
		return VTEST_FAIL;
	}
	/* Retrive Rt public key */
	retVal = v2xSe_getRtEccPublicKey(MAX_SLOT, &statusCode, &curveId,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRtEccPublicKey returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify curveId is correct */
	if (curveId != V2XSE_CURVE_BP256T1) {
		printf("ERROR: Incorrect curveId, expected %d, got %d\n",
						V2XSE_CURVE_BP256T1, curveId);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_activateRtKeyForSigning(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeHash_t hash;
	TypeSignature_t signature;
	TypeLowlatencyIndicator_t fastIndicator;

	/* Create dummy hash data */
	hash.data[0] = 20;
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

	/* TODO:see above - test should return CONF until all complete */
	return VTEST_CONF;
}
